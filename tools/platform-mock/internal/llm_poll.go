package mock

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// defaultLLMPollSeconds is how often the platform calls the LLM. The
	// instance answers a heartbeat from memory, so the cadence only bounds how
	// quickly the panel notices a restart; it is not an inference load.
	defaultLLMPollSeconds = 10
	// llmLogPageSize is the per-poll log page. The instance clamps anything
	// above 1000, and 500 keeps one page small enough that a busy first poll
	// cannot dominate the response.
	llmLogPageSize = 500
	// llmRequestTimeout bounds one platform→LLM call.
	llmRequestTimeout = 5 * time.Second
	// llmRunIDResolution quantizes the start time the run id is derived from.
	// Uptime is an integer and the poll instant moves by up to a second between
	// calls, so the start time must be rounded or the id would flip every poll
	// and reset the log cursor each time.
	llmRunIDResolution = 10 * time.Second
)

// llmEnvelope is the {msg, result, error} wrapper every teellm platform
// endpoint answers with.
type llmEnvelope struct {
	Msg    string          `json:"msg"`
	Result json.RawMessage `json:"result"`
	Error  int             `json:"error"`
}

type llmHeartbeatResult struct {
	Alive         bool   `json:"alive"`
	Model         string `json:"model"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
}

type llmLogPullEntry struct {
	Seq     uint64 `json:"seq"`
	Message string `json:"message"`
}

type llmLogPullResult struct {
	Entries   []llmLogPullEntry `json:"entries"`
	LatestSeq uint64            `json:"latestSeq"`
	Dropped   bool              `json:"dropped"`
}

type llmAttestationResult struct {
	RequestID         string `json:"requestId"`
	VerifiedPass      bool   `json:"verifiedPass"`
	Attestation       string `json:"attestation"`
	AttestationValues string `json:"attestationValues"`
}

// llmPoller is the platform's half of every platform↔TEE-LLM interface. The
// instance never reports out, so liveness, logs and the attestation report all
// exist here only because this loop asked for them.
type llmPoller struct {
	cfg    Config
	state  *llmStateStore
	logs   *taaLogStore
	client *http.Client

	mu    sync.Mutex
	addr  string
	runID string
}

func newLLMPoller(cfg Config, state *llmStateStore, logs *taaLogStore) *llmPoller {
	return &llmPoller{
		cfg:    cfg,
		state:  state,
		logs:   logs,
		client: &http.Client{Timeout: llmRequestTimeout},
	}
}

// Start polls until ctx is cancelled. The first poll runs immediately: a mock
// started after the LLM should show it without waiting a full interval.
func (p *llmPoller) Start(ctx context.Context) {
	interval := time.Duration(p.cfg.LLMPollSeconds) * time.Second
	if interval <= 0 {
		interval = defaultLLMPollSeconds * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		p.PollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pollSeconds is the configured cadence, defaulted.
func (p *llmPoller) pollSeconds() int {
	if p.cfg.LLMPollSeconds <= 0 {
		return defaultLLMPollSeconds
	}
	return p.cfg.LLMPollSeconds
}

// PollOnce performs one heartbeat and one log pull. Exported for tests; a
// failure is recorded in the state, not returned, because the panel is the
// consumer and there is no caller to fail.
func (p *llmPoller) PollOnce(ctx context.Context) {
	addr := p.resolveAddr()
	if addr == "" {
		p.state.recordPollError("未发现 TEE-LLM 地址：设置 LLM_POD/LLM_NS 供 kubectl 自动发现，或用 LLM_TARGET 直接指定")
		return
	}

	hb, err := p.fetchHeartbeat(ctx, addr)
	if err != nil {
		// A stale Pod IP is the most common cause; drop it and rediscover next
		// poll instead of hammering an address nothing answers.
		p.invalidateAddr(addr)
		p.state.recordPollError("心跳失败: " + err.Error())
		return
	}
	p.state.recordHeartbeat(hb.Model, hb.UptimeSeconds)

	if err := p.pullLogs(ctx, addr, hb.UptimeSeconds); err != nil {
		p.state.recordLogError("日志拉取失败: " + err.Error())
	}
}

// resolveAddr returns the base URL to call, discovering it once and keeping it
// until a failure invalidates it.
func (p *llmPoller) resolveAddr() string {
	p.mu.Lock()
	addr := p.addr
	p.mu.Unlock()
	if addr != "" {
		return addr
	}

	if target := strings.TrimSpace(p.cfg.LLMTarget); target != "" {
		addr = normalizeLLMBaseURL(target)
	} else {
		addr = discoverTAAAddr(p.cfg.LLMPod, p.cfg.LLMNS, p.cfg.LLMPort)
	}
	if addr != "" {
		p.mu.Lock()
		p.addr = addr
		p.mu.Unlock()
		p.state.recordAddress(addr)
	}
	return addr
}

func (p *llmPoller) invalidateAddr(addr string) {
	p.mu.Lock()
	if p.addr == addr {
		p.addr = ""
	}
	p.mu.Unlock()
}

// normalizeLLMBaseURL accepts a bare host:port and drops a trailing slash.
func normalizeLLMBaseURL(target string) string {
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	if target == "" {
		return ""
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	return target
}

func (p *llmPoller) fetchHeartbeat(ctx context.Context, addr string) (llmHeartbeatResult, error) {
	var out llmHeartbeatResult
	raw, err := p.post(ctx, addr, "/v1/llm/heartbeat", struct{}{})
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("解析心跳结果失败: %w", err)
	}
	if !out.Alive {
		return out, errors.New("实例报告 alive=false")
	}
	return out, nil
}

// pullLogs reads everything the instance has beyond the stored cursor. The
// cursor advances to latestSeq, not to the last entry returned, so a page limit
// does not skip records: they are older than latestSeq and will be read next
// time.
func (p *llmPoller) pullLogs(ctx context.Context, addr string, uptimeSeconds int64) error {
	runID := llmRunID(time.Now(), uptimeSeconds)
	p.mu.Lock()
	previousRun := p.runID
	p.runID = runID
	p.mu.Unlock()

	cursor := p.state.get().LogCursor
	if previousRun != "" && previousRun != runID {
		// The instance restarted: its seq numbering started over, so the old
		// cursor would either stall the pull or make the new run's records look
		// like duplicates.
		p.state.resetLogCursor()
		cursor = 0
	}

	raw, err := p.post(ctx, addr, "/v1/llm/log", map[string]any{
		"sinceSeq": cursor,
		"limit":    llmLogPageSize,
	})
	if err != nil {
		return err
	}
	var result llmLogPullResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("解析日志结果失败: %w", err)
	}
	if result.LatestSeq < cursor {
		// Belt and braces for a restart the run id could not tell apart.
		p.state.resetLogCursor()
		cursor = 0
	}

	entries := make([]taaLogEntry, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if entry.Seq <= cursor {
			continue
		}
		entries = append(entries, taaLogEntry{Seq: entry.Seq, Message: entry.Message})
	}
	added := p.logs.addEntries(addr, runID, "", entries)
	p.state.recordLogPull(result.LatestSeq, added, result.Dropped)
	return nil
}

// FetchAttestation pulls the report on demand. It is not part of the polling
// loop: the report is a hardware call on the instance and changes only on
// restart, so the panel asks for it when the operator asks to see it.
func (p *llmPoller) FetchAttestation(ctx context.Context) (llmAttestationState, error) {
	addr := p.resolveAddr()
	if addr == "" {
		return llmAttestationState{}, errors.New("未发现 TEE-LLM 地址")
	}
	requestID := "mock-" + time.Now().UTC().Format("20060102T150405")
	raw, err := p.post(ctx, addr, "/v1/llm/getAttestation", map[string]any{"requestId": requestID})
	if err != nil {
		return llmAttestationState{}, err
	}
	var result llmAttestationResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return llmAttestationState{}, fmt.Errorf("解析证明结果失败: %w", err)
	}
	state := llmAttestationState{
		FetchedAt:         time.Now().Format(time.RFC3339),
		RequestID:         result.RequestID,
		VerifiedPass:      result.VerifiedPass,
		AttestationValues: result.AttestationValues,
		AttestationBase64: result.Attestation,
	}
	if result.Attestation != "" {
		attBytes, decodeErr := base64.StdEncoding.DecodeString(result.Attestation)
		if decodeErr != nil {
			state.Error = "attestation Base64 解码失败: " + decodeErr.Error()
		} else {
			state.AttestationSize = len(attBytes)
		}
	}
	p.state.setAttestation(state)
	if state.Error != "" {
		return state, errors.New(state.Error)
	}
	return state, nil
}

// post calls one platform→LLM endpoint and unwraps the envelope.
func (p *llmPoller) post(ctx context.Context, addr, path string, payload any) (json.RawMessage, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("编码请求失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	var env llmEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("响应不是 {msg,result,error}: HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || env.Error != 0 {
		msg := env.Msg
		if strings.TrimSpace(msg) == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	return env.Result, nil
}

// llmRunID identifies one run of the instance by when it started. Uptime is the
// only start-time signal the heartbeat carries and it is deliberately not an
// identity, so the value is quantized into a change detector, not a name.
func llmRunID(now time.Time, uptimeSeconds int64) string {
	if uptimeSeconds < 0 {
		uptimeSeconds = 0
	}
	start := now.UTC().Add(-time.Duration(uptimeSeconds) * time.Second)
	return strconv.FormatInt(start.Truncate(llmRunIDResolution).Unix(), 10)
}
