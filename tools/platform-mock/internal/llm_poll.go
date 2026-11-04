package mock

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	// llmRunIDResolution quantizes the start time the fallback run id is derived
	// from. It only applies when the instance does not report a dockerId: uptime
	// is an integer and the poll instant moves by up to a second between calls,
	// so the start time must be rounded or the id would flip every poll and
	// reset the log cursor each time.
	llmRunIDResolution = 10 * time.Second
)

// llmEnvelope is the {msg, result, error} wrapper every teellm platform
// endpoint answers with. DockerID is the instance's per-process identity: the
// mock stores the last value it saw and reads a change as "the instance was
// restarted or rebuilt".
type llmEnvelope struct {
	Msg      string          `json:"msg"`
	Result   json.RawMessage `json:"result"`
	Error    int             `json:"error"`
	DockerID string          `json:"dockerId"`
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
		// Resume from the identity that was persisted with the last poll. Without
		// this a mock restart would forget the run and stop treating a restart that
		// happened meanwhile as a new instance.
		runID: state.get().DockerID,
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
	p.PollOnceFrom(ctx, nil)
}

// PollOnceFrom is PollOnce with the log read position overridden for this pull.
// A non-nil sinceSeq is sent exactly as given and the records below the stored
// cursor are kept, which is what makes it a probe: the operator is asking what
// the interface answers at that position, not advancing the poller.
func (p *llmPoller) PollOnceFrom(ctx context.Context, sinceSeq *uint64) {
	addr := p.resolveAddr()
	if addr == "" {
		p.state.recordPollError("未发现 TEE-LLM 地址：设置 LLM_POD/LLM_NS 供 kubectl 自动发现，或用 LLM_TARGET 直接指定")
		return
	}

	hb, dockerID, err := p.fetchHeartbeat(ctx, addr)
	if err != nil {
		// A stale Pod IP is the most common cause; drop it and rediscover next
		// poll instead of hammering an address nothing answers.
		p.invalidateAddr(addr)
		p.state.recordPollError("心跳失败: " + err.Error())
		return
	}
	p.state.recordHeartbeat(hb.Model, hb.UptimeSeconds, dockerID)

	if err := p.pullLogs(ctx, addr, dockerID, hb.UptimeSeconds, sinceSeq); err != nil {
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

// fetchHeartbeat asks for liveness and also returns the instance id the answer
// carried, which is what the panel displays and what the log pull keys restarts
// on.
func (p *llmPoller) fetchHeartbeat(ctx context.Context, addr string) (llmHeartbeatResult, string, error) {
	var out llmHeartbeatResult
	env, err := p.post(ctx, addr, "/v1/llm/heartbeat", struct{}{})
	if err != nil {
		return out, "", err
	}
	if err := json.Unmarshal(env.Result, &out); err != nil {
		return out, env.DockerID, fmt.Errorf("解析心跳结果失败: %w", err)
	}
	if !out.Alive {
		return out, env.DockerID, errors.New("实例报告 alive=false")
	}
	return out, env.DockerID, nil
}

// pullLogs reads what the instance has beyond the stored cursor. sinceSeq is
// the first seq to return, so the request carries cursor+1; the stored cursor
// then advances to the instance's latestSeq. A non-nil override is used as the
// request's sinceSeq instead, and the response is not filtered against the
// stored cursor, so a probe can inspect records that were already consumed.
func (p *llmPoller) pullLogs(ctx context.Context, addr, dockerID string, uptimeSeconds int64, sinceSeq *uint64) error {
	// The instance's dockerId is an exact run identity: it changes on every
	// process start and nowhere else. Fall back to the uptime-quantized id only
	// for an instance that does not report one, so an older teellm still gets
	// restart detection.
	runID := dockerID
	if runID == "" {
		runID = llmRunID(time.Now(), uptimeSeconds)
	}
	p.mu.Lock()
	previousRun := p.runID
	p.runID = runID
	p.mu.Unlock()

	cursor := p.state.get().LogCursor
	if previousRun != "" && previousRun != runID {
		// The instance restarted: its seq numbering started over, so the records
		// collected so far belong to a process that no longer exists. Drop them
		// along with the cursor; keeping them would show several runs' seq numbers
		// interleaved in one list and read as duplicates.
		p.state.resetLogCursor()
		p.logs.reset()
		log.Printf("TEE-LLM 实例已更换（%s → %s），已清空此前收集的日志", previousRun, runID)
		cursor = 0
	}

	// sinceSeq is inclusive: the cursor stores the last seq consumed, so the
	// next record to ask for is the one immediately after it. An override is
	// sent as typed, including 0, which the instance answers from its oldest
	// retained record.
	from := cursor + 1
	probe := sinceSeq != nil
	if probe {
		from = *sinceSeq
	}
	env, err := p.post(ctx, addr, "/v1/llm/log", map[string]any{
		"sinceSeq": from,
		"limit":    llmLogPageSize,
	})
	if err != nil {
		return err
	}
	var result llmLogPullResult
	if err := json.Unmarshal(env.Result, &result); err != nil {
		return fmt.Errorf("解析日志结果失败: %w", err)
	}
	if result.LatestSeq < cursor {
		// Belt and braces for a restart the run id could not tell apart: the seq
		// numbering moved backwards, so the stored records are from another run.
		p.state.resetLogCursor()
		p.logs.reset()
		cursor = 0
	}

	entries := make([]taaLogEntry, 0, len(result.Entries))
	for _, entry := range result.Entries {
		// The normal pull only adds what is new to the store; a probe keeps what
		// the instance returned, which is the whole point of naming sinceSeq.
		if !probe && entry.Seq <= cursor {
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
	env, err := p.post(ctx, addr, "/v1/llm/getAttestation", map[string]any{"requestId": requestID})
	if err != nil {
		return llmAttestationState{}, err
	}
	var result llmAttestationResult
	if err := json.Unmarshal(env.Result, &result); err != nil {
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

// post calls one platform→LLM endpoint and returns the whole envelope: the
// caller needs the result body and the instance id that rides beside it.
func (p *llmPoller) post(ctx context.Context, addr, path string, payload any) (llmEnvelope, error) {
	var env llmEnvelope
	body, err := json.Marshal(payload)
	if err != nil {
		return env, fmt.Errorf("编码请求失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr+path, bytes.NewReader(body))
	if err != nil {
		return env, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return env, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return env, fmt.Errorf("读取响应失败: %w", err)
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return env, fmt.Errorf("响应不是 {msg,result,error}: HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || env.Error != 0 {
		msg := env.Msg
		if strings.TrimSpace(msg) == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return env, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	return env, nil
}

// llmRunID identifies one run of the instance by when it started. It is the
// fallback for an instance whose response carries no dockerId; uptime is not an
// identity, so the value is quantized into a change detector, not a name.
func llmRunID(now time.Time, uptimeSeconds int64) string {
	if uptimeSeconds < 0 {
		uptimeSeconds = 0
	}
	start := now.UTC().Add(-time.Duration(uptimeSeconds) * time.Second)
	return strconv.FormatInt(start.Truncate(llmRunIDResolution).Unix(), 10)
}
