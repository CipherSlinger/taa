package mock

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/CipherSlinger/teetls"
	"github.com/CipherSlinger/teetls/pkg/csvattest"
)

const (
	// consoleCookieName is the session cookie. The prefix keeps it distinct from
	// any cookie the TAA console page might set on the same origin.
	consoleCookieName = "pm_llm_session"
	// consoleSessionTTL is the idle window, slid forward on every authenticated
	// request. Eight hours covers a working day without forcing a re-login.
	consoleSessionTTL = 8 * time.Hour
	// consoleUserRole is what the UI displays beside the account name. The mock
	// has one account, so the role is fixed rather than stored.
	consoleUserRole = "管理员"

	consoleMaxLoginFailures = 5
	consoleLockoutDuration  = 60 * time.Second

	// consoleTLSDefaultPort is the TEE-LLM secure listener. The instance's
	// plaintext platform port is different and is polled, not inferred.
	consoleTLSDefaultPort = "18443"
	// consoleGenerateTimeout matches the production inference deadline: a cold
	// model load is the dominant term and the service was tuned around 120s.
	consoleGenerateTimeout = 120 * time.Second
	// consoleHandshakeTimeout bounds the diagnostic dial only. A handshake is
	// independent of model state, so it must not inherit the inference deadline.
	consoleHandshakeTimeout = 30 * time.Second

	consoleHistoryCapacity = 200
	consoleLatencyCapacity = 200
	// consoleRecentLatencyLimit is how many points the overview chart receives;
	// the UI draw width does not benefit from more.
	consoleRecentLatencyLimit = 60
	consolePromptPreviewRunes = 120
)

// consoleTLSSettings is the mutable half of the TEE-TLS client configuration.
// Timeout stays fixed: it is a consequence of cold-load behaviour, not a knob.
type consoleTLSSettings struct {
	Mode            string `json:"mode"`
	SkipChainVerify bool   `json:"skipChainVerify"`
}

// consoleHandshake is the diagnostic record of one TEE-TLS handshake. It is
// built from the connection's own peer material, never from a self-report.
type consoleHandshake struct {
	OK             bool   `json:"ok"`
	At             string `json:"at"`
	ElapsedMs      int64  `json:"elapsedMs"`
	MeasurementHex string `json:"measurementHex"`
	PublicKeyBound bool   `json:"publicKeyBound"`
	CertSubject    string `json:"certSubject"`
	Error          string `json:"error"`
}

type consoleLatency struct {
	At string `json:"at"`
	Ms int64  `json:"ms"`
	OK bool   `json:"ok"`
}

type consoleLatencyStats struct {
	Last int64 `json:"last"`
	P50  int64 `json:"p50"`
	P95  int64 `json:"p95"`
	Avg  int64 `json:"avg"`
}

type consoleMetricsResponse struct {
	Requests  uint64              `json:"requests"`
	Success   uint64              `json:"success"`
	Failures  uint64              `json:"failures"`
	LatencyMs consoleLatencyStats `json:"latencyMs"`
}

type consoleHistoryEntry struct {
	RequestID     string `json:"requestId"`
	At            string `json:"at"`
	Model         string `json:"model"`
	ElapsedMs     int64  `json:"elapsedMs"`
	OK            bool   `json:"ok"`
	Status        string `json:"status"`
	PromptChars   int    `json:"promptChars"`
	ResponseChars int    `json:"responseChars"`
	PromptPreview string `json:"promptPreview"`
	Error         string `json:"error"`
}

type consoleHistoryResponse struct {
	Entries []consoleHistoryEntry `json:"entries"`
	Total   int                   `json:"total"`
}

type consoleHistoryClearResponse struct {
	OK      bool `json:"ok"`
	Cleared int  `json:"cleared"`
}

// llmConsole is the state behind the TEE-LLM console tab. Everything here is
// either derived from a call the mock made or a session it minted; nothing is
// persisted, because the console is an operator view of one running mock.
type llmConsole struct {
	cfg    Config
	poller *llmPoller
	state  *llmStateStore

	user     string
	password string

	// now is a seam for the session and lockout tests; production leaves it at
	// time.Now.
	now func() time.Time

	mu            sync.RWMutex
	sessions      map[string]*consoleSession
	attempts      map[string]*consoleLoginAttempt
	settings      consoleTLSSettings
	history       []consoleHistoryEntry
	latencies     []consoleLatency
	requests      uint64
	successes     uint64
	failures      uint64
	lastHandshake consoleHandshake
}

func newLLMConsole(cfg Config, poller *llmPoller, state *llmStateStore) *llmConsole {
	cfg = cfg.withDefaults()
	return &llmConsole{
		cfg:      cfg,
		poller:   poller,
		state:    state,
		user:     cfg.ConsoleUser,
		password: cfg.ConsolePassword,
		now:      time.Now,
		sessions: make(map[string]*consoleSession),
		attempts: make(map[string]*consoleLoginAttempt),
		// Permissive without chain anchoring is the only combination that works
		// against an instance whose vendor HRK/HSK certificates are not on the
		// mock host. It is also what every other TAA-side TEE-TLS client uses.
		settings: consoleTLSSettings{Mode: string(teetls.ModePermissive), SkipChainVerify: true},
	}
}

func consoleRequireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 " + method + " 方法"})
	return false
}

// normalizeConsoleTLSHost accepts a bare host, host:port, or a URL and returns
// host:port. A missing port gets the secure listener's default rather than
// whatever scheme the operator pasted.
func normalizeConsoleTLSHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		raw = u.Host
	}
	raw = strings.TrimSuffix(raw, "/")
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if host == "" {
			host = "127.0.0.1"
		}
		if port == "" {
			port = consoleTLSDefaultPort
		}
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(strings.Trim(raw, "[]"), consoleTLSDefaultPort)
}

// plaintextEndpoint is the polled platform URL. It prefers the stored address
// so an overview refresh cannot trigger kubectl discovery on its own.
func (c *llmConsole) plaintextEndpoint() string {
	if addr := c.state.get().Address; addr != "" {
		return addr
	}
	return normalizeLLMBaseURL(c.cfg.LLMTarget)
}

// teeTLSEndpoint resolves the secure listener. It derives the host from the
// poller's target and swaps in the secure port, because TEE-LLM has no separate
// discovery record: the deployment names one pod and both listeners sit in it.
func (c *llmConsole) teeTLSEndpoint() string {
	if host := normalizeConsoleTLSHost(c.cfg.ConsoleTLSHost); host != "" {
		return host
	}
	base := c.plaintextEndpoint()
	if base == "" {
		// Last resort: ask the poller, which may run pod discovery. This only
		// happens when neither an explicit endpoint nor a polled address exists,
		// i.e. before the first successful poll.
		base = c.poller.resolveAddr()
	}
	if base == "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return net.JoinHostPort(u.Hostname(), consoleTLSDefaultPort)
}

func (c *llmConsole) settingsSnapshot() consoleTLSSettings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.settings
}

// newTEEHTTPClient builds a client for the current settings. Recording the
// handshake inside DialTLSContext means every call reports the evidence it
// actually negotiated, instead of a separately probed connection that could
// succeed while the real call fails.
func (c *llmConsole) newTEEHTTPClient(settings consoleTLSSettings) *http.Client {
	cfg := &teetls.Config{
		Mode:            teetls.AttestationMode(settings.Mode),
		SkipChainVerify: settings.SkipChainVerify,
		Timeout:         consoleGenerateTimeout,
	}
	transport := teetls.NewHTTPTransport(cfg)
	inner := transport.DialTLSContext
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		started := time.Now()
		conn, err := inner(ctx, network, addr)
		// The transport's signature is net.Conn, but its dialer is ours and only
		// ever returns a *teetls.Conn; a failed assertion therefore reads as "no
		// peer material" rather than as a second error.
		teeConn, _ := conn.(*teetls.Conn)
		c.recordHandshake(evaluateHandshake(teeConn, err, time.Since(started)))
		return conn, err
	}
	return &http.Client{Transport: transport, Timeout: consoleGenerateTimeout}
}

// evaluateHandshake reads the peer material while the connection is still
// open. The measurement is masked in the report, so it is unmasked with the
// report's own anonce; the public-key binding is recomputed from the peer
// certificate rather than inherited from the verifier's verdict, so the panel
// shows the same answer in permissive and insecure modes.
func evaluateHandshake(conn *teetls.Conn, err error, elapsed time.Duration) consoleHandshake {
	hs := consoleHandshake{
		OK:        err == nil && conn != nil,
		At:        time.Now().Format(time.RFC3339),
		ElapsedMs: elapsed.Milliseconds(),
	}
	if err != nil {
		hs.Error = err.Error()
		return hs
	}
	if conn == nil {
		hs.Error = "握手未返回连接"
		return hs
	}
	cert := conn.PeerCertificate()
	if cert == nil {
		hs.Error = "对端未提供证书"
		return hs
	}
	hs.CertSubject = cert.Subject.String()
	evidence := conn.PeerEvidence()
	if evidence == nil || len(evidence.Report) < csvattest.ReportSize {
		return hs
	}
	report, parseErr := csvattest.ParseReport(evidence.Report)
	if parseErr != nil {
		hs.Error = "解析证明报告失败: " + parseErr.Error()
		return hs
	}
	hs.MeasurementHex = hex.EncodeToString(report.Digest)
	digest := teetls.ComputePublicKeySM3(cert.RawSubjectPublicKeyInfo)
	hs.PublicKeyBound = len(report.UserData) >= 32 && bytes.Equal(report.UserData[:32], digest[:])
	return hs
}

func (c *llmConsole) recordHandshake(hs consoleHandshake) {
	c.mu.Lock()
	c.lastHandshake = hs
	c.mu.Unlock()
}

// diagnoseHandshake opens one connection purely to inspect the peer, then
// closes it. It is used where the caller has no inference call to piggyback on
// (the attestation view and its verify button).
func (c *llmConsole) diagnoseHandshake(ctx context.Context) consoleHandshake {
	endpoint := c.teeTLSEndpoint()
	if endpoint == "" {
		return consoleHandshake{
			At:    time.Now().Format(time.RFC3339),
			Error: "未发现 TEE-TLS 端点：请设置 TEELLM_TLS_ENDPOINT，或让 LLM_TARGET/LLM_POD 指向可发现的实例",
		}
	}
	settings := c.settingsSnapshot()
	cfg := &teetls.Config{
		Mode:            teetls.AttestationMode(settings.Mode),
		SkipChainVerify: settings.SkipChainVerify,
		Timeout:         consoleHandshakeTimeout,
	}
	dialCtx, cancel := context.WithTimeout(ctx, consoleHandshakeTimeout)
	defer cancel()

	started := time.Now()
	conn, err := teetls.DialContext(dialCtx, "tcp", endpoint, cfg)
	elapsed := time.Since(started)
	hs := evaluateHandshake(conn, err, elapsed)
	if conn != nil {
		_ = conn.Close()
	}
	c.recordHandshake(hs)
	return hs
}

// ---------------------------------------------------------------------------
// Overview

type consoleInstanceOverview struct {
	Address       string `json:"address"`
	Reachable     bool   `json:"reachable"`
	Model         string `json:"model"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	DockerID      string `json:"dockerId"`
	HeartbeatAt   string `json:"heartbeatAt"`
	LastError     string `json:"lastError"`
	PollSeconds   int    `json:"pollSeconds"`
}

type consoleTEETLSOverview struct {
	Endpoint        string           `json:"endpoint"`
	Mode            string           `json:"mode"`
	SkipChainVerify bool             `json:"skipChainVerify"`
	LastHandshake   consoleHandshake `json:"lastHandshake"`
}

type consoleOverviewResponse struct {
	Instance        consoleInstanceOverview `json:"instance"`
	TeeTLS          consoleTEETLSOverview   `json:"teeTLS"`
	Metrics         consoleMetricsResponse  `json:"metrics"`
	RecentLatencies []consoleLatency        `json:"recentLatencies"`
}

func (c *llmConsole) handleOverview(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	polled := c.state.get()
	settings := c.settingsSnapshot()

	c.mu.RLock()
	handshake := c.lastHandshake
	requests, successes, failures := c.requests, c.successes, c.failures
	latencies := append([]consoleLatency(nil), c.latencies...)
	c.mu.RUnlock()

	successLatencies := make([]int64, 0, len(latencies))
	for _, sample := range latencies {
		if sample.OK {
			successLatencies = append(successLatencies, sample.Ms)
		}
	}
	last, p50, p95, avg := latencyStats(successLatencies)

	recent := latencies
	if len(recent) > consoleRecentLatencyLimit {
		recent = recent[len(recent)-consoleRecentLatencyLimit:]
	}
	if recent == nil {
		recent = []consoleLatency{}
	}

	writeJSON(w, http.StatusOK, consoleOverviewResponse{
		Instance: consoleInstanceOverview{
			Address:       c.plaintextEndpoint(),
			Reachable:     polled.Reachable,
			Model:         polled.Model,
			UptimeSeconds: polled.UptimeSeconds,
			DockerID:      polled.DockerID,
			HeartbeatAt:   polled.LastHeartbeatAt,
			LastError:     polled.LastError,
			PollSeconds:   c.poller.pollSeconds(),
		},
		TeeTLS: consoleTEETLSOverview{
			Endpoint:        c.teeTLSEndpoint(),
			Mode:            settings.Mode,
			SkipChainVerify: settings.SkipChainVerify,
			LastHandshake:   handshake,
		},
		Metrics: consoleMetricsResponse{
			Requests: requests,
			Success:  successes,
			Failures: failures,
			LatencyMs: consoleLatencyStats{
				Last: last,
				P50:  p50,
				P95:  p95,
				Avg:  avg,
			},
		},
		RecentLatencies: recent,
	})
}

// latencyStats works on successful samples only. Failures are recorded in the
// counters and the history but must not pull the percentiles down: a timeout is
// not a slow success.
func latencyStats(samples []int64) (last, p50, p95, avg int64) {
	n := len(samples)
	if n == 0 {
		return 0, 0, 0, 0
	}
	last = samples[n-1]
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p50 = percentile(sorted, 50)
	p95 = percentile(sorted, 95)
	var sum int64
	for _, v := range sorted {
		sum += v
	}
	return last, p50, p95, sum / int64(n)
}

// percentile is nearest-rank: ceil(p/100 * n) - 1, clamped. With one sample
// every percentile is that sample, which is what an operator expects from a
// freshly started console.
func percentile(sorted []int64, p int) int64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	idx := (p*n+99)/100 - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

// ---------------------------------------------------------------------------
// Generate

type consoleGenerateRequest struct {
	Prompt    string         `json:"prompt"`
	Model     string         `json:"model,omitempty"`
	System    string         `json:"system,omitempty"`
	Options   map[string]any `json:"options,omitempty"`
	RequestID string         `json:"requestId,omitempty"`
}

type consoleGenerateResponse struct {
	RequestID    string `json:"requestId"`
	Status       string `json:"status"`
	Model        string `json:"model,omitempty"`
	Text         string `json:"text,omitempty"`
	ElapsedMs    int64  `json:"elapsedMs"`
	HTTPStatus   int    `json:"httpStatus"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// consoleGenerateFailure is the 502 shape: no upstream response existed, so
// httpStatus is 0 and the field is named error, matching the contract.
type consoleGenerateFailure struct {
	RequestID  string `json:"requestId"`
	Status     string `json:"status"`
	ElapsedMs  int64  `json:"elapsedMs"`
	HTTPStatus int    `json:"httpStatus"`
	Error      string `json:"error"`
}

type consoleUpstreamGenerateRequest struct {
	ProtocolVersion string         `json:"protocolVersion"`
	RequestID       string         `json:"requestId"`
	Model           string         `json:"model,omitempty"`
	Prompt          string         `json:"prompt"`
	Options         map[string]any `json:"options,omitempty"`
}

type consoleUpstreamGenerateResponse struct {
	ProtocolVersion string `json:"protocolVersion"`
	RequestID       string `json:"requestId"`
	Status          string `json:"status"`
	ErrorMessage    string `json:"errorMessage,omitempty"`
	Model           string `json:"model,omitempty"`
	Text            string `json:"text,omitempty"`
}

func newConsoleRequestID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return "console-" + hex.EncodeToString(raw[:])
	}
	return "console-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func (c *llmConsole) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodPost) {
		return
	}
	var body consoleGenerateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误: " + err.Error()})
		return
	}
	if strings.TrimSpace(body.Prompt) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prompt 不能为空"})
		return
	}

	requestID := strings.TrimSpace(body.RequestID)
	if requestID == "" {
		requestID = newConsoleRequestID()
	}
	prompt := body.Prompt
	if strings.TrimSpace(body.System) != "" {
		// teellm-protocol/v1 has no system field: the gateway treats the prompt
		// as opaque text. Folding the system instruction in front keeps the
		// operator's intent without inventing a protocol extension the instance
		// would ignore.
		prompt = body.System + "\n\n" + body.Prompt
	}
	options := body.Options
	if len(options) == 0 {
		// Deterministic by default so a console replay can be compared with an
		// audit run; an explicit options object is passed through untouched.
		options = map[string]any{"temperature": 0}
	}

	endpoint := c.teeTLSEndpoint()
	if endpoint == "" {
		elapsed := int64(0)
		c.recordGenerate(requestID, body.Model, prompt, 0, false, "ERROR", elapsed, "未发现 TEE-TLS 端点")
		writeJSON(w, http.StatusBadGateway, consoleGenerateFailure{
			RequestID:  requestID,
			Status:     "ERROR",
			ElapsedMs:  elapsed,
			HTTPStatus: 0,
			Error:      "未发现 TEE-TLS 端点：请设置 TEELLM_TLS_ENDPOINT，或让 LLM_TARGET/LLM_POD 指向可发现的实例",
		})
		return
	}

	payload, err := json.Marshal(consoleUpstreamGenerateRequest{
		ProtocolVersion: "teellm-protocol/v1",
		RequestID:       requestID,
		Model:           body.Model,
		Prompt:          prompt,
		Options:         options,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "编码请求失败: " + err.Error()})
		return
	}

	client := c.newTEEHTTPClient(c.settingsSnapshot())
	ctx, cancel := context.WithTimeout(r.Context(), consoleGenerateTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+endpoint+"/v1/llm/generate", bytes.NewReader(payload))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "构建请求失败: " + err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	started := time.Now()
	resp, err := client.Do(req)
	elapsedMs := time.Since(started).Milliseconds()
	if err != nil {
		c.recordGenerate(requestID, body.Model, prompt, 0, false, "ERROR", elapsedMs, err.Error())
		writeJSON(w, http.StatusBadGateway, consoleGenerateFailure{
			RequestID:  requestID,
			Status:     "ERROR",
			ElapsedMs:  elapsedMs,
			HTTPStatus: 0,
			Error:      err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var upstream consoleUpstreamGenerateResponse
	_ = json.Unmarshal(raw, &upstream)

	status := strings.TrimSpace(upstream.Status)
	if status == "" {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			status = "SUCCESS"
		} else {
			status = "HTTP_ERROR"
		}
	}
	errorMessage := strings.TrimSpace(upstream.ErrorMessage)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if errorMessage == "" && readErr == nil {
			errorMessage = "上游返回 HTTP " + strconv.Itoa(resp.StatusCode)
			if trimmed := strings.TrimSpace(string(raw)); trimmed != "" {
				errorMessage += ": " + truncateRunes(trimmed, consolePromptPreviewRunes)
			}
		}
	}
	ok := resp.StatusCode == http.StatusOK && status == "SUCCESS"

	model := upstream.Model
	if model == "" {
		model = body.Model
	}
	if model == "" {
		model = c.state.get().Model
	}

	c.recordGenerate(requestID, model, prompt, len([]rune(upstream.Text)), ok, status, elapsedMs, errorMessage)
	writeJSON(w, http.StatusOK, consoleGenerateResponse{
		RequestID:    requestID,
		Status:       status,
		Model:        model,
		Text:         upstream.Text,
		ElapsedMs:    elapsedMs,
		HTTPStatus:   resp.StatusCode,
		ErrorMessage: errorMessage,
	})
}

// recordGenerate updates the counters, the latency ring and the history in one
// critical section so the three views can never disagree about one call.
func (c *llmConsole) recordGenerate(requestID, model, prompt string, responseChars int, ok bool, status string, elapsedMs int64, errMsg string) {
	now := c.now()
	at := now.Format(time.RFC3339)

	c.mu.Lock()
	c.requests++
	if ok {
		c.successes++
	} else {
		c.failures++
	}
	c.latencies = append(c.latencies, consoleLatency{At: at, Ms: elapsedMs, OK: ok})
	if len(c.latencies) > consoleLatencyCapacity {
		c.latencies = append([]consoleLatency(nil), c.latencies[len(c.latencies)-consoleLatencyCapacity:]...)
	}
	c.history = append(c.history, consoleHistoryEntry{
		RequestID:     requestID,
		At:            at,
		Model:         model,
		ElapsedMs:     elapsedMs,
		OK:            ok,
		Status:        status,
		PromptChars:   utf8.RuneCountInString(prompt),
		ResponseChars: responseChars,
		PromptPreview: truncateRunes(prompt, consolePromptPreviewRunes),
		Error:         errMsg,
	})
	if len(c.history) > consoleHistoryCapacity {
		c.history = append([]consoleHistoryEntry(nil), c.history[len(c.history)-consoleHistoryCapacity:]...)
	}
	c.mu.Unlock()
}

func truncateRunes(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	count := 0
	for i := range s {
		if count == limit {
			return s[:i]
		}
		count++
	}
	return s
}

// ---------------------------------------------------------------------------
// History

func (c *llmConsole) handleHistory(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > consoleHistoryCapacity {
		limit = consoleHistoryCapacity
	}

	c.mu.RLock()
	total := len(c.history)
	// Newest first: the panel opens on the most recent call, and limit is a
	// window over the tail rather than the head.
	start := total - limit
	if start < 0 {
		start = 0
	}
	entries := make([]consoleHistoryEntry, 0, total-start)
	for i := total - 1; i >= start; i-- {
		entries = append(entries, c.history[i])
	}
	c.mu.RUnlock()

	if entries == nil {
		entries = []consoleHistoryEntry{}
	}
	writeJSON(w, http.StatusOK, consoleHistoryResponse{Entries: entries, Total: total})
}

func (c *llmConsole) handleHistoryClear(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodPost) {
		return
	}
	c.mu.Lock()
	cleared := len(c.history)
	c.history = nil
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, consoleHistoryClearResponse{OK: true, Cleared: cleared})
}

// ---------------------------------------------------------------------------
// Attestation

// consoleAttestationResponse keeps the existing {msg, result, error} envelope
// and adds the TEE-TLS handshake beside it, so the old panel code keeps
// decoding the same shape.
type consoleAttestationResponse struct {
	Msg    string           `json:"msg"`
	Result any              `json:"result"`
	Error  int              `json:"error"`
	TeeTLS consoleHandshake `json:"teeTLS"`
}

func (c *llmConsole) handleAttestation(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodPost) {
		return
	}
	// The report is a plaintext-endpoint call bounded like the existing handler;
	// the handshake has its own timeout so a slow report does not hide it.
	ctx, cancel := context.WithTimeout(r.Context(), 3*llmRequestTimeout)
	defer cancel()

	attestation, err := c.poller.FetchAttestation(ctx)
	handshake := c.diagnoseHandshake(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, consoleAttestationResponse{
			Msg:    "获取远程证明失败: " + err.Error(),
			Result: nil,
			Error:  http.StatusBadGateway,
			TeeTLS: handshake,
		})
		return
	}
	writeJSON(w, http.StatusOK, consoleAttestationResponse{
		Msg:    "success",
		Result: attestation,
		Error:  0,
		TeeTLS: handshake,
	})
}

// ---------------------------------------------------------------------------
// Health

type consoleHealthResponse struct {
	OK         bool   `json:"ok"`
	HTTPStatus int    `json:"httpStatus"`
	ElapsedMs  int64  `json:"elapsedMs"`
	Error      string `json:"error"`
}

func (c *llmConsole) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	endpoint := c.teeTLSEndpoint()
	if endpoint == "" {
		writeJSON(w, http.StatusOK, consoleHealthResponse{
			OK:    false,
			Error: "未发现 TEE-TLS 端点",
		})
		return
	}
	client := c.newTEEHTTPClient(c.settingsSnapshot())
	ctx, cancel := context.WithTimeout(r.Context(), consoleGenerateTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+endpoint+"/v1/llm/healthz", nil)
	if err != nil {
		writeJSON(w, http.StatusOK, consoleHealthResponse{OK: false, Error: err.Error()})
		return
	}
	started := time.Now()
	resp, err := client.Do(req)
	elapsedMs := time.Since(started).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusOK, consoleHealthResponse{OK: false, ElapsedMs: elapsedMs, Error: err.Error()})
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	out := consoleHealthResponse{OK: resp.StatusCode == http.StatusOK, HTTPStatus: resp.StatusCode, ElapsedMs: elapsedMs}
	if !out.OK {
		out.Error = strings.TrimSpace(string(raw))
		if out.Error == "" {
			out.Error = "HTTP " + strconv.Itoa(resp.StatusCode)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Settings

type consoleModelInfo struct {
	Name           string `json:"name"`
	ParameterSize  string `json:"parameterSize"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

type consoleSettingsSession struct {
	TTLSeconds int    `json:"ttlSeconds"`
	User       string `json:"user"`
}

type consoleSettingsTLS struct {
	Mode            string `json:"mode"`
	SkipChainVerify bool   `json:"skipChainVerify"`
	TimeoutSeconds  int    `json:"timeoutSeconds"`
}

type consoleSettingsResponse struct {
	Endpoint          string                 `json:"endpoint"`
	PlaintextEndpoint string                 `json:"plaintextEndpoint"`
	TeeTLS            consoleSettingsTLS     `json:"teeTLS"`
	Session           consoleSettingsSession `json:"session"`
	Models            []consoleModelInfo     `json:"models"`
	ActiveModel       string                 `json:"activeModel"`
}

// consoleModelCatalog mirrors teellm/configs/models.json. teellm exposes no
// catalog endpoint, so the mock cannot discover it; the mirror is display-only
// and the active model is always read from the instance's own heartbeat.
var consoleModelCatalog = []consoleModelInfo{
	{Name: "qwen2.5-coder:0.5b", ParameterSize: "0.5B", TimeoutSeconds: 30},
	{Name: "qwen2.5-coder:1.5b", ParameterSize: "1.5B", TimeoutSeconds: 45},
	{Name: "qwen2.5-coder:3b", ParameterSize: "3B", TimeoutSeconds: 60},
	{Name: "qwen2.5-coder:7b", ParameterSize: "7B", TimeoutSeconds: 90},
	{Name: "qwen3:8b", ParameterSize: "8B", TimeoutSeconds: 120},
	{Name: "qwen3:14b", ParameterSize: "14B", TimeoutSeconds: 180},
}

func (c *llmConsole) settingsResponse() consoleSettingsResponse {
	settings := c.settingsSnapshot()
	active := c.state.get().Model
	if active == "" {
		active = "qwen2.5-coder:7b"
	}
	models := append([]consoleModelInfo(nil), consoleModelCatalog...)
	return consoleSettingsResponse{
		Endpoint:          c.teeTLSEndpoint(),
		PlaintextEndpoint: c.plaintextEndpoint(),
		TeeTLS: consoleSettingsTLS{
			Mode:            settings.Mode,
			SkipChainVerify: settings.SkipChainVerify,
			TimeoutSeconds:  int(consoleGenerateTimeout.Seconds()),
		},
		Session: consoleSettingsSession{
			TTLSeconds: int(consoleSessionTTL.Seconds()),
			User:       c.user,
		},
		Models:      models,
		ActiveModel: active,
	}
}

// handleSettings dispatches the one settings path, which reads with GET and
// writes with POST. ServeMux allows a single registration per pattern, so the
// method split lives here instead of in two registrations.
func (c *llmConsole) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.handleSettingsGet(w, r)
	case http.MethodPost:
		c.handleSettingsUpdate(w, r)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET 或 POST 方法"})
	}
}

func (c *llmConsole) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, c.settingsResponse())
}

func (c *llmConsole) handleSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		TeeTLS struct {
			Mode            *string `json:"mode"`
			SkipChainVerify *bool   `json:"skipChainVerify"`
		} `json:"teeTLS"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误: " + err.Error()})
		return
	}

	c.mu.Lock()
	if body.TeeTLS.Mode != nil {
		mode := string(teetls.AttestationMode(strings.TrimSpace(*body.TeeTLS.Mode)))
		if mode != string(teetls.ModeStrict) && mode != string(teetls.ModePermissive) {
			c.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "不支持的证明模式: " + mode})
			return
		}
		c.settings.Mode = mode
	}
	if body.TeeTLS.SkipChainVerify != nil {
		c.settings.SkipChainVerify = *body.TeeTLS.SkipChainVerify
	}
	c.mu.Unlock()

	writeJSON(w, http.StatusOK, c.settingsResponse())
}
