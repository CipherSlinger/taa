package mock

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CipherSlinger/teetls"
)

// consoleTestRig wires a console to a state store the test can seed, with a
// controllable clock. The clock is only mutated by the calling goroutine, so it
// is race-free under -race.
type consoleTestRig struct {
	console *llmConsole
	state   *llmStateStore
	clock   *time.Time
}

func newConsoleTestRig(t *testing.T, tlsEndpoint string) *consoleTestRig {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		StateDir:       dir,
		ConsoleTLSHost: tlsEndpoint,
		LLMPollSeconds: 10,
	}.withDefaults()
	state := newLLMStateStore(dir)
	logs := newTaaLogStoreAt(filepath.Join(dir, "llm-log-state.json"), 100)
	poller := newLLMPoller(cfg, state, logs)
	console := newLLMConsole(cfg, poller, state)
	clock := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	console.now = func() time.Time { return clock }
	return &consoleTestRig{console: console, state: state, clock: &clock}
}

func (r *consoleTestRig) login(t *testing.T, user, password, remote string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, user, password)
	req := httptest.NewRequest(http.MethodPost, "/api/llm/console/login", strings.NewReader(body))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	r.console.handleLogin(rec, req)
	return rec
}

// loginCookie performs a successful login and returns the session cookie.
func (r *consoleTestRig) loginCookie(t *testing.T) *http.Cookie {
	t.Helper()
	rec := r.login(t, "admin", "teellm@2026", "192.0.2.10:5555")
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body %s", rec.Code, rec.Body.String())
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == consoleCookieName {
			return cookie
		}
	}
	t.Fatal("login response carried no session cookie")
	return nil
}

func (r *consoleTestRig) call(handler http.HandlerFunc, method, target, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decodeConsoleJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

// newTEELLMTestServer starts a real TEE-TLS listener with the library's mock
// evidence provider. Using the actual handshake is the point: the console's
// evidence extraction has to survive the masking the report applies.
func newTEELLMTestServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	serverCfg := &teetls.Config{
		EvidenceProvider: teetls.NewMockEvidenceProvider(),
		Timeout:          5 * time.Second,
	}
	listener, err := teetls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("teetls listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })
	return listener.Addr().String()
}

func consoleGenerateTestHandler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/llm/generate", func(w http.ResponseWriter, r *http.Request) {
		var req consoleUpstreamGenerateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, consoleUpstreamGenerateResponse{
			ProtocolVersion: req.ProtocolVersion,
			RequestID:       req.RequestID,
			Status:          "SUCCESS",
			Model:           "qwen2.5-coder:7b",
			Text:            "Pong!",
		})
	})
	mux.HandleFunc("/v1/llm/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})
	return mux
}

func TestConsoleLoginSessionLifecycle(t *testing.T) {
	rig := newConsoleTestRig(t, "")
	cookie := rig.loginCookie(t)

	rec := rig.call(rig.console.handleSession, http.MethodGet, "/api/llm/console/session", "", cookie)
	session := decodeConsoleJSON[consoleSessionResponse](t, rec)
	if !session.Authenticated || session.User == nil || session.User.Name != "admin" {
		t.Fatalf("session = %+v", session)
	}
	if session.ExpiresAt == "" {
		t.Fatal("authenticated session has no expiresAt")
	}

	rec = rig.call(rig.console.handleLogout, http.MethodPost, "/api/llm/console/logout", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d", rec.Code)
	}
	rec = rig.call(rig.console.handleSession, http.MethodGet, "/api/llm/console/session", "", cookie)
	session = decodeConsoleJSON[consoleSessionResponse](t, rec)
	if session.Authenticated {
		t.Fatal("session survived logout")
	}
}

func TestConsoleLoginFailureCountsDownAndLocks(t *testing.T) {
	rig := newConsoleTestRig(t, "")

	for attempt := 1; attempt <= 4; attempt++ {
		rec := rig.login(t, "admin", "wrong", "192.0.2.20:1000")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", attempt, rec.Code)
		}
		body := decodeConsoleJSON[consoleLoginFailure](t, rec)
		if body.AttemptsLeft == nil || *body.AttemptsLeft != consoleMaxLoginFailures-attempt {
			t.Fatalf("attempt %d attemptsLeft = %v", attempt, body.AttemptsLeft)
		}
	}

	rec := rig.login(t, "admin", "wrong", "192.0.2.20:1000")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("fifth attempt status = %d, want 429", rec.Code)
	}
	body := decodeConsoleJSON[consoleLoginFailure](t, rec)
	if body.RetryAfterSeconds == nil || *body.RetryAfterSeconds != 60 {
		t.Fatalf("retryAfterSeconds = %v, want 60", body.RetryAfterSeconds)
	}

	// Even the correct password is refused while the source is locked.
	rec = rig.login(t, "admin", "teellm@2026", "192.0.2.20:1000")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("login during lockout status = %d, want 429", rec.Code)
	}

	// Another source is unaffected: the lock is per address.
	rec = rig.login(t, "admin", "teellm@2026", "192.0.2.21:1000")
	if rec.Code != http.StatusOK {
		t.Fatalf("other source status = %d, body %s", rec.Code, rec.Body.String())
	}

	// After the lockout window the same source may try again.
	*rig.clock = rig.clock.Add(consoleLockoutDuration + time.Second)
	rec = rig.login(t, "admin", "teellm@2026", "192.0.2.20:1000")
	if rec.Code != http.StatusOK {
		t.Fatalf("post-lockout login status = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestConsoleProtectedRoutesRequireSession(t *testing.T) {
	rig := newConsoleTestRig(t, "")
	protected := map[string]http.HandlerFunc{
		"/api/llm/console/overview":      rig.console.handleOverview,
		"/api/llm/console/generate":      rig.console.handleGenerate,
		"/api/llm/console/history":       rig.console.handleHistory,
		"/api/llm/console/history/clear": rig.console.handleHistoryClear,
		"/api/llm/console/attestation":   rig.console.handleAttestation,
		"/api/llm/console/health":        rig.console.handleHealth,
		"/api/llm/console/settings":      rig.console.handleSettings,
	}
	for path, handler := range protected {
		rec := rig.call(rig.console.requireSession(handler), http.MethodGet, path, "", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want 401", path, rec.Code)
			continue
		}
		body := decodeConsoleJSON[map[string]string](t, rec)
		if body["error"] != "未登录或会话已过期" {
			t.Errorf("%s error = %q", path, body["error"])
		}
	}
}

func TestConsoleExpiredSessionIsRejected(t *testing.T) {
	rig := newConsoleTestRig(t, "")
	cookie := rig.loginCookie(t)
	*rig.clock = rig.clock.Add(consoleSessionTTL + time.Second)
	rec := rig.call(rig.console.handleSession, http.MethodGet, "/api/llm/console/session", "", cookie)
	session := decodeConsoleJSON[consoleSessionResponse](t, rec)
	if session.Authenticated {
		t.Fatal("expired session still authenticated")
	}
}

func TestConsoleGenerateProxiesAndRecords(t *testing.T) {
	endpoint := newTEELLMTestServer(t, consoleGenerateTestHandler(t))
	rig := newConsoleTestRig(t, endpoint)
	rig.state.recordHeartbeat("qwen2.5-coder:7b", 675407, "teellm-1887112800")
	cookie := rig.loginCookie(t)

	rec := rig.call(rig.console.requireSession(rig.console.handleGenerate), http.MethodPost, "/api/llm/console/generate",
		`{"prompt":"ping","system":"be terse"}`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate status = %d, body %s", rec.Code, rec.Body.String())
	}
	generated := decodeConsoleJSON[consoleGenerateResponse](t, rec)
	if generated.Status != "SUCCESS" || generated.Text != "Pong!" || generated.HTTPStatus != http.StatusOK {
		t.Fatalf("generate response = %+v", generated)
	}
	if generated.RequestID == "" {
		t.Fatal("generate response has no requestId")
	}

	// The handshake was recorded from the real connection, including the
	// measurement the report masks and the key-binding conclusion.
	rig.console.mu.RLock()
	handshake := rig.console.lastHandshake
	rig.console.mu.RUnlock()
	if !handshake.OK || !handshake.PublicKeyBound {
		t.Fatalf("handshake = %+v", handshake)
	}
	if !strings.EqualFold(handshake.MeasurementHex, teetls.DefaultMockMeasurementHex) {
		t.Fatalf("measurement = %q, want %q", handshake.MeasurementHex, teetls.DefaultMockMeasurementHex)
	}
	if handshake.CertSubject == "" {
		t.Fatal("handshake has no certificate subject")
	}

	rec = rig.call(rig.console.requireSession(rig.console.handleHistory), http.MethodGet, "/api/llm/console/history?limit=50", "", cookie)
	history := decodeConsoleJSON[consoleHistoryResponse](t, rec)
	if history.Total != 1 || len(history.Entries) != 1 {
		t.Fatalf("history = %+v", history)
	}
	entry := history.Entries[0]
	if !entry.OK || entry.Status != "SUCCESS" || entry.ResponseChars != len("Pong!") {
		t.Fatalf("history entry = %+v", entry)
	}
	// The system instruction is folded into the prompt, so both count.
	if entry.PromptChars != len("be terse\n\nping") || !strings.Contains(entry.PromptPreview, "be terse") {
		t.Fatalf("history prompt accounting = %+v", entry)
	}

	rec = rig.call(rig.console.requireSession(rig.console.handleOverview), http.MethodGet, "/api/llm/console/overview", "", cookie)
	overview := decodeConsoleJSON[consoleOverviewResponse](t, rec)
	if overview.Metrics.Requests != 1 || overview.Metrics.Success != 1 || overview.Metrics.Failures != 0 {
		t.Fatalf("metrics = %+v", overview.Metrics)
	}
	if len(overview.RecentLatencies) != 1 || !overview.RecentLatencies[0].OK {
		t.Fatalf("recent latencies = %+v", overview.RecentLatencies)
	}
	if overview.Instance.Model != "qwen2.5-coder:7b" || overview.Instance.DockerID != "teellm-1887112800" {
		t.Fatalf("instance = %+v", overview.Instance)
	}
}

func TestConsoleGenerateUnreachableReturns502(t *testing.T) {
	// Port 1 on loopback refuses immediately, so this exercises the no-response
	// path without a timeout.
	rig := newConsoleTestRig(t, "127.0.0.1:1")
	cookie := rig.loginCookie(t)

	rec := rig.call(rig.console.requireSession(rig.console.handleGenerate), http.MethodPost, "/api/llm/console/generate",
		`{"prompt":"ping"}`, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	failure := decodeConsoleJSON[consoleGenerateFailure](t, rec)
	if failure.HTTPStatus != 0 || failure.Error == "" {
		t.Fatalf("failure = %+v", failure)
	}

	rig.console.mu.RLock()
	failures := rig.console.failures
	rig.console.mu.RUnlock()
	if failures != 1 {
		t.Fatalf("failures = %d, want 1", failures)
	}
}

func TestConsoleHistoryClear(t *testing.T) {
	endpoint := newTEELLMTestServer(t, consoleGenerateTestHandler(t))
	rig := newConsoleTestRig(t, endpoint)
	cookie := rig.loginCookie(t)

	rec := rig.call(rig.console.requireSession(rig.console.handleGenerate), http.MethodPost, "/api/llm/console/generate",
		`{"prompt":"one"}`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate status = %d", rec.Code)
	}
	rec = rig.call(rig.console.requireSession(rig.console.handleHistoryClear), http.MethodPost, "/api/llm/console/history/clear", "", cookie)
	cleared := decodeConsoleJSON[consoleHistoryClearResponse](t, rec)
	if !cleared.OK || cleared.Cleared != 1 {
		t.Fatalf("clear = %+v", cleared)
	}
	rec = rig.call(rig.console.requireSession(rig.console.handleHistory), http.MethodGet, "/api/llm/console/history", "", cookie)
	history := decodeConsoleJSON[consoleHistoryResponse](t, rec)
	if history.Total != 0 || len(history.Entries) != 0 {
		t.Fatalf("history after clear = %+v", history)
	}
}

func TestConsoleSettingsReadWrite(t *testing.T) {
	rig := newConsoleTestRig(t, "172.16.10.178:18443")
	cookie := rig.loginCookie(t)

	rec := rig.call(rig.console.requireSession(rig.console.handleSettings), http.MethodGet, "/api/llm/console/settings", "", cookie)
	settings := decodeConsoleJSON[consoleSettingsResponse](t, rec)
	if settings.Endpoint != "172.16.10.178:18443" {
		t.Fatalf("endpoint = %q", settings.Endpoint)
	}
	if settings.TeeTLS.Mode != "permissive" || !settings.TeeTLS.SkipChainVerify {
		t.Fatalf("default teeTLS = %+v", settings.TeeTLS)
	}
	if settings.TeeTLS.TimeoutSeconds != int(consoleGenerateTimeout.Seconds()) {
		t.Fatalf("timeoutSeconds = %d", settings.TeeTLS.TimeoutSeconds)
	}
	if settings.Session.TTLSeconds != int(consoleSessionTTL.Seconds()) || settings.Session.User != "admin" {
		t.Fatalf("session = %+v", settings.Session)
	}
	if len(settings.Models) == 0 || settings.ActiveModel == "" {
		t.Fatalf("models/activeModel = %+v/%q", settings.Models, settings.ActiveModel)
	}

	rec = rig.call(rig.console.requireSession(rig.console.handleSettings), http.MethodPost, "/api/llm/console/settings",
		`{"teeTLS":{"mode":"strict","skipChainVerify":false}}`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body %s", rec.Code, rec.Body.String())
	}
	settings = decodeConsoleJSON[consoleSettingsResponse](t, rec)
	if settings.TeeTLS.Mode != "strict" || settings.TeeTLS.SkipChainVerify {
		t.Fatalf("updated teeTLS = %+v", settings.TeeTLS)
	}

	rec = rig.call(rig.console.requireSession(rig.console.handleSettings), http.MethodPost, "/api/llm/console/settings",
		`{"teeTLS":{"mode":"bogus"}}`, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode status = %d, want 400", rec.Code)
	}
}

func TestConsoleHealthReportsUpstreamFailure(t *testing.T) {
	rig := newConsoleTestRig(t, "127.0.0.1:1")
	cookie := rig.loginCookie(t)
	rec := rig.call(rig.console.requireSession(rig.console.handleHealth), http.MethodGet, "/api/llm/console/health", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}
	health := decodeConsoleJSON[consoleHealthResponse](t, rec)
	if health.OK || health.HTTPStatus != 0 || health.Error == "" {
		t.Fatalf("health = %+v", health)
	}
}

func TestConsoleLatencyStatsUseSuccessfulSamplesOnly(t *testing.T) {
	last, p50, p95, avg := latencyStats([]int64{100, 200, 300, 400})
	if last != 400 || p50 != 200 || p95 != 400 || avg != 250 {
		t.Fatalf("stats = (%d,%d,%d,%d)", last, p50, p95, avg)
	}
	if last, p50, p95, avg := latencyStats(nil); last != 0 || p50 != 0 || p95 != 0 || avg != 0 {
		t.Fatalf("empty stats = (%d,%d,%d,%d)", last, p50, p95, avg)
	}
}
