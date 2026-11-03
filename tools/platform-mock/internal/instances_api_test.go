package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"taa/pkg/crypto"
)

func TestInstancesEndpointListsEveryInstanceAndMarksTheDefault(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate docker-a's key: %v", err)
	}
	keyB, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate docker-b's key: %v", err)
	}
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)
	mgr.lookup("docker-a").reportRes.set(reportState{DockerID: "docker-a", Received: true, ReceivedAt: "2026-05-01T00:00:00Z"})

	req := httptest.NewRequest(http.MethodGet, "/api/instances", nil)
	w := httptest.NewRecorder()
	instancesHandler(mgr).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var payload struct {
		Result struct {
			Instances []instanceSummary `json:"instances"`
			Default   string            `json:"defaultDockerId"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode instances: %v", err)
	}
	if len(payload.Result.Instances) != 2 {
		t.Fatalf("instances = %d, want 2", len(payload.Result.Instances))
	}
	if payload.Result.Default == "" {
		t.Fatal("defaultDockerId is empty")
	}
	foundTarget := false
	for _, item := range payload.Result.Instances {
		if item.DockerID == "docker-a" {
			if item.LastReportAt != "2026-05-01T00:00:00Z" {
				t.Fatalf("lastReportAt = %q", item.LastReportAt)
			}
			foundTarget = item.TaaTarget != ""
		}
	}
	if !foundTarget {
		t.Fatal("the registered target is missing from the instance summary")
	}
	defaultCount := 0
	defaultItem := instanceSummary{}
	for _, item := range payload.Result.Instances {
		if item.Default {
			defaultCount++
			defaultItem = item
		}
	}
	if defaultCount != 1 {
		t.Fatalf("instances marked default = %d, want exactly 1", defaultCount)
	}
	if defaultItem.DockerID != payload.Result.Default {
		t.Fatalf("default instance dockerId = %q, defaultDockerId = %q", defaultItem.DockerID, payload.Result.Default)
	}
}

func TestRegisterStatusAnswersBeforeAnyRegistration(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/register/status", nil)
	w := httptest.NewRecorder()
	registerStatusHandler(mgr).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the readiness probe; body = %s", w.Code, w.Body.String())
	}
	var payload apiResponse
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Error != 0 {
		t.Fatalf("envelope error = %d, want 0", payload.Error)
	}
}

func TestRegisterResetAllAndOne(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	mgr := newInstanceManager(t.TempDir(), Config{})
	keyA, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate docker-a's key: %v", err)
	}
	keyB, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate docker-b's key: %v", err)
	}
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	reset := registerResetHandler(mgr)
	wResetA := httptest.NewRecorder()
	reset.ServeHTTP(wResetA, httptest.NewRequest(http.MethodPost, "/api/register/reset?dockerId=docker-a", nil))
	assertResetResponse(t, wResetA)
	if mgr.lookup("docker-a").register.get().Received {
		t.Fatal("docker-a was not reset")
	}
	if !mgr.lookup("docker-b").register.get().Received {
		t.Fatal("resetting docker-a also reset docker-b")
	}

	wResetAll := httptest.NewRecorder()
	reset.ServeHTTP(wResetAll, httptest.NewRequest(http.MethodPost, "/api/register/reset", nil))
	assertResetResponse(t, wResetAll)
	if mgr.lookup("docker-b").register.get().Received {
		t.Fatal("reset-all did not clear docker-b")
	}

	w := httptest.NewRecorder()
	reset.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/register/reset?dockerId=missing", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("reset of an unknown dockerId = %d, want 404", w.Code)
	}
}

func TestDashboardIncludesTheInstanceList(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	mgr := newInstanceManager(t.TempDir(), Config{TAATarget: "http://10.0.0.9:6001"})
	keyA, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate docker-a's key: %v", err)
	}
	registerInstanceForTest(t, mgr, "docker-a", keyA)

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/status?dockerId=docker-a", nil)
	w := httptest.NewRecorder()
	dashboardStatusHandler(mgr).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var payload struct {
		Result struct {
			DockerID string            `json:"dockerId"`
			Target   string            `json:"taaTarget"`
			Items    []instanceSummary `json:"instances"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if payload.Result.DockerID != "docker-a" {
		t.Fatalf("dockerId = %q", payload.Result.DockerID)
	}
	if payload.Result.Target != "http://10.0.0.9:6001" {
		t.Fatalf("taaTarget = %q", payload.Result.Target)
	}
	if len(payload.Result.Items) != 1 {
		t.Fatalf("instances = %d, want 1", len(payload.Result.Items))
	}
	if payload.Result.Items[0].TaaTarget != payload.Result.Target {
		t.Fatalf("item taaTarget = %q, dashboard taaTarget = %q", payload.Result.Items[0].TaaTarget, payload.Result.Target)
	}
}

func assertResetResponse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("reset status = %d, body = %s", w.Code, w.Body.String())
	}
	var payload apiResponse
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode reset response: %v", err)
	}
	if payload.Error != 0 || payload.Msg != "reset" {
		t.Fatalf("reset envelope = error:%d msg:%q, want error 0 and msg reset", payload.Error, payload.Msg)
	}
}

// TestInstanceListHidesTheLegacyBundle pins that the empty-id bundle a lenient
// console call creates is a write fallback only: it must not surface as an
// addressable instance or become the default.
func TestInstanceListHidesTheLegacyBundle(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})

	wDashboard := httptest.NewRecorder()
	dashboardStatusHandler(mgr).ServeHTTP(wDashboard, httptest.NewRequest(http.MethodGet, "/api/dashboard/status", nil))
	if wDashboard.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, body = %s", wDashboard.Code, wDashboard.Body.String())
	}
	if mgr.lookup("") == nil {
		t.Fatal("the dashboard did not create the legacy bundle")
	}

	w := httptest.NewRecorder()
	instancesHandler(mgr).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/instances", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("instances status = %d, body = %s", w.Code, w.Body.String())
	}
	var payload struct {
		Result struct {
			Instances []instanceSummary `json:"instances"`
			Default   string            `json:"defaultDockerId"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode instances: %v", err)
	}
	if len(payload.Result.Instances) != 0 {
		t.Fatalf("instances = %d, want 0 while only the legacy bundle exists", len(payload.Result.Instances))
	}
	if payload.Result.Default != "" {
		t.Fatalf("defaultDockerId = %q, want empty", payload.Result.Default)
	}
}

func TestConsoleStatusRejectsUnknownDockerID(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	w := httptest.NewRecorder()
	taaLogStatusHandler(mgr).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/taaLog/status?dockerId=missing", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown dockerId; body = %s", w.Code, w.Body.String())
	}
}

func TestConsoleStatusRejectsWrongMethod(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})

	w := httptest.NewRecorder()
	instancesHandler(mgr).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/instances", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 for POST; body = %s", w.Code, w.Body.String())
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", allow)
	}

	// A preflight must be answered by the method guard, before the handler
	// resolves an instance: resolving would create the legacy bundle.
	w = httptest.NewRecorder()
	taaLogStatusHandler(mgr).ServeHTTP(w, httptest.NewRequest(http.MethodOptions, "/api/taaLog/status", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204; body = %s", w.Code, w.Body.String())
	}
	if mgr.lookup("") != nil {
		t.Fatal("a CORS preflight created the legacy bundle")
	}
}

func TestConsoleStatusLenientBeforeRegistration(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	w := httptest.NewRecorder()
	modelLogStatusHandler(mgr).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/modelLog/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 before any registration; body = %s", w.Code, w.Body.String())
	}
	var payload struct {
		Msg    string `json:"msg"`
		Error  int    `json:"error"`
		Result struct {
			Entries []modelLogEntry `json:"entries"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode status envelope: %v", err)
	}
	if payload.Error != 0 || payload.Msg != "success" {
		t.Fatalf("envelope = %+v, want error 0 and msg success", payload)
	}
	if payload.Result.Entries == nil || len(payload.Result.Entries) != 0 {
		t.Fatalf("entries = %v, want an empty array", payload.Result.Entries)
	}
}
