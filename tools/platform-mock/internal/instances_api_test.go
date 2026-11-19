package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/CipherSlinger/teeaudit/pkg/crypto"
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

// The registration carries no explicit server type, so the console's kind is
// derived from the report: an FHE instance registers an empty attestation and
// verifiedPass false, while a TEE instance submits one. The empty-report case is
// the FHE one because that is all the platform was told.
func TestRegistrationKindIsDerivedFromTheReport(t *testing.T) {
	cases := []struct {
		name string
		reg  registerState
		want string
	}{
		{"not registered", registerState{}, ""},
		{"fhe empty report", registerState{Received: true, Accepted: true}, instanceKindFHE},
		{"tee report", registerState{Received: true, Accepted: true, AttestationSize: 1024, VerifiedPass: true}, instanceKindTEE},
		{"tee report that failed verification", registerState{Received: true, Accepted: true, AttestationSize: 1024}, instanceKindTEE},
		// A report recorded only as the base64 request field (persisted state
		// from before the decoded size was kept) still identifies a TEE.
		{"tee base64 only", registerState{Received: true, Accepted: true, AttestationBase64: "AA=="}, instanceKindTEE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := registrationKind(tc.reg); got != tc.want {
				t.Fatalf("kind = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInstancesEndpointReportsTheDerivedKind(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	mgr.getOrCreate("docker-tee").register.set(registerState{
		Received: true, Accepted: true, DockerID: "docker-tee", AttestationSize: 1024, VerifiedPass: true,
	})
	mgr.getOrCreate("docker-fhe").register.set(registerState{
		Received: true, Accepted: true, DockerID: "docker-fhe",
	})

	items, _ := instanceListPayload(mgr)
	kinds := make(map[string]string, len(items))
	for _, item := range items {
		kinds[item.DockerID] = item.Kind
	}
	if kinds["docker-tee"] != instanceKindTEE {
		t.Fatalf("docker-tee kind = %q, want %q", kinds["docker-tee"], instanceKindTEE)
	}
	if kinds["docker-fhe"] != instanceKindFHE {
		t.Fatalf("docker-fhe kind = %q, want %q", kinds["docker-fhe"], instanceKindFHE)
	}
}

// The list is an inventory now, so there is no delete route: an instance whose
// Pod is gone stays listed (未连接) instead of being forgotten, and nothing in
// the console can remove a row the operator is still expected to run. This pins
// both halves — the handler is gone and the route answers like any unhandled
// path — so re-adding one silently would fail here.
func TestInstancesDeleteRouteIsGone(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	b := mgr.getOrCreate("docker-gone")
	b.register.set(registerState{Received: true, Accepted: true, DockerID: "docker-gone"})
	if _, err := os.Stat(b.dir); err != nil {
		t.Fatalf("instance directory was not created: %v", err)
	}

	if strings.Contains(frontendBundle, "/api/instances/delete") {
		t.Fatal("the console still calls /api/instances/delete, so its 删除 action survived the inventory rework")
	}
	if strings.Contains(frontendBundle, "function deleteInstance(") {
		t.Fatal("deleteInstance survived the inventory rework")
	}

	// Nothing removed the instance as a side effect of the listing either: the
	// row is still the recorded registration, which is what makes 未连接 the
	// only thing that changes when the Pod disappears.
	items, _ := instanceListPayload(mgr)
	if len(items) != 1 || items[0].DockerID != "docker-gone" {
		t.Fatalf("items = %+v, want the recorded instance still listed", items)
	}
	if _, err := os.Stat(b.dir); err != nil {
		t.Fatalf("the instance directory disappeared: %v", err)
	}
}

// TestRegisterStatusShowsTheEffectiveTarget pins the register card to the
// address outbound calls actually use. The stored record keeps the address the
// registration arrived from -- and behind NAT that is the relay, not the
// instance -- so a mock started with -instance-targets must not go on
// displaying the stored one as though it were in use. SourceAddr still names
// where the registration came from, so nothing the record knew is lost.
func TestRegisterStatusShowsTheEffectiveTarget(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	const override = "http://172.16.10.178:31121"
	mgr := newInstanceManager(t.TempDir(), Config{
		TAAPort:         "6001",
		InstanceTargets: "docker-a=" + override,
	})
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

	registerStatus := func(dockerID string) registerState {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/register/status?dockerId="+dockerID, nil)
		w := httptest.NewRecorder()
		registerStatusHandler(mgr).ServeHTTP(w, req)
		var payload struct {
			Result registerState `json:"result"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode %s's register status: %v", dockerID, err)
		}
		return payload.Result
	}

	withOverride := registerStatus("docker-a")
	if withOverride.TaaTarget != override {
		t.Fatalf("overridden instance taaTarget = %q, want %q", withOverride.TaaTarget, override)
	}
	if withOverride.SourceAddr == "" {
		t.Fatal("the overridden instance lost the registration's source address")
	}

	withoutOverride := registerStatus("docker-b")
	if withoutOverride.TaaTarget == override {
		t.Fatalf("docker-b picked up docker-a's override: %q", withoutOverride.TaaTarget)
	}
	if withoutOverride.TaaTarget == "" {
		t.Fatal("an instance without an override lost its derived target")
	}
}
