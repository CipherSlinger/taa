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
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
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
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	registerInstanceForTest(t, mgr, "docker-a", keyA)
	registerInstanceForTest(t, mgr, "docker-b", keyB)

	reset := registerResetHandler(mgr)
	reset.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/register/reset?dockerId=docker-a", nil))
	if mgr.lookup("docker-a").register.get().Received {
		t.Fatal("docker-a was not reset")
	}
	if !mgr.lookup("docker-b").register.get().Received {
		t.Fatal("resetting docker-a also reset docker-b")
	}

	reset.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/register/reset", nil))
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
	keyA, _ := crypto.GenerateSM2KeyPair()
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
}

func TestConsoleStatusReportsNoInstance(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	w := httptest.NewRecorder()
	taaLogStatusHandler(mgr).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/taaLog/status", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 before any registration; body = %s", w.Code, w.Body.String())
	}
}
