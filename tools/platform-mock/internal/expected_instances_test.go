package mock

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseExpectedInstancesAcceptsTheConfiguredList(t *testing.T) {
	got := parseExpectedInstances(" tee:docker-tee , fhe:docker-fhe,data-anaylsis:docker-data ")
	want := []expectedInstance{
		{Kind: instanceKindTEE, DockerID: "docker-tee"},
		{Kind: instanceKindFHE, DockerID: "docker-fhe"},
		{Kind: instanceKindDataAnalysis, DockerID: "docker-data"},
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A malformed or unknown-type entry is dropped, not guessed at: listing a TEE
// instance under FHE would put the wrong panel set in front of it, and the
// console still shows whatever registered.
func TestParseExpectedInstancesDropsWhatItCannotTrust(t *testing.T) {
	got := parseExpectedInstances("tee:one,bogus:two,no-colon,tee:one,fhe:three,:four,tee:")
	want := []expectedInstance{
		{Kind: instanceKindTEE, DockerID: "one"},
		{Kind: instanceKindFHE, DockerID: "three"},
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if parseExpectedInstances("   ") != nil {
		t.Fatal("an empty configuration should produce no inventory")
	}
}

// The inventory is the list: an entry that never registered is still a row, so
// the operator sees the instance as 未连接 instead of absent.
func TestInstanceListIncludesEntriesThatNeverRegistered(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{
		ExpectedInstances: "tee:docker-tee,fhe:docker-fhe,data-anaylsis:docker-data",
	})
	mgr.getOrCreate("docker-fhe").register.set(registerState{
		Received: true, Accepted: true, DockerID: "docker-fhe", ReceivedAt: "2026-05-01T00:00:00Z",
	})

	items, defaultID := instanceListPayload(mgr)
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3 (the inventory, not just what registered): %+v", len(items), items)
	}
	byID := make(map[string]instanceSummary, len(items))
	for _, item := range items {
		byID[item.DockerID] = item
	}
	for id, kind := range map[string]string{
		"docker-tee":  instanceKindTEE,
		"docker-fhe":  instanceKindFHE,
		"docker-data": instanceKindDataAnalysis,
	} {
		item, ok := byID[id]
		if !ok {
			t.Fatalf("%s missing from the list", id)
		}
		if item.Kind != kind {
			t.Fatalf("%s kind = %q, want %q", id, item.Kind, kind)
		}
		if !item.Expected {
			t.Fatalf("%s is not marked expected, so the console cannot tell it comes from the inventory", id)
		}
	}
	if byID["docker-tee"].Received || byID["docker-data"].Received {
		t.Fatal("an entry that never registered is marked received")
	}
	if !byID["docker-fhe"].Received || !byID["docker-fhe"].Accepted {
		t.Fatal("the registered entry lost its registration facts")
	}
	// The default is the instance the console addresses; it cannot be one that
	// never answered, or every panel would show a transport error instead.
	if defaultID != "docker-fhe" {
		t.Fatalf("defaultDockerId = %q, want docker-fhe", defaultID)
	}
	for _, item := range items {
		if item.Default && item.DockerID != "docker-fhe" {
			t.Fatalf("default marked on %q", item.DockerID)
		}
	}
}

// The configured type wins over the report-based guess. A TEE instance without
// /dev/csv-guest registers exactly like FHE, and the inference says so; the
// inventory is the operator's statement of what the instance is.
func TestConfiguredKindOverridesTheInferredOne(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{ExpectedInstances: "tee:docker-tee"})
	// An empty report is what registrationKind calls FHE.
	mgr.getOrCreate("docker-tee").register.set(registerState{Received: true, Accepted: true, DockerID: "docker-tee"})

	items, _ := instanceListPayload(mgr)
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	if items[0].Kind != instanceKindTEE {
		t.Fatalf("kind = %q, want the configured tee", items[0].Kind)
	}
}

// A registration the inventory does not name is still listed, after the
// inventory: dropping it would hide an instance that is actually running.
func TestUnlistedRegistrationIsListedAfterTheInventory(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{ExpectedInstances: "tee:docker-tee"})
	mgr.getOrCreate("docker-stray").register.set(registerState{
		Received: true, Accepted: true, DockerID: "docker-stray", AttestationSize: 1,
	})

	items, defaultID := instanceListPayload(mgr)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2: %+v", len(items), items)
	}
	if items[0].DockerID != "docker-tee" || !items[0].Expected {
		t.Fatalf("first item = %+v, want the inventory entry", items[0])
	}
	if items[1].DockerID != "docker-stray" || items[1].Expected {
		t.Fatalf("second item = %+v, want the unlisted registration", items[1])
	}
	if defaultID != "docker-stray" {
		t.Fatalf("defaultDockerId = %q, want docker-stray (the only accepted registration)", defaultID)
	}
}

// With no inventory the endpoint behaves exactly as before, which is what every
// existing deployment relies on until it passes -instances.
func TestNoInventoryKeepsTheOldListing(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	mgr.getOrCreate("docker-a").register.set(registerState{Received: true, Accepted: true, DockerID: "docker-a"})

	items, defaultID := instanceListPayload(mgr)
	if len(items) != 1 || items[0].DockerID != "docker-a" || items[0].Expected {
		t.Fatalf("items = %+v, want just docker-a and not marked expected", items)
	}
	if defaultID != "docker-a" {
		t.Fatalf("defaultDockerId = %q, want docker-a", defaultID)
	}
}

// The endpoint has to carry the inventory too, not just instanceListPayload:
// the console reads it from /api/instances.
func TestInstancesEndpointServesTheInventory(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{ExpectedInstances: "fhe:docker-fhe"})
	w := httptest.NewRecorder()
	instancesHandler(mgr).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/instances", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !containsAll(got, `"dockerId":"docker-fhe"`, `"expected":true`, `"kind":"fhe"`, `"defaultDockerId":""`) {
		t.Fatalf("body = %s", got)
	}
}

// The console groups rows by kind, so a data-analysis instance needs a group
// and a label of its own or its row would fall into 未识别类型.
func TestFrontendGroupsDataAnalysisInstances(t *testing.T) {
	for _, want := range []string{
		"{ kind: 'data-anaylsis', label:",
		"if (kind === 'data-anaylsis') return '数据分析';",
	} {
		if !containsAll(frontendBundle, want) {
			t.Fatalf("frontendBundle missing %q", want)
		}
	}
	// 未连接 is the wording for an unregistered inventory entry; a registered
	// instance whose checks fail reads 重连中 and then 断开连接, and the
	// tooltips have to tell those apart from "never registered".
	start := strings.Index(frontendBundle, "function instanceConnectionState(")
	if start == -1 {
		t.Fatal("frontendBundle missing instanceConnectionState")
	}
	end := strings.Index(frontendBundle[start:], "\n}")
	fn := frontendBundle[start : start+end]
	for _, want := range []string{
		"item.expected",
		"'未连接'",
		"'重连中'",
		"'断开连接'",
		"实例可能已被删除",
	} {
		if !containsAll(fn, want) {
			t.Fatalf("instanceConnectionState missing %q", want)
		}
	}
}

// A helper so the assertions above read as one condition rather than a chain of
// string searches.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Index(s, sub) == -1 {
			return false
		}
	}
	return true
}

// A connectivity check addresses an instance by dockerId. An inventory entry
// that has not registered must answer "configured but not registered" rather
// than "no such dockerId": the second sends the operator looking for a typo in
// a name they configured themselves.
func TestExpectedButUnregisteredIsNotAnUnknownID(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{ExpectedInstances: "tee:docker-pending"})

	_, _, err := mgr.targetFor("docker-pending")
	if !errors.Is(err, errExpectedNotRegistered) {
		t.Fatalf("targetFor(expected, unregistered) = %v, want errExpectedNotRegistered", err)
	}
	_, _, err = mgr.targetFor("docker-unknown")
	if !errors.Is(err, errInstanceNotFound) {
		t.Fatalf("targetFor(unknown) = %v, want errInstanceNotFound", err)
	}

	// The console's proxy must report the difference, since that is the message
	// an operator sees when the check fails.
	w := httptest.NewRecorder()
	dynamicTAAProxyHandler(mgr, newProxyPool()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/taa/health?dockerId=docker-pending", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "尚未向平台注册") {
		t.Fatalf("body = %s, want the not-registered reason", w.Body.String())
	}
}
