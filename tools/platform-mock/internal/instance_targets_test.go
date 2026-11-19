package mock

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CipherSlinger/teeaudit/pkg/crypto"
)

// TestParseInstanceTargets pins the accepted form and the entries that are
// dropped. A typo must not take the mock down: the instance keeps its derived
// address instead, which is what it had before the map existed.
func TestParseInstanceTargets(t *testing.T) {
	got := parseInstanceTargets(" a=http://10.0.0.1:31001 , b=http://10.0.0.2:31002/ ")
	if len(got) != 2 {
		t.Fatalf("parsed %d targets, want 2: %v", len(got), got)
	}
	if got["a"] != "http://10.0.0.1:31001" {
		t.Fatalf("a = %q", got["a"])
	}
	// The trailing slash is removed so the proxy never builds a double slash.
	if got["b"] != "http://10.0.0.2:31002" {
		t.Fatalf("b = %q, want the trailing slash trimmed", got["b"])
	}

	for _, raw := range []string{
		"",
		"no-equals-sign",
		"id=",
		"=http://10.0.0.1:1",
		"id=10.0.0.1:31001", // no scheme
		" , , ",
	} {
		if got := parseInstanceTargets(raw); len(got) != 0 {
			t.Fatalf("parseInstanceTargets(%q) = %v, want nothing", raw, got)
		}
	}

	// The last entry for one dockerId wins, so a duplicated id is usable rather
	// than an error: the operator's most recent statement is the intention.
	got = parseInstanceTargets("id=http://10.0.0.1:1,id=http://10.0.0.2:2")
	if got["id"] != "http://10.0.0.2:2" {
		t.Fatalf("duplicate id = %q, want the last entry", got["id"])
	}
}

// TestConfiguredTargetOutranksTheDerivedAddress pins the whole point of the
// map: a registration relayed across a NAT arrives with the sender's address
// rewritten, so the derived address names the relay. The configured address has
// to win even though a usable-looking derived address exists.
func TestConfiguredTargetOutranksTheDerivedAddress(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{
		InstanceTargets: "docker-a=http://172.16.10.178:31001",
	})
	key, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate the instance key: %v", err)
	}
	// The registration arrives from the masquerading host, so the derived
	// address would be http://172.16.10.178:6001 — wrong, and the address every
	// other instance would collide on.
	registerInstanceFromForTest(t, mgr, "docker-a", key, "172.16.10.178:51234")

	_, target, err := mgr.targetFor("docker-a")
	if err != nil {
		t.Fatalf("targetFor: %v", err)
	}
	if target != "http://172.16.10.178:31001" {
		t.Fatalf("target = %q, want the configured NodePort address", target)
	}

	// An instance without an entry keeps the derived address.
	keyB, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate docker-b's key: %v", err)
	}
	registerInstanceFromForTest(t, mgr, "docker-b", keyB, "10.244.0.50:51234")
	_, targetB, err := mgr.targetFor("docker-b")
	if err != nil {
		t.Fatalf("targetFor docker-b: %v", err)
	}
	if targetB != "http://10.244.0.50:6001" {
		t.Fatalf("docker-b target = %q, want the derived address", targetB)
	}
}

// TestConfiguredTargetReachesTheConsole pins that the override is what the
// console shows and what the API tester targets, not just what the proxy dials:
// an operator reading a stale address would send a hand-built request to the
// wrong host.
func TestConfiguredTargetReachesTheConsole(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{
		InstanceTargets: "docker-a=http://172.16.10.178:31001",
	})
	mgr.getOrCreate("docker-a").register.set(registerState{
		Received: true, Accepted: true, DockerID: "docker-a",
	})

	items, _ := instanceListPayload(mgr)
	if len(items) != 1 {
		t.Fatalf("instances = %d, want 1", len(items))
	}
	if items[0].TaaTarget != "http://172.16.10.178:31001" {
		t.Fatalf("taaTarget = %q, want the configured address", items[0].TaaTarget)
	}

	w := httptest.NewRecorder()
	taaTargetHandler(mgr).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/taa-target?dockerId=docker-a", nil))
	if body := w.Body.String(); !containsAll(body, `"taaTarget":"http://172.16.10.178:31001"`) {
		t.Fatalf("/api/taa-target body = %s", body)
	}
}
