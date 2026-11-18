package mock

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"taa/pkg/crypto"
)

// TestInstanceSummaryRecordsWhereTheRegistrationCameFrom pins the two facts
// that explain a name the operator cannot place: dockerId is what the instance
// was configured with, while sourceAddr is where the request actually arrived
// from. Without the second, "the name is not the Pod name" is unanswerable from
// the console.
func TestInstanceSummaryRecordsWhereTheRegistrationCameFrom(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	mgr := newInstanceManager(t.TempDir(), Config{})
	key, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate the instance key: %v", err)
	}
	// The registration is sent from a Pod address that has nothing to do with
	// the dockerId: exactly the shape that used to look like a mismatch bug.
	registerInstanceFromForTest(t, mgr, "kata-csv2-taa-test-0001", key, "10.244.0.186:51234")

	items, _ := instanceListPayload(mgr)
	if len(items) != 1 {
		t.Fatalf("instances = %d, want 1", len(items))
	}
	item := items[0]
	if item.DockerID != "kata-csv2-taa-test-0001" {
		t.Fatalf("dockerId = %q", item.DockerID)
	}
	if item.SourceAddr != "10.244.0.186" {
		t.Fatalf("sourceAddr = %q, want the bare host 10.244.0.186", item.SourceAddr)
	}

	// The same two values must reach the console through /api/instances.
	req := httptest.NewRequest(http.MethodGet, "/api/instances", nil)
	w := httptest.NewRecorder()
	instancesHandler(mgr).ServeHTTP(w, req)
	body := w.Body.String()
	for _, want := range []string{`"dockerId":"kata-csv2-taa-test-0001"`, `"sourceAddr":"10.244.0.186"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("payload missing %s: %s", want, body)
		}
	}
}

// TestSourceHostTrimsThePortAndBrackets keeps the recorded origin a bare host,
// so the console can print it beside the Pod address without mangling an IPv6
// literal into ":port".
func TestSourceHostTrimsThePortAndBrackets(t *testing.T) {
	cases := map[string]string{
		"10.244.0.186:51234": "10.244.0.186",
		"[fd00::1]:51234":    "fd00::1",
		"10.244.0.186":       "10.244.0.186",
		"":                   "",
	}
	for in, want := range cases {
		if got := sourceHost(in); got != want {
			t.Errorf("sourceHost(%q) = %q, want %q", in, got, want)
		}
	}
}
