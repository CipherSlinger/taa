package mock

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

// ── host status ─────────────────────────────────────────────────────────

func TestParseKubePodsSummarizesTheFieldsThePanelRenders(t *testing.T) {
	raw := []byte(`{"items":[
	  {"metadata":{"name":"taa-deploy","namespace":"osr","creationTimestamp":"2026-11-16T09:00:00Z"},
	   "spec":{"nodeName":"hygon-master","containers":[{"name":"taa"}]},
	   "status":{"phase":"Running","podIP":"10.244.0.135",
	     "containerStatuses":[{"ready":true,"restartCount":3}]}},
	  {"metadata":{"name":"taa-teellm","namespace":"osr","creationTimestamp":"2026-11-16T10:00:00Z"},
	   "spec":{"nodeName":"hygon-master","containers":[{"name":"llm"}]},
	   "status":{"phase":"Pending","containerStatuses":[{"ready":false,"restartCount":0}]}}
	]}`)
	pods, err := parseKubePods(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pods) != 2 {
		t.Fatalf("got %d pods, want 2", len(pods))
	}
	// Sorted by name within the namespace.
	if pods[0].Name != "taa-deploy" || pods[1].Name != "taa-teellm" {
		t.Fatalf("unexpected order: %s, %s", pods[0].Name, pods[1].Name)
	}
	first := pods[0]
	if first.Ready != "1/1" || first.Restarts != 3 || first.PodIP != "10.244.0.135" || first.Phase != "Running" {
		t.Fatalf("taa-deploy = %+v", first)
	}
	if first.AgeSeconds <= 0 {
		t.Fatalf("age should be positive, got %d", first.AgeSeconds)
	}
	// A Pending Pod has no containerStatuses at all: ready must still count
	// against the declared container, not read as "0/0".
	if pods[1].Ready != "0/1" {
		t.Fatalf("pending pod ready = %q, want 0/1", pods[1].Ready)
	}
}

func TestHostIPRankPrefersTheManagementRange(t *testing.T) {
	ordered := []string{"172.16.10.178", "192.168.1.5", "10.0.0.1", "8.8.8.8", "100.103.193.56"}
	for i := 1; i < len(ordered); i++ {
		if hostIPRank(ordered[i-1]) > hostIPRank(ordered[i]) {
			t.Fatalf("%q should rank at least as high as %q", ordered[i-1], ordered[i])
		}
	}
}

func TestDescribeKubectlErrorKeepsTheUsefulLine(t *testing.T) {
	err := execExitErrorForTest(t, "E1117 the server rejected our request\nsecond line\n")
	msg := describeKubectlError(err).Error()
	if !strings.Contains(msg, "the server rejected our request") {
		t.Fatalf("message lost kubectl's own text: %q", msg)
	}
	if strings.Contains(msg, "second line") {
		t.Fatalf("message should stop at the first line: %q", msg)
	}
}

func TestHostStatusHandlerAnswersWithTheEnvelopeShape(t *testing.T) {
	cache := newHostStatusCache(localHostProbe{}, hostStatusTTL)
	cache.now = func() time.Time { return timeFixed }
	cache.last = hostSnapshot{HostIP: "10.0.0.9"}
	cache.at = timeFixed

	req := httptest.NewRequest(http.MethodGet, "/api/host/status", nil)
	w := httptest.NewRecorder()
	hostStatusHandler(cache)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"hostIp":"10.0.0.9"`) {
		t.Fatalf("body = %s", w.Body.String())
	}
}

// The table is filtered by namespace because the whole cluster is too long to
// read. The counts stay cluster-wide while the rows narrow, and a namespace
// whose Pods are gone resolves back to "all" instead of an empty panel.
func TestHostStatusFiltersPodsByNamespace(t *testing.T) {
	snapshot := hostSnapshot{
		HostIP: "10.0.0.9",
		Pods: []hostPod{
			{Name: "a", Namespace: "osr"},
			{Name: "b", Namespace: "osr"},
			{Name: "c", Namespace: "default"},
		},
	}

	all := snapshot.forNamespace("")
	if len(all.Pods) != 3 || all.PodCount != 3 || all.Namespace != "" {
		t.Fatalf("all = %+v", all)
	}
	if len(all.Namespaces) != 2 || all.Namespaces[0].Name != "osr" || all.Namespaces[0].Count != 2 {
		t.Fatalf("namespaces = %+v", all.Namespaces)
	}

	one := snapshot.forNamespace("osr")
	if len(one.Pods) != 2 || one.Namespace != "osr" {
		t.Fatalf("osr = %+v", one)
	}
	// PodCount stays the cluster total: it is what the header compares against.
	if one.PodCount != 3 {
		t.Fatalf("podCount = %d, want the cluster total 3", one.PodCount)
	}

	// A remembered namespace that no longer exists falls back to all, so the
	// panel is never empty while the host is plainly running Pods.
	gone := snapshot.forNamespace("deleted-ns")
	if gone.Namespace != "" || len(gone.Pods) != 3 {
		t.Fatalf("unknown namespace = %+v", gone)
	}
}

// A cluster larger than one response must not lose a namespace: the collect cap
// is applied before filtering, the display cap after.
func TestHostStatusFiltersBeforeTruncating(t *testing.T) {
	pods := make([]hostPod, 0, hostPodTableLimit+10)
	for i := 0; i < hostPodTableLimit; i++ {
		pods = append(pods, hostPod{Name: "filler", Namespace: "bulk"})
	}
	pods = append(pods, hostPod{Name: "needle", Namespace: "osr"})

	got := hostSnapshot{Pods: pods}.forNamespace("osr")
	if len(got.Pods) != 1 || got.Pods[0].Name != "needle" {
		t.Fatalf("a namespace after the display cap was dropped: %+v", got.Pods)
	}

	all := hostSnapshot{Pods: pods}.forNamespace("")
	if len(all.Pods) != hostPodTableLimit || !all.PodsTruncated {
		t.Fatalf("unfiltered view: %d pods, truncated=%v", len(all.Pods), all.PodsTruncated)
	}
}

// ── open-response ────────────���──────────────────────────────────────────

func TestOpenResponseReturnsPlaintextForANonEnvelope(t *testing.T) {
	// The common real case: the call never reached TAA, so what came back is a
	// plain error. Printing it verbatim is the whole answer and must not be
	// wrapped in an "unseal failed" message.
	req := httptest.NewRequest(http.MethodPost, "/api/taa/open-response?raw=1",
		strings.NewReader(`{"msg":"TAA down"}`))
	w := httptest.NewRecorder()
	taOpenResponseHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"msg":"TAA down"}` {
		t.Fatalf("body = %q", got)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Fatalf("content type = %q, want json", ct)
	}
}

func TestOpenResponseRefusesAnEnvelopeItCannotVerify(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	// A well-formed envelope sealed by somebody who is not the registered TAA:
	// it parses, so the handler must go on to the signature check and refuse.
	other := testOtherTAAKey(t)
	platformPub := ks.platformPrivate().PublicKey
	sealed := sealForTest(t, other, &platformPub, `{"error":0}`)

	req := httptest.NewRequest(http.MethodPost, "/api/taa/open-response?raw=1", strings.NewReader(string(sealed)))
	w := httptest.NewRecorder()
	taOpenResponseHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "解封 TAA 响应失败") {
		t.Fatalf("body = %s", w.Body.String())
	}
}

func TestOpenResponseOpensWhatTheRegisteredTAASigned(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)
	registerTestTAAKey(t)

	sealed := sealAsTAA(t, `{"msg":"阶段切换成功","error":0}`)
	req := httptest.NewRequest(http.MethodPost, "/api/taa/open-response?dockerId=&raw=1", strings.NewReader(string(sealed)))
	w := httptest.NewRecorder()
	taOpenResponseHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	// raw mode prints the business JSON itself, not an envelope around it.
	if got := strings.TrimSpace(w.Body.String()); got != `{"msg":"阶段切换成功","error":0}` {
		t.Fatalf("body = %q", got)
	}
}

func TestOpenResponseFindsTheKeyWhenTheCallerNamesNoInstance(t *testing.T) {
	// This is the hand-written curl case: a terminal has no instance selector,
	// and TAA does not put its dockerId in the response envelope, so the only
	// way in is to try the registered keys.
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)
	// Registered under an id, not as the legacy key: the multi-instance shape.
	if err := ks.setTaaPublicKeyFor("kata-csv2-taa-test-0001", &testTAAKey(t).PublicKey); err != nil {
		t.Fatalf("register: %v", err)
	}

	sealed := sealAsTAA(t, `{"msg":"阶段切换成功","error":0}`)
	req := httptest.NewRequest(http.MethodPost, "/api/taa/open-response", strings.NewReader(string(sealed)))
	w := httptest.NewRecorder()
	taOpenResponseHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `\"阶段切换成功\"`) {
		t.Fatalf("body = %s", body)
	}
	// The structured answer names the instance the key search matched, so an
	// operator can see which one answered.
	if !strings.Contains(body, `"dockerId":"kata-csv2-taa-test-0001"`) {
		t.Fatalf("body does not name the matched instance: %s", body)
	}
}

// ── test plumbing ───────────────────────────────────────────────────────

var timeFixed = timeMustParse("2026-11-17T10:00:00Z")

func timeMustParse(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

// execExitErrorForTest builds a real *exec.ExitError carrying stderr, which is
// the shape describeKubectlError has to interpret.
func execExitErrorForTest(t *testing.T, stderr string) error {
	t.Helper()
	cmd := exec.Command("sh", "-c", "printf %s "+shellSingleQuote(stderr)+" >&2; exit 1")
	// Output, not Run: only Output populates ExitError.Stderr, and producing the
	// same error shape as listHostPods is the point of this helper.
	_, err := cmd.Output()
	if err == nil {
		t.Fatal("the helper command should have failed")
	}
	return err
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

var testOtherKeyOnce sync.Once
var testOtherKeyPriv *crypto.SM2PrivateKey

// testOtherTAAKey is a second TAA key pair: an instance that is not the one the
// keystore has registered, which is what a forged or stale response looks like.
func testOtherTAAKey(t *testing.T) *crypto.SM2PrivateKey {
	t.Helper()
	testOtherKeyOnce.Do(func() {
		priv, err := crypto.GenerateSM2KeyPair()
		if err != nil {
			t.Fatalf("generate the second TAA key pair: %v", err)
		}
		testOtherKeyPriv = priv
	})
	return testOtherKeyPriv
}

func sealForTest(t *testing.T, taaPriv *crypto.SM2PrivateKey, platformPub *crypto.SM2PublicKey, plaintext string) []byte {
	t.Helper()
	sealed, err := envelope.SealForPlatform(taaPriv, platformPub, nil, []byte(plaintext))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed
}
