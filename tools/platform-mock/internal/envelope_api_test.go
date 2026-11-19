package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CipherSlinger/teeaudit/pkg/crypto"
)

type envelopeAPIResponse struct {
	Error  int            `json:"error"`
	Msg    string         `json:"msg"`
	Result map[string]any `json:"result"`
}

func callEnvelopeAPI(t *testing.T, method, body string) (int, envelopeAPIResponse) {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/api/crypto/envelope", reader)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	cryptoEnvelopeHandler(w, req)
	var resp envelopeAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode the envelope response (%s): %v", w.Body.String(), err)
	}
	return w.Code, resp
}

// TestEnvelopeAPIGETPrefillsTheKeysInEffect checks that the console is handed
// the platform private key it must sign with and the TAA public key registered
// for the selected instance - a mismatch in either produces an envelope TAA
// rejects, so the prefill has to be the real material, not a placeholder.
func TestEnvelopeAPIGETPrefillsTheKeysInEffect(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)
	if err := ks.setTaaPublicKeyFor("docker-a", &testTAAKey(t).PublicKey); err != nil {
		t.Fatalf("register docker-a's TAA key: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/crypto/envelope?dockerId=docker-a", nil)
	w := httptest.NewRecorder()
	cryptoEnvelopeHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp envelopeAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := resp.Result["taaPublicKeyHex"]; got != taaPublicKeyHex(t) {
		t.Fatalf("taaPublicKeyHex = %v, want the registered key", got)
	}
	if got := resp.Result["identity"]; got != string(ks.userIDBytes()) {
		t.Fatalf("identity = %v, want %q", got, ks.userIDBytes())
	}
	privPEM, ok := resp.Result["platformPrivateKey"].(string)
	if !ok || privPEM == "" {
		t.Fatalf("platformPrivateKey is missing")
	}
	if _, err := crypto.ParseSM2PrivateKeyPEM([]byte(privPEM)); err != nil {
		t.Fatalf("prefilled private key does not parse: %v", err)
	}
	if got := resp.Result["platformPublicKeyHex"]; got != ks.platformPublicHex() {
		t.Fatalf("platformPublicKeyHex = %v, want %q", got, ks.platformPublicHex())
	}
}

// TestEnvelopeAPISealsWithTheKeystoreWhenKeysAreEmpty proves the default path:
// an empty key pair uses the mock's own identity, and the result opens exactly
// as TAA would open it.
func TestEnvelopeAPISealsWithTheKeystoreWhenKeysAreEmpty(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)
	if err := ks.setTaaPublicKey(&testTAAKey(t).PublicKey); err != nil {
		t.Fatalf("register the test TAA key: %v", err)
	}

	status, resp := callEnvelopeAPI(t, http.MethodPost, `{"plaintext":{"requestId":"req-1","resourceUrl":"http://example.com/a.tar.gz"}}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, msg = %s", status, resp.Msg)
	}
	body, _ := resp.Result["body"].(string)
	if body == "" {
		t.Fatalf("no sealed body returned")
	}
	plaintext := openAsTAA(t, []byte(body))
	if string(plaintext) != `{"requestId":"req-1","resourceUrl":"http://example.com/a.tar.gz"}` {
		t.Fatalf("plaintext = %s", plaintext)
	}
	if got := resp.Result["usedKeystore"]; got != true {
		t.Fatalf("usedKeystore = %v, want true", got)
	}
}

// TestEnvelopeAPISealsWithExplicitKeys covers the editable key boxes. The keys
// handed in here are the pair the fake TAA trusts, so the envelope verifies only
// if the handler used exactly those values.
func TestEnvelopeAPISealsWithExplicitKeys(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)
	if err := ks.setTaaPublicKey(&testTAAKey(t).PublicKey); err != nil {
		t.Fatalf("register the test TAA key: %v", err)
	}
	privPEM, _, _, err := ks.keyPEMs()
	if err != nil {
		t.Fatalf("read the platform key pairs: %v", err)
	}
	payload := map[string]any{
		"plaintext":          `{"phase":3}`,
		"platformPrivateKey": privPEM,
		"taaPublicKeyHex":    taaPublicKeyHex(t),
		"identity":           string(ks.userIDBytes()),
	}
	raw, _ := json.Marshal(payload)
	status, resp := callEnvelopeAPI(t, http.MethodPost, string(raw))
	if status != http.StatusOK {
		t.Fatalf("status = %d, msg = %s", status, resp.Msg)
	}
	if got := resp.Result["usedKeystore"]; got != false {
		t.Fatalf("usedKeystore = %v, want false", got)
	}
	body, _ := resp.Result["body"].(string)
	if plaintext := openAsTAA(t, []byte(body)); string(plaintext) != `{"phase":3}` {
		t.Fatalf("plaintext = %s", plaintext)
	}
}

// TestEnvelopeAPIFillsAMissingSideFromTheKeystore covers a console that could
// only prefill one box: the other side must still come from the mock, and the
// envelope must verify with the keys TAA holds.
func TestEnvelopeAPIFillsAMissingSideFromTheKeystore(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)
	if err := ks.setTaaPublicKey(&testTAAKey(t).PublicKey); err != nil {
		t.Fatalf("register the test TAA key: %v", err)
	}
	privPEM, _, _, err := ks.keyPEMs()
	if err != nil {
		t.Fatalf("read the platform key pairs: %v", err)
	}

	for name, body := range map[string]string{
		"only the TAA public key":    `{"plaintext":"{\"phase\":2}","taaPublicKeyHex":"` + taaPublicKeyHex(t) + `"}`,
		"only the platform key pair": `{"plaintext":"{\"phase\":2}","platformPrivateKey":` + mustJSONString(t, privPEM) + `}`,
	} {
		status, resp := callEnvelopeAPI(t, http.MethodPost, body)
		if status != http.StatusOK {
			t.Fatalf("%s: status = %d, msg = %s", name, status, resp.Msg)
		}
		sealed, _ := resp.Result["body"].(string)
		if plaintext := openAsTAA(t, []byte(sealed)); string(plaintext) != `{"phase":2}` {
			t.Fatalf("%s: plaintext = %s", name, plaintext)
		}
	}
}

func mustJSONString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode a JSON string: %v", err)
	}
	return string(encoded)
}

func TestEnvelopeAPIRejectsAnEmptyOrBrokenPlaintext(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	for _, body := range []string{`{}`, `{"plaintext":""}`, `{"plaintext":"   "}`, `{"plaintext":123,}`} {
		status, resp := callEnvelopeAPI(t, http.MethodPost, body)
		if status != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400 (msg = %s)", body, status, resp.Msg)
		}
	}
}

// TestEnvelopeAPIReportsAMissingRegistration checks the error an operator sees
// before the instance has registered: sealing to a key that does not exist must
// name the cause instead of producing an envelope TAA silently rejects.
func TestEnvelopeAPIReportsAMissingRegistration(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	prev := currentPlatformKeys()
	setPlatformKeys(ks)
	defer setPlatformKeys(prev)

	status, resp := callEnvelopeAPI(t, http.MethodPost, `{"plaintext":"{}","dockerId":"docker-unknown"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (msg = %s)", status, resp.Msg)
	}
	if !strings.Contains(resp.Msg, "docker-unknown") {
		t.Fatalf("msg = %q should name the instance", resp.Msg)
	}
}
