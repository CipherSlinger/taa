package mock

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

// ── envelope test helpers ────────────────────────────────────────────────
//
// TAA now seals every callback and every request to it must be sealed, so the
// tests speak the envelope too. The helpers below are the test-side TAA: one
// fixed key pair stands in for the instance, it is registered with whatever
// keystore the current test is using, and bodies are sealed/opened through the
// same envelope package production uses.
//
// Keeping one shared key pair (rather than one per test) is deliberate: the
// keystore is a process singleton, and a test that installed its own pair
// would only work when it happened to run alone.

var (
	testTAAKeyOnce sync.Once
	testTAAPriv    *crypto.SM2PrivateKey
)

// testTAAKey returns the key pair that plays TAA in the tests.
func testTAAKey(t *testing.T) *crypto.SM2PrivateKey {
	t.Helper()
	testTAAKeyOnce.Do(func() {
		priv, err := crypto.GenerateSM2KeyPair()
		if err != nil {
			t.Fatalf("generate the test TAA key pair: %v", err)
		}
		testTAAPriv = priv
	})
	return testTAAPriv
}

// registerTestTAAKey makes taaPublicKey the key the current keystore expects,
// so sealed requests verify and reports can be produced.
func registerTestTAAKey(t *testing.T) *keystore {
	t.Helper()
	ks := currentPlatformKeys()
	if ks == nil {
		t.Fatalf("no platform keystore is installed")
	}
	if err := ks.setTaaPublicKey(&testTAAKey(t).PublicKey); err != nil {
		t.Fatalf("register the test TAA key: %v", err)
	}
	return ks
}

// sealAsTAA builds what TAA sends: encrypted to the platform public key and
// signed with the test TAA private key.
func sealAsTAA(t *testing.T, plaintext string) []byte {
	t.Helper()
	ks := registerTestTAAKey(t)
	platformPriv := ks.platformPrivate()
	if platformPriv == nil {
		t.Fatalf("the platform private key is not available")
	}
	keys, err := envelope.NewKeys(&platformPriv.PublicKey, testTAAKey(t), ks.userIDBytes())
	if err != nil {
		t.Fatalf("build the test TAA envelope keys: %v", err)
	}
	sealed, err := keys.Seal([]byte(plaintext), "")
	if err != nil {
		t.Fatalf("seal the test TAA body: %v", err)
	}
	return sealed
}

// sealedReader is a one-liner for httptest.NewRequest: it seals plaintext and
// returns it as the request body.
func sealedReader(t *testing.T, plaintext string) io.Reader {
	t.Helper()
	return strings.NewReader(string(sealAsTAA(t, plaintext)))
}

// sealedBody is sealedReader for callers that need the raw bytes.
func sealedBody(t *testing.T, plaintext string) []byte {
	t.Helper()
	return sealAsTAA(t, plaintext)
}

// sealedRequest builds a request whose body is the sealed form of plaintext.
func sealedRequest(t *testing.T, method, path, plaintext string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, sealedReader(t, plaintext))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// openBodyForTest opens a report TAA sent: platform private key + registered
// TAA public key. This is what the mock itself does on receipt.
func openBodyForTest(t *testing.T, body []byte) []byte {
	t.Helper()
	ks := registerTestTAAKey(t)
	plaintext, err := ks.openBody(body)
	if err != nil {
		t.Fatalf("open the sealed TAA body: %v", err)
	}
	return plaintext
}

// openAsTAA opens a request the mock sent: TAA private key + platform public
// key. Fake TAA servers use this, since openBodyForTest is the platform's
// direction and cannot decrypt what the platform sealed to TAA.
func openAsTAA(t *testing.T, body []byte) []byte {
	t.Helper()
	ks := registerTestTAAKey(t)
	platformPriv := ks.platformPrivate()
	if platformPriv == nil {
		t.Fatalf("the platform private key is not available")
	}
	keys, err := envelope.NewKeys(&platformPriv.PublicKey, testTAAKey(t), ks.userIDBytes())
	if err != nil {
		t.Fatalf("build the test TAA envelope keys: %v", err)
	}
	env, err := envelope.Parse(body)
	if err != nil {
		t.Fatalf("parse the request sent to TAA: %v", err)
	}
	plaintext, err := keys.Open(env)
	if err != nil {
		t.Fatalf("open the request sent to TAA: %v", err)
	}
	return plaintext
}

// taaPublicKeyHex is the hex form the register request carries.
func taaPublicKeyHex(t *testing.T) string {
	t.Helper()
	hexKey, err := crypto.MarshalSM2PublicKeyHex(&testTAAKey(t).PublicKey)
	if err != nil {
		t.Fatalf("encode the test TAA public key: %v", err)
	}
	return hexKey
}
