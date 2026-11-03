package mock

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

// testManagerWith builds an instance manager whose bundle uses dockerID and a
// temp root. Tests that built a store themselves install it through configure.
// With dockerID == "" the bundle is the legacy one, which instanceForWrite
// falls back to for ids the manager has never seen - that is what keeps the
// single-instance handler tests unchanged.
func testManagerWith(t *testing.T, dockerID string, configure func(*instanceStores)) *instanceManager {
	t.Helper()
	root := t.TempDir()
	dir := root
	if dockerID != "" {
		dir = filepath.Join(root, instancesDirName, instanceDirName(dockerID))
	}
	b := newInstanceStores(dir, dockerID)
	if configure != nil {
		configure(b)
	}
	return &instanceManager{
		root:    root,
		cfg:     Config{},
		byID:    map[string]*instanceStores{dockerID: b},
		scanned: true,
	}
}

// registerInstanceForTest runs a real registration through registerHandler, so
// the manager, the keystore and the derived target all take the production path.
func registerInstanceForTest(t *testing.T, mgr *instanceManager, dockerID string, priv *crypto.SM2PrivateKey) {
	t.Helper()
	ks := currentPlatformKeys()
	hexKey, err := crypto.MarshalSM2PublicKeyHex(&priv.PublicKey)
	if err != nil {
		t.Fatalf("encode %s's public key: %v", dockerID, err)
	}
	body := fmt.Sprintf(
		`{"dockerId":%q,"authInfo":null,"taaPublicKey":%q,"timestamp":"2026-01-01T00:00:00Z","verifiedPass":true}`,
		dockerID, hexKey,
	)
	keys, err := envelope.NewKeys(&ks.platformPrivate().PublicKey, priv, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build envelope keys for %s: %v", dockerID, err)
	}
	sealed, err := keys.Seal([]byte(body), dockerID)
	if err != nil {
		t.Fatalf("seal the registration for %s: %v", dockerID, err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/register", bytes.NewReader(sealed))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	registerHandler(mgr, true).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register %s: status = %d, body = %s", dockerID, w.Code, w.Body.String())
	}
}
