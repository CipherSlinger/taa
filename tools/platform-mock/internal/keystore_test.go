package mock

import (
	"testing"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

// A restart must keep the platform key: every running TAA has cached the public
// key, so a fresh pair would make its envelopes undecryptable.
func TestKeystorePersistsThePlatformKey(t *testing.T) {
	stateDir := t.TempDir()

	first, err := newKeystore(stateDir, "", nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	firstHex := first.platformPublicHex()
	if firstHex == "" {
		t.Fatal("the platform public key is empty")
	}

	second, err := newKeystore(stateDir, "", nil)
	if err != nil {
		t.Fatalf("reopen the keystore: %v", err)
	}
	if got := second.platformPublicHex(); got != firstHex {
		t.Fatalf("platform public key after reopening = %s, want %s", got, firstHex)
	}
}

// The TAA public key has to survive too: without it nothing TAA sends can be
// verified until it registers again.
func TestKeystorePersistsTheRegisteredTAAPublicKey(t *testing.T) {
	stateDir := t.TempDir()
	ks, err := newKeystore(stateDir, "", nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	taaKey, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate the TAA key pair: %v", err)
	}
	if err := ks.setTaaPublicKey(&taaKey.PublicKey); err != nil {
		t.Fatalf("register the TAA public key: %v", err)
	}

	reopened, err := newKeystore(stateDir, "", nil)
	if err != nil {
		t.Fatalf("reopen the keystore: %v", err)
	}
	if !reopened.hasTaaPublicKey() {
		t.Fatal("the registered TAA public key was not persisted")
	}
	want, err := crypto.MarshalSM2PublicKeyHex(&taaKey.PublicKey)
	if err != nil {
		t.Fatalf("encode the TAA public key: %v", err)
	}
	got, err := crypto.MarshalSM2PublicKeyHex(reopened.taaPublic())
	if err != nil {
		t.Fatalf("encode the reloaded TAA public key: %v", err)
	}
	if got != want {
		t.Fatalf("reloaded TAA public key = %s, want %s", got, want)
	}
}

// Registration is a rotation: the new key replaces the old one, so a TAA that
// regenerated its pair is served rather than stuck on the stale key.
func TestKeystoreReplacesTheTAAPublicKeyOnRegistration(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	oldKey, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate the old key pair: %v", err)
	}
	newKey, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate the new key pair: %v", err)
	}
	if err := ks.setTaaPublicKey(&oldKey.PublicKey); err != nil {
		t.Fatalf("register the old key: %v", err)
	}
	if err := ks.setTaaPublicKey(&newKey.PublicKey); err != nil {
		t.Fatalf("register the new key: %v", err)
	}
	want, err := crypto.MarshalSM2PublicKeyHex(&newKey.PublicKey)
	if err != nil {
		t.Fatalf("encode the new key: %v", err)
	}
	got, err := crypto.MarshalSM2PublicKeyHex(ks.taaPublic())
	if err != nil {
		t.Fatalf("encode the current key: %v", err)
	}
	if got != want {
		t.Fatalf("current TAA public key = %s, want the newly registered %s", got, want)
	}
}

// Without a registered key there is nothing to seal to, and sending plaintext
// would only turn a local error into a remote rejection.
func TestKeystoreRefusesToSealWithoutATAAPublicKey(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	if _, err := ks.sealForTAA([]byte(`{}`)); err == nil {
		t.Fatal("sealing without a registered TAA public key succeeded, want an error")
	}
}

// Registration is sealed like every other message, but its signature is checked
// against the key carried in the plaintext, since the platform has no other copy.
func TestKeystoreOpensRegistrationWithTheCarriedKey(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	taaKey, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate the TAA key pair: %v", err)
	}
	hexKey, err := crypto.MarshalSM2PublicKeyHex(&taaKey.PublicKey)
	if err != nil {
		t.Fatalf("encode the TAA public key: %v", err)
	}

	body := []byte(`{"dockerId":"docker-1","taaPublicKey":"` + hexKey + `"}`)
	platformPriv := ks.platformPrivate()
	keys, err := envelope.NewKeys(&platformPriv.PublicKey, taaKey, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build the TAA envelope keys: %v", err)
	}
	sealed, err := keys.Seal(body, "")
	if err != nil {
		t.Fatalf("seal the registration: %v", err)
	}

	plaintext, pub, err := ks.openRegister(sealed)
	if err != nil {
		t.Fatalf("open the registration: %v", err)
	}
	if string(plaintext) != string(body) {
		t.Fatalf("registration plaintext = %s, want %s", plaintext, body)
	}
	if pub == nil {
		t.Fatal("the carried TAA public key was not returned")
	}
	if ks.hasTaaPublicKey() {
		t.Fatal("openRegister adopted the key; adoption belongs to the caller after validation")
	}
}

// A tampered registration must not be accepted: the signature covers the
// plaintext, and the plaintext is what names the key.
func TestKeystoreRejectsARegistrationSignedByAnotherKey(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	carried, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate the carried key: %v", err)
	}
	signer, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate the signing key: %v", err)
	}
	hexKey, err := crypto.MarshalSM2PublicKeyHex(&carried.PublicKey)
	if err != nil {
		t.Fatalf("encode the carried key: %v", err)
	}
	body := []byte(`{"dockerId":"docker-1","taaPublicKey":"` + hexKey + `"}`)
	platformPriv := ks.platformPrivate()
	keys, err := envelope.NewKeys(&platformPriv.PublicKey, signer, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build the signing envelope keys: %v", err)
	}
	sealed, err := keys.Seal(body, "")
	if err != nil {
		t.Fatalf("seal the registration: %v", err)
	}
	if _, _, err := ks.openRegister(sealed); err == nil {
		t.Fatal("a registration signed by a key other than the carried one was accepted")
	}
}

func TestKeystoreKeepsOneKeyPerInstance(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	if err := ks.setTaaPublicKeyFor("docker-a", &keyA.PublicKey); err != nil {
		t.Fatalf("register key A: %v", err)
	}
	if err := ks.setTaaPublicKeyFor("docker-b", &keyB.PublicKey); err != nil {
		t.Fatalf("register key B: %v", err)
	}

	for id, want := range map[string]*crypto.SM2PrivateKey{"docker-a": keyA, "docker-b": keyB} {
		got, err := crypto.MarshalSM2PublicKeyHex(ks.taaPublicFor(id))
		if err != nil {
			t.Fatalf("encode key for %s: %v", id, err)
		}
		expected, _ := crypto.MarshalSM2PublicKeyHex(&want.PublicKey)
		if got != expected {
			t.Fatalf("key for %s = %s, want %s", id, got, expected)
		}
	}
	if ks.taaPublicFor("docker-c") != nil {
		t.Fatal("an unregistered dockerId resolved to a key")
	}
}

func TestKeystorePersistsOneKeyPerInstance(t *testing.T) {
	stateDir := t.TempDir()
	ks, err := newKeystore(stateDir, "", nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	if err := ks.setTaaPublicKeyFor("docker-a", &keyA.PublicKey); err != nil {
		t.Fatalf("register key A: %v", err)
	}
	if err := ks.setTaaPublicKeyFor("docker-b", &keyB.PublicKey); err != nil {
		t.Fatalf("register key B: %v", err)
	}

	reopened, err := newKeystore(stateDir, "", nil)
	if err != nil {
		t.Fatalf("reopen the keystore: %v", err)
	}
	for _, id := range []string{"docker-a", "docker-b"} {
		if reopened.taaPublicFor(id) == nil {
			t.Fatalf("key for %s did not survive a restart", id)
		}
	}
}

func TestKeystoreFallsBackToTheLegacySingleKey(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	legacy, _ := crypto.GenerateSM2KeyPair()
	if err := ks.setTaaPublicKey(&legacy.PublicKey); err != nil {
		t.Fatalf("register the legacy key: %v", err)
	}
	if ks.taaPublicFor("any-docker") == nil {
		t.Fatal("the legacy single key was not offered as a fallback")
	}
}

func TestKeystoreRejectsAPlaintextDockerIDMismatch(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	keyA, _ := crypto.GenerateSM2KeyPair()
	if err := ks.setTaaPublicKeyFor("docker-a", &keyA.PublicKey); err != nil {
		t.Fatalf("register key A: %v", err)
	}

	platformPriv := ks.platformPrivate()
	keys, err := envelope.NewKeys(&platformPriv.PublicKey, keyA, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build the TAA envelope keys: %v", err)
	}
	// The hint says A, the plaintext claims B: both are non-empty and differ.
	sealed, err := keys.Seal([]byte(`{"dockerId":"docker-b"}`), "docker-a")
	if err != nil {
		t.Fatalf("seal the mismatched body: %v", err)
	}
	if _, _, err := ks.openBodyWithID(sealed); err == nil {
		t.Fatal("a hint/plaintext dockerId mismatch was accepted")
	}
}

func TestKeystoreOpensWithTheHintedInstanceKey(t *testing.T) {
	ks, err := newMemoryKeystore(nil)
	if err != nil {
		t.Fatalf("create the keystore: %v", err)
	}
	keyA, _ := crypto.GenerateSM2KeyPair()
	keyB, _ := crypto.GenerateSM2KeyPair()
	_ = ks.setTaaPublicKeyFor("docker-a", &keyA.PublicKey)
	_ = ks.setTaaPublicKeyFor("docker-b", &keyB.PublicKey)

	platformPriv := ks.platformPrivate()
	keys, err := envelope.NewKeys(&platformPriv.PublicKey, keyA, ks.userIDBytes())
	if err != nil {
		t.Fatalf("build the TAA envelope keys: %v", err)
	}
	sealed, err := keys.Seal([]byte(`{"dockerId":"docker-a"}`), "docker-a")
	if err != nil {
		t.Fatalf("seal as A: %v", err)
	}
	plaintext, id, err := ks.openBodyWithID(sealed)
	if err != nil {
		t.Fatalf("open as A: %v", err)
	}
	if id != "docker-a" {
		t.Fatalf("recovered dockerId = %q, want docker-a", id)
	}
	if string(plaintext) != `{"dockerId":"docker-a"}` {
		t.Fatalf("plaintext = %s", plaintext)
	}
}
