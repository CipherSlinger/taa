package mock

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"taa/internal/platform/envelope"
	teecrypto "taa/pkg/crypto"
)

// platformKeyState is the on-disk form of the keystore. The platform pair is
// stored as PEM because it is long-lived key material, not a display value.
type platformKeyState struct {
	PrivateKeyPEM string `json:"privateKeyPem"`
	PublicKeyHex  string `json:"publicKeyHex"`
	TaaPublicKey  string `json:"taaPublicKeyHex,omitempty"`
}

// keystore holds the mock's half of the envelope exchange: the platform SM2 key
// pair, fixed for the life of the state directory, and the TAA public key,
// learned at registration and replaced on every later registration.
//
// Persistence of the platform pair is mandatory, not a convenience. TAA caches
// the platform public key (PLATFORM_PUBLIC_KEY) and seals every message to it,
// so a restart that generated a fresh pair would make the running TAA's
// envelopes undecryptable until it was reconfigured and restarted with the new
// value. The TAA public key is persisted too: it is the only thing that can
// verify TAA's signatures, and losing it across a mock restart would reject
// every report until the next registration.
type keystore struct {
	mu     sync.RWMutex
	path   string
	userID []byte
	priv   *teecrypto.SM2PrivateKey
	taaPub *teecrypto.SM2PublicKey
}

// newKeystore loads the keystore from keyFile (or <stateDir>/platform-key.json
// when empty), generating and persisting the platform pair on first use.
//
// A key file that exists but cannot be parsed is a hard error rather than a
// silent regeneration: the failure mode of regenerating is that a running TAA
// keeps sealing to a key the mock no longer holds, which looks like a protocol
// bug rather than a lost file. The file in the state directory is the source of
// truth; there is no flag that replaces it.
func newKeystore(stateDir, keyFile string, id []byte) (*keystore, error) {
	path := strings.TrimSpace(keyFile)
	if path == "" {
		path = defaultStateFile(stateDir, "platform-key.json")
	}
	return loadOrCreateKeystore(path, id)
}

// newMemoryKeystore builds a keystore that never touches disk. It backs the
// handlers invoked without a Server (unit tests, embedders); a process that
// serves traffic always goes through NewServer and its persisted store.
func newMemoryKeystore(id []byte) (*keystore, error) {
	return loadOrCreateKeystore("", id)
}

func loadOrCreateKeystore(path string, id []byte) (*keystore, error) {
	ks := &keystore{path: path, userID: userIDOrProtocolDefault(id)}

	state, err := loadJSONFile[platformKeyState](path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load the platform key from %s: %w", path, err)
	}

	if strings.TrimSpace(state.PrivateKeyPEM) == "" {
		if err := ks.generate(); err != nil {
			return nil, err
		}
	} else {
		priv, err := teecrypto.ParseSM2PrivateKeyPEM([]byte(state.PrivateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse the persisted platform private key %s: %w", path, err)
		}
		ks.priv = priv
		if strings.TrimSpace(state.TaaPublicKey) != "" {
			pub, err := teecrypto.ParseSM2PublicKeyHex(state.TaaPublicKey)
			if err != nil {
				// The registered key is replaceable at the next registration, so a
				// damaged one is dropped with a warning rather than blocking startup.
				log.Printf("persisted TAA public key is unparseable, waiting for the next registration: %v", err)
			} else {
				ks.taaPub = pub
			}
		}
		log.Printf("platform SM2 key loaded from %s", path)
	}

	// Log the effective identity and public key once. Both are public
	// parameters, and an operator needs the key to put it in TAA's
	// PLATFORM_PUBLIC_KEY after every restart, not only the first one.
	log.Printf("[envelope] platform SM2 identity in effect: %q", string(ks.userID))
	log.Printf("[envelope] PLATFORM_PUBLIC_KEY for TAA: %s", ks.platformPublicHex())
	return ks, nil
}

// generate creates a fresh platform pair and persists it.
func (s *keystore) generate() error {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		return fmt.Errorf("generate the platform SM2 key pair: %w", err)
	}
	s.mu.Lock()
	s.priv = priv
	persistErr := s.persistLocked()
	s.mu.Unlock()
	if persistErr != nil {
		return persistErr
	}
	log.Printf("[envelope] generated a new platform SM2 key pair in %s", s.path)
	return nil
}

// persistLocked writes the current state. Callers must hold mu.
func (s *keystore) persistLocked() error {
	if s.priv == nil || s.path == "" {
		return nil
	}
	privPEM, err := teecrypto.MarshalSM2PrivateKeyPEM(s.priv)
	if err != nil {
		return fmt.Errorf("encode the platform SM2 private key: %w", err)
	}
	pubHex, err := teecrypto.MarshalSM2PublicKeyHex(&s.priv.PublicKey)
	if err != nil {
		return fmt.Errorf("encode the platform SM2 public key: %w", err)
	}
	state := platformKeyState{PrivateKeyPEM: string(privPEM), PublicKeyHex: pubHex}
	if s.taaPub != nil {
		taaHex, err := teecrypto.MarshalSM2PublicKeyHex(s.taaPub)
		if err != nil {
			return fmt.Errorf("encode the TAA public key: %w", err)
		}
		state.TaaPublicKey = taaHex
	}
	if err := saveJSONFile(s.path, state); err != nil {
		return fmt.Errorf("save the platform key to %s: %w", s.path, err)
	}
	return nil
}

// platformPrivate returns the platform's SM2 private key.
func (s *keystore) platformPrivate() *teecrypto.SM2PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.priv
}

// platformPublicHex returns the platform public key in the "04||X||Y" hex form
// TAA is configured with (PLATFORM_PUBLIC_KEY).
func (s *keystore) platformPublicHex() string {
	s.mu.RLock()
	priv := s.priv
	s.mu.RUnlock()
	if priv == nil {
		return ""
	}
	hexValue, err := teecrypto.MarshalSM2PublicKeyHex(&priv.PublicKey)
	if err != nil {
		return ""
	}
	return hexValue
}

// taaPublic returns the registered TAA public key, or nil when no TAA has
// registered yet.
func (s *keystore) taaPublic() *teecrypto.SM2PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.taaPub
}

// hasTaaPublicKey reports whether an outbound request can be sealed at all.
func (s *keystore) hasTaaPublicKey() bool {
	return s.taaPublic() != nil
}

// setTaaPublicKey records the key from a registration, replacing any previous
// one, and persists it so a restart does not have to wait for a re-registration.
// An unparseable value is rejected: storing it would only turn into a seal
// failure later, away from the request that supplied the bad key.
func (s *keystore) setTaaPublicKey(pub *teecrypto.SM2PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.taaPub = pub
	if err := s.persistLocked(); err != nil {
		return err
	}
	log.Printf("TAA public key registered and persisted")
	return nil
}

// userIDBytes returns the SM2 identity this keystore signs and verifies with.
func (s *keystore) userIDBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.userID
}

// sealForTAA produces a platform-direction envelope for plaintext.
//
// It returns an error instead of falling back to plaintext when no TAA public
// key is registered: TAA now refuses every unsealed request, so sending
// plaintext would only turn a local "no key yet" into a remote rejection that
// gives no hint about the actual cause.
func (s *keystore) sealForTAA(plaintext []byte) ([]byte, error) {
	s.mu.RLock()
	priv := s.priv
	taaPub := s.taaPub
	userID := s.userID
	s.mu.RUnlock()
	if priv == nil {
		return nil, fmt.Errorf("platform SM2 private key is not available")
	}
	if taaPub == nil {
		return nil, fmt.Errorf("no TAA public key registered yet: wait for TAA to register before sending it requests")
	}
	return envelope.SealForPlatform(priv, taaPub, userID, plaintext)
}

// openBody parses and verifies a sealed report from TAA, returning the
// plaintext body the handlers decode exactly as before.
func (s *keystore) openBody(body []byte) ([]byte, error) {
	env, err := envelope.Parse(body)
	if err != nil {
		return nil, err
	}
	return s.openFromTAAResponse(env)
}

// openRegister opens a registration body and verifies its signature against
// the TAA public key carried inside it.
//
// Registration is sealed like every other message; what differs is the key the
// signature is checked against. The protocol says the platform verifies this
// one self-signature with the taaPublicKey in the plaintext (see
// docs/taa-agent-delivery.md), because the platform has no other copy yet. That
// makes the first registration trust-on-first-use, and every later one a key
// rotation.
//
// The plaintext is produced by decrypting first - decryption needs only the
// platform private key - and the signature is then checked by replaying the
// whole envelope through OpenFromPlatform with the carried key. Decrypting
// twice is deliberate: the verification stays inside the envelope package
// instead of duplicating the signature rules here.
//
// Adopting the key is the caller's job, and only after the registration has
// otherwise been accepted: a rejected registration must not replace the key a
// running TAA is already using.
func (s *keystore) openRegister(body []byte) ([]byte, *teecrypto.SM2PublicKey, error) {
	env, err := envelope.Parse(body)
	if err != nil {
		return nil, nil, err
	}
	priv := s.platformPrivate()
	if priv == nil {
		return nil, nil, fmt.Errorf("platform SM2 private key is not available")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(env.Cipher)
	if err != nil {
		return nil, nil, fmt.Errorf("decode register cipher: %w", err)
	}
	plaintext, err := teecrypto.DecryptSM2(priv, ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt register body: %w", err)
	}

	var req struct {
		TaaPublicKey string `json:"taaPublicKey"`
	}
	if err := json.Unmarshal(plaintext, &req); err != nil {
		return nil, nil, fmt.Errorf("parse register body: %w", err)
	}
	if strings.TrimSpace(req.TaaPublicKey) == "" {
		return nil, nil, fmt.Errorf("register body carries no taaPublicKey")
	}
	pub, err := teecrypto.ParseSM2PublicKeyHex(req.TaaPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse register taaPublicKey: %w", err)
	}

	if _, err := envelope.OpenFromPlatform(priv, pub, s.userID, env); err != nil {
		return nil, nil, fmt.Errorf("verify the registration self-signature: %w", err)
	}
	return plaintext, pub, nil
}

// readSealedBody reads r.Body and returns the plaintext inside its envelope.
func (s *keystore) readSealedBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("读取请求体失败: %w", err)
	}
	return s.openBody(body)
}

// openFromTAAResponse opens a response TAA sealed. TAA signs with the same key
// it registers, so this is the ordinary inbound path with the roles swapped.
func (s *keystore) openFromTAAResponse(env *envelope.Envelope) ([]byte, error) {
	s.mu.RLock()
	priv := s.priv
	taaPub := s.taaPub
	userID := s.userID
	s.mu.RUnlock()
	if priv == nil {
		return nil, fmt.Errorf("platform SM2 private key is not available")
	}
	if taaPub == nil {
		return nil, fmt.Errorf("no TAA public key registered yet")
	}
	return envelope.OpenFromPlatform(priv, taaPub, userID, env)
}

// userIDOrProtocolDefault resolves nil/empty to the protocol identity without
// copying; the envelope package copies where it stores.
func userIDOrProtocolDefault(id []byte) []byte {
	if len(id) == 0 {
		return teecrypto.SM2DefaultUserID
	}
	return id
}

// platformKeys is the process-wide keystore. The mock represents one platform
// instance, so every handler has to share one identity; this follows the
// package's existing singleton (requestLogs) rather than threading a pointer
// through every handler.
//
// It is set by NewServer from the configured state directory. Handlers invoked
// without a server (unit tests, and any future embedder) fall back to a
// generated in-memory keystore through platformKeyStore.
var (
	platformKeysMu sync.Mutex
	platformKeys   *keystore
)

// currentPlatformKeys is the resolver the handlers and the proxy use. It is a
// variable so tests can pin one deterministic keystore; production leaves it at
// platformKeyStore, which follows the installed server keystore.
var currentPlatformKeys = platformKeyStore

// platformKeyStore returns the process keystore, creating an in-memory one on
// first use when no server has installed one.
func platformKeyStore() *keystore {
	platformKeysMu.Lock()
	defer platformKeysMu.Unlock()
	if platformKeys == nil {
		ks, err := newMemoryKeystore(nil)
		if err != nil {
			// newKeystore only fails on a damaged file; with no path there is
			// nothing to damage, so this is a key-generation failure and no
			// envelope can ever be produced.
			log.Printf("create the in-memory platform keystore: %v", err)
		}
		platformKeys = ks
	}
	return platformKeys
}

// setPlatformKeys installs the server's keystore. It is for NewServer and for
// tests that need a deterministic identity.
func setPlatformKeys(ks *keystore) {
	platformKeysMu.Lock()
	platformKeys = ks
	platformKeysMu.Unlock()
}
