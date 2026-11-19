package main

import (
	"errors"
	"fmt"
	"io"

	"taa/internal/hctproto"
)

// errAuthFailed marks a failed SM4-GCM tag check. The server maps it to
// StatusAuthFailed so the client can distinguish "wrong key/tampered data"
// from an internal helper failure.
var errAuthFailed = errors.New("gcm tag verification failed")

// engine is the thin interface between the frame server and the HCT library.
// The cgo implementation lives in bridge_hct_linux_amd64.go; every other build
// gets the stub in bridge_stub.go, so the package always compiles.
type engine interface {
	Version() string
	Close()

	KeyGen() (priv, pub []byte, err error)
	Encrypt(pub, plaintext []byte) ([]byte, error)
	Decrypt(priv, ciphertext []byte) ([]byte, error)
	SignDigest(priv, digest []byte) ([]byte, error)
	VerifyDigest(pub, digest, sig []byte) (bool, error)

	NewSM3() (sm3Stream, error)
	SM3Sum(data []byte) ([]byte, error)
	NewHMACSM3(key []byte) (sm3Stream, error)

	NewGCM(key, iv []byte, enc bool) (gcmStream, error)
}

// sm3Stream is an incremental SM3 (or HMAC-SM3) context.
type sm3Stream interface {
	Write(p []byte) error
	Sum() ([]byte, error)
	Free()
}

// gcmStream is an incremental SM4-GCM context. Update writes len(src) bytes to
// dst; Final reports the authentication verdict on decrypt and the tag becomes
// available on encrypt.
type gcmStream interface {
	AAD(p []byte) error
	Update(dst, src []byte) error
	Final() error
	SetTag(tag []byte) error
	Tag() ([]byte, error)
	Free()
}

const (
	sm3DigestSize = 32
	gcmIVSize     = 12
	gcmTagSize    = 16
	sm2PrivSize   = 32
	sm2PubSize    = 64
	sm2DigestSize = 32
	sm2SigSize    = 64
)

type gcmEntry struct {
	st  gcmStream
	enc bool
}

type server struct {
	eng     engine
	sm3s    map[uint64]sm3Stream
	gcms    map[uint64]gcmEntry
	write   func(hctproto.Header, []byte) error
	verbose bool
}

func newServer(eng engine, write func(hctproto.Header, []byte) error) *server {
	return &server{
		eng:   eng,
		sm3s:  make(map[uint64]sm3Stream),
		gcms:  make(map[uint64]gcmEntry),
		write: write,
	}
}

// serve runs the single-threaded request loop. A slow operation blocks the
// helper; the client's request timeout is the safety net and a timeout kills
// the helper rather than leaving it in an unknown state.
func (s *server) serve(r io.Reader) error {
	for {
		h, payload, err := hctproto.ReadFrame(r)
		if err != nil {
			return err
		}
		status, resp := s.handle(h.Op, payload)
		out := hctproto.Header{
			Version: hctproto.Version,
			Op:      h.Op,
			Status:  status,
			ReqID:   h.ReqID,
		}
		if err := s.write(out, resp); err != nil {
			return err
		}
		if h.Op == hctproto.OpClose {
			return nil
		}
	}
}

// freeStreams releases every live context. Called when the loop exits.
func (s *server) freeStreams() {
	for id, st := range s.sm3s {
		st.Free()
		delete(s.sm3s, id)
	}
	for id, e := range s.gcms {
		e.st.Free()
		delete(s.gcms, id)
	}
}

func okResp(payload []byte) (uint16, []byte) { return hctproto.StatusOK, payload }

func badRequest(err error) (uint16, []byte) {
	return hctproto.StatusBadRequest, []byte(err.Error())
}

func internal(err error) (uint16, []byte) {
	if errors.Is(err, errAuthFailed) {
		return hctproto.StatusAuthFailed, []byte(err.Error())
	}
	return hctproto.StatusInternal, []byte(err.Error())
}

func (s *server) handle(op uint16, payload []byte) (uint16, []byte) {
	switch op {
	case hctproto.OpHello:
		return s.handleHello()
	case hctproto.OpPing:
		return okResp(nil)
	case hctproto.OpClose:
		return okResp(nil)

	case hctproto.OpSM2Keygen:
		priv, pub, err := s.eng.KeyGen()
		if err != nil {
			return internal(err)
		}
		out := make([]byte, 0, sm2PrivSize+sm2PubSize)
		out = append(out, priv...)
		out = append(out, pub...)
		return okResp(out)
	case hctproto.OpSM2Encrypt:
		r := hctproto.NewReader(payload)
		pub := r.Bytes(sm2PubSize)
		plaintext := r.Rest()
		if err := r.Err(); err != nil {
			return badRequest(err)
		}
		if len(plaintext) == 0 {
			return badRequest(errors.New("empty plaintext"))
		}
		out, err := s.eng.Encrypt(pub, plaintext)
		if err != nil {
			return internal(err)
		}
		return okResp(out)
	case hctproto.OpSM2Decrypt:
		r := hctproto.NewReader(payload)
		priv := r.Bytes(sm2PrivSize)
		ciphertext := r.Rest()
		if err := r.Err(); err != nil {
			return badRequest(err)
		}
		if len(ciphertext) < sm2PubSize+sm3DigestSize {
			return badRequest(fmt.Errorf("SM2 ciphertext too short: %d", len(ciphertext)))
		}
		out, err := s.eng.Decrypt(priv, ciphertext)
		if err != nil {
			return internal(err)
		}
		return okResp(out)
	case hctproto.OpSM2SignDigest:
		r := hctproto.NewReader(payload)
		priv := r.Bytes(sm2PrivSize)
		digest := r.Bytes(sm2DigestSize)
		if err := r.Err(); err != nil {
			return badRequest(err)
		}
		if len(r.Rest()) != 0 {
			return badRequest(errors.New("trailing bytes in sign request"))
		}
		sig, err := s.eng.SignDigest(priv, digest)
		if err != nil {
			return internal(err)
		}
		return okResp(sig)
	case hctproto.OpSM2VerifyDigest:
		r := hctproto.NewReader(payload)
		pub := r.Bytes(sm2PubSize)
		digest := r.Bytes(sm2DigestSize)
		sig := r.Bytes(sm2SigSize)
		if err := r.Err(); err != nil {
			return badRequest(err)
		}
		if len(r.Rest()) != 0 {
			return badRequest(errors.New("trailing bytes in verify request"))
		}
		valid, err := s.eng.VerifyDigest(pub, digest, sig)
		if err != nil {
			return internal(err)
		}
		if !valid {
			return hctproto.StatusInvalidSignature, nil
		}
		return okResp(nil)

	case hctproto.OpSM3Init:
		id, err := streamID(payload)
		if err != nil {
			return badRequest(err)
		}
		st, err := s.eng.NewSM3()
		if err != nil {
			return internal(err)
		}
		s.sm3s[id] = st
		return okResp(nil)
	case hctproto.OpSM3Update, hctproto.OpHMACSM3Update:
		id, data, err := streamAndData(payload)
		if err != nil {
			return badRequest(err)
		}
		st, ok := s.sm3s[id]
		if !ok {
			return hctproto.StatusNotFound, []byte(fmt.Sprintf("unknown stream %d", id))
		}
		// libhct rejects a zero-length update; a no-op write is a no-op.
		if len(data) > 0 {
			if err := st.Write(data); err != nil {
				return internal(err)
			}
		}
		return okResp(nil)
	case hctproto.OpSM3Final, hctproto.OpHMACSM3Final:
		id, err := streamID(payload)
		if err != nil {
			return badRequest(err)
		}
		st, ok := s.sm3s[id]
		if !ok {
			return hctproto.StatusNotFound, []byte(fmt.Sprintf("unknown stream %d", id))
		}
		delete(s.sm3s, id)
		sum, err := st.Sum()
		st.Free()
		if err != nil {
			return internal(err)
		}
		return okResp(sum)
	case hctproto.OpSM3Abort, hctproto.OpHMACSM3Abort:
		id, err := streamID(payload)
		if err != nil {
			return badRequest(err)
		}
		if st, ok := s.sm3s[id]; ok {
			delete(s.sm3s, id)
			st.Free()
		}
		return okResp(nil)
	case hctproto.OpSM3Sum:
		sum, err := s.eng.SM3Sum(payload)
		if err != nil {
			return internal(err)
		}
		return okResp(sum)
	case hctproto.OpHMACSM3Init:
		r := hctproto.NewReader(payload)
		id := r.U64()
		key := r.Rest()
		if err := r.Err(); err != nil {
			return badRequest(err)
		}
		st, err := s.eng.NewHMACSM3(key)
		if err != nil {
			return internal(err)
		}
		s.sm3s[id] = st
		return okResp(nil)

	case hctproto.OpGCMInit:
		r := hctproto.NewReader(payload)
		id := r.U64()
		mode := r.U8()
		keyLen := int(r.U32())
		key := r.Bytes(keyLen)
		iv := r.Rest()
		if err := r.Err(); err != nil {
			return badRequest(err)
		}
		if mode > 1 {
			return badRequest(fmt.Errorf("invalid GCM mode %d", mode))
		}
		if len(iv) != gcmIVSize {
			return badRequest(fmt.Errorf("invalid GCM IV length %d", len(iv)))
		}
		st, err := s.eng.NewGCM(key, iv, mode == 1)
		if err != nil {
			return badRequest(err)
		}
		s.gcms[id] = gcmEntry{st: st, enc: mode == 1}
		return okResp(nil)
	case hctproto.OpGCMAAD, hctproto.OpGCMUpdate:
		id, data, err := streamAndData(payload)
		if err != nil {
			return badRequest(err)
		}
		e, ok := s.gcms[id]
		if !ok {
			return hctproto.StatusNotFound, []byte(fmt.Sprintf("unknown stream %d", id))
		}
		st := e.st
		if op == hctproto.OpGCMAAD {
			if len(data) > 0 {
				if err := st.AAD(data); err != nil {
					return internal(err)
				}
			}
			return okResp(nil)
		}
		out := make([]byte, len(data))
		if len(data) > 0 {
			if err := st.Update(out, data); err != nil {
				return internal(err)
			}
		}
		return okResp(out)
	case hctproto.OpGCMFinal:
		id, err := streamID(payload)
		if err != nil {
			return badRequest(err)
		}
		e, ok := s.gcms[id]
		if !ok {
			return hctproto.StatusNotFound, []byte(fmt.Sprintf("unknown stream %d", id))
		}
		delete(s.gcms, id)
		st := e.st
		ferr := st.Final()
		if ferr != nil {
			st.Free()
			return internal(ferr)
		}
		if !e.enc {
			st.Free()
			return okResp(nil)
		}
		tag, terr := st.Tag()
		st.Free()
		if terr != nil {
			return internal(terr)
		}
		return okResp(tag)
	case hctproto.OpGCMSetTag:
		id, tag, err := streamAndData(payload)
		if err != nil {
			return badRequest(err)
		}
		if len(tag) != gcmTagSize {
			return badRequest(fmt.Errorf("invalid GCM tag length %d", len(tag)))
		}
		e, ok := s.gcms[id]
		if !ok {
			return hctproto.StatusNotFound, []byte(fmt.Sprintf("unknown stream %d", id))
		}
		if err := e.st.SetTag(tag); err != nil {
			return internal(err)
		}
		return okResp(nil)
	case hctproto.OpGCMAbort:
		id, err := streamID(payload)
		if err != nil {
			return badRequest(err)
		}
		if e, ok := s.gcms[id]; ok {
			delete(s.gcms, id)
			e.st.Free()
		}
		return okResp(nil)

	default:
		return hctproto.StatusUnknownOp, []byte(fmt.Sprintf("unknown op %d", op))
	}
}

func (s *server) handleHello() (uint16, []byte) {
	version := s.eng.Version()
	accel := "sw"
	build := buildID
	var b hctproto.Builder
	b.U8(uint8(len(version)))
	b.Bytes([]byte(version))
	b.U8(uint8(len(accel)))
	b.Bytes([]byte(accel))
	b.U8(uint8(len(build)))
	b.Bytes([]byte(build))
	return okResp(b.Payload())
}

func streamID(payload []byte) (uint64, error) {
	r := hctproto.NewReader(payload)
	id := r.U64()
	if err := r.Err(); err != nil {
		return 0, err
	}
	if len(r.Rest()) != 0 {
		return 0, errors.New("trailing bytes in stream request")
	}
	return id, nil
}

func streamAndData(payload []byte) (uint64, []byte, error) {
	r := hctproto.NewReader(payload)
	id := r.U64()
	if err := r.Err(); err != nil {
		return 0, nil, err
	}
	return id, r.Rest(), nil
}
