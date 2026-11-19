package main

import (
	"strings"
	"testing"

	"taa/internal/hctproto"
)

// fakeEngine implements every operation so it can stand in for a complete
// backend. It records which operation was routed to it, which is what the
// dispatch tests assert on.
type fakeEngine struct {
	closed bool
	last   string
}

func (f *fakeEngine) Version() string                 { return "fake-3.0.10" }
func (f *fakeEngine) Close()                          { f.closed = true }
func (f *fakeEngine) KeyGen() ([]byte, []byte, error) { f.last = "keygen"; return nil, nil, nil }
func (f *fakeEngine) Encrypt(pub, plaintext []byte) ([]byte, error) {
	f.last = "encrypt"
	return nil, nil
}
func (f *fakeEngine) Decrypt(priv, ciphertext []byte) ([]byte, error) {
	f.last = "decrypt"
	return nil, nil
}
func (f *fakeEngine) SignDigest(priv, digest []byte) ([]byte, error) {
	f.last = "sign"
	return nil, nil
}
func (f *fakeEngine) VerifyDigest(pub, digest, sig []byte) (bool, error) {
	f.last = "verify"
	return true, nil
}
func (f *fakeEngine) NewSM3() (sm3Stream, error) { f.last = "sm3-stream"; return &fakeSM3{f}, nil }
func (f *fakeEngine) SM3Sum(data []byte) ([]byte, error) {
	f.last = "sm3-sum"
	return make([]byte, sm3DigestSize), nil
}
func (f *fakeEngine) NewHMACSM3(key []byte) (sm3Stream, error) {
	f.last = "hmac-sm3"
	return &fakeSM3{f}, nil
}
func (f *fakeEngine) NewGCM(key, iv []byte, enc bool) (gcmStream, error) {
	f.last = "gcm"
	return &fakeGCM{f}, nil
}

// cappedEngine declares that it serves only the capabilities in caps. An
// engine without this method is assumed to serve everything.
type cappedEngine struct {
	*fakeEngine
	caps capability
}

func (c *cappedEngine) Supports(want capability) bool { return c.caps&want != 0 }

type fakeSM3 struct{ owner *fakeEngine }

func (s *fakeSM3) Write(p []byte) error { s.owner.last = "sm3-write"; return nil }
func (s *fakeSM3) Sum() ([]byte, error) { return make([]byte, sm3DigestSize), nil }
func (s *fakeSM3) Free()                {}

type fakeGCM struct{ owner *fakeEngine }

func (g *fakeGCM) AAD(p []byte) error           { return nil }
func (g *fakeGCM) Update(dst, src []byte) error { return nil }
func (g *fakeGCM) Final() error                 { return nil }
func (g *fakeGCM) SetTag(tag []byte) error      { return nil }
func (g *fakeGCM) Tag() ([]byte, error)         { return make([]byte, gcmTagSize), nil }
func (g *fakeGCM) Free()                        {}

// TestRouterDispatchesByCapability pins the point of the router: an engine
// that cannot serve an operation is skipped for that operation only.
func TestRouterDispatchesByCapability(t *testing.T) {
	partial := &cappedEngine{fakeEngine: &fakeEngine{}, caps: capSM3Sum}
	full := &fakeEngine{}
	r := newRouter("mixed", route{name: "partial", eng: partial}, route{name: "full", eng: full})

	if _, err := r.SM3Sum(nil); err != nil {
		t.Fatalf("SM3Sum: %v", err)
	}
	if partial.last != "sm3-sum" {
		t.Fatalf("SM3Sum went to %q, want the capable engine", partial.last)
	}
	if _, err := r.NewGCM(nil, nil, true); err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	if full.last != "gcm" {
		t.Fatalf("NewGCM went to the complete engine (%q), want it to skip the partial one", full.last)
	}
	if partial.last != "sm3-sum" {
		t.Fatalf("partial engine served an operation it does not support: %q", partial.last)
	}
}

func TestRouterReportsUnservedCapability(t *testing.T) {
	r := newRouter("none", route{name: "empty", eng: &cappedEngine{fakeEngine: &fakeEngine{}}})
	if _, _, err := r.KeyGen(); err == nil {
		t.Fatal("expected an error when no engine serves key generation")
	} else if !strings.Contains(err.Error(), "sm2-keygen") {
		t.Fatalf("err = %v, want it to name the unserved capability", err)
	}
}

func TestRouterDescribeUniform(t *testing.T) {
	eng := &fakeEngine{}
	r := newRouter("sw", route{name: "sw", eng: eng})
	const want = "sm2=sw sm3=sw hmac-sm3=sw sm4-gcm=sw"
	if got := r.Describe(); got != want {
		t.Fatalf("Describe() = %q, want %q", got, want)
	}
	if r.Accel() != "sw" {
		t.Fatalf("Accel() = %q, want sw", r.Accel())
	}
}

// TestRouterDescribeSplitGroup keeps the report honest when one algorithm
// family is split across engines: the group is expanded per operation instead
// of naming a single engine that does not serve all of it.
func TestRouterDescribeSplitGroup(t *testing.T) {
	signOnly := &cappedEngine{fakeEngine: &fakeEngine{}, caps: capSM2Sign}
	rest := &cappedEngine{fakeEngine: &fakeEngine{}, caps: capSM2Keygen | capSM2Encrypt | capSM2Decrypt | capSM2Verify | capSM3Stream | capSM3Sum | capHMACSM3 | capGCM}
	r := newRouter("mixed", route{name: "signer", eng: signOnly}, route{name: "rest", eng: rest})

	got := r.Describe()
	for _, want := range []string{
		"sm2-keygen=rest",
		"sm2-sign=signer",
		"sm2-verify=rest",
		"sm3=rest",
		"hmac-sm3=rest",
		"sm4-gcm=rest",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Describe() = %q, want it to contain %q", got, want)
		}
	}
}

// TestRouterAssumesCompleteEngine has to hold for engines written before
// capabilities existed: they must keep serving every operation.
func TestRouterAssumesCompleteEngine(t *testing.T) {
	eng := &fakeEngine{}
	r := newRouter("sw", route{name: "sw", eng: eng})
	if _, err := r.NewHMACSM3(nil); err != nil {
		t.Fatalf("NewHMACSM3 on an undeclared engine: %v", err)
	}
	if eng.last != "hmac-sm3" {
		t.Fatalf("operation not dispatched: %q", eng.last)
	}
}

func TestRouterCloseClosesEveryRoute(t *testing.T) {
	a := &fakeEngine{}
	b := &fakeEngine{}
	newRouter("mixed", route{name: "a", eng: a}, route{name: "b", eng: b}).Close()
	if !a.closed || !b.closed {
		t.Fatalf("Close() closed a=%v b=%v, want both", a.closed, b.closed)
	}
}

// TestHelloCarriesEngineMap pins the handshake extension the TAA log relies
// on: the helper reports the effective accel and the per-operation engines,
// not the configured values.
func TestHelloCarriesEngineMap(t *testing.T) {
	eng := &fakeEngine{}
	srv := newServer(newRouter("sw", route{name: "sw", eng: eng}),
		func(hctproto.Header, []byte) error { return nil })

	status, payload := srv.handle(hctproto.OpHello, nil)
	if status != hctproto.StatusOK {
		t.Fatalf("hello status = %d", status)
	}
	r := hctproto.NewReader(payload)
	version := string(r.Bytes(int(r.U8())))
	accel := string(r.Bytes(int(r.U8())))
	_ = r.Bytes(int(r.U8())) // build id
	engines := string(r.Bytes(int(r.U8())))
	if err := r.Err(); err != nil {
		t.Fatalf("parse hello: %v", err)
	}
	if version != "fake-3.0.10" || accel != "sw" {
		t.Fatalf("hello version=%q accel=%q", version, accel)
	}
	if engines != "sm2=sw sm3=sw hmac-sm3=sw sm4-gcm=sw" {
		t.Fatalf("hello engines = %q", engines)
	}
}
