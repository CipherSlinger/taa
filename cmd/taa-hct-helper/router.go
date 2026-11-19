package main

import (
	"fmt"
	"strings"
)

// capability names one operation family the frame server can route to an
// engine. It exists because HCT's backends do not all cover the same
// algorithms: the CCP device can do SM2, SM3 and SM4-GCM, while the
// instruction-set paths only cover SM3 and SM4 block modes. Routing per
// operation lets a partially capable engine sit in front of a complete one
// without pretending it can serve everything.
type capability uint32

const (
	capSM2Keygen capability = 1 << iota
	capSM2Encrypt
	capSM2Decrypt
	capSM2Sign
	capSM2Verify
	capSM3Stream
	capSM3Sum
	capHMACSM3
	capGCM
)

func (c capability) String() string {
	switch c {
	case capSM2Keygen:
		return "sm2-keygen"
	case capSM2Encrypt:
		return "sm2-encrypt"
	case capSM2Decrypt:
		return "sm2-decrypt"
	case capSM2Sign:
		return "sm2-sign"
	case capSM2Verify:
		return "sm2-verify"
	case capSM3Stream:
		return "sm3-stream"
	case capSM3Sum:
		return "sm3-sum"
	case capHMACSM3:
		return "hmac-sm3"
	case capGCM:
		return "sm4-gcm"
	}
	return fmt.Sprintf("capability(%d)", uint32(c))
}

// capabilityReporter is implemented by an engine that can serve only part of
// the engine interface. An engine that does not implement it is assumed to
// serve every operation, which is how the interface behaved before routing.
type capabilityReporter interface {
	Supports(capability) bool
}

func engineSupports(e engine, c capability) bool {
	if r, ok := e.(capabilityReporter); ok {
		return r.Supports(c)
	}
	return true
}

// route binds an engine to the name it is reported under. The name is what the
// handshake sends back to TAA, so it must say which implementation is doing
// the work ("sw", "ccp"), not which knob was configured.
type route struct {
	name string
	eng  engine
}

// router dispatches every operation to the first route whose engine supports
// it. Today it wraps a single software engine; it is the seam the CCP engine
// plugs into, and it is what makes the handshake report per-operation routing
// instead of a single configured label.
type router struct {
	accel  string
	routes []route
}

func newRouter(accel string, routes ...route) *router {
	return &router{accel: accel, routes: routes}
}

func (r *router) Accel() string { return r.accel }

func (r *router) pick(c capability) (route, error) {
	for _, rt := range r.routes {
		if engineSupports(rt.eng, c) {
			return rt, nil
		}
	}
	return route{}, fmt.Errorf("no HCT engine can serve %s", c)
}

// capabilityGroups is the report granularity of Describe. Grouping keeps the
// log line short in the normal case (every operation in a group is served by
// the same engine) while still naming individual operations when a group is
// split across engines.
var capabilityGroups = []struct {
	name string
	caps []capability
}{
	{"sm2", []capability{capSM2Keygen, capSM2Encrypt, capSM2Decrypt, capSM2Sign, capSM2Verify}},
	{"sm3", []capability{capSM3Stream, capSM3Sum}},
	{"hmac-sm3", []capability{capHMACSM3}},
	{"sm4-gcm", []capability{capGCM}},
}

// Describe reports which engine serves each operation group, for example
// "sm2=sw sm3=sw hmac-sm3=sw sm4-gcm=sw". A group split across engines is
// reported per operation so the answer is never ambiguous.
func (r *router) Describe() string {
	var b strings.Builder
	for _, g := range capabilityGroups {
		name, uniform := r.groupName(g.caps)
		if uniform {
			fmt.Fprintf(&b, "%s=%s ", g.name, name)
			continue
		}
		for _, c := range g.caps {
			name := "none"
			if rt, err := r.pick(c); err == nil {
				name = rt.name
			}
			fmt.Fprintf(&b, "%s=%s ", c, name)
		}
	}
	return strings.TrimSpace(b.String())
}

// groupName returns the single engine serving every capability in caps. The
// second result is false when the set is empty, unserved, or split.
func (r *router) groupName(caps []capability) (string, bool) {
	name := ""
	for _, c := range caps {
		rt, err := r.pick(c)
		if err != nil {
			return "", false
		}
		if name == "" {
			name = rt.name
			continue
		}
		if rt.name != name {
			return "", false
		}
	}
	return name, name != ""
}

func (r *router) Version() string {
	if len(r.routes) == 0 {
		return ""
	}
	return r.routes[0].eng.Version()
}

func (r *router) Close() {
	for _, rt := range r.routes {
		rt.eng.Close()
	}
}

func (r *router) KeyGen() ([]byte, []byte, error) {
	rt, err := r.pick(capSM2Keygen)
	if err != nil {
		return nil, nil, err
	}
	return rt.eng.KeyGen()
}

func (r *router) Encrypt(pub, plaintext []byte) ([]byte, error) {
	rt, err := r.pick(capSM2Encrypt)
	if err != nil {
		return nil, err
	}
	return rt.eng.Encrypt(pub, plaintext)
}

func (r *router) Decrypt(priv, ciphertext []byte) ([]byte, error) {
	rt, err := r.pick(capSM2Decrypt)
	if err != nil {
		return nil, err
	}
	return rt.eng.Decrypt(priv, ciphertext)
}

func (r *router) SignDigest(priv, digest []byte) ([]byte, error) {
	rt, err := r.pick(capSM2Sign)
	if err != nil {
		return nil, err
	}
	return rt.eng.SignDigest(priv, digest)
}

func (r *router) VerifyDigest(pub, digest, sig []byte) (bool, error) {
	rt, err := r.pick(capSM2Verify)
	if err != nil {
		return false, err
	}
	return rt.eng.VerifyDigest(pub, digest, sig)
}

func (r *router) NewSM3() (sm3Stream, error) {
	rt, err := r.pick(capSM3Stream)
	if err != nil {
		return nil, err
	}
	return rt.eng.NewSM3()
}

func (r *router) SM3Sum(data []byte) ([]byte, error) {
	rt, err := r.pick(capSM3Sum)
	if err != nil {
		return nil, err
	}
	return rt.eng.SM3Sum(data)
}

func (r *router) NewHMACSM3(key []byte) (sm3Stream, error) {
	rt, err := r.pick(capHMACSM3)
	if err != nil {
		return nil, err
	}
	return rt.eng.NewHMACSM3(key)
}

func (r *router) NewGCM(key, iv []byte, enc bool) (gcmStream, error) {
	rt, err := r.pick(capGCM)
	if err != nil {
		return nil, err
	}
	return rt.eng.NewGCM(key, iv, enc)
}
