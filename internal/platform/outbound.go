package platform

import (
	"fmt"
	"sync/atomic"
)

// outboundSealer turns a plaintext platform payload into the bytes that go on
// the wire. It is set once at startup and read-only afterwards.
//
// It lives here, at the lowest common send path, rather than at each of the six
// reporting functions: those all end in SendPlatformJSON, so one seam covers
// them and a new reporting function cannot forget to seal. The only other
// outbound path is controller.sendReportingJSON, which is why
// SealOutbound is exported for it.
//
// nil means "not configured". Production never runs that way - startup refuses
// to continue without the platform public key - but the package tests and any
// tool built directly on the package do, and refusing every send there would
// make the package untestable.
var outboundSealer atomic.Pointer[func([]byte) ([]byte, error)]

// SetOutboundEnvelope installs the sealer. It is called once from TAA startup
// with the instance's key material and its dockerID already bound.
//
// A nil sealer disables sealing; pass nil only from tests and tools.
func SetOutboundEnvelope(seal func(plaintext []byte) ([]byte, error)) {
	if seal == nil {
		outboundSealer.Store(nil)
		return
	}
	outboundSealer.Store(&seal)
}

// SealOutbound applies the installed sealer.
//
// sealed reports whether a sealer was installed. A caller that owns the send
// itself (controller.sendReportingJSON) must use it and must not fall back to
// the plaintext when sealing fails: the platform would reject the request, and
// the fallback would put business data on the wire unsealed.
func SealOutbound(payload []byte) (out []byte, sealed bool, err error) {
	seal := outboundSealer.Load()
	if seal == nil {
		return payload, false, nil
	}
	out, err = (*seal)(payload)
	if err != nil {
		return nil, true, fmt.Errorf("seal platform request: %w", err)
	}
	return out, true, nil
}
