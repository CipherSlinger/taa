package main

import "fmt"

// engineBuild is the set of backends a helper binary can construct. The cgo
// bridge fills it with the real engines; tests substitute fakes, so engine
// selection and the accelerator fallback can be checked without hardware.
type engineBuild struct {
	// sw is always present: it is the backend the helper has always run on.
	sw engine
	// ccp constructs the hardware CCP backend. It is nil when the build has
	// no CCP support and may still fail when the binary has it but the device
	// cannot be opened.
	ccp func() (engine, error)
	// logf receives the fallback reason; nil discards it.
	logf func(format string, args ...any)
}

// buildEngine turns the --accel value into a router. "sw" is unchanged from
// the single-engine behaviour. "ccp" puts the CCP engine in front and keeps sw
// behind it, so operations the CCP header cannot do incrementally (HMAC-SM3
// is burst-only) keep working. A CCP request that cannot be satisfied degrades
// to a pure-sw router rather than failing startup: the handshake then reports
// "sw", which is the truth.
func buildEngine(accel string, b engineBuild) (engine, error) {
	if accel == "" {
		accel = "sw"
	}
	switch accel {
	case "sw":
		return newRouter("sw", route{name: "sw", eng: b.sw}), nil
	case "ccp":
		ccp, err := constructCCP(b)
		if err != nil {
			b.log("accel ccp unavailable, falling back to sw: %v", err)
			return newRouter("sw", route{name: "sw", eng: b.sw}), nil
		}
		return newRouter("ccp",
			route{name: "ccp", eng: ccp},
			route{name: "sw", eng: b.sw},
		), nil
	default:
		return nil, fmt.Errorf("unsupported HCT accel %q (want sw or ccp)", accel)
	}
}

func (b engineBuild) log(format string, args ...any) {
	if b.logf != nil {
		b.logf(format, args...)
	}
}

func constructCCP(b engineBuild) (engine, error) {
	if b.ccp == nil {
		return nil, fmt.Errorf("CCP backend is not compiled into this binary")
	}
	return b.ccp()
}
