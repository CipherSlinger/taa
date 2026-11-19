//go:build !(hct && cgo && linux && amd64)

package main

import "errors"

// newEngine reports that HCT support is not compiled in. This is the default
// build: TAA itself and its tests never need libhct. The production helper is
// built with `-tags hct CGO_ENABLED=1` on linux/amd64 (see
// deploy/guest-build/build-hct-helper.sh).
func newEngine(accel string) (engine, error) {
	return nil, errors.New("HCT support is not compiled into this binary (build with -tags hct and CGO_ENABLED=1 on linux/amd64)")
}
