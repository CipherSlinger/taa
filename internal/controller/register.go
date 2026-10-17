package controller

import (
	"context"

	"taa/internal/platform"
)

// NoticeRegister makes one best-effort attempt to POST /v1/taa/register.
// The request carries the attestation report, TAA public key and, when
// available, the wrapped TAA private key.
func NoticeRegister(ctx context.Context, platformAddr, dockerID, attestationFile, taaPublicKey string, timestamp int64, verifiedPass bool, taaSecretKey string) error {
	return platform.NoticeRegister(ctx, platformAddr, dockerID, attestationFile, taaPublicKey, timestamp, verifiedPass, taaSecretKey)
}
