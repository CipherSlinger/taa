# Attestation chain verification on by default

Date: 2026-11-19

## Goal

Turn the remote-attestation certificate-chain check back on in the three places where it had
been switched off, using the machine's own `deploy/certs/hrk.cert` and
`deploy/certs/hsk_cek.cert`:

1. TAA verifies its own CSV attestation report at startup (`internal/attestation.VerifyReport`).
2. TAA verifies the TEE-LLM gateway's chain in the TEE-TLS handshake (the code-audit client).
3. `teellm-service` verifies a client that requests mutual attestation.

Mutual attestation itself stays opt-in: the client initiates it, the server verifies it, and
neither side requires it by default.

## Decisions

- **Self-check: chain required, failure is advisory.** A report whose PEK signature verifies but
  whose chain is missing or unanchored fails `VerifyReport`; the caller logs a WARNING and
  reports `verifiedPass=false` without stopping the process. The report signature is checked
  first so the error distinguishes a forged report from an absent chain.
- **Certificate lookup.** The first directory holding both files wins, in order
  `/root/taa/certs`, `/etc/taa/certs`, `deploy/certs` (relative, for a checkout). Explicit file
  paths are passed to `pkg/csvattest` so it never falls back to downloading the chain from the
  vendor KDS on the boot path.
- **Client.** The shipped templates stop setting `attestation.skipChainVerify` (and
  `insecureSkipVerify` in `taa-docker.json`), so the existing `false` defaults apply. The client
  config now receives `HRKCertPath`/`HSKCekCertPath`, which it previously used only to build the
  evidence provider, so the verifier anchors on the local files instead of the KDS.
- **Server.** `teellm-service` drops its hardcoded `InsecureSkipAttestationVerify: true` and
  points the config at `/root/taa/certs`. `VerifyMutualAttestation` stays false: the server does
  not demand attestation, but when a client requests it (`clientRequestedMutual`) the client's
  certificate and CSV evidence are now actually verified. The shipped
  `teellm-production.json` moves `attestation.mode` from `strict` to `permissive`, because
  strict with no expected measurement rejects every verified peer and the service has no
  measurement setting.
- **Packaging.** `deploy/certs` is copied to `/root/taa/certs` in the TAA production image
  (`deploy.sh save`), the remote TAA container, the CSV2 initrd guest rootfs
  (`build-initrd.sh`) and the TEE-LLM Pod (`deploy-llm.sh`, both create and update paths).
  Missing files fail the build/deploy. `deploy-llm.sh`'s image fingerprint and Pod content
  verification include the certs, so a changed chain forces a rebuild.

## Consequences

- `deploy/certs` is one machine's chain. On another machine the self-check reports
  `verifiedPass=false` and the TAA → TEE-LLM handshake fails; with `failClosed=true` that turns
  into rejected imports. A deployment must install its own pair at `/root/taa/certs`.
- Adding files to the initrd changes its bytes, so the guest's boot MEASUREMENT changes.
- The TEE-LLM image still carries no TAA payload; the certificate directory is the deliberate
  exception under `/root/taa`.

## Verification

- `go test ./cmd/... ./internal/... ./pkg/...` (avoids the Semgrep fixtures at the repo root).
- `cd teellm && GOWORK=off go test ./cmd/teellm-service/` and
  `cd teellm/teetls && GOWORK=off go test ./...`.
- `bash -n deploy.sh deploy-llm.sh deploy/guest-build/build-initrd.sh`.
- New tests pin: chain required, unanchored PEK rejected even with fixture certs, and the
  directory search order.
