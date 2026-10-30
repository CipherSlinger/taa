# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# TAA Project Guidelines

## Common Commands

- Build TAA: `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa` (static, matching the production image; the CSV2 initrd build rejects a dynamically linked binary)
- Build Platform-Mock: `go build -o bin/platform-mock ./tools/platform-mock/cmd/platform-mock`
- Build TEE-LLM: `(cd teellm && go build -o bin/teellm-service ./cmd/teellm-service)`
- Run tests: `go test ./cmd/... ./internal/... ./pkg/...`
- Run one Go test: `go test ./internal/controller/ -run TestPhase1Reimport -count=1`
- Format / vet: `gofmt -w .` and `go vet ./cmd/... ./internal/... ./pkg/...`

**`go test ./...` from the repo root does not work.** `models/audit/holdout-sources/` contains
Semgrep rule fixtures written in Go that are not real packages (missing imports, conflicting
package names), so the pattern fails to build before any test runs. Scope `./...` to
`cmd`, `internal` and `pkg`. The same trap applies to `go build ./...` and `go vet ./...`.

Python tooling under `tests/` and `models/audit/tools/` is pytest-based and expects to be run
from the repo root (imports resolve as `models.audit.tools.*`). The system `python3` has no
pytest installed; use a venv that does, e.g. `~/.venv/bin/python -m pytest tests/test_cpg_builder.py`.
Single test: append `::TestClass::test_method`.

`go.work` spans four modules (`taa`, `teellm`, `teellm/teetls`, `tools/sdk`), so Go commands
from any of those directories resolve against the workspace.

## Architecture

TAA is a Go daemon that runs inside a Hygon CSV confidential VM (a Kata CSV2 Pod). It is the
**first userspace process in the guest** — it boots before `kata-agent`, before the guest has
a network — and performs hardware attestation, platform registration, ciphertext ingress,
code audit and sandboxed execution.

### Startup lifecycle (`internal/app/taa`)

`Run` → `RunWithConfig`, in this order: probe the LLM inference service (advisory only — a
fatal probe would deadlock the initrd path, which has no network yet) → load or recover the
SM2 key pair → build 64-byte USERDATA from the public key → generate the CSV attestation
report → register with the platform (with bounded background retry, because the first attempt
always loses the race with guest networking) → build the security config → start the HTTP
server on `:6001`. `buildSecurityConfig` is the only production constructor of
`controller.SecurityConfig`; its zero value silently disables the binary audit channel.

The guest-side deployment has three shapes, selected by `server.type` in `taa-config.json`:
`tee` (default), `fhe` (orchestrates an FHE service on a GPU host, no attestation of its own)
and `data-anaylsis`. Most `fhe` branching keys on `Runner != nil`, not on the config string.

### Request pipeline (`internal/controller`)

`router.go` mounts every route under `/v1/taa/*`, POST-only. `TAAState` (`route.go`) is the
single mutable state object; it owns a phase machine (`1` debug / `2` test / `3` train /
`4` inference) and per-operation locks. Phase switching is refused while any task, import or
audit is in flight.

The import path is the core flow: download → resolve plaintext (URL-carried data key, legacy
in-file envelope, or plaintext archive sniffing) → decrypt with SM2/SM4-GCM → extract with
zip-slip guards → for models, report the import, then **launch the audit asynchronously and
return** (`launchModelAudit`). The audit verdict is advisory: it is reported to the platform
as a reference result and neither blocks training nor rolls back the import. Removing or
changing that decoupling would change the product contract, not just the code.

Persistent state is a sealed store (`internal/store`): an SM4-GCM encrypted JSON file keyed by
either the SM2 private scalar or the CSV hardware sealing key, with a monotonic sequence number
and a `AuditPending` marker so an audit interrupted by a crash is still reported after restart.

### Code audit (`internal/codeaudit`)

Two tiers plus an independent binary channel:
- **Tier 1** is a `StaticEngine` interface with two implementations — the built-in regex
  scanner and an offline Semgrep CLI adapter. The engine is chosen by
  `codeAudit.codeScan.engine` and constructed once at startup; a semgrep deployment without a
  usable rules path fails at startup, not per import.
- **Tier 2** asks the TEE-LLM gateway (over RFC 8998 TLS 1.3 with attestation, via the `teellm`
  submodule) to adjudicate each Tier 1 finding. `FailClosed` makes an unreachable gateway
  reject the import rather than silently degrading to static-only.
- **Binary channel** (`binary_*.go`) reads ELF/archives/pickles independently of the engine
  choice; `BIN_001` (packed executable) is HIGH and blocks regardless of arbitration.

The pass decision is `ComputeStatistics` + `ComputeConclusionContext` over classified findings;
`Report.Passed` still folds in scan completeness but the audit conclusion no longer ANDs it.

### Runtime and resources

`internal/runtime` executes the model's `runtimeConfig` (`commands` + `env`) through
`/bin/sh -c` in a dedicated process group under the model directory, so a stop can SIGKILL the
whole tree. `internal/resource` handles envelope crypto, archive extraction, SM3 checksums and
the import index that maps `requestId/taskId` to data and result directories.

`teellm/` is a git submodule (plus a nested `teetls` submodule) providing the inference gateway
and the ShangMi TLS stack. It is a separate deployment (`deploy-llm.sh`), not part of the TAA
image.

### Deployment scripts

These are large, production-shaped Bash scripts; there is no Makefile.

- `deploy.sh [docker|remote] [start|stop|save] [components]` — the main one. `save` is
  docker-only and builds the TAA-only production image (it needs a prebuilt semgrep payload
  archive; see `deploy/guest-build/build-semgrep-payload-container.sh`).
- `deploy-llm.sh` — deploys TEE-LLM into its own Kata CSV2 Pod (`--create-pod` the first time).
- `deploy-fhe.sh`, `deploy-dataanaylsis.sh`, `build-teellm-image.sh` — the other image chains.
- `deploy-taa-vm.sh` and `deploy/guest-build/build-initrd.sh` — the CSV2 initrd that injects TAA
  into the Kata guest image (`build|fetch-base|deploy|render|launch`).
- `deploy.md` documents what each base image already ships and what each packaging path adds.

Config templates live in `configs/` (`taa-docker.json`, `taa-production.json`, `taa-fhe.json`,
`taa-initrd.json`, `taa-dataanaylsis.json`). Environment identity precedence is asymmetric:
on `tee` instances the config file wins over `PLATFORM_IP`/`DOCKER_ID`; on `fhe` instances the
environment wins. `LLM_IP` / `TAA_LLM_ENDPOINT` always override the file.

## Documentation pointers

`README.md` (architecture diagram, API table, config field reference), `docs/architecture-design.md`
and `docs/api-design.md` (Chinese design docs), `api/openapi.yaml`, `deploy.md`, and
`CHANGELOG.md` — the changelog entries explain the *why* behind most non-obvious code comments,
so read the relevant entry before changing a subsystem.

## Documentation Style (outward-facing documents)
- **Logo**: every outward-facing document (HTML manuals, exported DOCX/PDF, reports) puts the 纽创信安 / OSR logo in the top-left corner of the page header.
- **Colors**: the whole document uses the OSR brand palette — red and orange, matching the logo. Red `#b81c18`, orange `#e0630a`; support with warm neutrals (body `#241b17`, secondary `#6b5b54`, rule `#e9dad2`). Do not introduce a blue/gray corporate theme.
- Logo source: `word/media/image1.png` inside the original handbook DOCX (266×80). For a single-file HTML, inline it as a base64 `data:` URI so the page works offline.

## Coding and Comment Guidelines
- **Code comments**: Must use English comments only.

## Planning and Documentation (Plan & Spec)
- All solution designs (spec) and implementation plans (plan) must be saved uniformly in `.claude/specs/` and `.claude/plans/`, strictly forbidden to be stored in `docs/`.
- `docs/` holds only core, long-lived design documents (e.g. `architecture-design.md`, `api-design.md`, user guides). Working notes, roadmaps, specs and plans never go there.
- `.claude/` is gitignored, so specs and plans must be tracked explicitly with `git add -f`. (`CLAUDE.md` is gitignored too — force-add it if a change to it should be committed.)

## Git and Version Control
- **Automatic commit**: Automatically execute Git commits after completing feature development or modifications.
- **Commit language and format**: Commit messages must be in **English** and strictly follow Conventional Commits conventions (e.g., `feat(scope): ...`, `docs(guide): ...`).
- **Remove AI traces**: Strictly prohibit any `Co-Authored-By`, `anthropic`, `Claude`, `AI`, or similar signatures and identifiers.

## Agent Collaboration and Communication
- **Progress reporting**: Keep reporting progress and milestones in real-time during the working process, but keep every report short and easy to understand — no walls of text.
- **Answer style**: Answer the question that was asked — concisely and directly. Do not diverge into unrelated topics, and do not expand the scope on your own initiative. Write so it is immediately understandable: plain wording, no obscure phrasing, no walls of text — a summary should be short and easy to scan, not long and hard to follow.