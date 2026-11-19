# CLAUDE.md

Guidance for Claude Code in this repository.

## Common Commands

- Build TAA: `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa` (keep it static — the CSV2 initrd build rejects a dynamically linked binary)
- Build Platform-Mock: `go build -o bin/platform-mock ./tools/platform-mock/cmd/platform-mock`
- Build TEE-LLM: `(cd teellm && go build -o bin/teellm-service ./cmd/teellm-service)`
- Build / test TEE-Audit: `(cd teeaudit && GOWORK=off go build ./...)` / `(cd teeaudit && GOWORK=off go test ./...)`
- Tests: `go test ./cmd/... ./internal/... ./pkg/...`
- One test: `go test ./internal/controller/ -run TestPhase1Reimport -count=1`
- Format / vet: `gofmt -w .` and `go vet ./cmd/... ./internal/... ./pkg/...`

Gotchas:

- **`./...` is safe at the root now**, but keep scoping to `cmd`, `internal`, `pkg` out of habit.
  The Semgrep fixtures written in Go (`models/audit/holdout-sources/`) — 248 files that are not
  real packages — moved to `teeaudit/models/` behind a nested `go.mod`, so Go no longer walks
  them from either module.
- Python tests under `tests/` and `teeaudit/models/audit/tools/` are pytest-based and must run
  from the repo root. The audit tree now lives in the submodule, so the root `conftest.py` puts
  `teeaudit/` on `sys.path`; imports still resolve as `models.audit.tools.*` (the `models`
  namespace package merges `teeaudit/models` and the root `models/`). The system `python3` has no
  pytest; use e.g. `~/.venv/bin/python -m pytest tests/test_cpg_builder.py` (single test: append
  `::Class::method`).
- `go.work` spans three workspace modules (`taa`, `teeaudit`, `tools/sdk`); `teeaudit/teetls` is a
  replace target rather than a member, because every module that needs it replaces it. Resolving
  teetls through teeaudit keeps `teellm/` (22 GB, deployment only) out of the build path.
- `teellm/` and `teeaudit/` are submodules. A fresh clone needs
  `git submodule update --init --recursive` before any build; the deploy scripts do not do it.
  Only `teeaudit/` (with its nested `teetls`) is required to build and test TAA.

## Architecture (essentials)

TAA is a Go daemon running inside a Hygon CSV confidential VM (a Kata CSV2 Pod), and the **first
userspace process in the guest** — before `kata-agent`, before networking.

- **Startup** (`internal/app/taa`): probe the LLM service (advisory only — a fatal probe would
  deadlock the initrd path) → SM2 key pair → 64-byte USERDATA → CSV attestation report → platform
  registration (bounded background retry; the first attempt always loses the race with guest
  networking) → security config → HTTP on `:6001`. `buildSecurityConfig` is the only production
  constructor of `controller.SecurityConfig`; its zero value silently disables the binary audit
  channel. Deployment shape is chosen by `server.type`: `tee` (default), `fhe`, `data-anaylsis`;
  most `fhe` branching keys on `Runner != nil`, not the config string.
- **Request pipeline** (`internal/controller`): all routes are POST under `/v1/taa/*`.
  `TAAState` (`route.go`) owns the phase machine (1 debug / 2 test / 3 train / 4 inference) and
  per-operation locks; phase switching is refused while any task, import or audit is in flight.
  Import = download → resolve plaintext (URL data key, in-file envelope, or plaintext sniffing) →
  SM2/SM4-GCM decrypt → zip-slip-guarded extract → for models, report the import, then launch the
  audit **asynchronously and return**. The audit verdict is advisory: never make it block training
  or roll back an import — that decoupling is the product contract.
- **Persistent state** (`internal/store`): SM4-GCM sealed JSON keyed by the SM2 private scalar or
  the CSV sealing key, monotonic sequence number, `AuditPending` marker so a crash-interrupted
  audit is still reported after restart.
- **Code audit** (`teeaudit/` submodule, package `codeaudit`): Tier 1 is a `StaticEngine` (built-in
  regex scanner or
  offline Semgrep CLI, chosen by `codeAudit.codeScan.engine` at startup; missing rules path falls
  back to regex with a warning, unknown engine is refused). The rules, the benchmark tooling and
  the evaluation evidence live in the same submodule under `teeaudit/models/audit/`; deploy
  scripts read the rules from that path in the working copy. Tier 2 asks the TEE-LLM gateway to
  adjudicate each Tier 1 finding; `FailClosed` rejects the import when the gateway is unreachable.
  The binary channel (`binary_*.go`) runs independently of the engine; `BIN_001` (packed
  executable) is HIGH and blocks regardless of arbitration. Pass decision is
  `ComputeStatistics` + `ComputeConclusionContext`; `Report.Passed` still folds in scan
  completeness but the conclusion no longer ANDs it.
- **Runtime / resources**: `internal/runtime` runs `runtimeConfig` (`commands` + `env`) through
  `/bin/sh -c` in a dedicated process group under the model directory, so a stop SIGKILLs the
  whole tree. `internal/resource` handles envelope crypto, extraction, SM3 checksums and the
  index mapping `requestId/taskId` to data/result directories.
- `teellm/` is a git submodule (plus nested `teetls`) providing the inference gateway and the
  ShangMi TLS stack; deployed separately via `deploy-llm.sh`, not part of the TAA image.
- `teeaudit/` is a git submodule (GitHub `CipherSlinger/teeaudit`, plus nested `teetls`) holding
  the whole audit path: `codeaudit` (+ `codeaudit/cpg`), `llmclient`, and the `pkg/crypto`,
  `pkg/archiveentry`, `hctclient`, `hctproto` packages those depend on. TAA consumes it through
  `github.com/CipherSlinger/teeaudit/...` and a `replace` to `./teeaudit`.

## Deployment

Large production-shaped Bash scripts; there is no Makefile.

- `deploy.sh [start|stop|save] [components]` — always targets the remote Kata CSV2 Pod
  (`docker`/`local`/`remote` were removed and error out). `save` builds the TAA-only production
  image and needs a prebuilt semgrep payload archive
  (`deploy/guest-build/build-semgrep-payload-container.sh`).
- `deploy-llm.sh` (TEE-LLM pod, `--create-pod` on first run), `deploy-fhe.sh`,
  `deploy-dataanaylsis.sh`, `build-teellm-image.sh`.
- `deploy-taa-vm.sh` and `deploy/guest-build/build-initrd.sh` build the CSV2 initrd that injects
  TAA into the Kata guest image (`build|fetch-base|deploy|render|launch`).
- Config templates: `configs/taa-{docker,production,fhe,initrd,dataanaylsis}.json`. Identity
  precedence is asymmetric: on `tee` the config file wins over `PLATFORM_IP`/`DOCKER_ID`; on `fhe`
  the environment wins. `LLM_IP` / `TAA_LLM_ENDPOINT` always override the file.
- `deploy.md` lists what each base image ships and what each packaging path adds.

## Documentation

`README.md` (architecture, API, config reference), `docs/` (long-lived design docs only:
`architecture-design.md`, `api-design.md`, user guides), `api/openapi.yaml`, `deploy.md`, and
`CHANGELOG.md` — changelog entries explain the *why* behind most non-obvious code comments, so
read the relevant entry before changing a subsystem.

**Vendor reference — `docs/c86-devkit/`** — an offline mirror of the Hygon C86 DevKit docs site
(`https://c86.sourcefind.cn/documents/2/`, SSO-gated), 184 upstream Markdown pages plus their
images. Start at `docs/c86-devkit/README.md`, which indexes the whole tree. Read the relevant
page before changing anything that depends on vendor behaviour:

- `01. 机密计算/` — CSV/CSV2/CSV3 white papers (architecture, attestation, sealing, disk
  encryption, Confidential_AI, 1G hugetlb), plus step-by-step host setup and test guides
  including the QEMU parameters for encrypted VMs, DCU passthrough and Kata confidential
  containers.
- `03. 密码技术/` — HCT and TKM, i.e. the interface `internal/hct` speaks.
- `02. 可信计算/` — TPM / TCM / TDM / TSB.

It is vendor prose, not a contract: where the doc disagrees with what the hardware or the guest
actually does, the observation wins — note the divergence in the code comment or CHANGELOG.

Outward-facing documents (HTML manuals, DOCX/PDF, reports):

- Put the 纽创信安 / OSR logo in the page header's top-left corner.
- Use only the OSR palette: red `#b81c18`, orange `#e0630a`, warm neutrals for body `#241b17`,
  secondary `#6b5b54`, rules `#e9dad2`. No blue/gray corporate theme.
- Logo source: `word/media/image1.png` in the handbook DOCX (266×80); inline it as a base64
  `data:` URI in single-file HTML so the page works offline.

## Conventions

- **Comments: English only.**
- **Specs and plans** go in `.claude/specs/` and `.claude/plans/` — never in `docs/`. `.claude/`
  is gitignored, so force-add them with `git add -f`.
- **Commits**: commit automatically after finishing a change; English, Conventional Commits
  (`feat(scope): ...`, `docs(guide): ...`); no AI signatures or `Co-Authored-By` lines.
- **Reporting**: keep progress and milestone updates short and scannable; answer the question
  asked without expanding scope.