# Platform Mock

The Platform Mock is a lightweight, self-contained management platform simulator designed for TAA (Trusted Application Agent) development, testing, and debugging. It simulates the production control plane by handling node registration, remote attestation verification, model package delivery, progress tracking, execution log streaming, and result retrieval.

It includes an embedded Web GUI console for interactive operation and observability during local or remote development.

## Features

- **Platform Protocol Simulation**: Implements platform registration, model/training reporting, progress callbacks, and log ingestion endpoints.
- **Reverse Proxy**: Transparently proxies frontend requests to the target TAA instance (`/taa/*`), sealing them on the way out.
- **Interactive Web Console**: Fully embedded responsive UI (served directly via `embed.FS` from `internal/static/`), enabling manual inspection of nodes, attestation reports, model ingress, audit results, live logs, and task interruptions.
- **Hardware Attestation Validation**: Verifies Hygon CSV attestation reports received during node registration, with optional fallback for non-TEE test environments (`-allow-empty-attestation`).
- **SM2 Envelope**: Speaks the same `{dockerId, cipher, sign}` framing as the production platform — every request to TAA is sealed, every callback from TAA is opened and verified, and the platform key pair is persisted.
- **File Upload & Delivery Service**: Handles encrypted model package uploads and serves them to TAA via HTTP.

## Build & Run

### Build

From the repository root:

```bash
go build -o bin/platform-mock ./tools/platform-mock/cmd/platform-mock
```

### Run

Run standalone with a direct HTTP target to TAA:

```bash
./bin/platform-mock -addr 0.0.0.0:8080 -taa-target http://127.0.0.1:6001
```

On first start the mock creates and persists a platform SM2 key pair and logs the
`PLATFORM_PUBLIC_KEY` value to give TAA (see [SM2 Envelope](#sm2-envelope)). Set the same
`PLATFORM_SM2_ID` for both processes if you override the default identity.

### Lifecycle (local or remote)

`deploy-platform-mock.sh` at the repository root owns build, start, stop, restart and status.
`deploy.sh` and `deploy-fhe.sh` delegate to it, so the flags and readiness probe are defined
in one place.

```bash
# Local: builds bin/platform-mock, then runs it detached
./deploy-platform-mock.sh local start --taa-target http://127.0.0.1:6001 --allow-empty-attestation
./deploy-platform-mock.sh local status
./deploy-platform-mock.sh local restart
./deploy-platform-mock.sh local stop

# Remote: builds linux/static, uploads over SSH and starts it detached
./deploy-platform-mock.sh remote start --host 172.16.10.178 --user root --password '...' \
  --remote-dir /root/taa --taa-target http://127.0.0.1:6001
./deploy-platform-mock.sh remote status --host 172.16.10.178
./deploy-platform-mock.sh remote stop --host 172.16.10.178
```

Useful options: `--state-dir` / `--upload-dir` (omitted when empty, which keeps the binary's
own defaults), `--reuse` (start only if nothing already answers), `--reset-register` (POST
`/api/register/reset` after the instance is ready), `--skip-build`, `--dry-run`, and
`--ready-timeout` / `--ready-interval`. Run `./deploy-platform-mock.sh --help` for the full
list.

## Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | Mock platform HTTP listen address. |
| `-state-dir` | `/root/taa` (or `$STATE_DIR`) | Directory used to persist registration and execution state files (`register.json`, `report.json`). |
| `-upload-dir` | `.local/upload` (or `$UPLOAD_DIR`) | Directory used to store uploaded model files, served at `/files/`. |
| `-taa-target` | `""` | Direct URL of the TAA instance for reverse proxying (e.g. `http://127.0.0.1:6001`). When omitted, auto-discovers via Kubernetes Pod. |
| `-taa-pod` | `simple-busybox` (or `$TAA_POD`) | Target Kubernetes pod name used for auto-discovering the TAA IP address via `kubectl` when `-taa-target` is empty. |
| `-taa-ns` | `""` (or `$TAA_NS`) | Target Kubernetes namespace for `-taa-pod` (empty string indicates default namespace). |
| `-taa-port` | `6001` (or `$TAA_PORT`) | Port on the target pod where TAA listens. |
| `-allow-empty-attestation` | `false` | When set to `true`, permits node registration without a valid Hygon CSV attestation report (useful for simulated non-TEE environments). |
| `-sm2-id` | `""` = `1234567812345678` (or `$PLATFORM_SM2_ID`) | SM2 signature identity (`ID_A`). Must be byte-identical to the `PLATFORM_SM2_ID` TAA was started with, or signatures will not verify. The effective value is logged at startup. |
| `-platform-key-file` | `<state-dir>/platform-key.json` (or `$PLATFORM_KEY_FILE`) | Where the platform SM2 key pair (and the last registered TAA public key) is persisted. Generated on first use; a restart reuses the same pair. |

## SM2 Envelope

TAA seals every platform message, so the mock does the same and nothing is sent in cleartext.

- **Outbound (mock → TAA)**: every request (`/v1/taa/status`, `getResourceInfo`, `stopTraining`, `/v1/taa/import`, and everything the console sends through the `/taa/*` reverse proxy) is sealed with `envelope.SealForPlatform` using the platform private key and the registered TAA public key. If no TAA has registered yet, the request fails locally with `no TAA public key registered yet` — there is no plaintext fallback, because TAA would reject the plaintext anyway and the failure would be misleading. Responses are opened when they are envelopes and passed through untouched otherwise; the reverse proxy only opens JSON responses, so binary exports are streamed through unchanged.
- **Inbound (TAA → mock)**: `register`, `reportResourceRes`, `reportRes`, `reportModelImport`, `reportAudit`, `reportProgress`, `modelLog` and `taaLog` all decrypt-then-verify the body before decoding the business JSON. A body that is not a valid envelope, or whose signature does not verify, is answered with HTTP 401 and the callback stores nothing.
- **Registration**: sealed like every other message; there is no exemption. The one difference is the key its signature is checked against — the `taaPublicKey` carried in the plaintext, since the platform has no other copy yet. The key is adopted (and replaces any previous one) only after the registration passes its other checks, then persisted.
- **Key persistence is mandatory**: TAA caches the platform public key (`PLATFORM_PUBLIC_KEY`) and seals to it, so a mock restart that generated a fresh pair would make every running TAA's envelopes undecryptable. The mock logs the key to use on every start:

  ```text
  [envelope] platform SM2 identity in effect: "1234567812345678"
  [envelope] PLATFORM_PUBLIC_KEY for TAA: 04...
  ```

  Set that value as TAA's `PLATFORM_PUBLIC_KEY` before starting TAA. Deleting `platform-key.json` is equivalent to rotating the platform key: every TAA must be reconfigured and restarted.

## Web Console

The platform mock provides an embedded single-page Web console accessible by opening `http://localhost:8080` (or the configured `-addr`) in a browser:

- **Static Asset Embedding**: The UI assets are statically bundled into the binary using Go `embed.FS` from `internal/static/`.
- **Node Status & Attestation**: Displays registered node metadata, ephemeral SM2 public key, and CSV hardware attestation report validation status.
- **Model Ingress & Audit**: Upload model packages, inspect static AST rule violations, and observe Ollama LLM semantic verification outcomes.
- **Real-Time Progress & Logs**: Displays real-time progress bars, streamed terminal logs (`modelLog`), and TAA daemon operational logs (`taaLog`).
- **Execution Control**: Send graceful stop commands (`/v1/taa/stopTraining`) to interrupt running workloads.

## Directory Structure

```text
tools/platform-mock/
├── cmd/
│   └── platform-mock/
│       └── main.go              # Minimal CLI entry point, flag parsing, signal handling
├── internal/
│   ├── config.go                # Runtime configuration and environment variable defaults
│   ├── server.go                # HTTP server orchestration and lifecycle management
│   ├── server_test.go           # HTTP routing, validation, and handler unit tests
│   ├── handlers_api.go          # Platform mock UI API endpoints (/api/*)
│   ├── handlers_crypto.go       # Cryptographic utilities and key validation
│   ├── handlers_taa.go          # TAA callback endpoints (/api/register, /v1/taa/*)
│   ├── handlers_upload.go       # File upload and static asset serving (/files/*)
│   ├── keystore.go              # Platform SM2 key pair + registered TAA public key (persisted)
│   ├── proxy.go                 # TAA reverse proxy and Kubernetes pod discovery
│   ├── store.go                 # Thread-safe in-memory state and log ring buffer
│   └── static/                  # Embedded Web console assets (embed.FS)
│       ├── index.html           # Main dashboard template
│       ├── css/                 # Stylesheets (layout, components, variables)
│       └── js/                  # Frontend scripts (api, app, drawer, logs, tree, crypto)
└── README.md                    # This documentation
```
