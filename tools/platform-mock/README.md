# Platform Mock

The Platform Mock is a lightweight, self-contained management platform simulator designed for TAA (Trusted Application Agent) development, testing, and debugging. It simulates the production control plane by handling node registration, remote attestation verification, model package delivery, progress tracking, execution log streaming, and result retrieval.

It includes an embedded Web GUI console for interactive operation and observability during local or remote development.

## Features

- **Platform Protocol Simulation**: Implements platform registration, model/training reporting, progress callbacks, and log ingestion endpoints.
- **Reverse Proxy**: Transparently proxies frontend requests to the target TAA instance (`/v1/taa/*`).
- **Interactive Web Console**: Fully embedded responsive UI (served directly via `embed.FS` from `internal/static/`), enabling manual inspection of nodes, attestation reports, model ingress, audit results, live logs, and task interruptions.
- **Hardware Attestation Validation**: Verifies Hygon CSV attestation reports received during node registration, with optional fallback for non-TEE test environments (`-allow-empty-attestation`).
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

Or run via the repository deployment script (starts in Docker or host mode):

```bash
./deploy.sh docker platform-mock
```

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
│   ├── proxy.go                 # TAA reverse proxy and Kubernetes pod discovery
│   ├── store.go                 # Thread-safe in-memory state and log ring buffer
│   └── static/                  # Embedded Web console assets (embed.FS)
│       ├── index.html           # Main dashboard template
│       ├── css/                 # Stylesheets (layout, components, variables)
│       └── js/                  # Frontend scripts (api, app, drawer, logs, tree, crypto)
└── README.md                    # This documentation
```
