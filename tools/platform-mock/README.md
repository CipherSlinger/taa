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

### Lifecycle (remote host)

`deploy-platform-mock.sh` at the repository root owns build, start, stop, restart and status.
`deploy.sh` and `deploy-fhe.sh` do not deploy the mock; they only point TAA at a platform, so
the flags and readiness probe are defined in one place. Local mode has been removed: the mock
runs on the remote host.

```bash
# Builds linux/static, uploads over SSH and starts it detached
./deploy-platform-mock.sh start --host 172.16.10.178 --user root --remote-password '...' \
  --remote-dir /root/taa --taa-target http://127.0.0.1:6001 --allow-empty-attestation
./deploy-platform-mock.sh status --host 172.16.10.178
./deploy-platform-mock.sh restart --host 172.16.10.178
./deploy-platform-mock.sh stop --host 172.16.10.178
```

Useful options: `--state-dir` / `--upload-dir` (omitted when empty, which keeps the binary's
own defaults), `--reuse` (start only if nothing already answers), `--reset-register` (POST
`/api/register/reset` after the instance is ready), `--skip-build`, `--dry-run`, and
`--ready-timeout` / `--ready-interval`. For the code audit workbench (whose 安全引擎 view
contains the TEE-LLM module), `--console-user` /
`--console-password` set the login (default `admin` / `teellm@2026`) and
`--tee-tls-endpoint HOST:PORT` overrides the secure listener (default `<llm-target host>:18443`);
they are passed to the remote process through the environment, so the password does not show
up in its command line. Run `./deploy-platform-mock.sh --help` for the full list.

## Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | Mock platform HTTP listen address. |
| `-state-dir` | `/root/taa` (or `$STATE_DIR`) | Directory used to persist registration and execution state files (`register-state.json`, `report*-state.json`, `modelLog-state.json`, `taaLog-state.json`). |
| `-upload-dir` | `.local/upload` (or `$UPLOAD_DIR`) | Directory used to store uploaded model files, served at `/files/`. |
| `-taa-target` | `""` | Single-instance fixed TAA URL for reverse proxying (e.g. `http://127.0.0.1:6001`). When omitted, each instance's address is derived from its own registration. |
| `-taa-pod` | `simple-busybox` (or `$TAA_POD`) | Kubernetes pod name for discovering a fallback TAA address via `kubectl`; used when the per-instance address cannot be derived and `-taa-target` is not set. |
| `-taa-ns` | `""` (or `$TAA_NS`) | Target Kubernetes namespace for `-taa-pod` (empty string indicates default namespace). |
| `-taa-port` | `6001` (or `$TAA_PORT`) | Port on the target pod where TAA listens; also the port used to derive each instance's address from its registration. |
| `-allow-empty-attestation` | `false` | When set to `true`, permits node registration without a valid Hygon CSV attestation report (useful for simulated non-TEE environments). |
| `-sm2-id` | `""` = `1234567812345678` (or `$PLATFORM_SM2_ID`) | SM2 signature identity (`ID_A`). Must be byte-identical to the `PLATFORM_SM2_ID` TAA was started with, or signatures will not verify. The effective value is logged at startup. |
| `-platform-key-file` | `<state-dir>/platform-key.json` (or `$PLATFORM_KEY_FILE`) | Where the platform SM2 key pair (and the last registered TAA public key) is persisted. Generated on first use; a restart reuses the same pair. |
| `-console-user` | `admin` (or `$CONSOLE_USER`) | Login name for the code audit workbench. |
| `-console-password` | `teellm@2026` (or `$CONSOLE_PASSWORD`) | Login password for the code audit workbench. |

## SM2 Envelope

TAA seals every platform message, so the mock does the same and nothing is sent in cleartext.

- **Outbound (mock → TAA)**: every request (`/v1/taa/status`, `stopTraining`, `/v1/taa/import`, and everything the console sends through the `/taa/*` reverse proxy) is sealed with `envelope.SealForPlatform` using the platform private key and the registered TAA public key. If no TAA has registered yet, the request fails locally with `no TAA public key registered yet` — there is no plaintext fallback, because TAA would reject the plaintext anyway and the failure would be misleading. Responses are opened when they are envelopes and passed through untouched otherwise; the reverse proxy only opens JSON responses, so binary exports are streamed through unchanged.
- **Inbound (TAA → mock)**: `register`, `reportResourceRes`, `reportRes`, `reportModelImport`, `reportAudit`, `reportProgress`, `modelLog` and `taaLog` all decrypt-then-verify the body before decoding the business JSON. A body that is not a valid envelope, or whose signature does not verify, is answered with HTTP 401 and the callback stores nothing.
- **Registration**: sealed like every other message; there is no exemption. The one difference is the key its signature is checked against — the `taaPublicKey` carried in the plaintext, since the platform has no other copy yet. The key is adopted (and replaces any previous one) only after the registration passes its other checks, then persisted.
- **Key persistence is mandatory**: TAA caches the platform public key (`PLATFORM_PUBLIC_KEY`) and seals to it, so a mock restart that generated a fresh pair would make every running TAA's envelopes undecryptable. The mock logs the key to use on every start:

  ```text
  [envelope] platform SM2 identity in effect: "1234567812345678"
  [envelope] PLATFORM_PUBLIC_KEY for TAA: 04...
  ```

  Set that value as TAA's `PLATFORM_PUBLIC_KEY` before starting TAA. The console's
  regenerate button rotates the same pair: it generates a new one and writes it over
  `platform-key.json`, so every TAA must then be reconfigured with the new key and
  restarted. Deleting `platform-key.json` has the same effect (a fresh pair is generated
  on the next start).

## Web Console

The platform mock provides an embedded single-page Web console accessible by opening `http://localhost:8080` (or the configured `-addr`) in a browser:

- **Static Asset Embedding**: The UI assets are statically bundled into the binary using Go `embed.FS` from `internal/static/`.
- **Node Status & Attestation**: Displays registered node metadata, ephemeral SM2 public key, and CSV hardware attestation report validation status.
- **Model Ingress & Audit**: Upload model packages, inspect static AST rule violations, and observe Ollama LLM semantic verification outcomes. The console shows the platform SM2 key pair the mock generated and persisted at startup (the same pair its envelopes use), and the regenerate button rotates that pair and overwrites the key file; loading the page never rotates it.
- **Real-Time Progress & Logs**: Displays real-time progress bars, streamed terminal logs (`modelLog`), and TAA daemon operational logs (`taaLog`).
- **Execution Control**: Send graceful stop commands (`/v1/taa/stopTraining`) to interrupt running workloads.
- **Instance-Kind Panels**: the console shows the TEE or FHE panel set for the instance
  selected in the 平台注册 card; there is no separate mode switch. The registration carries
  no explicit server type, so `GET /api/instances` derives `kind` from the report (empty
  attestation and `verifiedPass=false` ⇒ `fhe`, otherwise `tee`) and the selector labels
  each entry with it. An unattested TEE instance registers the same way as FHE and is shown
  as FHE, because that is all the platform was told.
- **Code Audit Workbench tab**: the page has two tabs — `平台模拟` (everything above) and
  `代码审计工作台`, a login-gated workspace for the code-security audit product. TEE-LLM is
  one module inside it (the AI semantic adjudicator), not the page's subject. It signs in with
  `-console-user` / `-console-password` (defaults `admin` / `teellm@2026`) and keeps an
  HttpOnly, SameSite=Strict session cookie for 8 hours (sliding); five failed attempts lock
  that source IP for 60 seconds. Views:
  - **审计任务** — pick or drop a model/code package (no size cap) and the workbench audits it
    **in this process**, with no TAA instance, no registration and no SM2/SM4 envelope. The
    plaintext archive is unpacked under a per-submission temp directory (zip-slip guarded) and
    walks the same design TAA uses: Tier 1 static scan, the binary channel, optional Tier 2 AI
    adjudication, then the conclusion. The verdict is written to an in-memory ring of 200 jobs,
    so it is lost on a restart; the stored report keeps TAA's projection shape
    (`conclusion`, `file_reports`, `duration_ms`). Only one audit runs at a time — a second
    submission while one is in flight answers 409. A package that is not a zip/gzip/tar archive
    is refused with 400, and the temp directory is removed whether the audit succeeds or fails.
    Every accepted archive is also kept in a **file area** (`<uploadDir>/audit-files/`, a
    metadata index capped at 100 entries, newest first), so a run can be repeated by selecting
    or dragging the stored entry into the drop zone instead of uploading the bytes again. A
    stored entry is submitted by `fileId`; deleting it from the area only forgets the copy.
    The vertical rail on the right follows the six steps (`receive`, `extract`, `static`,
    `binary`, `ai`, `conclude`) with a status pill and a fill bar; when no TEE-LLM endpoint is
    configured, or the configured one does not accept a TCP connection, the `ai` step is marked
    `跳过` and the static + binary verdict still stands (`FailClosed` is off here). A reachable
    gateway keeps TAA's long-running request, so a cold model can stay on `ai` for minutes.
    Completed and failed rows can be deleted from the list; a running row cannot.
    `requestId` / `taskId` are generated by the console, so nothing has to be typed.
  - **审计结果** — the findings explorer: severity and AI-verdict filters, search, a per-file
    list, and a detail drawer with the code snippet, AI reason and CPG/taint evidence.
  - **安全引擎** — the Tier 1 static-scan summary plus the AI semantic module's gateway
    status, CSV attestation and TEE-TLS handshake evidence (measurement, public-key binding,
    certificate subject, elapsed time), a prompt self-check and the polled gateway logs.
  - **设置** — read-only endpoints, the TLS verification mode, and the editable code-audit
    prompt. This is the **actual judgement prompt** sent to TEE-LLM, not an addendum: it
    replaces the instruction half of each finding prompt (everything before `## 代码片段`),
    while the matched code, rule id and JSON answer contract are always appended. Saving the
    built-in text clears the override. It lives in process memory, applies to the next audit,
    and is gone after a restart.
  Real `reportAudit` callbacks still arrive from registered TAA instances and keep their own
  per-`dockerId` ring, but this workbench reads only the `local` bucket, so those callbacks are
  not shown. The read endpoints live under `/api/audit/console/*`; submissions use
  `POST /api/audit/console/submit` (multipart: either `file` or `fileId`, plus optional
  `requestId` and `taskId`), one job is deleted with `DELETE /api/audit/console/jobs/{id}`,
  the file area is listed with `GET /api/audit/console/files` and an entry is dropped with
  `DELETE /api/audit/console/files/{id}`, and the prompt is read with
  `GET /api/audit/console/prompt` (returns `{prompt, custom}`) and replaced with `PUT`
  `{"prompt": "..."}`. They share the
  session with the `/api/console/{login,logout,session}` aliases; the TEE-LLM module still
  exposes `/api/llm/console/*`, and `TEELLM_TLS_ENDPOINT` (or the settings page) selects the
  secure listener when it is not derivable from `-llm-target`.
- **TEE-LLM Instance**: the mock polls the instance's plaintext `/v1/llm/*` routes, so the console
  gives it a dedicated card (TEE mode only): the address it polls — the host address
  `http://<host>:16001` by default (`--llm-target` / `LLM_TARGET`), which is the host port the
  TEE-LLM Pod publishes and therefore survives recreating the Pod; `--llm-pod` / `--llm-ns` /
  `--llm-port` opt back into kubectl Pod-IP discovery — the instance's per-process
  `dockerId` (`teellm-<10 digits>`; a change means the instance was restarted or rebuilt, and the
  log cursor resets with it), model and uptime, heartbeat liveness, the batched run logs from
  `/v1/llm/log`, and the report fetched from `/v1/llm/getAttestation` on demand. Reset clears the
  polled state and the LLM log store.

## Multiple Instances

A single mock process serves several TAA instances at once. This is the default and needs no
flag: instance identity is the registration's `dockerId`.

- **State layout**: each instance keeps its own state under
  `<state-dir>/instances/i-<sha256(dockerId)[:16]>/`, with per-instance `register-state.json`,
  `report*-state.json`, logs and `instance.json`. Per-instance TAA public keys are stored per
  `dockerId` in `<state-dir>/platform-key.json` (the `taaPublicKeysHex` map).
- **Migration**: legacy single-instance state files are migrated at startup into one instance
  directory. When `instances/` already exists, nothing is migrated.
- **Derived address**: with no `-taa-target`, an instance's outbound address is derived from
  the registration request's source IP as `http://<RemoteAddr IP>:<taa-port>` (default port
  6001). Behind a reverse proxy or port forward the source IP is lost, so use `-taa-target`
  (a single fixed address) there.
- **Selecting an instance**: instance-scoped console endpoints (`/api/dashboard/status`, the
  register/report/progress/modelLog/taaLog `*/status` and `*/reset` routes, `/api/taa/*`,
  `/api/upload`, `/api/taa-target`, `/api/fhe/submit`) accept `?dockerId=`; absent means the
  most recently accepted registration. Global endpoints (`/api/instances`, `/api/uploads*`,
  `/api/crypto/*`, `/api/request-logs/*`) ignore it. `GET /api/instances` returns the instance
  list, each instance's derived `kind` (`tee` or `fhe`) and `defaultDockerId`. Selecting an
  instance also switches the console panels to that kind.
- **Removing a stale instance**: `POST /api/instances/delete?dockerId=...` deletes that
  instance's state directory and its stored TAA public key. The console's 删除实例 button
  calls it. A Pod that has been deleted sends nothing, so this is the only way a stale entry
  leaves the selector.
- **Proxying**: `/taa/*` proxies to the selected instance and strips `dockerId` before
  forwarding.

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
│   ├── audit_jobs.go            # In-memory audit job ring with per-step stage states
│   ├── audit_local.go           # In-process audit runner (unpack → static → binary → AI)
│   ├── audit_files.go           # Persistent file area for reusable uploaded archives
│   ├── audit_console.go         # Audit workbench read APIs (/api/audit/console/*)
│   ├── audit_submit.go          # Plaintext archive upload and local audit submission
│   ├── llm_console.go           # TEE-LLM module APIs (/api/llm/console/*)
│   ├── llm_console_session.go   # Shared console login/session for both tabs
│   ├── keystore.go              # Platform SM2 key pair + registered TAA public key (persisted)
│   ├── proxy.go                 # TAA reverse proxy and Kubernetes pod discovery
│   ├── store.go                 # Thread-safe in-memory state and log ring buffer
│   └── static/                  # Embedded Web console assets (embed.FS)
│       ├── index.html           # Main dashboard template
│       ├── css/                 # Stylesheets (layout, components, variables, audit-console)
│       └── js/                  # Frontend scripts (api, app, drawer, logs, tree, crypto, audit-console)
└── README.md                    # This documentation
```
