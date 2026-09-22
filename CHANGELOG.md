# Changelog

All notable changes to the **Trusted Application Agent (TAA)** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).

---

## [Unreleased]

### Added
- **Container Supervisor Daemon (`deploy/start.sh`)**: Extracted container autostart supervisor into version-controlled source code. Provides automated process keep-alive, 10s exit restart backoff, and manual debugging toggle via `touch /root/taa/manual`.
- **Platform-Mock UI/UX Advanced Polish**:
  - **Lifecycle Pipeline Stepper**: Interactive visual stage indicator (`Register` ➔ `Ingress` ➔ `Audit` ➔ `Switch` ➔ `Train` ➔ `Export`) with live auto-synchronization against TAA state.
  - **Visual Audit Dashboard**: Interactive findings accordion with report-level risk verdict and severity statistics, per-finding line numbers, rule identifiers, matched code snippets, LLM verdict badges, and LLM arbitration reasoning.
  - **Live Dual-Log Streaming Viewer**: Dedicated real-time viewer for training terminal logs (`/v1/taa/modelLog`) and TAA operational logs (`/v1/taa/taaLog`) with log-level filtering, instant search, smart auto-scroll, and pause/resume toggles.
  - **Inbound & Outbound Payload Inspector**: Modal tabs for inspecting raw JSON payloads across all API requests and callbacks.
  - **Global Stacked Toast System**: Non-blocking asynchronous toast notifications and micro-interactions for instant operation feedback.
- **Independent TEE-LLM Inference Microservice (`teellm`)**:
  - Extracted `teellm` into an independent repository and integrated as a recursive Git submodule.
  - Added standalone `teellm/deploy.sh` supporting independent Docker and Remote Kubernetes deployment workflows.
  - Added JSON configuration parsing (`teellm-docker.json`, `teellm-production.json`) for `cmd/teellm-service`.
- **RFC 8998 TEE-TLS 1.3 ShangMi Protocol Submodule (`teetls`)**:
  - Extracted `teetls` into a dedicated submodule providing RFC 8998 TLS 1.3 ShangMi cipher suites (`TLS_SM4_GCM_SM3`, `0x00c6`).
  - Cryptographically bound Hygon CSV hardware attestation reports to X.509 certificate extensions (OID `1.3.6.1.4.1.58270.1.1`).
- **Two-Tier Code Security Audit Engine (Static Rules + TEE-LLM)**:
  - Tier 1 static scanner: 13 built-in pattern rules over Python source (`internal/codeaudit/rules.go`) covering command execution, network egress, sensitive file and environment access, obfuscation/deserialization, dynamic execution, persistence, and result-embedded plaintext data, with a physical ±3 line context window per finding.
  - Added resilient TEE-LLM client over TEE-TLS 1.3 featuring circuit breakers, jittered exponential backoff retries, and fail-closed security gates.
- **Offline Audit Benchmark Engine (Semgrep + CPG, evaluation-only)**:
  - Added a Semgrep-native scanner (`models/audit/tools/semgrep_runner.py`) with 22 AST and taint rules across Python (13), Go (6), and Shell (3).
- Added an engine rule-parity conformance test (`tests/test_engine_rule_parity.py`) that compares the Semgrep rule set against the regex baseline over 59 source fixtures, taking the expected rule set from the baseline itself rather than writing it down, so a rule ported too loosely (missing detections) or too broadly (invented detections) fails. Added a companion corpus audit (`tests/test_engine_rule_parity_corpus.py`, opt-in via `TAA_CORPUS_PARITY=1`) that runs the same comparison per sample over the 100 `audit-100` samples and writes its numbers to `rule-parity-audit.json`. The two are not substitutes: the fixtures caught what someone thought to enumerate, the corpus audit caught `EMB_001` over-reporting every checkpoint write on a construct no fixture covered. Both assert the control arm actually fired, since two empty finding lists agree trivially. The corpus audit additionally checks that each Semgrep `code_snippet` is the real source line rather than Semgrep CE's `"requires login"` placeholder.
  - Added an AST scope slicer and an inter-procedural CPG taint engine with taint trajectory extraction.
  - Wired as selectable engines (`--engine regex|semgrep`) in the offline benchmark evaluator. These engines are evaluation tooling and are **not** wired into the TAA runtime audit path; migrating the runtime scanner to Semgrep is tracked in `TODO`.
- **Active Operational Log Streaming (`/v1/taa/taaLog`)**:
  - Added proactive streaming of TAA internal runtime operational logs with monotonic sequence IDs and ring-buffer deduplication.
- **CipherFlow Specification Alignment**:
  - Aligned model runtime contracts with the three-tier output directory hierarchy (`/opt/taa/output/{result,log,progress}`).
  - Upgraded Python SDK path resolution (`get_output_dir`, `get_log_dir`, `get_progress_dir`).

### Changed
- **Toolchain Reorganization (`tools/`)**: Reorganized auxiliary tools into top-level `tools/` directory, moving platform mock to `tools/platform-mock/` and cryptographic tools to `tools/sdk/`.
- **Go Workspace Orchestration**: Configured `go.work` multi-module workspace orchestrating `taa`, `teellm`, `teetls`, and `tools/sdk` on Go 1.22+.
- **Configuration Templates**:
  - Streamlined `configs/taa-docker.json` and `configs/taa-production.json` by removing backend LLM server-specific paths.
  - Added `attestation` certificate path configurations (`hrkCertPath`, `hskCekCertPath`) and TEE-TLS transport parameters.
- **Deployment Script (`deploy.sh`)**: Refactored root `deploy.sh` to focus exclusively on `taa` and `platform-mock`, delegating LLM model distribution and runtime management to `teellm/deploy.sh`.
- **Dynamic File Size Threshold**: Replaced hardcoded size limits with configurable `maxFileBytes` (default 3 GB) for export data leakage inspection.

### Fixed
- **Offline audit benchmark (evaluation-only): the Semgrep rule set was realigned with the regex baseline it is meant to mirror.** The two arms diverged in both directions, which would have made any engine comparison uninterpretable:
  - `FIL_001` had lost its sensitive-path predicate and matched *any* `open()` call while carrying `HIGH` severity where the baseline has `MEDIUM`. This is the rule that flagged all 100 audit-100 samples in the one recorded full-corpus Semgrep run.
  - `CMD_001` kept only the `shell=True` form, so every list-form invocation was missed, including the primary attack of samples M1-02/M1-07 (`subprocess.check_output(["bash", "-c", "whoami"])`).
  - `NET_001` had no `httpx`, `http.client`, `httplib2` or `urlretrieve` coverage (M2-04 uses `httpx.post`).
  - `OBF_001` was expressed as a taint rule (decode → `eval`/`exec`) where the baseline flags decode *use*, so payloads that are decoded and then exfiltrated instead of executed were invisible to it (M4-01), as were `pickle`, `marshal`, `codecs.decode` and `binascii`.
  - `PER_001` required the persistence path to be an argument of `open()` with a write mode, missing a path built on one line and opened on the next (M5-01); `EMB_002` matched every `shutil.copy` while missing `shutil.move`, and `EMB_003`/`EMB_004` matched literal argument names the baseline does not list.
  - Severity is not cosmetic in this comparison: under the production `gate` policy a `HIGH` finding blocks unless the LLM returns `BENIGN`, while a `MEDIUM` finding is counted but never blocks (`internal/codeaudit/verifier.go:160-178`), so a mistranslated severity changes whether a rule can block at all.
  - `EMB_001` was ported as a bare `torch.save($DATA, $PATH)` with only `state_dict()`/`model.pt` exclusions, dropping the baseline's payload-name list. It therefore flagged *every* checkpoint write — a `HIGH` finding on `train.py` in 75 of the 100 samples, most of them benign — while the `np.save`, `np.savez`, `shutil.copy` and `shutil.copytree` branches were missing entirely. Found by re-running the corpus-wide parity audit, not by the fixture tests: `EMB_001` had only a negative fixture, so nothing pinned what it was supposed to *not* catch. Both gates now also assert the control arm actually fired, since two empty finding lists agree trivially.
- **Offline audit benchmark (evaluation-only): the hand-authored matrix generator no longer implies an engine nobody named.** `generate_matrix_results.py` writes its `summary.json` files in the same shape and location as real evaluator runs, but every count in them comes from a hardcoded table, and `engine`/`rule_set_version` were derived from the audit mode name — so `engine: "semgrep"` was recorded without anyone claiming it, and the design report cited the result as a Semgrep measurement. Each row now carries `provenance: "hand-authored-spec"`, and both fields must be declared explicitly: `generate_matrix` takes a required track declaration with no default, and the CLI's `--track MODE:ENGINE:RULE_SET_VERSION` is required.
- **Offline audit benchmark (evaluation-only): `code_snippet` is no longer forwarded from Semgrep's JSON output.** Semgrep CE returns the literal string `"requires login"` in `extra.lines` when not logged in, and that field was mapped straight to `code_snippet` — the code the LLM is asked to adjudicate. No Semgrep+LLM arbitration had therefore ever run on real source. The runner now slices the matched line range out of the source file and records a `slice_error` when it cannot.
- **Offline audit benchmark (evaluation-only): an unfinished scan is no longer scored as a clean one.** A crashed, timed-out, uninstalled or rules-broken scanner produced the same empty finding list as a genuinely clean scan, and that list was recorded as a bypass — so an infrastructure failure improved the score. Scan status (`scan_complete`, `scan_timed_out`, `scan_parser_errors`, `scan_error`, `slice_error_count`, `ast_error_count`, `cpg_error`) now reaches every sample row, `incomplete` samples are excluded from the metrics, and the three swallowed exceptions in the evaluator record their cause instead of passing silently. The exclusion was initially incomplete: counting the failures was not enough, because the confusion matrix still scored the unscanned rows. A smoke-test run where all four samples failed to scan reported `tn: 4` with `accuracy: 1.0` — and since the Semgrep arm is the only one that can be incomplete, and a crashed scan *lowers* the false-positive rate, the defect could have manufactured a pass on the very criterion being judged. `confusion_counts` now drops unscanned rows instead of assigning them a cell (which also corrects the bootstrap intervals, computed through the same function), the metrics state `scored_count` next to `scan_incomplete_count` so a 96-of-100 matrix cannot read as the whole corpus, and each run carries `round_complete` — with the void notice leading `final-report.md` and zeros in `confusion-matrix.json` when it is false.
- **Offline audit benchmark (evaluation-only): the LLM sampling seed is now fixed and recorded.** Added `--llm-seed` (default `42`) to both the analyzer CLI and the benchmark evaluator, threaded through to the Ollama `options.seed`. The three paired repetitions are meant to isolate the engine, and an unpinned seed folds sampling noise into that comparison. Temperature is unchanged at `0.1`.
- Fixed orphan `platform-mock` process leaks on redeployment by enforcing port termination preflight checks.
- Fixed HTML browser cache invalidation in platform mock by adding no-cache headers.
- Fixed fail-closed arbitration in code auditing: assist mode now blocks the import when every finding's LLM verification failed (service down or circuit breaker open) instead of silently falling back to the static verdict.
- Fixed the LLM readiness pre-check to require an active `generate` probe against the target model, instead of matching the model name against the `/api/tags` listing.
- Corrected `README.md` and this changelog, which described the Semgrep AST/taint engine as part of the runtime audit path. The runtime path uses the built-in static rule scanner; the Semgrep and CPG engines live in the offline audit benchmark harness only.
- Corrected the documented `llm.policy` values in `README.md`: the strict mode recognized by the code is `gate`, not `enforce`. Setting an unrecognized value silently falls back to `assist` behavior and skips gate arbitration.
- Fixed Hygon CSV attestation mock report byte layout alignment with the `OffsetUserData` hardware specification.

---

## [0.2.0] - 2026-09-16

### Added
- **Dynamic Attestation Certificate Verification**: Integrated Hygon CSV certificate chain (HRK/HSK/CEK) self-verification with dynamic configuration loading.
- **Three-Track Audit Benchmark Suite**: Developed quantitative evaluation framework comparing rule-only static analysis, pure-LLM analysis, and hybrid two-tier auditing with bootstrap confidence intervals.
- **AST Dynamic Context Slicing (benchmark evaluation engine)**: Implemented semantic code slicer extracting target functions and enclosing scopes to reduce LLM prompt token consumption.

### Changed
- Refactored controller routing and state management for enhanced modularity.
- Aligned 13 baseline static security rules and enforced fail-closed gate policy.

---

## [0.1.0] - 2026-09-15

### Added
- **Initial Core Confidential Computing Framework**:
  - Pure-Go Hygon CSV guest ioctl driver (`pkg/csvattest`) interfacing directly with `/dev/csv-guest`.
  - Ephemeral SM2 key generation and hardware `USERDATA` binding on enclave startup.
  - Platform registration callback (`/v1/taa/register`) submitting hardware attestation reports and SM2 public keys.
- **GM/T National Cryptography Implementation**:
  - SM2 asymmetric encryption, digital signature, and key exchange.
  - SM3 cryptographic hashing.
  - SM4-GCM authenticated symmetric digital envelope encryption for model inputs, datasets, and exported training results.
- **Three-Tier Runtime Sandbox**:
  - Separated execution sandbox into `/opt/taa/output/result` (artifacts), `/opt/taa/output/log` (terminal logs), and `/opt/taa/output/progress` (intermediate progress).
- **Execution Lifecycle & State Machine**:
  - Supported Phase transitions (`Phase 1` Debug, `Phase 2` Test, `Phase 3` Train).
  - Implemented one-click process tree termination via `/v1/taa/stopTraining`.
- **Platform Mock Emulator**: Standalone testing emulator with embedded web interface for simulating platform-to-enclave interactions.
