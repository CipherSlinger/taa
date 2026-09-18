# Changelog

All notable changes to the **Trusted Application Agent (TAA)** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).

---

## [Unreleased]

### Added
- **Container Supervisor Daemon (`deploy/start.sh`)**: Extracted container autostart supervisor into version-controlled source code. Provides automated process keep-alive, 10s exit restart backoff, and manual debugging toggle via `touch /root/taa/manual`.
- **Platform-Mock UI/UX Advanced Polish**:
  - **Lifecycle Pipeline Stepper**: Interactive visual stage indicator (`Register` ➔ `Ingress` ➔ `Audit` ➔ `Switch` ➔ `Train` ➔ `Export`) with live auto-synchronization against TAA state.
  - **Visual Audit Dashboard**: Interactive findings accordion featuring risk severity badges (`HIGH`/`MEDIUM`/`LOW`), line numbers, AST code context snippets, and taint propagation details.
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
- **Two-Tier Code Security Audit Engine (Semgrep + TEE-LLM)**:
  - Integrated 13 canonical Semgrep security rules covering Python, Go, and Shell scripts for OS command injection, path traversal, arbitrary file writes, SSRF, and dynamic execution.
  - Added AST scope slicer and taint trajectory extraction.
  - Added resilient TEE-LLM client over TEE-TLS 1.3 featuring circuit breakers, jittered exponential backoff retries, and fail-closed security gates.
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
- Fixed orphan `platform-mock` process leaks on redeployment by enforcing port termination preflight checks.
- Fixed HTML browser cache invalidation in platform mock by adding no-cache headers.
- Fixed fail-closed security gate in code auditing to treat parser errors and scan timeouts as blocking violations.
- Fixed Hygon CSV attestation mock report byte layout alignment with the `OffsetUserData` hardware specification.

---

## [0.2.0] - 2026-09-16

### Added
- **Dynamic Attestation Certificate Verification**: Integrated Hygon CSV certificate chain (HRK/HSK/CEK) self-verification with dynamic configuration loading.
- **Three-Track Audit Benchmark Suite**: Developed quantitative evaluation framework comparing rule-only static analysis, pure-LLM analysis, and hybrid two-tier auditing with bootstrap confidence intervals.
- **AST Dynamic Context Slicing**: Implemented semantic code slicer extracting target functions and enclosing scopes to reduce LLM prompt token consumption.

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
