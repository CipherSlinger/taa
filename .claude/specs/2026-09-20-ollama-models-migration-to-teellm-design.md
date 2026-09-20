# Design Spec: Migrate Ollama Runtime & Models to TEE-LLM with Multi-Model Configuration Support

**Document ID:** `.claude/specs/2026-09-20-ollama-models-migration-to-teellm-design.md`  
**Date:** 2026-09-20  
**Status:** Approved  
**Author:** Engineering Team  

---

## 1. Overview & Objectives

In the prior architecture, the Ollama inference engine and Qwen model assets were placed under `taa/models/audit/ollama-qwen`. With TEE-LLM successfully decoupled into an independent submodule (`teellm/`), the inference runtime and weights should reside natively within the `teellm` project.

This specification details:
1. **Physical Migration**: Migrate Ollama runtime and model weights from `models/audit/ollama-qwen` in the root repository to `teellm/models/ollama/` (without symlinks, updating all hardcoded references).
2. **Multi-Model Catalog & Profiles**: Introduce a structured model catalog (`configs/models.json`) supporting diverse models (Qwen2.5-Coder 0.5B/1.5B/3B/7B, Qwen3 8B/14B, DeepSeek, etc.) with fine-tuned hyperparameters (context size, timeout, temperature, options).
3. **CLI Model Management**: Enhance `teellm/deploy.sh` with a `models` management command suite (`models list`, `models info <model>`, `models switch <model>`) and seamless `--model` deployment workflows.
4. **Cleanup & Decoupling**: Completely purge `models/audit/ollama-qwen` from `taa`, update `.gitignore` in both repositories, and update legacy references and tests.

---

## 2. Directory Structure & Physical Migration

### 2.1 Target Structure in `teellm`

```text
teellm/
├── configs/
│   ├── models.json                    # Multi-model profiles & parameter presets
│   ├── teellm-docker.json             # Docker service config referencing active model
│   └── teellm-production.json         # Production config referencing active model
├── models/
│   ├── README.md                      # Model maintenance & download guide
│   └── ollama/                        # Ollama engine runtime & offline model library
│       ├── ollama                     # Ollama binary executable
│       ├── start-ollama.sh            # Background daemon startup wrapper
│       ├── lib/                       # Dynamic shared libraries (e.g. libllama-server-impl.so)
│       └── models/                    # Standard Ollama manifest & blob store
│           ├── manifests/             # Model manifest descriptors
│           └── blobs/                 # Model weights and layer blobs
```

### 2.2 Hardcoded Path Adjustments (No Symlinks)
All existing references to `ollama-qwen` across scripts are updated to `models/ollama`:
- **`teellm/deploy.sh`**:
  - `resolve_ollama_local_dir`: Look in `$PROJECT_DIR/models/ollama`, fallback `$PROJECT_DIR/models`.
  - `CONTAINER_OLLAMA_DIR`: Default to `/root/taa/ollama` (formerly `/root/taa/ollama-qwen`).
- **`teellm/deploy/start.sh`**:
  - `OLLAMA_DIR`: Set to `/root/taa/ollama`.
- **`teellm/.gitignore`**:
  - Ignore heavy binaries and blobs:
    ```gitignore
    # Ollama runtime and model blobs
    models/ollama/ollama
    models/ollama/ollama.*
    models/ollama/lib/
    models/ollama/models/blobs/
    models/ollama/models/models/blobs/
    ```

---

## 3. Multi-Model Catalog & Parameter Presets

### 3.1 `configs/models.json`
A declarative catalog file mapping model identifiers to recommended runtime parameters:

```json
{
  "version": "1.0",
  "activeModel": "qwen2.5-coder:3b",
  "models": {
    "qwen2.5-coder:0.5b": {
      "family": "qwen2.5-coder",
      "parameterSize": "0.5B",
      "weightSizeMB": 397,
      "recommendedRamGB": 2,
      "timeoutSeconds": 30,
      "options": {
        "num_ctx": 2048,
        "temperature": 0.1,
        "num_predict": 160
      },
      "description": "Ultra-lightweight model for fast rule pre-screening (1-2s response)"
    },
    "qwen2.5-coder:1.5b": {
      "family": "qwen2.5-coder",
      "parameterSize": "1.5B",
      "weightSizeMB": 986,
      "recommendedRamGB": 4,
      "timeoutSeconds": 45,
      "options": {
        "num_ctx": 2048,
        "temperature": 0.1,
        "num_predict": 200
      },
      "description": "Balanced lightweight model combining speed and code comprehension"
    },
    "qwen2.5-coder:3b": {
      "family": "qwen2.5-coder",
      "parameterSize": "3B",
      "weightSizeMB": 1900,
      "recommendedRamGB": 6,
      "timeoutSeconds": 60,
      "options": {
        "num_ctx": 4096,
        "temperature": 0.1,
        "num_predict": 256
      },
      "description": "Code specialized model with high precision on AST and sensitive sink analysis"
    },
    "qwen2.5-coder:7b": {
      "family": "qwen2.5-coder",
      "parameterSize": "7B",
      "weightSizeMB": 4700,
      "recommendedRamGB": 8,
      "timeoutSeconds": 90,
      "options": {
        "num_ctx": 4096,
        "temperature": 0.1,
        "num_predict": 300
      },
      "description": "Deep code security audit model for extensive multi-file contexts"
    },
    "qwen3:8b": {
      "family": "qwen3",
      "parameterSize": "8B",
      "weightSizeMB": 5200,
      "recommendedRamGB": 10,
      "timeoutSeconds": 120,
      "options": {
        "num_ctx": 4096,
        "temperature": 0.1,
        "think": false,
        "num_predict": 300
      },
      "description": "General high-capacity reasoning model with strict security boundaries"
    },
    "qwen3:14b": {
      "family": "qwen3",
      "parameterSize": "14B",
      "weightSizeMB": 9000,
      "recommendedRamGB": 16,
      "timeoutSeconds": 180,
      "options": {
        "num_ctx": 8192,
        "temperature": 0.1,
        "think": false,
        "num_predict": 512
      },
      "description": "High precision model for deep offline compliance verification"
    }
  }
}
```

### 3.2 Service Catalog Loader (`teellm/model_catalog.go`)
- Defines `ModelCatalog`, `ModelProfile`, and `ModelOptions`.
- `LoadModelCatalog(path string) (*ModelCatalog, error)`: Loads `models.json` if present; returns a safe default catalog otherwise.
- `GetModelProfile(name string) *ModelProfile`: Retrieves matching profile or generates standard fallback options for unlisted models.
- Integrates with `OllamaBackend`: When processing requests with `req.ModelRef`, merges model-specific options (`num_ctx`, `think`, `temperature`) into Ollama `/api/generate` parameters unless explicitly overridden by `req.Policy`.

---

## 4. CLI Model Management & Deployment Pipeline

### 4.1 CLI Commands in `teellm/deploy.sh`
Add a dedicated `models` command handler:
1. `./deploy.sh models list`:
   - Inspects `models/ollama/models/models/manifests`.
   - Compares with `configs/models.json`.
   - Displays a formatted table with model name, parameter size, disk footprint, context window, and active status.
2. `./deploy.sh models info <name>`:
   - Verifies manifest existence.
   - Verifies presence of all required blobs.
   - Displays configuration parameters, description, and status.
3. `./deploy.sh models switch <name>`:
   - Validates that the requested model is locally available and complete.
   - Atomically updates `defaultModel` in `configs/teellm-docker.json` and `configs/teellm-production.json`.
   - Prompts for service restart.

### 4.2 Streamlined Deployment Workflow
- Command `./deploy.sh docker start --model <name>`:
  - If `--model` is specified, checks model availability.
  - Automatically transfers only the selected model weights and runtime.
  - Starts the service with the targeted model.

---

## 5. Cleanup, Decoupling & Verification

### 5.1 Root Repository Cleanup (`taa`)
- Remove `models/audit/ollama-qwen` entirely.
- Update `models/audit/MODELS.md` with instructions redirecting to `teellm/models/`.
- Ensure tests in `taa` pass (`go test ./...`).
- Adapt `tests/deploy_ollama_preflight_test.sh` to validate `teellm/deploy.sh`.

### 5.2 Testing & Quality Assurance
- **Go Unit Tests**:
  - `model_catalog_test.go`: Verify JSON parsing, fallback logic, and profile resolution.
  - `ollama_backend_test.go`: Test option merging and request construction for different models.
  - `teellm/cmd/teellm-service/main_test.go`: Verify config loading with `modelCatalogPath`.
- **CLI Shell Tests**:
  - Test `./deploy.sh models list`, `info`, and `switch`.
  - Validate `./deploy.sh --help` output.

---

## 6. Commit Strategy
In strict compliance with `CLAUDE.md`:
- Conventional commits in English (e.g. `feat(models): migrate ollama runtime to teellm and add multi-model catalog`).
- Strictly no AI-generated badges or attribution signatures.
