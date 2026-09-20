# Migrate Ollama Runtime & Models to TEE-LLM with Multi-Model Configuration Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the Ollama runtime binary and model weight blobs from `taa/models/audit/ollama-qwen` to `teellm/models/ollama/`, provide a declarative multi-model catalog (`configs/models.json`) and Go catalog loader, enhance `teellm/deploy.sh` with `models [list|info|switch]` CLI management, and cleanly purge legacy directories and references in `taa`.

**Architecture:** Model storage and inference runtime are consolidated under `teellm/models/ollama/`. A structured model catalog `configs/models.json` defines optimal hyperparameters (context window, timeout, temperature, options) for diverse models (Qwen2.5-Coder 0.5B-7B, Qwen3 8B-14B, DeepSeek). Go components in `teellm` (`model_catalog.go`, `ollama_backend.go`) load and apply these profiles dynamically per request. `teellm/deploy.sh` provides CLI inspection, verification, and active model switching while retaining fast incremental weight deployment. Legacy directories in `taa` are removed and references redirected.

**Tech Stack:** Go 1.22+, Bash, Python 3, Ollama v0.3.x REST API, JSON.

---

## File Structure Map

### `teellm` (Submodule)
- Create:
  - `teellm/configs/models.json`: Declarative model profiles and parameter presets.
  - `teellm/models/README.md`: Guide for offline model storage, manifests, blobs, and download procedures.
  - `teellm/model_catalog.go`: Go catalog loader and model profile resolution.
  - `teellm/model_catalog_test.go`: Unit tests for catalog parsing, defaults, and option merging.
- Modify:
  - `teellm/.gitignore`: Add ignore rules for `models/ollama/ollama*`, `models/ollama/lib/`, `models/ollama/models/blobs/`.
  - `teellm/ollama_backend.go`: Support model options injection from catalog.
  - `teellm/ollama_backend_test.go`: Add test cases for model-specific options.
  - `teellm/cmd/teellm-service/main.go`: Wire `modelCatalogPath` into config loading and backend initialization.
  - `teellm/cmd/teellm-service/main_test.go`: Add config parsing tests for `modelCatalogPath`.
  - `teellm/configs/teellm-docker.json`: Reference `modelCatalogPath`.
  - `teellm/configs/teellm-production.json`: Reference `modelCatalogPath`.
  - `teellm/deploy/start.sh`: Update `OLLAMA_DIR` to `/root/taa/ollama`.
  - `teellm/deploy.sh`: Implement `models list`, `models info`, `models switch` subcommands; update default paths from `ollama-qwen` to `models/ollama` and container dir to `/root/taa/ollama`.

### `taa` (Root Repository)
- Delete:
  - `models/audit/ollama-qwen/` (Entire directory and files).
- Modify:
  - `models/audit/MODELS.md`: Update documentation to direct users to `teellm/models/` and `./deploy.sh models`.
  - `tests/deploy_ollama_preflight_test.sh`: Update test to target `teellm/deploy.sh`.

---

## Tasks

### Task 1: Physical Asset Migration & `.gitignore` Configuration in `teellm`

**Files:**
- Create: `teellm/models/ollama/` (Copied from `models/audit/ollama-qwen`)
- Modify: `teellm/.gitignore`

- [ ] **Step 1: Update `teellm/.gitignore` to ignore large binaries and blobs**

In `/home/hjy/taa/teellm/.gitignore`, append:
```gitignore
# Ollama runtime & models
models/ollama/ollama
models/ollama/ollama.*
models/ollama/lib/
models/ollama/models/blobs/
models/ollama/models/models/blobs/
models/ollama/models/cache/
models/ollama/models/models/cache/
*.log
```

- [ ] **Step 2: Copy valid runtime and model files to `teellm/models/ollama/`**

Run:
```bash
mkdir -p /home/hjy/taa/teellm/models/ollama
cp /home/hjy/taa/models/audit/ollama-qwen/ollama /home/hjy/taa/teellm/models/ollama/
chmod +x /home/hjy/taa/teellm/models/ollama/ollama
cp /home/hjy/taa/models/audit/ollama-qwen/start-ollama.sh /home/hjy/taa/teellm/models/ollama/
chmod +x /home/hjy/taa/teellm/models/ollama/start-ollama.sh
cp -r /home/hjy/taa/models/audit/ollama-qwen/lib /home/hjy/taa/teellm/models/ollama/
cp -r /home/hjy/taa/models/audit/ollama-qwen/models /home/hjy/taa/teellm/models/ollama/
```

- [ ] **Step 3: Verify copied assets and check git status**

Run:
```bash
ls -la /home/hjy/taa/teellm/models/ollama
cd /home/hjy/taa/teellm && git status
```
Expected:
`ollama`, `start-ollama.sh`, `lib`, and `models` exist. Git only sees new tracked manifests, `.gitignore`, and no 400MB+ binaries or blobs.

- [ ] **Step 4: Commit `.gitignore` and manifests in `teellm`**

Run:
```bash
cd /home/hjy/taa/teellm
git add .gitignore models/ollama/start-ollama.sh models/ollama/models/models/manifests models/ollama/models/id_ed25519* models/ollama/models/models/id_ed25519*
git commit -m "chore(models): migrate ollama runtime and model manifests into models/ollama"
```

---

### Task 2: Declarative Model Catalog & Documentation in `teellm`

**Files:**
- Create: `teellm/configs/models.json`
- Create: `teellm/models/README.md`
- Modify: `teellm/configs/teellm-docker.json`
- Modify: `teellm/configs/teellm-production.json`

- [ ] **Step 1: Create `teellm/configs/models.json`**

Write `/home/hjy/taa/teellm/configs/models.json`:
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

- [ ] **Step 2: Create `teellm/models/README.md`**

Write `/home/hjy/taa/teellm/models/README.md`:
```markdown
# TEE-LLM Models and Runtime Directory

This directory houses the offline Ollama inference runtime and model manifests/weights used by the TEE-LLM service.

## Directory Structure

- `ollama/`: Root of the Ollama runtime and offline weight bundle.
  - `ollama`: Ollama server executable.
  - `start-ollama.sh`: Wrapper script launching `ollama serve` with configured models and library paths.
  - `lib/ollama/`: Dynamic shared libraries (`libllama-server-impl.so`, CUDA/ROCm/CPU backends).
  - `models/models/`: Standard Ollama model store containing:
    - `manifests/`: Model layer metadata and digests.
    - `blobs/`: Actual tensor weights and configurations (sha256-*).

## Managing Models via CLI

Use `./deploy.sh models` from the `teellm` root:
- `./deploy.sh models list`: List all available models and their readiness status.
- `./deploy.sh models info <model>`: Display details and verify weight integrity.
- `./deploy.sh models switch <model>`: Switch active default model in configuration files.

## Adding New Models

1. Pull or copy the model into Ollama format:
   ```bash
   OLLAMA_MODELS="$(pwd)/models/ollama/models/models" ./models/ollama/ollama pull <model_name>
   ```
2. Add recommended parameters in `configs/models.json`.
3. Verify readiness using `./deploy.sh models info <model_name>`.
```

- [ ] **Step 3: Update `configs/teellm-docker.json` and `configs/teellm-production.json`**

In `teellm/configs/teellm-docker.json`, add `"modelCatalogPath": "./configs/models.json"` under `backend`:
```json
  "backend": {
    "type": "ollama",
    "endpoint": "http://127.0.0.1:11434",
    "defaultModel": "qwen2.5-coder:3b",
    "timeoutSeconds": 60,
    "modelCatalogPath": "./configs/models.json"
  }
```

In `teellm/configs/teellm-production.json`, add `"modelCatalogPath": "./configs/models.json"` under `backend`:
```json
  "backend": {
    "type": "ollama",
    "endpoint": "http://127.0.0.1:11434",
    "defaultModel": "qwen2.5-coder:3b",
    "timeoutSeconds": 60,
    "modelCatalogPath": "./configs/models.json"
  }
```

- [ ] **Step 4: Commit catalog and documentation**

Run:
```bash
cd /home/hjy/taa/teellm
git add configs/models.json models/README.md configs/teellm-docker.json configs/teellm-production.json
git commit -m "feat(config): add multi-model catalog and documentation"
```

---

### Task 3: Implement `model_catalog.go` in `teellm` (TDD)

**Files:**
- Create: `teellm/model_catalog_test.go`
- Create: `teellm/model_catalog.go`

- [ ] **Step 1: Write failing test in `teellm/model_catalog_test.go`**

Write `/home/hjy/taa/teellm/model_catalog_test.go`:
```go
package teellm

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadModelCatalog_Success(t *testing.T) {
	tempDir := t.TempDir()
	jsonPath := filepath.Join(tempDir, "models.json")
	sampleJSON := `{
		"version": "1.0",
		"activeModel": "qwen2.5-coder:3b",
		"models": {
			"qwen2.5-coder:0.5b": {
				"family": "qwen2.5-coder",
				"parameterSize": "0.5B",
				"weightSizeMB": 397,
				"timeoutSeconds": 30,
				"options": {
					"num_ctx": 2048,
					"temperature": 0.1,
					"num_predict": 160
				}
			},
			"qwen3:8b": {
				"family": "qwen3",
				"options": {
					"num_ctx": 4096,
					"think": false
				}
			}
		}
	}`

	if err := os.WriteFile(jsonPath, []byte(sampleJSON), 0644); err != nil {
		t.Fatalf("failed to write test json: %v", err)
	}

	catalog, err := LoadModelCatalog(jsonPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if catalog.ActiveModel != "qwen2.5-coder:3b" {
		t.Errorf("expected active model qwen2.5-coder:3b, got %s", catalog.ActiveModel)
	}

	p05 := catalog.GetProfile("qwen2.5-coder:0.5b")
	if p05 == nil {
		t.Fatalf("expected profile for qwen2.5-coder:0.5b")
	}
	if p05.TimeoutSeconds != 30 {
		t.Errorf("expected timeout 30, got %d", p05.TimeoutSeconds)
	}
	if p05.Options["num_ctx"] != float64(2048) {
		t.Errorf("expected num_ctx 2048, got %v", p05.Options["num_ctx"])
	}

	p8b := catalog.GetProfile("qwen3:8b")
	if p8b == nil {
		t.Fatalf("expected profile for qwen3:8b")
	}
	if p8b.Options["think"] != false {
		t.Errorf("expected think=false, got %v", p8b.Options["think"])
	}

	// Test fallback for unknown model
	pUnknown := catalog.GetProfile("custom-model:latest")
	if pUnknown == nil {
		t.Fatalf("expected fallback profile for unknown model")
	}
	if pUnknown.TimeoutDuration(60 * time.Second) != 60*time.Second {
		t.Errorf("expected default timeout 60s")
	}
}

func TestLoadModelCatalog_NotFoundFallback(t *testing.T) {
	catalog, err := LoadModelCatalog("/non/existent/path.json")
	if err == nil {
		t.Errorf("expected error for non-existent path")
	}
	if catalog == nil {
		t.Fatalf("expected non-nil default fallback catalog even on error")
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run:
```bash
cd /home/hjy/taa/teellm && go test -run TestLoadModelCatalog ./...
```
Expected: FAIL (undefined: LoadModelCatalog)

- [ ] **Step 3: Implement `teellm/model_catalog.go`**

Write `/home/hjy/taa/teellm/model_catalog.go`:
```go
package teellm

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ModelProfile defines configuration, metadata, and generation options for a model.
type ModelProfile struct {
	Family           string         `json:"family,omitempty"`
	ParameterSize    string         `json:"parameterSize,omitempty"`
	WeightSizeMB     int            `json:"weightSizeMB,omitempty"`
	RecommendedRAMGB int            `json:"recommendedRamGB,omitempty"`
	TimeoutSeconds   int            `json:"timeoutSeconds,omitempty"`
	Options          map[string]any `json:"options,omitempty"`
	Description      string         `json:"description,omitempty"`
}

// TimeoutDuration returns the configured timeout duration, or the fallback if unspecified.
func (p *ModelProfile) TimeoutDuration(fallback time.Duration) time.Duration {
	if p != nil && p.TimeoutSeconds > 0 {
		return time.Duration(p.TimeoutSeconds) * time.Second
	}
	return fallback
}

// ModelCatalog holds all registered model profiles and active model selection.
type ModelCatalog struct {
	Version     string                  `json:"version"`
	ActiveModel string                  `json:"activeModel"`
	Models      map[string]ModelProfile `json:"models"`
	mu          sync.RWMutex
}

// DefaultModelCatalog returns an initialized standard fallback catalog.
func DefaultModelCatalog() *ModelCatalog {
	return &ModelCatalog{
		Version:     "1.0",
		ActiveModel: "qwen2.5-coder:3b",
		Models: map[string]ModelProfile{
			"qwen2.5-coder:0.5b": {
				Family:         "qwen2.5-coder",
				ParameterSize:  "0.5B",
				TimeoutSeconds: 30,
				Options: map[string]any{
					"num_ctx":     2048,
					"temperature": 0.1,
					"num_predict": 160,
				},
			},
			"qwen2.5-coder:1.5b": {
				Family:         "qwen2.5-coder",
				ParameterSize:  "1.5B",
				TimeoutSeconds: 45,
				Options: map[string]any{
					"num_ctx":     2048,
					"temperature": 0.1,
					"num_predict": 200,
				},
			},
			"qwen2.5-coder:3b": {
				Family:         "qwen2.5-coder",
				ParameterSize:  "3B",
				TimeoutSeconds: 60,
				Options: map[string]any{
					"num_ctx":     4096,
					"temperature": 0.1,
					"num_predict": 256,
				},
			},
			"qwen2.5-coder:7b": {
				Family:         "qwen2.5-coder",
				ParameterSize:  "7B",
				TimeoutSeconds: 90,
				Options: map[string]any{
					"num_ctx":     4096,
					"temperature": 0.1,
					"num_predict": 300,
				},
			},
			"qwen3:8b": {
				Family:         "qwen3",
				ParameterSize:  "8B",
				TimeoutSeconds: 120,
				Options: map[string]any{
					"num_ctx":     4096,
					"temperature": 0.1,
					"think":       false,
					"num_predict": 300,
				},
			},
			"qwen3:14b": {
				Family:         "qwen3",
				ParameterSize:  "14B",
				TimeoutSeconds: 180,
				Options: map[string]any{
					"num_ctx":     8192,
					"temperature": 0.1,
					"think":       false,
					"num_predict": 512,
				},
			},
		},
	}
}

// LoadModelCatalog reads and decodes a ModelCatalog from a JSON file.
// If the path is empty or unreadable, it returns a default catalog alongside the error.
func LoadModelCatalog(path string) (*ModelCatalog, error) {
	fallback := DefaultModelCatalog()
	if strings.TrimSpace(path) == "" {
		return fallback, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fallback, fmt.Errorf("read model catalog %q: %w", path, err)
	}

	var catalog ModelCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return fallback, fmt.Errorf("parse model catalog json: %w", err)
	}

	if catalog.Models == nil {
		catalog.Models = make(map[string]ModelProfile)
	}
	return &catalog, nil
}

// GetProfile retrieves the profile for a given model name, or a default fallback.
func (c *ModelCatalog) GetProfile(modelName string) *ModelProfile {
	if c == nil {
		return &ModelProfile{
			Options: map[string]any{
				"temperature": 0.1,
				"num_predict": 200,
			},
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	trimmed := strings.TrimSpace(modelName)
	if p, ok := c.Models[trimmed]; ok {
		return &p
	}

	// Case/prefix insensitive match
	for k, v := range c.Models {
		if strings.EqualFold(k, trimmed) {
			return &v
		}
	}

	// Safe fallback profile for unregistered models
	return &ModelProfile{
		TimeoutSeconds: 60,
		Options: map[string]any{
			"temperature": 0.1,
			"num_predict": 200,
		},
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /home/hjy/taa/teellm && go test -v -run TestLoadModelCatalog ./...
```
Expected: PASS

- [ ] **Step 5: Commit `model_catalog.go` and tests**

Run:
```bash
cd /home/hjy/taa/teellm
git add model_catalog.go model_catalog_test.go
git commit -m "feat(catalog): implement model catalog loader and profile resolver"
```

---

### Task 4: Integrate Model Catalog into `teellm-service` and `OllamaBackend`

**Files:**
- Modify: `teellm/ollama_backend.go`
- Modify: `teellm/ollama_backend_test.go`
- Modify: `teellm/cmd/teellm-service/main.go`
- Modify: `teellm/cmd/teellm-service/main_test.go`

- [ ] **Step 1: Write failing test in `teellm/ollama_backend_test.go` for catalog options**

Append to `teellm/ollama_backend_test.go`:
```go
func TestOllamaBackend_CatalogOptionsMerged(t *testing.T) {
	var capturedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/generate" {
			_ = json.NewDecoder(r.Body).Decode(&capturedBody)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"response": "{\"verdict\":\"BENIGN\",\"reason\":\"ok\"}"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	catalog := &ModelCatalog{
		Models: map[string]ModelProfile{
			"qwen3:8b": {
				Options: map[string]any{
					"num_ctx": float64(4096),
					"think":   false,
				},
			},
		},
	}

	b, err := NewOllamaBackend(OllamaBackendConfig{
		Endpoint:     server.URL,
		DefaultModel: "qwen3:8b",
		Catalog:      catalog,
	})
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	req := &RequestEnvelope{
		RequestID: "req-cat-1",
		ModelRef: &ModelReference{
			Name: "qwen3:8b",
		},
		FindingPayload: &FindingPayload{
			RuleID: "RULE_01",
			Target: CodeTarget{
				FilePath: "test.py",
				Line:     10,
			},
		},
	}

	_, err = b.HandleVerifyFinding(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	options, ok := capturedBody["options"].(map[string]any)
	if !ok {
		t.Fatalf("expected options map in request body, got %v", capturedBody["options"])
	}

	if options["num_ctx"] != float64(4096) {
		t.Errorf("expected num_ctx=4096, got %v", options["num_ctx"])
	}
	if options["think"] != false {
		t.Errorf("expected think=false, got %v", options["think"])
	}
}
```

- [ ] **Step 2: Update `teellm/ollama_backend.go` to accept `Catalog` and merge options**

In `teellm/ollama_backend.go`:
Add `Catalog *ModelCatalog` to `OllamaBackendConfig`:
```go
type OllamaBackendConfig struct {
	Endpoint     string
	DefaultModel string
	Timeout      time.Duration
	HTTPClient   *http.Client
	Catalog      *ModelCatalog
}
```
Add `catalog *ModelCatalog` to `OllamaBackend`:
```go
type OllamaBackend struct {
	endpoint     string
	defaultModel string
	client       *http.Client
	catalog      *ModelCatalog
}
```
In `NewOllamaBackend`:
```go
	catalog := cfg.Catalog
	if catalog == nil {
		catalog = DefaultModelCatalog()
	}

	return &OllamaBackend{
		endpoint:     endpoint,
		defaultModel: model,
		client:       client,
		catalog:      catalog,
	}, nil
```
In `HandleVerifyFinding`:
Merge catalog options for target model before creating `ollamaReqBody`:
```go
	model := b.defaultModel
	if req.ModelRef != nil && strings.TrimSpace(req.ModelRef.Name) != "" {
		model = strings.TrimSpace(req.ModelRef.Name)
	}

	profile := b.catalog.GetProfile(model)
	genOptions := map[string]any{
		"temperature": 0.1,
		"num_predict": 200,
	}
	if profile != nil && len(profile.Options) > 0 {
		for k, v := range profile.Options {
			genOptions[k] = v
		}
	}
	if req.Policy.Temperature != nil {
		genOptions["temperature"] = *req.Policy.Temperature
	}
	if req.Policy.MaxCompletionTokens > 0 {
		genOptions["num_predict"] = req.Policy.MaxCompletionTokens
	}

	ollamaReqBody := ollamaGenerateReq{
		Model:   model,
		Prompt:  prompt,
		Stream:  false,
		Options: genOptions,
	}
```

- [ ] **Step 3: Update `teellm/cmd/teellm-service/main.go` to load `modelCatalogPath`**

In `teellm/cmd/teellm-service/main.go`:
Update `BackendConfigSection`:
```go
type BackendConfigSection struct {
	Type             string `json:"type"`
	Endpoint         string `json:"endpoint"`
	DefaultModel     string `json:"defaultModel"`
	TimeoutSeconds   int    `json:"timeoutSeconds"`
	ModelCatalogPath string `json:"modelCatalogPath,omitempty"`
}
```
In `main()`:
Load catalog from `cfg.Backend.ModelCatalogPath`:
```go
	catalog, err := teellm.LoadModelCatalog(cfg.Backend.ModelCatalogPath)
	if err != nil {
		log.Printf("warning: could not load model catalog from %q: %v (using defaults)", cfg.Backend.ModelCatalogPath, err)
	} else {
		log.Printf("loaded model catalog from %s (activeModel=%s, registered=%d)", cfg.Backend.ModelCatalogPath, catalog.ActiveModel, len(catalog.Models))
	}

	backend, err := teellm.NewOllamaBackend(teellm.OllamaBackendConfig{
		Endpoint:     cfg.Backend.Endpoint,
		DefaultModel: cfg.Backend.DefaultModel,
		Timeout:      backendTimeout,
		Catalog:      catalog,
	})
```

- [ ] **Step 4: Run unit tests across `teellm`**

Run:
```bash
cd /home/hjy/taa/teellm && go test -v ./...
```
Expected: PASS

- [ ] **Step 5: Commit backend and service integration**

Run:
```bash
cd /home/hjy/taa/teellm
git add ollama_backend.go ollama_backend_test.go cmd/teellm-service/main.go
git commit -m "feat(service): integrate model catalog into ollama backend and daemon"
```

---

### Task 5: Enhance `teellm/deploy.sh` with `models` CLI & Path Modernization

**Files:**
- Modify: `teellm/deploy.sh`
- Modify: `teellm/deploy/start.sh`

- [ ] **Step 1: Update `teellm/deploy/start.sh` default path**

In `teellm/deploy/start.sh`:
Change line 7:
```bash
OLLAMA_DIR="${OLLAMA_DIR:-/root/taa/ollama}"
```

- [ ] **Step 2: Update path resolution in `teellm/deploy.sh`**

In `teellm/deploy.sh`:
Change line 220:
```bash
CONTAINER_OLLAMA_DIR="${CONTAINER_OLLAMA_DIR:-/root/taa/ollama}"
```
Change `resolve_ollama_local_dir`:
```bash
resolve_ollama_local_dir() {
  if [[ -n "${OLLAMA_LOCAL_DIR:-}" ]]; then
    printf '%s' "$OLLAMA_LOCAL_DIR"
    return 0
  fi
  if [[ -n "${CLI_OLLAMA_DIR:-}" ]]; then
    printf '%s' "$CLI_OLLAMA_DIR"
    return 0
  fi
  if [[ -d "$PROJECT_DIR/models/ollama" ]]; then
    printf '%s' "$PROJECT_DIR/models/ollama"
    return 0
  fi
  if [[ -d "$PROJECT_DIR/models" ]]; then
    printf '%s' "$PROJECT_DIR/models"
    return 0
  fi
  printf '%s' "$PROJECT_DIR/models/ollama"
}
```

- [ ] **Step 3: Implement `handle_models_command` in `teellm/deploy.sh`**

Add `handle_models_command()` function to `teellm/deploy.sh`:
- `list`: Scans manifests directory in `$OLLAMA_LOCAL_DIR/models/models/manifests` and joins with `configs/models.json` if available. Formats and prints a clean table.
- `info <model>`: Checks manifest and verifies that every blob in the manifest exists on disk, outputs parameter details.
- `switch <model>`: Verifies model readiness, updates `configs/teellm-docker.json` and `configs/teellm-production.json` with Python atomic rewrite, and prints next steps.

Wire `models` into main argument dispatcher:
```bash
    models)
      shift
      handle_models_command "$@"
      exit 0
      ;;
```

Update `--help` documentation in `deploy.sh` to include `models` commands and descriptions.

- [ ] **Step 4: Verify `deploy.sh models` commands**

Run:
```bash
cd /home/hjy/taa/teellm
./deploy.sh models list
./deploy.sh models info qwen2.5-coder:3b
./deploy.sh --help
```
Expected:
`models list` prints table of models (`0.5b`, `1.5b`, `3b`, `7b`, `8b`, `14b`).
`models info qwen2.5-coder:3b` prints model layer & blob readiness.
`--help` displays updated usage.

- [ ] **Step 5: Commit `deploy.sh` and `start.sh` changes**

Run:
```bash
cd /home/hjy/taa/teellm
git add deploy.sh deploy/start.sh
git commit -m "feat(cli): add models command suite and modernize ollama paths"
```

---

### Task 6: Purge Legacy Directory in `taa` & Run End-to-End Verification

**Files:**
- Delete: `models/audit/ollama-qwen/` (in `taa`)
- Modify: `models/audit/MODELS.md` (in `taa`)
- Modify: `tests/deploy_ollama_preflight_test.sh` (in `taa`)
- Modify: `taa/.gitignore` (clean up `models/audit/ollama-qwen/` rules)

- [ ] **Step 1: Delete `taa/models/audit/ollama-qwen`**

Run:
```bash
rm -rf /home/hjy/taa/models/audit/ollama-qwen
```

- [ ] **Step 2: Update `models/audit/MODELS.md`**

Update `/home/hjy/taa/models/audit/MODELS.md` with header stating:
"Ollama 运行时与离线模型资产已全面迁移至 `teellm/models/ollama`。请使用 `cd teellm && ./deploy.sh models list` 查看和管理模型，或使用 `./deploy.sh models switch <model>` 切换激活模型。"

- [ ] **Step 3: Update `taa/.gitignore`**

In `/home/hjy/taa/.gitignore`, ensure `models/audit/ollama-qwen` entries are cleaned or generalized to `models/` rule.

- [ ] **Step 4: Adapt `tests/deploy_ollama_preflight_test.sh`**

Update `tests/deploy_ollama_preflight_test.sh` to test `teellm/deploy.sh` preflight check.
Run:
```bash
bash /home/hjy/taa/tests/deploy_ollama_preflight_test.sh
```
Expected: PASS

- [ ] **Step 5: Run tests across `teellm` and `taa`**

Run:
```bash
cd /home/hjy/taa/teellm && go test -v ./...
cd /home/hjy/taa && go test ./...
bash /home/hjy/taa/tests/deploy_docker_transfer_test.sh
```
Expected: All tests pass.

- [ ] **Step 6: Commit changes in `taa`**

Run:
```bash
cd /home/hjy/taa
git add .gitignore models/audit/MODELS.md tests/deploy_ollama_preflight_test.sh teellm
git commit -m "refactor(models): purge legacy ollama-qwen and update teellm submodule"
```
