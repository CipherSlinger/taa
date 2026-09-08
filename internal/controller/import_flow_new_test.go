package controller

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	teecrypto "taa/crypto"
	"taa/internal/codeaudit"
)

type importedReportPayload struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
	Code      int     `json:"code"`
	Msg       *string `json:"msg"`
	Report    string  `json:"report"`
}

func TestPhase1RequiresBothModelAndDataBeforeTraining(t *testing.T) {
	t.Run("model first then data triggers runtimeConfig", func(t *testing.T) {
		runPhase1FlowCase(t, phase1FlowCase{
			name: "model first then data",
			modelArchiveData: buildTarGzArchive(t, map[string]archiveEntry{
				"bundle/train.py": {
					mode: 0o755,
					data: []byte("#!/usr/bin/env python3\nfrom argparse import ArgumentParser\nfrom pathlib import Path\nimport json\nparser = ArgumentParser(add_help=False)\nparser.add_argument(\"--data-dir\", dest=\"data_dir\", required=True)\nparser.add_argument(\"--output\", \"-o\", dest=\"output_dir\", required=True)\nargs, _ = parser.parse_known_args()\noutput_dir = Path(args.output_dir)\noutput_dir.mkdir(parents=True, exist_ok=True)\nresult = {\"dataset\": {\"total_samples\": 1, \"splits\": {\"train\": 1, \"test\": 0}}, \"metrics\": {\"loss\": 0.0, \"accuracy\": 1.0}}\n(output_dir / \"marker.txt\").write_text(\"phase1-train\\n\")\n(output_dir / \"training_result.json\").write_text(json.dumps(result, indent=2, ensure_ascii=False) + \"\\n\")\n"),
				},
			}),
			dataArchiveData: buildTarGzArchive(t, map[string]archiveEntry{
				"data/sample.txt": {
					mode: 0o644,
					data: []byte("training data\n"),
				},
			}),
			plaintextResource: true,
			wantTrainMarker:   true,
		})
	})

	t.Run("data first then model triggers runtimeConfig", func(t *testing.T) {
		runPhase1FlowCase(t, phase1FlowCase{
			name: "data first then model",
			modelArchiveData: buildTarGzArchive(t, map[string]archiveEntry{
				"bundle/train.py": {
					mode: 0o755,
					data: []byte("#!/usr/bin/env python3\nfrom argparse import ArgumentParser\nfrom pathlib import Path\nimport json\nparser = ArgumentParser(add_help=False)\nparser.add_argument(\"--data-dir\", dest=\"data_dir\", required=True)\nparser.add_argument(\"--output\", \"-o\", dest=\"output_dir\", required=True)\nargs, _ = parser.parse_known_args()\noutput_dir = Path(args.output_dir)\noutput_dir.mkdir(parents=True, exist_ok=True)\nresult = {\"dataset\": {\"total_samples\": 1, \"splits\": {\"train\": 1, \"test\": 0}}, \"metrics\": {\"loss\": 0.0, \"accuracy\": 1.0}}\n(output_dir / \"marker.txt\").write_text(\"phase1-train-reverse\\n\")\n(output_dir / \"training_result.json\").write_text(json.dumps(result, indent=2, ensure_ascii=False) + \"\\n\")\n"),
				},
			}),
			dataArchiveData: buildTarGzArchive(t, map[string]archiveEntry{
				"data/sample.txt": {
					mode: 0o644,
					data: []byte("training data\n"),
				},
			}),
			plaintextResource: true,
			wantTrainMarker:   true,
			importDataFirst:   true,
		})
	})
}

func TestPhase1ModelImportFailureReportsModelImport(t *testing.T) {
	t.Run("decrypt failure reports model import", func(t *testing.T) {
		state, server := setupTestServer(t)
		state.mu.Lock()
		state.CurrentPhase = 1
		state.DockerID = "docker-import-failure"
		state.mu.Unlock()

		state.mu.RLock()
		priv := state.SM2PrivateKey
		state.mu.RUnlock()
		pubKeyPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
		if err != nil {
			t.Fatalf("marshal SM2 public key PEM: %v", err)
		}

		modelImportCh := make(chan importedReportPayload, 1)
		trainingResCh := make(chan importedReportPayload, 1)
		platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload importedReportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode report payload: %v", err)
			}
			switch r.URL.Path {
			case reportModelImportEndpoint:
				modelImportCh <- payload
			case reportResEndpoint:
				trainingResCh <- payload
			default:
				t.Fatalf("unexpected report endpoint: %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer platformServer.Close()

		state.mu.Lock()
		state.PlatformIP = platformServer.URL
		state.mu.Unlock()

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not-a-sealed-resource"))
		}))
		defer resourceServer.Close()

		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": resourceServer.URL + "/broken.enc",
			"requestId":   "req-import-failure",
			"taskId":      "task-import-failure",
			"publicKey":   string(pubKeyPEM),
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("import model: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}

		select {
		case payload := <-modelImportCh:
			if payload.Code != 1 {
				t.Fatalf("reportModelImport code = %d, want 1", payload.Code)
			}
			if payload.RequestID != "req-import-failure" || payload.TaskID != "task-import-failure" {
				t.Fatalf("reportModelImport payload = %+v", payload)
			}
			if payload.Msg == nil || !strings.Contains(*payload.Msg, "解密资源失败") {
				t.Fatalf("reportModelImport msg = %v, want decrypt failure", payload.Msg)
			}
		case payload := <-trainingResCh:
			t.Fatalf("got reportRes instead of reportModelImport: %+v", payload)
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for model import failure report")
		}
	})
}

func TestPhase1ModelAuditFailureStillTrains(t *testing.T) {
	cases := []struct {
		name string
		llm  codeaudit.LLMConfig
	}{
		{name: "static audit failure continues training", llm: codeaudit.LLMConfig{Enabled: false}},
		{name: "fail-closed continues training", llm: codeaudit.LLMConfig{Enabled: true, Model: "qwen2.5-coder:0.5b", FailClosed: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, server := setupTestServer(t)
			state.mu.Lock()
			state.CurrentPhase = 1
			state.DockerID = "docker-audit-" + strings.ReplaceAll(tc.name, " ", "-")
			state.mu.Unlock()

			llmConfig := tc.llm
			var llmDown *httptest.Server
			if llmConfig.Enabled && llmConfig.FailClosed {
				llmDown = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
				defer llmDown.Close()
				llmConfig.Endpoint = llmDown.URL
			}

			state.Security.ScanEnabled = true
			state.Security.LLM = llmConfig

			state.mu.RLock()
			priv := state.SM2PrivateKey
			state.mu.RUnlock()
			pubKeyPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
			if err != nil {
				t.Fatalf("marshal SM2 public key PEM: %v", err)
			}

			modelImportCh := make(chan importedReportPayload, 1)
			trainingResCh := make(chan importedReportPayload, 1)
			platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload importedReportPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatalf("decode report payload: %v", err)
				}
				switch r.URL.Path {
				case reportModelImportEndpoint:
					modelImportCh <- payload
				case reportResEndpoint:
					trainingResCh <- payload
				default:
					t.Fatalf("unexpected report endpoint: %s", r.URL.Path)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer platformServer.Close()

			state.mu.Lock()
			state.PlatformIP = platformServer.URL
			state.mu.Unlock()

			modelArchiveData := buildTarGzArchive(t, map[string]archiveEntry{
				"bundle/train.py": {
					mode: 0o755,
					data: []byte(`#!/usr/bin/env python3
from argparse import ArgumentParser
from pathlib import Path
import json
import subprocess

parser = ArgumentParser(add_help=False)
parser.add_argument("--data-dir", dest="data_dir", required=True)
parser.add_argument("--output", "-o", dest="output_dir", required=True)
args, _ = parser.parse_known_args()
output_dir = Path(args.output_dir)
output_dir.mkdir(parents=True, exist_ok=True)
subprocess.run(["echo", "audit-failure"], check=True)
result = {"dataset": {"total_samples": 1, "splits": {"train": 1, "test": 0}}, "metrics": {"loss": 0.0, "accuracy": 1.0}}
(output_dir / "marker.txt").write_text("audit-failure\n")
(output_dir / "training_result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
`),
				},
			})
			dataArchiveData := buildTarGzArchive(t, map[string]archiveEntry{
				"data/sample.txt": {
					mode: 0o644,
					data: []byte("training data\n"),
				},
			})
			resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "model") {
					_, _ = w.Write(modelArchiveData)
					return
				}
				_, _ = w.Write(dataArchiveData)
			}))
			defer resourceServer.Close()

			importModel := func() {
				resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
					"resourceUrl":   resourceServer.URL + "/model.tar.gz",
					"requestId":     "req-" + strings.ReplaceAll(tc.name, " ", "-") + "-model",
					"taskId":        "task-" + strings.ReplaceAll(tc.name, " ", "-"),
					"publicKey":     string(pubKeyPEM),
					"runtimeConfig": makePhase1TrainingRuntimeConfigJSON(t, tc.name),
				})
				api := decodeResponse(t, resp)
				if resp.StatusCode != http.StatusOK || api.Error != 0 {
					t.Fatalf("import model: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
				}
			}

			importData := func() {
				resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
					"resourceUrl": resourceServer.URL + "/data.tar.gz",
					"requestId":   "req-" + strings.ReplaceAll(tc.name, " ", "-") + "-data",
					"taskId":      "task-" + strings.ReplaceAll(tc.name, " ", "-"),
				})
				api := decodeResponse(t, resp)
				if resp.StatusCode != http.StatusOK || api.Error != 0 {
					t.Fatalf("import data: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
				}
			}

			importModel()
			importData()

			gotModelImport := false
			gotTraining := false
			deadline := time.After(15 * time.Second)
			for !gotModelImport || !gotTraining {
				select {
				case payload := <-modelImportCh:
					if payload.Code != 2 {
						t.Fatalf("reportModelImport code = %d, want 2", payload.Code)
					}
					if payload.RequestID != "req-"+strings.ReplaceAll(tc.name, " ", "-")+"-model" {
						t.Fatalf("reportModelImport requestId = %q", payload.RequestID)
					}
					if payload.Msg == nil || *payload.Msg == "" {
						t.Fatal("reportModelImport msg empty, want audit failure")
					}
					gotModelImport = true
				case payload := <-trainingResCh:
					if payload.Code != 0 {
						t.Fatalf("reportRes code = %d, want 0", payload.Code)
					}
					if payload.Report == "" {
						t.Fatal("reportRes payload missing report")
					}
					var report map[string]any
					if err := json.Unmarshal([]byte(payload.Report), &report); err != nil {
						t.Fatalf("reportRes report is not valid JSON: %v", err)
					}
					trainingTask := report["training_task"].(map[string]any)
					if trainingTask["status"] != "succeeded" {
						t.Fatalf("training_task.status = %v, want succeeded", trainingTask["status"])
					}
					gotTraining = true
				case <-deadline:
					t.Fatal("timed out waiting for audit failure training flow")
				}
			}

			markerDir := resultDirForRequestTask(state.Security.ResultDir, "req-"+strings.ReplaceAll(tc.name, " ", "-")+"-data", "task-"+strings.ReplaceAll(tc.name, " ", "-"))
			markerPath := filepath.Join(markerDir, "marker.txt")
			if _, err := os.Stat(markerPath); err != nil {
				t.Fatalf("train marker missing at %s: %v", markerPath, err)
			}
		})
	}
}

type phase1FlowCase struct {
	name              string
	modelArchiveData  []byte
	dataArchiveData   []byte
	plaintextResource bool
	wantTrainMarker   bool
	importDataFirst   bool
}

func runPhase1FlowCase(t *testing.T, tc phase1FlowCase) {
	t.Helper()

	state, server := setupTestServer(t)
	state.mu.Lock()
	state.CurrentPhase = 1
	state.DockerID = "docker-" + strings.ReplaceAll(tc.name, " ", "-")
	state.mu.Unlock()

	platformReportCh := make(chan importedReportPayload, 1)
	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == reportResEndpoint {
			var payload importedReportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode reportRes payload: %v", err)
			}
			platformReportCh <- payload
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platformServer.Close()

	state.mu.Lock()
	state.PlatformIP = platformServer.URL
	state.mu.Unlock()

	state.mu.RLock()
	priv := state.SM2PrivateKey
	state.mu.RUnlock()

	pubKeyPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal SM2 public key PEM: %v", err)
	}

	modelData := tc.modelArchiveData
	dataData := tc.dataArchiveData
	if !tc.plaintextResource {
		modelData = sealForTAA(t, priv, modelData)
		dataData = sealForTAA(t, priv, dataData)
	}

	resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "model") {
			_, _ = w.Write(modelData)
		} else {
			_, _ = w.Write(dataData)
		}
	}))
	defer resourceServer.Close()

	importModel := func() {
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl":   resourceServer.URL + "/model.tar.gz",
			"requestId":     "req-" + strings.ReplaceAll(tc.name, " ", "-") + "-model",
			"taskId":        "task-" + strings.ReplaceAll(tc.name, " ", "-"),
			"publicKey":     string(pubKeyPEM),
			"runtimeConfig": makePhase1TrainingRuntimeConfigJSON(t, tc.name),
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("import model: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
	}

	importData := func() {
		resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": resourceServer.URL + "/data.tar.gz",
			"requestId":   "req-" + strings.ReplaceAll(tc.name, " ", "-") + "-data",
			"taskId":      "task-" + strings.ReplaceAll(tc.name, " ", "-"),
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("import data: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
		}
	}

	if tc.importDataFirst {
		importData()
		importModel()
	} else {
		importModel()
		importData()
	}

	var payload importedReportPayload
	select {
	case payload = <-platformReportCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for reportRes for case %s", tc.name)
	}
	if payload.Code != 0 {
		t.Fatalf("reportRes code = %d, want 0: %+v", payload.Code, payload)
	}
	if payload.Report == "" {
		t.Fatal("reportRes payload missing report")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(payload.Report), &report); err != nil {
		t.Fatalf("reportRes report is not valid JSON: %v", err)
	}
	if report["schema_version"] != "1.0" {
		t.Fatalf("report schema_version = %v, want 1.0", report["schema_version"])
	}
	trainingTask := report["training_task"].(map[string]any)
	if trainingTask["status"] != "succeeded" {
		t.Fatalf("training_task.status = %v, want succeeded", trainingTask["status"])
	}
	if tc.wantTrainMarker {
		markerDir := resultDirForRequestTask(state.Security.ResultDir, "req-"+strings.ReplaceAll(tc.name, " ", "-")+"-data", "task-"+strings.ReplaceAll(tc.name, " ", "-"))
		markerPath := filepath.Join(markerDir, "marker.txt")
		if _, err := os.Stat(markerPath); err != nil {
			t.Fatalf("train marker missing at %s: %v", markerPath, err)
		}
	}
}

type archiveEntry struct {
	mode os.FileMode
	data []byte
}

func augmentArchiveEntries(entries map[string]archiveEntry) map[string]archiveEntry {
	copyEntries := make(map[string]archiveEntry, len(entries))
	for name, entry := range entries {
		copyEntries[name] = entry
	}
	return copyEntries
}

func buildTarGzArchive(t *testing.T, entries map[string]archiveEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, entry := range augmentArchiveEntries(entries) {
		hdr := &tar.Header{
			Name: name,
			Mode: int64(entry.mode),
			Size: int64(len(entry.data)),
		}
		if strings.HasSuffix(name, "/") {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header for %s: %v", name, err)
		}
		if hdr.Typeflag != tar.TypeDir {
			if _, err := tw.Write(entry.data); err != nil {
				t.Fatalf("write tar data for %s: %v", name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func buildZipArchive(t *testing.T, entries map[string]archiveEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, entry := range augmentArchiveEntries(entries) {
		fh := &zip.FileHeader{Name: name, Method: zip.Deflate}
		fh.SetMode(entry.mode)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatalf("create zip header for %s: %v", name, err)
		}
		if _, err := io.Copy(w, bytes.NewReader(entry.data)); err != nil {
			t.Fatalf("write zip data for %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

func newMockQwenServer(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	callCount := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Fatalf("unexpected qwen path: %s", r.URL.Path)
		}
		var req struct {
			Prompt string `json:"prompt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode qwen request: %v", err)
		}
		mu.Lock()
		callCount++
		mu.Unlock()

		var response string
		if strings.Contains(req.Prompt, "risk_level") || strings.Contains(req.Prompt, "分析此 Python 文件") {
			response = `{"risk_level":"LOW","summary":"正常","chained":false,"exfiltration":false}`
		} else {
			response = `{"verdict":"BENIGN","reason":"仅用于测试","risk":""}`
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"response": response})
	}))
}
