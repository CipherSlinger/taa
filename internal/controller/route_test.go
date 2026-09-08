package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func postEmptyJSON(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func createTestTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Size: int64(len(content)),
			Mode: 0o644,
		}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write tar content: %v", err)
		}
	}
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func TestResourceInfoHandlerRequiresResourceUrl(t *testing.T) {
	_, server := setupTestServer(t)

	resp := postEmptyJSON(t, server.URL+"/v1/taa/getResourceInfo")
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if api.Error != http.StatusBadRequest {
		t.Fatalf("error = %d, want %d", api.Error, http.StatusBadRequest)
	}
}

func TestResourceInfoHandlerDownloadsAndBuildsFileTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python3 scripts are not supported on windows")
	}

	_, server := setupTestServer(t)

	archiveData := createTestTarGz(t, map[string]string{
		"dataset/users.csv": "user_id,name\n1,Alice\n2,Bob\n",
		"dataset/notes.txt": "hello\nworld\n",
	})

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(archiveData)
	}))
	defer fileServer.Close()

	body := map[string]string{"resourceUrl": fileServer.URL + "/dataset.tar.gz"}
	resp := postJSON(t, server.URL+"/v1/taa/getResourceInfo", body)
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; msg=%s", resp.StatusCode, http.StatusOK, api.Msg)
	}
	if api.Error != 0 {
		t.Fatalf("error = %d, want 0; msg=%s", api.Error, api.Msg)
	}

	result, ok := api.Result.(string)
	if !ok {
		t.Fatalf("result type = %T, want string", api.Result)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(result), &report); err != nil {
		t.Fatalf("unmarshal result JSON: %v", err)
	}
	if _, ok := report["tree"].(map[string]any); !ok {
		t.Fatalf("result tree missing or wrong type: %#v", report["tree"])
	}
	if _, ok := report["structured_files"]; !ok {
		t.Fatalf("result missing structured_files: %#v", report)
	}
}

func TestResourceInfoHandlerDecryptsEncryptedResource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python3 scripts are not supported on windows")
	}

	state, server := setupTestServer(t)

	archiveData := createTestTarGz(t, map[string]string{
		"dataset/users.csv": "user_id,name\n1,Alice\n2,Bob\n",
	})

	state.mu.RLock()
	priv := state.SM2PrivateKey
	state.mu.RUnlock()
	sealed := sealForTAA(t, priv, archiveData)

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(sealed)
	}))
	defer fileServer.Close()

	body := map[string]string{"resourceUrl": fileServer.URL + "/dataset.tar.gz.enc"}
	resp := postJSON(t, server.URL+"/v1/taa/getResourceInfo", body)
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; msg=%s", resp.StatusCode, http.StatusOK, api.Msg)
	}
	if api.Error != 0 {
		t.Fatalf("error = %d, want 0; msg=%s", api.Error, api.Msg)
	}

	result, ok := api.Result.(string)
	if !ok {
		t.Fatalf("result type = %T, want string", api.Result)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(result), &report); err != nil {
		t.Fatalf("unmarshal result JSON: %v", err)
	}
	if report["tree"] == nil {
		t.Fatalf("result missing tree: %#v", report)
	}
}

func TestRunScriptUsesPython3(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python3 scripts are not supported on windows")
	}

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "debug.py")
	outputDir := filepath.Join(tmpDir, "output")

	script := `#!/usr/bin/env python3
from argparse import ArgumentParser
from pathlib import Path
parser = ArgumentParser(add_help=False)
parser.add_argument("--output", "-o", dest="output_dir", required=True)
args, _ = parser.parse_known_args()
output_dir = Path(args.output_dir)
output_dir.mkdir(parents=True, exist_ok=True)
(output_dir / "result.txt").write_text("beta")
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	if _, err := runScript(scriptPath, outputDir); err != nil {
		t.Fatalf("runScript returned error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(outputDir, "result.txt"))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != "beta" {
		t.Fatalf("result = %q, want beta", string(got))
	}
}

func TestResolveRuntimeCommands(t *testing.T) {
	commands := []string{
		"python3 train.py --input <in> --output <out>",
		"echo in=<IN> out=<OUT>",
		"python3 eval.py --data <in>/dataset --save <out>/model",
		"echo no placeholder",
	}
	dataDir := "/data/store/abc123hash"
	outputDir := "/results/req01-task01"

	resolved := resolveRuntimeCommands(commands, dataDir, outputDir)
	want := []string{
		"python3 train.py --input /data/store/abc123hash --output /results/req01-task01",
		"echo in=/data/store/abc123hash out=/results/req01-task01",
		"python3 eval.py --data /data/store/abc123hash/dataset --save /results/req01-task01/model",
		"echo no placeholder",
	}

	for i := range want {
		if resolved[i] != want[i] {
			t.Errorf("command[%d] = %q, want %q", i, resolved[i], want[i])
		}
	}
}

func TestResolveRuntimeEnv(t *testing.T) {
	env := map[string]string{
		"DATA_PATH":   "<in>",
		"RESULT_PATH": "<out>",
		"NORMAL":      "value",
	}
	dataDir := "/data/store/hash"
	outputDir := "/results/task"

	resolved := resolveRuntimeEnv(env, dataDir, outputDir)
	if resolved["DATA_PATH"] != dataDir {
		t.Errorf("DATA_PATH = %q, want %q", resolved["DATA_PATH"], dataDir)
	}
	if resolved["RESULT_PATH"] != outputDir {
		t.Errorf("RESULT_PATH = %q, want %q", resolved["RESULT_PATH"], outputDir)
	}
	if resolved["NORMAL"] != "value" {
		t.Errorf("NORMAL = %q, want value", resolved["NORMAL"])
	}
}

func TestRunRuntimeConfigReplacesInOut(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data", "testhash")
	outputDir := filepath.Join(tmpDir, "results", "task-test")

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "input.txt"), []byte("sample-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := runtimeConfig{
		Commands: []string{
			`cat "<in>/input.txt" > "<out>/copied.txt"`,
		},
	}

	out, err := runRuntimeConfig(cfg, nil, tmpDir, dataDir, outputDir, "task-test", "2026-09-08T00:00:00Z")
	if err != nil {
		t.Fatalf("runRuntimeConfig failed: %v\noutput: %s", err, out)
	}

	copied, err := os.ReadFile(filepath.Join(outputDir, "copied.txt"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(copied) != "sample-data" {
		t.Fatalf("copied content = %q, want sample-data", string(copied))
	}
}
