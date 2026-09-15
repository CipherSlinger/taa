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
	"strings"
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

func TestHealthAndStatusExposeTrainingRunningOnly(t *testing.T) {
	state, server := setupTestServer(t)

	for _, endpoint := range []string{"/v1/taa/health", "/v1/taa/status"} {
		resp := postEmptyJSON(t, server.URL+endpoint)
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("%s returned status=%d error=%d", endpoint, resp.StatusCode, api.Error)
		}
		result, ok := api.Result.(map[string]any)
		if !ok {
			t.Fatalf("%s result type = %T, want map[string]any", endpoint, api.Result)
		}
		for _, removed := range []string{"dataImported", "trainingDataImported", "trainingDone"} {
			if _, exists := result[removed]; exists {
				t.Fatalf("%s result contains removed field %q: %#v", endpoint, removed, result)
			}
		}
		if _, exists := result["trainingRunning"]; !exists {
			t.Fatalf("%s result missing trainingRunning: %#v", endpoint, result)
		}
	}

	_ = state
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

	state, server := setupTestServer(t)

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
	checksum, ok := report["checksum"].(map[string]any)
	if !ok || checksum == nil {
		t.Fatalf("result missing checksum: %#v", report)
	}
	if checksum["algorithm"] != "sm3" {
		t.Fatalf("checksum algorithm = %v, want sm3", checksum["algorithm"])
	}
	hashVal, ok := checksum["value"].(string)
	if !ok || hashVal == "" {
		t.Fatalf("checksum value is empty: %#v", checksum)
	}

	// 验证资源已被持久化保存到数据目录下的 hash 文件夹
	savedDir := filepath.Join(state.Security.DataDir, hashVal)
	if fi, err := os.Stat(savedDir); err != nil || !fi.IsDir() {
		t.Fatalf("expected persistent dataDir at %s, err=%v", savedDir, err)
	}
	csvFile := filepath.Join(savedDir, "dataset", "users.csv")
	content, err := os.ReadFile(csvFile)
	if err != nil {
		t.Fatalf("read saved csv file: %v", err)
	}
	if string(content) != "user_id,name\n1,Alice\n2,Bob\n" {
		t.Fatalf("saved csv content mismatch: %q", string(content))
	}

	// 再次调用，验证复用现有 hash 数据目录
	resp2 := postJSON(t, server.URL+"/v1/taa/getResourceInfo", body)
	api2 := decodeResponse(t, resp2)
	if resp2.StatusCode != http.StatusOK || api2.Error != 0 {
		t.Fatalf("second call failed: status=%d, err=%d, msg=%s", resp2.StatusCode, api2.Error, api2.Msg)
	}
	if fi, err := os.Stat(savedDir); err != nil || !fi.IsDir() {
		t.Fatalf("expected persistent dataDir to remain at %s, err=%v", savedDir, err)
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
	checksum, ok := report["checksum"].(map[string]any)
	if !ok || checksum == nil {
		t.Fatalf("result missing checksum: %#v", report)
	}
	if checksum["algorithm"] != "sm3" {
		t.Fatalf("checksum algorithm = %v, want sm3", checksum["algorithm"])
	}
	hashVal, ok := checksum["value"].(string)
	if !ok || hashVal == "" {
		t.Fatalf("checksum value is empty: %#v", checksum)
	}

	savedDir := filepath.Join(state.Security.DataDir, hashVal)
	if fi, err := os.Stat(savedDir); err != nil || !fi.IsDir() {
		t.Fatalf("expected persistent dataDir for encrypted resource at %s, err=%v", savedDir, err)
	}
	csvFile := filepath.Join(savedDir, "dataset", "users.csv")
	if _, err := os.Stat(csvFile); err != nil {
		t.Fatalf("expected decrypted file at %s, err=%v", csvFile, err)
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
		"python3 train.py --input /opt/taa/input --output /opt/taa/output",
		"python3 train.py --input <input> --output <output>",
		"python3 train.py --input <INPUT> --output <OUTPUT>",
		"cat /opt/taa/input/data.csv > /opt/taa/output/result.csv",
	}
	dataDir := "/data/store/abc123hash"
	outputDir := "/results/req01-task01"

	resolved := resolveRuntimeCommands(commands, dataDir, outputDir)
	want := []string{
		"python3 train.py --input /data/store/abc123hash --output /results/req01-task01",
		"echo in=/data/store/abc123hash out=/results/req01-task01",
		"python3 eval.py --data /data/store/abc123hash/dataset --save /results/req01-task01/model",
		"echo no placeholder",
		"python3 train.py --input /data/store/abc123hash --output /results/req01-task01",
		"python3 train.py --input /data/store/abc123hash --output /results/req01-task01",
		"python3 train.py --input /data/store/abc123hash --output /results/req01-task01",
		"cat /data/store/abc123hash/data.csv > /results/req01-task01/result.csv",
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
		"OPT_IN":      "/opt/taa/input",
		"OPT_OUT":     "/opt/taa/output",
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
	if resolved["OPT_IN"] != dataDir {
		t.Errorf("OPT_IN = %q, want %q", resolved["OPT_IN"], dataDir)
	}
	if resolved["OPT_OUT"] != outputDir {
		t.Errorf("OPT_OUT = %q, want %q", resolved["OPT_OUT"], outputDir)
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

func TestRunRuntimeConfigReplacesOptTaaPaths(t *testing.T) {
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
			`cat "/opt/taa/input/input.txt" > "/opt/taa/output/copied.txt"`,
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

func TestRunRuntimeConfigWithCdAndRelativeModelDirs(t *testing.T) {
	tmpDir := t.TempDir()
	subModelDir := filepath.Join(tmpDir, "models", "my-sub-model")
	if err := os.MkdirAll(subModelDir, 0o755); err != nil {
		t.Fatal(err)
	}

	currWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(currWd) }()

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	relInput := filepath.Join(".local", "taa", "input")
	relOutput := filepath.Join(".local", "taa", "output")
	if err := os.MkdirAll(relInput, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(relInput, "input.txt"), []byte("sub-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	sec := SecurityConfig{
		ModelInputDir:  relInput,
		ModelOutputDir: relOutput,
	}

	if !filepath.IsAbs(sec.GetModelInputDir()) {
		t.Fatalf("GetModelInputDir should be absolute, got %s", sec.GetModelInputDir())
	}

	cfg := runtimeConfig{
		Commands: []string{
			"cd my-sub-model",
			`cat "` + sec.GetModelInputDir() + `/input.txt" > "` + sec.GetModelOutputDir() + `/copied.txt"`,
		},
	}

	out, err := runRuntimeConfig(cfg, nil, filepath.Join(tmpDir, "models"), sec.GetModelInputDir(), sec.GetModelOutputDir(), "task-sub", "2026-09-08T00:00:00Z")
	if err != nil {
		t.Fatalf("runRuntimeConfig failed: %v\noutput: %s", err, out)
	}

	copied, err := os.ReadFile(filepath.Join(sec.GetModelOutputDir(), "copied.txt"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(copied) != "sub-data" {
		t.Fatalf("copied content = %q, want sub-data", string(copied))
	}
}

func TestSecurityConfigModelDirs(t *testing.T) {
	var emptySec SecurityConfig
	if emptySec.GetModelInputDir() != DefaultModelInputDir {
		t.Errorf("GetModelInputDir = %q, want %q", emptySec.GetModelInputDir(), DefaultModelInputDir)
	}
	if emptySec.GetModelOutputDir() != DefaultModelOutputDir {
		t.Errorf("GetModelOutputDir = %q, want %q", emptySec.GetModelOutputDir(), DefaultModelOutputDir)
	}

	customSec := SecurityConfig{
		ModelInputDir:  "/custom/input",
		ModelOutputDir: "/custom/output",
	}
	if customSec.GetModelInputDir() != "/custom/input" {
		t.Errorf("GetModelInputDir = %q, want /custom/input", customSec.GetModelInputDir())
	}
	if customSec.GetModelOutputDir() != "/custom/output" {
		t.Errorf("GetModelOutputDir = %q, want /custom/output", customSec.GetModelOutputDir())
	}

	relSec := SecurityConfig{
		ModelInputDir:  ".local/taa/input",
		ModelOutputDir: ".local/taa/output",
	}
	wantInputAbs, _ := filepath.Abs(".local/taa/input")
	wantOutputAbs, _ := filepath.Abs(".local/taa/output")
	if relSec.GetModelInputDir() != wantInputAbs {
		t.Errorf("GetModelInputDir = %q, want %q", relSec.GetModelInputDir(), wantInputAbs)
	}
	if relSec.GetModelOutputDir() != wantOutputAbs {
		t.Errorf("GetModelOutputDir = %q, want %q", relSec.GetModelOutputDir(), wantOutputAbs)
	}
}

func TestCopyDirAndCleanDirContents(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	dstDir := filepath.Join(tmpDir, "dst")

	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "file2.txt"), []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. 测试 copyDir
	if err := copyDir(dstDir, srcDir); err != nil {
		t.Fatalf("copyDir failed: %v", err)
	}

	f1, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
	if err != nil || string(f1) != "hello" {
		t.Fatalf("file1 content mismatch or read error: %v, got %s", err, string(f1))
	}
	f2, err := os.ReadFile(filepath.Join(dstDir, "sub", "file2.txt"))
	if err != nil || string(f2) != "world" {
		t.Fatalf("file2 content mismatch or read error: %v, got %s", err, string(f2))
	}

	// 2. 测试同目录 copyDir 幂等
	if err := copyDir(dstDir, dstDir); err != nil {
		t.Fatalf("copyDir same dir should succeed, got: %v", err)
	}

	// 3. 测试 cleanDirContents
	if err := cleanDirContents(dstDir); err != nil {
		t.Fatalf("cleanDirContents failed: %v", err)
	}
	entries, err := os.ReadDir(dstDir)
	if err != nil {
		t.Fatalf("read dstDir after clean: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("cleanDirContents left %d entries, want 0", len(entries))
	}
	// 确认根目录本身仍存在
	if fi, err := os.Stat(dstDir); err != nil || !fi.IsDir() {
		t.Fatalf("dstDir itself should still exist as directory")
	}
}

func TestParseRuntimeConfig_EnvString(t *testing.T) {
	raw := `{"commands": ["echo 1", "python3 train.py"], "env": "{\"CUDA_VISIBLE_DEVICES\":\"0\"}"}`
	cfg, env, err := parseRuntimeConfig(raw)
	if err != nil {
		t.Fatalf("parseRuntimeConfig failed: %v", err)
	}
	if len(cfg.Commands) != 2 {
		t.Fatalf("commands length = %d, want 2", len(cfg.Commands))
	}
	if env["CUDA_VISIBLE_DEVICES"] != "0" {
		t.Fatalf("env[CUDA_VISIBLE_DEVICES] = %q, want '0'", env["CUDA_VISIBLE_DEVICES"])
	}
}

func TestParseRuntimeConfig_EnvObject(t *testing.T) {
	raw := `{"commands": ["echo 1", "python3 train.py"], "env": {"CUDA_VISIBLE_DEVICES": "0", "BATCH_SIZE": 32}}`
	cfg, env, err := parseRuntimeConfig(raw)
	if err != nil {
		t.Fatalf("parseRuntimeConfig with object env failed: %v", err)
	}
	if len(cfg.Commands) != 2 {
		t.Fatalf("commands length = %d, want 2", len(cfg.Commands))
	}
	if env["CUDA_VISIBLE_DEVICES"] != "0" {
		t.Fatalf("env[CUDA_VISIBLE_DEVICES] = %q, want '0'", env["CUDA_VISIBLE_DEVICES"])
	}
	if env["BATCH_SIZE"] != "32" {
		t.Fatalf("env[BATCH_SIZE] = %q, want '32'", env["BATCH_SIZE"])
	}
	if strings.TrimSpace(cfg.Env) == "" {
		t.Fatalf("cfg.Env should be populated after parsing object env, got empty")
	}
}

func TestParseRuntimeConfig_EnvEmptyObjectAndNull(t *testing.T) {
	// env is empty object {}
	rawObj := `{"commands": ["echo 1"], "env": {}}`
	cfg1, env1, err := parseRuntimeConfig(rawObj)
	if err != nil {
		t.Fatalf("parseRuntimeConfig with empty object env failed: %v", err)
	}
	if len(cfg1.Commands) != 1 || len(env1) != 0 {
		t.Fatalf("expected 1 command and 0 env, got %d commands, %d env", len(cfg1.Commands), len(env1))
	}

	// env is null
	rawNull := `{"commands": ["echo 1"], "env": null}`
	cfg2, env2, err := parseRuntimeConfig(rawNull)
	if err != nil {
		t.Fatalf("parseRuntimeConfig with null env failed: %v", err)
	}
	if len(cfg2.Commands) != 1 || len(env2) != 0 {
		t.Fatalf("expected 1 command and 0 env, got %d commands, %d env", len(cfg2.Commands), len(env2))
	}
}

func TestParseRuntimeConfig_EnvInvalidType(t *testing.T) {
	raw := `{"commands": ["echo 1"], "env": 12345}`
	_, _, err := parseRuntimeConfig(raw)
	if err == nil {
		t.Fatalf("parseRuntimeConfig with number env should fail, got nil err")
	}
}

func TestImportRequestUnmarshalJSON(t *testing.T) {
	// 1. runtimeConfig as string
	jsonStr := `{"resourceUrl":"http://example.com/res","requestId":"req-1","taskId":"task-1","runtimeConfig":"{\"commands\":[\"echo 1\"]}"}`
	var req1 importRequest
	if err := json.Unmarshal([]byte(jsonStr), &req1); err != nil {
		t.Fatalf("unmarshal req1 failed: %v", err)
	}
	if req1.RuntimeConfig != `{"commands":["echo 1"]}` {
		t.Fatalf("req1.RuntimeConfig = %q, want '{\"commands\":[\"echo 1\"]}'", req1.RuntimeConfig)
	}

	// 2. runtimeConfig as object
	jsonObj := `{"resourceUrl":"http://example.com/res","requestId":"req-2","taskId":"task-2","runtimeConfig":{"commands":["echo 2"],"env":{"A":"B"}}}`
	var req2 importRequest
	if err := json.Unmarshal([]byte(jsonObj), &req2); err != nil {
		t.Fatalf("unmarshal req2 failed: %v", err)
	}
	cfg, env, err := parseRuntimeConfig(req2.RuntimeConfig)
	if err != nil {
		t.Fatalf("parseRuntimeConfig on req2.RuntimeConfig failed: %v", err)
	}
	if len(cfg.Commands) != 1 || cfg.Commands[0] != "echo 2" {
		t.Fatalf("cfg.Commands = %v, want ['echo 2']", cfg.Commands)
	}
	if env["A"] != "B" {
		t.Fatalf("env['A'] = %q, want 'B'", env["A"])
	}
}
