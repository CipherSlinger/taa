package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeResourceInfoProbe(t *testing.T, modelDir string) {
	t.Helper()
	script := "#!/usr/bin/env python3\n" +
		"from argparse import ArgumentParser\n" +
		"import json\n" +
		"\n" +
		"parser = ArgumentParser(add_help=False)\n" +
		"parser.add_argument(\"--data-dir\", dest=\"data_dir\", default=None)\n" +
		"args, _ = parser.parse_known_args()\n" +
		"payload = {\n" +
		"    \"data_dir\": args.data_dir,\n" +
		"}\n" +
		"print(json.dumps(payload, indent=2, ensure_ascii=False))\n"
	if err := os.WriteFile(filepath.Join(modelDir, "resource_info.py"), []byte(script), 0o755); err != nil {
		t.Fatalf("write probe resource_info.py: %v", err)
	}
}

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

func TestResourceInfoHandlerDownloadsAndAnalyzes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python3 scripts are not supported on windows")
	}

	state, server := setupTestServer(t)
	writeResourceInfoProbe(t, state.Security.ModelDir)

	archiveData := createTestTarGz(t, map[string]string{
		"data.csv": "col1,col2\n1,2\n3,4\n",
	})

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(archiveData)
	}))
	defer fileServer.Close()

	body := map[string]string{"resourceUrl": fileServer.URL + "/data.tar.gz"}
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
	if !strings.Contains(result, "data_dir") {
		t.Fatalf("result = %q, want it to contain data_dir", result)
	}
}

func TestResourceInfoHandlerDecryptsEncryptedResource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python3 scripts are not supported on windows")
	}

	state, server := setupTestServer(t)
	writeResourceInfoProbe(t, state.Security.ModelDir)

	archiveData := createTestTarGz(t, map[string]string{
		"data.csv": "col1,col2\n1,2\n3,4\n",
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

	body := map[string]string{"resourceUrl": fileServer.URL + "/data.tar.gz.enc"}
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
	if !strings.Contains(result, "data_dir") {
		t.Fatalf("result = %q, want it to contain data_dir", result)
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
