package controller

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitForIdle(t *testing.T, state *TAAState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state.mu.RLock()
		op := state.CurrentOp
		state.mu.RUnlock()
		if op == "idle" || op == "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for state to become idle")
}

func TestImportParamValidation_BothEmptyRejected(t *testing.T) {
	_, server := setupTestServer(t)

	t.Run("import rejects when both requestId and taskId are empty", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": "http://example.com/data.tar.gz",
			"requestId":   "",
			"taskId":      "",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected 400 error, got status=%d error=%d", resp.StatusCode, api.Error)
		}
		if !strings.Contains(api.Msg, "requestId 和 taskId 不能同时为空") {
			t.Fatalf("expected error message to contain 'requestId 和 taskId 不能同时为空', got: %q", api.Msg)
		}
	})

	t.Run("importModel rejects when both requestId and taskId are empty", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": "http://example.com/model.tar.gz",
			"requestId":   "",
			"taskId":      "",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected 400 error, got status=%d error=%d", resp.StatusCode, api.Error)
		}
		if !strings.Contains(api.Msg, "requestId 和 taskId 不能同时为空") {
			t.Fatalf("expected error message to contain 'requestId 和 taskId 不能同时为空', got: %q", api.Msg)
		}
	})

	t.Run("export rejects when both requestId and taskId are empty", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"requestId": "",
			"taskId":    "",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected 400 error, got status=%d error=%d", resp.StatusCode, api.Error)
		}
		if !strings.Contains(api.Msg, "requestId 和 taskId 不能同时为空") {
			t.Fatalf("expected error message to contain 'requestId 和 taskId 不能同时为空', got: %q", api.Msg)
		}
	})
}

func TestImportParamValidation_EitherProvidedAccepted(t *testing.T) {
	tarBytes := createTestTarGz(t, map[string]string{"sample.txt": "hello"})
	resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarBytes)
	}))
	defer resourceServer.Close()

	t.Run("import accepts when only requestId is provided", func(t *testing.T) {
		state, server := setupTestServer(t)
		resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": resourceServer.URL + "/data.tar.gz",
			"requestId":   "req-only-001",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("expected success for requestId only, got status=%d error=%d msg=%q", resp.StatusCode, api.Error, api.Msg)
		}
		waitForIdle(t, state)
	})

	t.Run("import accepts when only taskId is provided", func(t *testing.T) {
		state, server := setupTestServer(t)
		resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": resourceServer.URL + "/data.tar.gz",
			"taskId":      "task-only-001",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("expected success for taskId only, got status=%d error=%d msg=%q", resp.StatusCode, api.Error, api.Msg)
		}
		waitForIdle(t, state)
	})

	t.Run("importModel accepts when only taskId is provided", func(t *testing.T) {
		state, server := setupTestServer(t)
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": resourceServer.URL + "/model.tar.gz",
			"taskId":      "task-model-only-001",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("expected success for taskId only in importModel, got status=%d error=%d msg=%q", resp.StatusCode, api.Error, api.Msg)
		}
		waitForIdle(t, state)
	})

	t.Run("importModel accepts when only requestId is provided", func(t *testing.T) {
		state, server := setupTestServer(t)
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": resourceServer.URL + "/model.tar.gz",
			"requestId":   "req-model-only-001",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("expected success for requestId only in importModel, got status=%d error=%d msg=%q", resp.StatusCode, api.Error, api.Msg)
		}
		waitForIdle(t, state)
	})

	t.Run("export accepts when only taskId is provided", func(t *testing.T) {
		state, server := setupTestServer(t)
		record := seedExportIndexRecord(t, state, "", "task-export-only-001", "export-task-only")
		if err := os.WriteFile(filepath.Join(record.ResultDir, "training_report.json"), []byte("{}"), 0o644); err != nil {
			t.Fatalf("write report failed: %v", err)
		}
		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"taskId": "task-export-only-001",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got status=%d body=%s", resp.StatusCode, body)
		}
		if got := resp.Header.Get("X-TAA-Task-Id"); got != "task-export-only-001" {
			t.Fatalf("X-TAA-Task-Id = %q, want task-export-only-001", got)
		}
	})

	t.Run("export accepts when only requestId is provided", func(t *testing.T) {
		state, server := setupTestServer(t)
		record := seedExportIndexRecord(t, state, "req-export-only-001", "", "export-req-only")
		if err := os.WriteFile(filepath.Join(record.ResultDir, "training_report.json"), []byte("{}"), 0o644); err != nil {
			t.Fatalf("write report failed: %v", err)
		}
		resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
			"requestId": "req-export-only-001",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got status=%d body=%s", resp.StatusCode, body)
		}
	})
}

func TestImportIndexStore_AllowsEitherRequestIDOrTaskID(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "import-index.json")

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("LoadImportIndexStore: %v", err)
	}

	// 1. Both empty should fail
	if err := store.Reserve("", ""); err == nil {
		t.Fatal("expected Reserve('', '') to fail")
	}

	// 2. Only requestId
	if err := store.Reserve("req-1", ""); err != nil {
		t.Fatalf("Reserve('req-1', '') failed: %v", err)
	}
	if err := store.Commit(ImportIndexRecord{
		RequestID: "req-1",
		Hash:      "hash-1",
		DataDir:   "/data/hash-1",
		ResultDir: "/result/hash-1",
	}); err != nil {
		t.Fatalf("Commit with only RequestID failed: %v", err)
	}

	// 3. Only taskId
	if err := store.Reserve("", "task-2"); err != nil {
		t.Fatalf("Reserve('', 'task-2') failed: %v", err)
	}
	if err := store.Commit(ImportIndexRecord{
		TaskID:    "task-2",
		Hash:      "hash-2",
		DataDir:   "/data/hash-2",
		ResultDir: "/result/hash-2",
	}); err != nil {
		t.Fatalf("Commit with only TaskID failed: %v", err)
	}

	// 4. Lookup
	rec1, err := store.Lookup("req-1", "")
	if err != nil || rec1.Hash != "hash-1" {
		t.Fatalf("Lookup('req-1', '') = %+v, err=%v", rec1, err)
	}
	rec2, err := store.Lookup("", "task-2")
	if err != nil || rec2.Hash != "hash-2" {
		t.Fatalf("Lookup('', 'task-2') = %+v, err=%v", rec2, err)
	}

	// 5. Reload from disk
	reloaded, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("reloading store failed: %v", err)
	}
	if _, err := reloaded.Lookup("req-1", ""); err != nil {
		t.Fatalf("Lookup on reloaded store for req-1 failed: %v", err)
	}
	if _, err := reloaded.Lookup("", "task-2"); err != nil {
		t.Fatalf("Lookup on reloaded store for task-2 failed: %v", err)
	}
}

func TestReportToPlatform_AllowsEitherRequestIDOrTaskID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Both empty should fail
	if err := ReportRes(context.Background(), server.URL, "docker-1", "", "", 0, "", "{}"); err == nil {
		t.Fatal("expected ReportRes with empty requestId and taskId to fail")
	}

	// Only taskId should succeed
	if err := ReportRes(context.Background(), server.URL, "docker-1", "", "task-1", 0, "", "{}"); err != nil {
		t.Fatalf("ReportRes with only taskId failed: %v", err)
	}

	// Only requestId should succeed
	if err := ReportRes(context.Background(), server.URL, "docker-1", "req-1", "", 0, "", "{}"); err != nil {
		t.Fatalf("ReportRes with only requestId failed: %v", err)
	}

	// ReportModelImport with only taskId should succeed
	if err := ReportModelImport(context.Background(), server.URL, "docker-1", "", "task-1", 0, "", "{}"); err != nil {
		t.Fatalf("ReportModelImport with only taskId failed: %v", err)
	}
}

func TestImportModel_ResourceURLReuseValidation(t *testing.T) {
	state, server := setupTestServer(t)

	// 1. Initially no model has been saved/imported. Empty resourceUrl must fail with 400.
	t.Run("empty resourceUrl fails when model never imported", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": "",
			"taskId":      "task-model-empty-url",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected 400 error, got status=%d error=%d", resp.StatusCode, api.Error)
		}
		if !strings.Contains(api.Msg, "resourceUrl 不能为空: 之前未传输过且请求中为空") {
			t.Fatalf("expected 'resourceUrl 不能为空: 之前未传输过且请求中为空', got: %q", api.Msg)
		}
	})

	// 2. Mark model as saved/imported in state
	state.setSavedModelResourceURL("http://example.com/saved-model.tar.gz")

	t.Run("empty resourceUrl fails when runtimeConfig is empty", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl":   "",
			"taskId":        "task-model-empty-url",
			"runtimeConfig": "",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected 400 error, got status=%d error=%d", resp.StatusCode, api.Error)
		}
		if !strings.Contains(api.Msg, "runtimeConfig 不能为空") {
			t.Fatalf("expected 'runtimeConfig 不能为空', got: %q", api.Msg)
		}
	})

	t.Run("empty resourceUrl fails when runtimeConfig commands is empty", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl":   "",
			"taskId":        "task-model-empty-url",
			"runtimeConfig": `{"commands": []}`,
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected 400 error, got status=%d error=%d", resp.StatusCode, api.Error)
		}
		if !strings.Contains(api.Msg, "runtimeConfig.commands 不能为空") {
			t.Fatalf("expected 'runtimeConfig.commands 不能为空', got: %q", api.Msg)
		}
	})

	t.Run("empty resourceUrl fails when no imported data exists", func(t *testing.T) {
		resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl":   "",
			"taskId":        "task-model-empty-url",
			"runtimeConfig": `{"commands": ["echo test"]}`,
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
			t.Fatalf("expected 400 error, got status=%d error=%d", resp.StatusCode, api.Error)
		}
		if !strings.Contains(api.Msg, "未找到已导入的数据，无法执行训练") {
			t.Fatalf("expected '未找到已导入的数据，无法执行训练', got: %q", api.Msg)
		}
	})
}

func TestImportIndexStore_LatestTracking(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "import-index.json")

	store, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("LoadImportIndexStore: %v", err)
	}

	// Initially empty
	_, ok := store.Latest()
	if ok {
		t.Fatal("expected Latest() to be false on empty store")
	}

	// Commit 1st record
	if err := store.Reserve("req-1", "task-1"); err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}
	rec1 := ImportIndexRecord{
		RequestID: "req-1",
		TaskID:    "task-1",
		Hash:      "hash-data-1",
		DataDir:   "/data/hash-1",
		ResultDir: "/result/hash-1",
	}
	if err := store.Commit(rec1); err != nil {
		t.Fatalf("Commit rec1 failed: %v", err)
	}

	latest, ok := store.Latest()
	if !ok || latest.Hash != "hash-data-1" {
		t.Fatalf("expected Latest to be rec1, got: %+v", latest)
	}

	// Commit 2nd record
	if err := store.Reserve("req-2", "task-2"); err != nil {
		t.Fatalf("Reserve failed: %v", err)
	}
	rec2 := ImportIndexRecord{
		RequestID: "req-2",
		TaskID:    "task-2",
		Hash:      "hash-data-2",
		DataDir:   "/data/hash-2",
		ResultDir: "/result/hash-2",
	}
	if err := store.Commit(rec2); err != nil {
		t.Fatalf("Commit rec2 failed: %v", err)
	}

	latest, ok = store.Latest()
	if !ok || latest.Hash != "hash-data-2" {
		t.Fatalf("expected Latest to be rec2, got: %+v", latest)
	}

	// Reload store from disk and check Latest() persistence
	reloaded, err := LoadImportIndexStore(indexPath)
	if err != nil {
		t.Fatalf("reload store failed: %v", err)
	}
	latest, ok = reloaded.Latest()
	if !ok || latest.Hash != "hash-data-2" {
		t.Fatalf("expected reloaded Latest to be rec2, got: %+v", latest)
	}
}
