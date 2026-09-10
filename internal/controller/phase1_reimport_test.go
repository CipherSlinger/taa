package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSwitchToPhase1_ResetsModelAndDataImported(t *testing.T) {
	state, server := setupTestServer(t)

	// 1. 模拟阶段1中模型与数据均已导入
	state.mu.Lock()
	state.CurrentPhase = 1
	state.ModelImported = true
	state.DataImported = true
	state.Phase1TrainingStarted = true
	state.mu.Unlock()

	// 2. 切换到阶段2：此时不会清除标志位
	resp := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 2})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("switch to phase 2 failed: %d / %s", resp.StatusCode, api.Msg)
	}
	if state.CurrentPhase != 2 {
		t.Fatalf("expected phase 2, got %d", state.CurrentPhase)
	}
	if !state.ModelImported || !state.DataImported {
		t.Fatalf("switching to phase 2 should not reset imported flags: model=%v data=%v",
			state.ModelImported, state.DataImported)
	}

	// 3. 从阶段2切回阶段1：必须重置 ModelImported 与 DataImported 为 false
	resp = postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 1})
	api = decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("switch to phase 1 failed: %d / %s", resp.StatusCode, api.Msg)
	}
	if state.CurrentPhase != 1 {
		t.Fatalf("expected phase 1, got %d", state.CurrentPhase)
	}
	if state.ModelImported {
		t.Fatalf("expected ModelImported=false after switching back to phase 1, got true")
	}
	if state.DataImported {
		t.Fatalf("expected DataImported=false after switching back to phase 1, got true")
	}
	if state.Phase1TrainingStarted {
		t.Fatalf("expected Phase1TrainingStarted=false after switching back to phase 1, got true")
	}

	// 4. 再次模拟导入，然后从阶段3切回阶段1，同样验证重置
	state.mu.Lock()
	state.CurrentPhase = 3
	state.ModelImported = true
	state.DataImported = true
	state.Phase1TrainingStarted = true
	state.mu.Unlock()

	resp = postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 1})
	api = decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("switch from phase 3 to phase 1 failed: %d / %s", resp.StatusCode, api.Msg)
	}
	if state.ModelImported || state.DataImported || state.Phase1TrainingStarted {
		t.Fatalf("expected flags reset after switching from phase 3 to phase 1: model=%v data=%v started=%v",
			state.ModelImported, state.DataImported, state.Phase1TrainingStarted)
	}
}

func TestPhase1ReimportWorkflow_ModelFirstEmptyURLThenData(t *testing.T) {
	state, server := setupTestServer(t)

	platformReportCh := make(chan importedReportPayload, 2)
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
	state.CurrentPhase = 1
	state.DockerID = "docker-reimport-test"
	state.PlatformIP = platformServer.URL
	state.mu.Unlock()

	// 准备模型与数据资源文件
	modelTar := buildTarGzArchive(t, map[string]archiveEntry{
		"train.py": {
			mode: 0o755,
			data: []byte("#!/usr/bin/env python3\n" +
				"from argparse import ArgumentParser\n" +
				"from pathlib import Path\n" +
				"import json\n" +
				"parser = ArgumentParser(add_help=False)\n" +
				"parser.add_argument('--data-dir', dest='data_dir', required=True)\n" +
				"parser.add_argument('--output', '-o', dest='output_dir', required=True)\n" +
				"parser.add_argument('--tag', dest='tag', default='default')\n" +
				"args, _ = parser.parse_known_args()\n" +
				"out = Path(args.output_dir)\n" +
				"out.mkdir(parents=True, exist_ok=True)\n" +
				"(out / 'tag.txt').write_text(args.tag + '\\n')\n" +
				"(out / 'training_result.json').write_text(json.dumps({'dataset': {'total_samples': 1}}, indent=2) + '\\n')\n"),
		},
	})

	data1Tar := buildTarGzArchive(t, map[string]archiveEntry{
		"data/sample.txt": {mode: 0o644, data: []byte("sample1\n")},
	})
	data2Tar := buildTarGzArchive(t, map[string]archiveEntry{
		"data/sample.txt": {mode: 0o644, data: []byte("sample2\n")},
	})

	resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		switch r.URL.Path {
		case "/model.tar.gz":
			_, _ = w.Write(modelTar)
		case "/data1.tar.gz":
			_, _ = w.Write(data1Tar)
		case "/data2.tar.gz":
			_, _ = w.Write(data2Tar)
		default:
			http.NotFound(w, r)
		}
	}))
	defer resourceServer.Close()

	// ── 轮次1：首次阶段1正常训练 ──
	modelResp1 := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   resourceServer.URL + "/model.tar.gz",
		"requestId":     "req-m-1",
		"taskId":        "task-1",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3 train.py --data-dir <in> --output <out> --tag run1"}, nil),
	})
	apiM1 := decodeResponse(t, modelResp1)
	if modelResp1.StatusCode != http.StatusOK || apiM1.Error != 0 {
		t.Fatalf("import model 1 failed: %d / %s", modelResp1.StatusCode, apiM1.Msg)
	}

	dataResp1 := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceServer.URL + "/data1.tar.gz",
		"requestId":   "req-d-1",
		"taskId":      "task-1",
	})
	apiD1 := decodeResponse(t, dataResp1)
	if dataResp1.StatusCode != http.StatusOK || apiD1.Error != 0 {
		t.Fatalf("import data 1 failed: %d / %s", dataResp1.StatusCode, apiD1.Msg)
	}

	select {
	case p := <-platformReportCh:
		if p.Code != 0 {
			t.Fatalf("run 1 failed: code=%d msg=%v", p.Code, p.Msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for run 1 report")
	}

	waitForIdle(t, state)

	// ── 轮次2：切换到阶段2，然后切回阶段1 ──
	respSwitch2 := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 2})
	decodeResponse(t, respSwitch2)
	respSwitch1 := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 1})
	decodeResponse(t, respSwitch1)

	if state.ModelImported || state.DataImported {
		t.Fatalf("expected ModelImported and DataImported reset to false: model=%v data=%v",
			state.ModelImported, state.DataImported)
	}

	// ── 轮次3：模型方重新下发模型import，url 为空，传入新参数命令 ──
	modelResp2 := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   "",
		"requestId":     "req-m-2",
		"taskId":        "task-2",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3 train.py --data-dir <in> --output <out> --tag run2-reused"}, nil),
	})
	apiM2 := decodeResponse(t, modelResp2)
	if modelResp2.StatusCode != http.StatusOK || apiM2.Error != 0 {
		t.Fatalf("import model empty url failed: %d / %s", modelResp2.StatusCode, apiM2.Msg)
	}
	if !strings.Contains(apiM2.Msg, "等待数据") {
		t.Fatalf("expected waiting for data message, got: %q", apiM2.Msg)
	}

	// 验证 ModelImported=true, DataImported=false，训练尚未触发
	if !state.ModelImported {
		t.Fatal("expected ModelImported=true after empty url model import")
	}
	if state.DataImported {
		t.Fatal("expected DataImported=false before data reimport")
	}

	select {
	case p := <-platformReportCh:
		t.Fatalf("unexpected report received before data was imported: %+v", p)
	case <-time.After(200 * time.Millisecond):
		// 预期无上报
	}

	// ── 轮次4：数据方重新导入数据 ──
	dataResp2 := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceServer.URL + "/data2.tar.gz",
		"requestId":   "req-d-2",
		"taskId":      "task-2",
	})
	apiD2 := decodeResponse(t, dataResp2)
	if dataResp2.StatusCode != http.StatusOK || apiD2.Error != 0 {
		t.Fatalf("import data 2 failed: %d / %s", dataResp2.StatusCode, apiD2.Msg)
	}

	// 此时双方就绪，训练触发并执行
	select {
	case p := <-platformReportCh:
		if p.Code != 0 {
			t.Fatalf("run 2 report code=%d msg=%v", p.Code, p.Msg)
		}
		if p.TaskID != "task-2" {
			t.Fatalf("run 2 taskId = %q, want task-2", p.TaskID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for run 2 report after data reimported")
	}

	waitForIdle(t, state)

	// 校验产物内容来自于空 url 更新后的新命令 run2-reused
	resultDir := resultDirForRequestTask(state.Security.ResultDir, "req-d-2", "task-2")
	tagData, err := os.ReadFile(filepath.Join(resultDir, "tag.txt"))
	if err != nil {
		t.Fatalf("read tag.txt: %v", err)
	}
	if string(tagData) != "run2-reused\n" {
		t.Fatalf("tag content = %q, want 'run2-reused\\n'", string(tagData))
	}
}

func TestPhase1ReimportWorkflow_DataFirstThenModelEmptyURL(t *testing.T) {
	state, server := setupTestServer(t)

	platformReportCh := make(chan importedReportPayload, 2)
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
	state.CurrentPhase = 1
	state.DockerID = "docker-reverse-reimport-test"
	state.PlatformIP = platformServer.URL
	state.mu.Unlock()

	modelTar := buildTarGzArchive(t, map[string]archiveEntry{
		"train.py": {
			mode: 0o755,
			data: []byte("#!/usr/bin/env python3\n" +
				"from argparse import ArgumentParser\n" +
				"from pathlib import Path\n" +
				"import json\n" +
				"parser = ArgumentParser(add_help=False)\n" +
				"parser.add_argument('--data-dir', dest='data_dir', required=True)\n" +
				"parser.add_argument('--output', '-o', dest='output_dir', required=True)\n" +
				"parser.add_argument('--tag', dest='tag', default='default')\n" +
				"args, _ = parser.parse_known_args()\n" +
				"out = Path(args.output_dir)\n" +
				"out.mkdir(parents=True, exist_ok=True)\n" +
				"(out / 'tag.txt').write_text(args.tag + '\\n')\n" +
				"(out / 'training_result.json').write_text(json.dumps({'dataset': {'total_samples': 1}}, indent=2) + '\\n')\n"),
		},
	})

	dataTar := buildTarGzArchive(t, map[string]archiveEntry{
		"data/sample.txt": {mode: 0o644, data: []byte("sample\n")},
	})

	resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		switch r.URL.Path {
		case "/model.tar.gz":
			_, _ = w.Write(modelTar)
		case "/data.tar.gz":
			_, _ = w.Write(dataTar)
		default:
			http.NotFound(w, r)
		}
	}))
	defer resourceServer.Close()

	// 首次导入模型（留存模型文件和 SavedModelResourceURL）
	respM0 := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   resourceServer.URL + "/model.tar.gz",
		"requestId":     "req-m-0",
		"taskId":        "task-0",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3 train.py --data-dir <in> --output <out> --tag run0"}, nil),
	})
	if respM0.StatusCode != http.StatusOK {
		t.Fatalf("import model failed: %d", respM0.StatusCode)
	}
	waitForIdle(t, state)

	// 切去阶段2并切回阶段1，触发重置
	postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 2})
	postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 1})

	if state.ModelImported || state.DataImported {
		t.Fatalf("expected reset flags: model=%v data=%v", state.ModelImported, state.DataImported)
	}

	// 顺序：数据先重新导入
	respD := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceServer.URL + "/data.tar.gz",
		"requestId":   "req-d-rev",
		"taskId":      "task-rev",
	})
	if respD.StatusCode != http.StatusOK {
		t.Fatalf("import data failed: %d", respD.StatusCode)
	}

	waitForIdle(t, state)

	if !state.DataImported {
		t.Fatal("expected DataImported=true after data import")
	}
	if state.ModelImported {
		t.Fatal("expected ModelImported=false before model reimport")
	}

	select {
	case p := <-platformReportCh:
		t.Fatalf("unexpected report before model import: %+v", p)
	case <-time.After(200 * time.Millisecond):
	}

	// 模型方下发空 url 模型导入，更新命令
	respM := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   "",
		"requestId":     "req-m-rev",
		"taskId":        "task-rev",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3 train.py --data-dir <in> --output <out> --tag run-rev-ok"}, nil),
	})
	if respM.StatusCode != http.StatusOK {
		t.Fatalf("import model empty url failed: %d", respM.StatusCode)
	}

	// 双方均已就绪，触发训练
	select {
	case p := <-platformReportCh:
		if p.Code != 0 {
			t.Fatalf("report failed: code=%d msg=%v", p.Code, p.Msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for report")
	}

	waitForIdle(t, state)

	resultDir := resultDirForRequestTask(state.Security.ResultDir, "req-m-rev", "task-rev")
	tagData, err := os.ReadFile(filepath.Join(resultDir, "tag.txt"))
	if err != nil {
		t.Fatalf("read tag.txt: %v", err)
	}
	if string(tagData) != "run-rev-ok\n" {
		t.Fatalf("tag content = %q, want 'run-rev-ok\\n'", string(tagData))
	}
}
