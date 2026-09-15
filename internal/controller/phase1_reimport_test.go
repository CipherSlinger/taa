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

// TestSwitchPreservesModelImported 验证无论在哪个阶段间切换，ModelImported 都不会被重置
func TestSwitchPreservesModelImported(t *testing.T) {
	state, server := setupTestServer(t)

	// 1. 模拟模型已导入
	state.mu.Lock()
	state.CurrentPhase = 1
	state.ModelImported = true
	state.mu.Unlock()

	// 2. 切换到阶段2：ModelImported 保持为 true
	resp := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 2})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("switch to phase 2 failed: %d / %s", resp.StatusCode, api.Msg)
	}
	if state.CurrentPhase != 2 {
		t.Fatalf("expected phase 2, got %d", state.CurrentPhase)
	}
	if !state.ModelImported {
		t.Fatalf("expected ModelImported=true after switching to phase 2")
	}

	// 3. 从阶段2切回阶段1：ModelImported 依然保持为 true（阶段切换不重置 ModelImported）
	resp = postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 1})
	api = decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("switch to phase 1 failed: %d / %s", resp.StatusCode, api.Msg)
	}
	if state.CurrentPhase != 1 {
		t.Fatalf("expected phase 1, got %d", state.CurrentPhase)
	}
	if !state.ModelImported {
		t.Fatalf("expected ModelImported=true after switching back to phase 1, got false")
	}

	// 4. 从阶段1切到阶段3，再切回阶段1：同样必须保持为 true
	resp = postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 3})
	decodeResponse(t, resp)
	resp = postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 1})
	decodeResponse(t, resp)
	if !state.ModelImported {
		t.Fatalf("expected ModelImported=true after switching from phase 3 to phase 1, got false")
	}
}

// TestRepeatedTrainingAcrossPhases 验证不管在哪个阶段均可重复跑训练任务，
// 训练完成后马上重置训练状态；数据下发检测到模型已下发即自动执行训练。
func TestRepeatedTrainingAcrossPhases(t *testing.T) {
	state, server := setupTestServer(t)

	platformReportCh := make(chan importedReportPayload, 10)
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
	state.DockerID = "docker-repeat-test"
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

	// ── 轮次1：阶段1中下发模型，然后下发数据1，触发训练1 ──
	modelResp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   resourceServer.URL + "/model.tar.gz",
		"requestId":     "req-m-1",
		"taskId":        "task-1",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3 train.py --data-dir <in> --output <out> --tag run1"}, nil),
	})
	apiM := decodeResponse(t, modelResp)
	if modelResp.StatusCode != http.StatusOK || apiM.Error != 0 {
		t.Fatalf("import model failed: %d / %s", modelResp.StatusCode, apiM.Msg)
	}

	// 校验非空 URL 请求下发后，ModelImported 立即为 true
	if !state.ModelImported {
		t.Fatalf("expected ModelImported=true immediately after receiving model request")
	}

	dataResp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceServer.URL + "/data1.tar.gz",
		"requestId":   "req-d-1",
		"taskId":      "task-1",
	})
	apiD := decodeResponse(t, dataResp)
	if dataResp.StatusCode != http.StatusOK || apiD.Error != 0 {
		t.Fatalf("import data 1 failed: %d / %s", dataResp.StatusCode, apiD.Msg)
	}

	select {
	case p := <-platformReportCh:
		if p.Code != 0 || p.TaskID != "task-1" {
			t.Fatalf("run 1 failed: %+v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for run 1 report")
	}

	waitForIdle(t, state)

	// 训练完成后状态必须立刻重置为 false
	state.mu.RLock()
	if state.TrainingRunning {
		t.Fatalf("expected TrainingRunning=false after training finished")
	}
	state.mu.RUnlock()

	// ── 轮次2：同在阶段1（不切换阶段），直接下发数据2，自动重复执行训练2 ──
	dataResp2 := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceServer.URL + "/data2.tar.gz",
		"requestId":   "req-d-2",
		"taskId":      "task-2",
	})
	apiD2 := decodeResponse(t, dataResp2)
	if dataResp2.StatusCode != http.StatusOK || apiD2.Error != 0 {
		t.Fatalf("import data 2 failed: %d / %s", dataResp2.StatusCode, apiD2.Msg)
	}

	select {
	case p := <-platformReportCh:
		if p.Code != 0 || p.TaskID != "task-2" {
			t.Fatalf("run 2 failed: %+v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for run 2 report")
	}

	waitForIdle(t, state)

	// ── 轮次3：切换到阶段2，再次下发数据，验证阶段2中也可重复跑训练 ──
	respSwitch := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 2})
	if respSwitch.StatusCode != http.StatusOK {
		t.Fatalf("switch to phase 2 failed: %d", respSwitch.StatusCode)
	}

	if !state.ModelImported {
		t.Fatalf("ModelImported should remain true in phase 2")
	}

	dataResp3 := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceServer.URL + "/data1.tar.gz",
		"requestId":   "req-d-3",
		"taskId":      "task-3",
	})
	if dataResp3.StatusCode != http.StatusOK {
		t.Fatalf("import data 3 failed: %d", dataResp3.StatusCode)
	}

	select {
	case p := <-platformReportCh:
		if p.Code != 0 || p.TaskID != "task-3" {
			t.Fatalf("run 3 failed: %+v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for run 3 report in phase 2")
	}

	waitForIdle(t, state)

	// ── 轮次4：切回阶段1，使用空 URL 复用模型更新 runtimeConfig，然后通过下发数据触发训练 ──
	respSwitch1 := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 1})
	if respSwitch1.StatusCode != http.StatusOK {
		t.Fatalf("switch back to phase 1 failed: %d", respSwitch1.StatusCode)
	}

	modelReuseResp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   "",
		"requestId":     "req-m-4",
		"taskId":        "task-4",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3 train.py --data-dir <in> --output <out> --tag reused-tag"}, nil),
	})
	if modelReuseResp.StatusCode != http.StatusOK {
		t.Fatalf("model reuse in phase 1 failed: %d", modelReuseResp.StatusCode)
	}

	// 空 URL 仅更新配置，不应触发训练
	select {
	case p := <-platformReportCh:
		t.Fatalf("unexpected training report triggered by empty url model import: %+v", p)
	case <-time.After(300 * time.Millisecond):
	}

	// 下发数据以触发训练
	dataResp4 := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceServer.URL + "/data1.tar.gz",
		"requestId":   "req-d-4",
		"taskId":      "task-4",
	})
	if dataResp4.StatusCode != http.StatusOK {
		t.Fatalf("import data 4 failed: %d", dataResp4.StatusCode)
	}

	select {
	case p := <-platformReportCh:
		if p.Code != 0 || p.TaskID != "task-4" {
			t.Fatalf("run 4 failed: %+v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for run 4 report")
	}

	waitForIdle(t, state)

	resultDir := resultDirForRequestTask(state.Security.ResultDir, "req-d-4", "task-4")
	tagData, err := os.ReadFile(filepath.Join(resultDir, "tag.txt"))
	if err != nil {
		t.Fatalf("read tag.txt: %v", err)
	}
	if string(tagData) != "reused-tag\n" {
		t.Fatalf("tag content = %q, want 'reused-tag\\n'", string(tagData))
	}
}

// TestTrainingRunningRejectsConcurrentExecution 验证无论在哪个阶段，
// 当有正在跑的训练任务时，任何新任务下发都会被 409 拦截拒绝。
func TestTrainingRunningRejectsConcurrentExecution(t *testing.T) {
	state, server := setupTestServer(t)

	for _, phase := range []int{1, 2, 3, 4} {
		state.mu.Lock()
		state.CurrentPhase = phase
		state.TrainingRunning = true
		state.ActiveTaskID = "task-training-busy"
		state.CurrentOp = "training"
		state.mu.Unlock()

		// 尝试下发数据任务，必须被 409 拒绝
		resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
			"resourceUrl": "http://127.0.0.1:9999/data.tar.gz",
			"requestId":   "req-concurrent",
			"taskId":      "task-concurrent",
		})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusConflict || api.Error != http.StatusConflict {
			t.Fatalf("phase %d: expected 409 when training busy, got status=%d error=%d",
				phase, resp.StatusCode, api.Error)
		}
		if !strings.Contains(api.Msg, "当前已有训练任务正在执行中") {
			t.Fatalf("phase %d: unexpected message: %s", phase, api.Msg)
		}

		// 尝试下发模型任务，同样必须被 409 拒绝
		respM := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
			"resourceUrl": "http://127.0.0.1:9999/model.tar.gz",
			"requestId":   "req-concurrent-m",
			"taskId":      "task-concurrent-m",
		})
		apiM := decodeResponse(t, respM)
		if respM.StatusCode != http.StatusConflict || apiM.Error != http.StatusConflict {
			t.Fatalf("phase %d: expected 409 for importModel when training busy, got status=%d",
				phase, respM.StatusCode)
		}

		// 恢复状态
		state.mu.Lock()
		state.TrainingRunning = false
		state.ActiveTaskID = ""
		state.CurrentOp = "idle"
		state.mu.Unlock()
	}
}

// TestModelImportDoesNotTriggerTraining_OnlyDataImportTriggersTraining 验证：
// 1. 重复下发模型（带URL）或空URL（纯 runtimeConfig）时，绝不会触发训练任务；
// 2. 只有下发数据时，才会做前置检查并触发训练任务。
func TestModelImportDoesNotTriggerTraining_OnlyDataImportTriggersTraining(t *testing.T) {
	state, server := setupTestServer(t)

	trainingReportCh := make(chan importedReportPayload, 5)
	modelReportCh := make(chan importedReportPayload, 5)

	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload importedReportPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		switch r.URL.Path {
		case reportResEndpoint:
			trainingReportCh <- payload
		case reportModelImportEndpoint:
			modelReportCh <- payload
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platformServer.Close()

	state.mu.Lock()
	state.CurrentPhase = 1
	state.DockerID = "docker-data-driven-test"
	state.PlatformIP = platformServer.URL
	state.Security.ScanEnabled = true
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
		"data/sample.txt": {mode: 0o644, data: []byte("sample-data\n")},
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

	// ── 步骤 1：先下发数据，此时模型尚未就绪，绝不触发训练 ──
	respData1 := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceServer.URL + "/data.tar.gz",
		"requestId":   "req-data-1",
		"taskId":      "task-data-1",
	})
	if respData1.StatusCode != http.StatusOK {
		t.Fatalf("import data 1 failed: %d", respData1.StatusCode)
	}
	waitForIdle(t, state)

	// 确认��任何训练上报
	select {
	case p := <-trainingReportCh:
		t.Fatalf("unexpected training report triggered by data when model not imported: %+v", p)
	case <-time.After(300 * time.Millisecond):
	}

	// ── 步骤 2：下发模型（带 URL），即使本地已有数据，也绝不触发训练 ──
	respModel := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   resourceServer.URL + "/model.tar.gz",
		"requestId":     "req-model-1",
		"taskId":        "task-model-1",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3 train.py --data-dir <in> --output <out> --tag v1"}, nil),
	})
	if respModel.StatusCode != http.StatusOK {
		t.Fatalf("import model failed: %d", respModel.StatusCode)
	}
	waitForIdle(t, state)

	// 收到模型导入回调
	select {
	case m := <-modelReportCh:
		if m.Code != 0 {
			t.Fatalf("model import failed: %+v", m)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for model import report")
	}

	// 确认下发模型绝不触发训练！
	select {
	case p := <-trainingReportCh:
		t.Fatalf("unexpected training report triggered by importModel: %+v", p)
	case <-time.After(500 * time.Millisecond):
	}

	// ── 步骤 3：重复下发空 URL 模型（纯更新 runtimeConfig），也绝不触发训练 ──
	respModelEmpty := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   "",
		"requestId":     "req-model-empty",
		"taskId":        "task-model-empty",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3 train.py --data-dir <in> --output <out> --tag v2-updated"}, nil),
	})
	if respModelEmpty.StatusCode != http.StatusOK {
		t.Fatalf("import model empty url failed: %d", respModelEmpty.StatusCode)
	}
	waitForIdle(t, state)

	// 确认空 URL 更新配置绝不触发训练！
	select {
	case p := <-trainingReportCh:
		t.Fatalf("unexpected training report triggered by empty url importModel: %+v", p)
	case <-time.After(500 * time.Millisecond):
	}

	// ── 步骤 4：下发数据（触发训练的唯一时刻），此时前置条件满足，触发训练 ──
	respData2 := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceServer.URL + "/data.tar.gz",
		"requestId":   "req-data-trigger",
		"taskId":      "task-data-trigger",
	})
	if respData2.StatusCode != http.StatusOK {
		t.Fatalf("import data trigger failed: %d", respData2.StatusCode)
	}

	// 此时应成功收到训练上报
	select {
	case p := <-trainingReportCh:
		if p.Code != 0 || p.TaskID != "task-data-trigger" {
			t.Fatalf("training report failed or wrong task: %+v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for training report triggered by data import")
	}

	waitForIdle(t, state)

	// 校验产物生效的是空 URL 更新后的 v2-updated 配置
	resultDir := resultDirForRequestTask(state.Security.ResultDir, "req-data-trigger", "task-data-trigger")
	tagData, err := os.ReadFile(filepath.Join(resultDir, "tag.txt"))
	if err != nil {
		t.Fatalf("read tag.txt: %v", err)
	}
	if string(tagData) != "v2-updated\n" {
		t.Fatalf("tag content = %q, want 'v2-updated\\n'", string(tagData))
	}
}
