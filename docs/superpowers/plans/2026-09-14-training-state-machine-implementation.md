# TAA 训练状态与导入触发逻辑重构 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 删除所有数据导入完成和历史训练完成状态，使用 `ModelImported` 表示模型可用、`TrainingRunning` 表示实时训练独占状态，并使任意阶段都能在无并发训练时重复执行训练。

**Architecture:** 保留现有 `TAAState`、`ActiveTaskSnapshot`、导入索引和崩溃恢复框架。数据导入只负责持久化最新数据索引；模型请求的非空 URL 在通过基础校验并取得任务执行权后立即置位 `ModelImported`，异步处理失败时回滚。训练触发统一通过“是否存在模型 + 是否存在最新数据 + `TrainingRunning` 是否为 false”判断，不再读取阶段专用标志。

**Tech Stack:** Go 1.26、标准库 `net/http`/`encoding/json`/`sync`、现有 SM4 密封状态存储、Go `testing`。

---

## 文件结构与职责映射

- Modify: `internal/controller/route.go`
  - 删除 `DataImported`、`TrainingDataImported`、`TrainingDone`、`Phase1TrainingStarted` 字段及其读写；
  - 增加 `TrainingRunning`；
  - 调整状态密封/恢复、health/status 返回、阶段切换、模型/数据 handler 和任务抢占逻辑；
  - 提供统一训练任务占用与释放接口。
- Modify: `internal/controller/state_store.go`
  - 从 `PersistentState` 删除三个历史/数据完成字段；
  - 增加 `TrainingRunning`，并将状态版本提升为 `1.4`。
- Modify: `internal/controller/import_processing.go`
  - 删除数据完成标志和阶段 1 专用训练门控；
  - 统一模型/数据完成后的训练触发；
  - 确保训练成功、失败、报告错误和 panic 都释放 `TrainingRunning`。
- Modify: `internal/app/taa/recovery.go`
  - 删除对已移除数据标志的间接依赖；
  - 崩溃恢复完成后清除 `TrainingRunning` 并密封状态。
- Modify: `internal/controller/*_test.go`
  - 删除旧字段断言，增加字段删除、状态接口、跨阶段训练、训练释放和并发拒绝测试。
- Create: `docs/superpowers/plans/2026-09-14-training-state-machine-implementation.md`
  - 本实现计划；不覆盖已有未提交的 `TODO` 和审计页面修改。

---

### Task 1: 重写状态结构、密封持久化和状态 API

**Files:**
- Modify: `internal/controller/route.go:84-119,160-252,254-317,621-705`
- Modify: `internal/controller/state_store.go:16-36,195-205`
- Test: `internal/controller/state_store_test.go`
- Test: `internal/controller/taa_state_store_integration_test.go`
- Test: `internal/controller/route_test.go`

- [ ] **Step 1: Add failing state-shape tests**

在 `internal/controller/state_store_test.go` 增加测试，直接序列化一个新状态并检查字段集合：

```go
func TestPersistentStateOmitsRemovedFlags(t *testing.T) {
	state := PersistentState{
		Version:         "1.4",
		CurrentPhase:    2,
		ModelImported:   true,
		TrainingRunning: true,
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	encoded := string(data)
	for _, field := range []string{"dataImported", "trainingDataImported", "trainingDone"} {
		if strings.Contains(encoded, field) {
			t.Fatalf("serialized state contains removed field %q: %s", field, encoded)
		}
	}
	if !strings.Contains(encoded, `"trainingRunning":true`) {
		t.Fatalf("serialized state does not contain trainingRunning: %s", encoded)
	}
}
```

在 `internal/controller/route_test.go` 增加状态响应断言：

```go
func TestStatusOmitsRemovedFlagsAndReportsTrainingRunning(t *testing.T) {
	state, server := setupTestServer(t)
	state.mu.Lock()
	state.ModelImported = true
	state.TrainingRunning = true
	state.mu.Unlock()

	resp := postEmptyJSON(t, server.URL+"/v1/taa/status")
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("status request failed: %d / %s", resp.StatusCode, api.Msg)
	}
	result, ok := api.Result.(map[string]any)
	if !ok {
		t.Fatalf("status result type = %T", api.Result)
	}
	if result["dataImported"] != nil || result["trainingDataImported"] != nil || result["trainingDone"] != nil {
		t.Fatalf("status contains removed fields: %#v", result)
	}
	if result["trainingRunning"] != true {
		t.Fatalf("trainingRunning = %#v, want true", result["trainingRunning"])
	}
}
```

- [ ] **Step 2: Run the focused tests and verify they fail to compile**

Run:

```bash
/usr/local/go/bin/go test ./internal/controller -run 'TestPersistentStateOmitsRemovedFlags|TestStatusOmitsRemovedFlagsAndReportsTrainingRunning' -count=1
```

Expected: compilation failure because `TrainingRunning` does not exist and the current status response still exposes removed fields.

- [ ] **Step 3: Change the state structs and state-version constant**

In `internal/controller/route.go`, change the state fields to:

```go
ModelImported   bool
TrainingRunning bool
```

and remove `DataImported`, `TrainingDone`, and `Phase1TrainingStarted`. In `internal/controller/state_store.go`, change `DefaultStateVersion` to `"1.4"`, remove `DataImported`, `TrainingDataImported`, and `TrainingDone` from `PersistentState`, and add:

```go
TrainingRunning bool `json:"trainingRunning"`
```

Do not add migration code for removed JSON keys: `encoding/json` already ignores unknown keys when loading old state data, and the next sealed write emits only the new structure.

- [ ] **Step 4: Update state restore and seal projections**

In `RestoreFromPersistentState` and `sealStateLocked`, copy `TrainingRunning` and stop copying the three removed fields:

```go
s.ModelImported = p.ModelImported
s.TrainingRunning = p.TrainingRunning
```

and:

```go
state.ModelImported = s.ModelImported
state.TrainingRunning = s.TrainingRunning
```

Keep `CurrentPhase`, `ExportPublicKey`, `SavedModelResourceURL`, `RuntimeConfig`, checksums and `ActiveTask` unchanged.

- [ ] **Step 5: Update health and status responses**

Remove `dataImported`, `trainingDataImported`, and `trainingDone` local reads and response keys. Add `trainingRunning` to both response maps:

```go
writeEnvelope(w, http.StatusOK, "ok", map[string]any{
	"phase":          phase,
	"phaseName":      phaseName(phase),
	"modelImported":  modelImported,
	"trainingRunning": trainingRunning,
	"currentOp":      currentOp,
}, 0)
```

Preserve the existing response envelope and all unrelated fields.

- [ ] **Step 6: Replace import-state helper behavior**

Remove `saveDataSuccess`’s writes to `DataImported` and `TrainingDataImported`; it must only update `LatestDataRecord` and `CurrentDataRecord`, then seal the state. Keep data failure cleanup by making `updateImportState` clear `CurrentDataRecord` without writing any data-completion flag:

```go
func (s *TAAState) updateImportState(isModel bool, imported bool, phase int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isModel {
		s.ModelImported = imported
		if !imported {
			s.SavedModelResourceURL = ""
			s.RuntimeConfig = ""
		}
	} else if !imported {
		s.CurrentDataRecord = ImportIndexRecord{}
	}
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化导入状态失败: %v", err)
	}
}
```

Update callers so model recovery uses the model branch and data failure uses only the record-cleanup branch; no caller may write a replacement data-completion flag.

- [ ] **Step 7: Run focused state tests and format modified files**

Run:

```bash
gofmt -w internal/controller/route.go internal/controller/state_store.go internal/controller/state_store_test.go internal/controller/taa_state_store_integration_test.go internal/controller/route_test.go
/usr/local/go/bin/go test ./internal/controller -run 'TestPersistentStateOmitsRemovedFlags|TestStatusOmitsRemovedFlagsAndReportsTrainingRunning' -count=1
```

Expected: the new tests pass; existing tests that reference removed fields may still fail to compile and are handled in later tasks.

- [ ] **Step 8: Commit the state-model change**

```bash
git add internal/controller/route.go internal/controller/state_store.go internal/controller/state_store_test.go internal/controller/taa_state_store_integration_test.go internal/controller/route_test.go
git commit -m "refactor(controller): 重构训练状态持久化模型"
```

Do not stage unrelated existing changes in `TODO` or `models/audit/research/taa-audit-design.html`.

---

### Task 2: 调整模型和数据导入的训练触发逻辑

**Files:**
- Modify: `internal/controller/route.go:707-805,959-1031,1033-1193`
- Modify: `internal/controller/import_processing.go:29-196,537-558`
- Test: `internal/controller/phase1_reimport_test.go`
- Test: `internal/controller/import_param_validation_test.go`
- Test: `internal/controller/import_flow_new_test.go`

- [ ] **Step 1: Replace old phase-gated tests with model/data ordering tests**

Rewrite the old assertions in `phase1_reimport_test.go` so they verify that phase transitions preserve `ModelImported`:

```go
func TestSwitchPreservesModelImportedAcrossAllPhases(t *testing.T) {
	state, server := setupTestServer(t)
	state.mu.Lock()
	state.CurrentPhase = 1
	state.ModelImported = true
	state.mu.Unlock()

	for _, phase := range []int{2, 3, 4, 1} {
		resp := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": phase})
		api := decodeResponse(t, resp)
		if resp.StatusCode != http.StatusOK || api.Error != 0 {
			t.Fatalf("switch to phase %d failed: %d / %s", phase, resp.StatusCode, api.Msg)
		}
		if !state.ModelImported {
			t.Fatalf("ModelImported reset while switching to phase %d", phase)
		}
	}
}
```

Add ordering coverage using the existing test HTTP fixtures: data-first must persist the latest index without starting training when no model exists; once `ModelImported` is true, the next data request must be eligible to start training. Model-first with an existing latest index must trigger training after model processing succeeds.

- [ ] **Step 2: Run the focused import tests to capture old behavior**

Run:

```bash
/usr/local/go/bin/go test ./internal/controller -run 'TestSwitchPreservesModelImportedAcrossAllPhases|TestPhase1ReimportWorkflow|TestImportModel' -count=1
```

Expected: old phase-switch test fails because current code resets model/data flags when returning to phase 1, and old phase-1 gating tests fail after the new expectations are installed.

- [ ] **Step 3: Remove phase-reset behavior**

In `switchHandler`, retain phase assignment and active-task cleanup, but remove all writes to the removed fields and do not reset `ModelImported`:

```go
current := s.CurrentPhase
s.CurrentPhase = req.Phase
s.activeToken = 0
s.ActiveTaskID = ""
s.ActiveRequestID = ""
s.activeTask = nil
```

The handler may continue to reset no historical training-start flag because `Phase1TrainingStarted` is deleted. Keep the existing conflict response while a real training task is running.

- [ ] **Step 4: Set ModelImported immediately for accepted non-empty model URLs**

In `modelImportHandler`, after the non-empty URL request has passed request-ID validation and `tryAcquireTask` succeeds, set and seal the model flag before starting the download:

```go
release, err := s.tryAcquireTask(req.TaskID, req.RequestID, "downloading", true)
if err != nil {
	...
}

s.mu.Lock()
s.ModelImported = true
if err := s.sealStateLocked(); err != nil {
	s.Logs.Add(LogError, "state", "持久化模型请求状态失败: %v", err)
}
s.mu.Unlock()
s.setSavedModelResourceURL(req.ResourceURL)
```

If download or asynchronous processing fails, call the model failure path so `ModelImported` returns to `false`. An HTTP request rejected by validation or training concurrency must not set the flag.

- [ ] **Step 5: Replace `processImportedResource` phase 1 gate**

After model or data processing succeeds, use a shared readiness check:

```go
modelReady := func() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ModelImported
}
```

For data imports:

- always commit the index and update latest/current data records;
- if `ModelImported` is false, set the operation idle and return with no training;
- if `ModelImported` is true, continue to resolve the latest record and start training.

For model imports:

- after audit success, keep `ModelImported` true;
- resolve the latest data record regardless of phase;
- if no data record exists, set idle and return, leaving the model available for a future data request;
- if data exists, parse the saved runtime configuration and start training.

Remove the `phase == 1` branches, the `DataImported` reads, the `Phase1TrainingStarted` reads/writes, and the “wait for data reimport” response. Keep the existing empty-URL model reuse path, but make it use `ModelImported` plus latest data rather than `DataImported`.

- [ ] **Step 6: Keep data records as the only data readiness source**

Do not add another data completion flag. `getLatestDataRecord()` and the import index remain the source of truth for whether there is data available to train. Keep `CurrentDataRecord` cleanup on data failure, but remove the phase switch that writes `TrainingDataImported`.

- [ ] **Step 7: Run ordering tests and format files**

Run:

```bash
gofmt -w internal/controller/route.go internal/controller/import_processing.go internal/controller/phase1_reimport_test.go internal/controller/import_param_validation_test.go internal/controller/import_flow_new_test.go
/usr/local/go/bin/go test ./internal/controller -run 'TestSwitchPreservesModelImportedAcrossAllPhases|TestPhase1ReimportWorkflow|TestImportModel' -count=1
```

Expected: model preservation and model/data ordering tests pass. Any failures must identify a stale phase-specific assertion or an incorrect trigger path before proceeding.

- [ ] **Step 8: Commit the import-trigger change**

```bash
git add internal/controller/route.go internal/controller/import_processing.go internal/controller/phase1_reimport_test.go internal/controller/import_param_validation_test.go internal/controller/import_flow_new_test.go
git commit -m "feat(controller): 按模型就绪状态触发训练"
```

---

### Task 3: Implement real training exclusivity with TrainingRunning

**Files:**
- Modify: `internal/controller/route.go:695-821,1035-1203`
- Modify: `internal/controller/import_processing.go:29-348,541-558`
- Test: `internal/controller/concurrency_test.go`
- Test: `internal/controller/route_test.go`

- [ ] **Step 1: Add failing concurrency and lifecycle tests**

在 `internal/controller/concurrency_test.go` 增加直接测试，覆盖四个阶段、同阶段串行重跑和同一 ActiveTask 从导入提升为训练：

```go
func TestTrainingRunningRejectsConcurrentTrainingInEveryPhase(t *testing.T) {
	state, _ := setupTestServer(t)
	for _, phase := range []int{1, 2, 3, 4} {
		state.mu.Lock()
		state.CurrentPhase = phase
		state.TrainingRunning = false
		state.mu.Unlock()

		release, err := state.tryAcquireTask("task-first", "req-first", "training", false)
		if err != nil {
			t.Fatalf("phase %d first acquire failed: %v", phase, err)
		}
		if !state.TrainingRunning {
			t.Fatalf("phase %d TrainingRunning=false after acquire", phase)
		}
		if _, err := state.tryAcquireTask("task-second", "req-second", "training", false); err == nil {
			t.Fatalf("phase %d concurrent acquire unexpectedly succeeded", phase)
		}
		release()
		if state.TrainingRunning {
			t.Fatalf("phase %d TrainingRunning=true after release", phase)
		}
	}
}
```

再增加 `promoteCurrentTaskToTraining` 测试：先以 `"downloading"` 获取任务，确认 `TrainingRunning=false`；提升后确认变为 `true`；释放后确认 `TrainingRunning=false` 且活动任务为空。增加密封状态断言，验证提升和释放分别写出 `trainingRunning:true/false`。

- [ ] **Step 2: Run the concurrency tests and verify the new behavior is absent**

Run:

```bash
/usr/local/go/bin/go test ./internal/controller -run 'TestTrainingRunningRejectsConcurrentTrainingInEveryPhase|TestPromoteCurrentTaskToTraining' -count=1
```

Expected: compilation failure because `TrainingRunning` and `promoteCurrentTaskToTraining` do not yet exist.

- [ ] **Step 3: Make `tryAcquireTask` the sole task owner and add promotion**

在 `route.go` 中保留现有 `tryAcquireTask`，不新增第二套训练任务 acquire/release。调整其行为：

1. 删除 `isPhase1Pair` 阶段配对放行逻辑；存在其他 `ActiveTaskID` 或非 idle `CurrentOp` 时统一拒绝；
2. 当 `initialOp` 为 `"staging"` 或 `"training"` 时，在创建 ActiveTask 的同一临界区检查 `TrainingRunning`；若为 `true` 返回 `409 Conflict`，否则设置 `TrainingRunning=true` 并将快照类型设为 `training`；
3. 对只负责下载/解密/审计的 `"downloading"` 任务，不使用 `TrainingRunning` 作为数据导入标志；其并发仍由现有 ActiveTask 生命周期保护；
4. 修改现有 `release` 闭包：仅当任务令牌仍匹配时，同时清除 `TrainingRunning`、活动任务、任务 ID 和操作状态，然后密封一次；
5. 保持 `release` 的 `sync.Once` 和 active-token 防护，确保导入任务提升为训练后仍由同一个 release 收尾。

新增方法：

```go
func (s *TAAState) promoteCurrentTaskToTraining() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TrainingRunning {
		return pkgerrors.New(pkgerrors.CodeConflict, "当前已有训练任务正在执行中，请等待完成后再提交")
	}
	if s.ActiveTaskID == "" && s.ActiveRequestID == "" {
		return pkgerrors.New(pkgerrors.CodeConflict, "当前没有可提升为训练的活动任务")
	}
	s.TrainingRunning = true
	s.CurrentOp = "training"
	if s.activeTask != nil {
		s.activeTask.Type = "training"
	}
	return s.sealStateLocked()
}
```

如果 `promoteCurrentTaskToTraining` 持久化失败，必须在同一锁内恢复 `TrainingRunning=false` 和原操作状态，并向调用方返回错误；不得启动训练。

- [ ] **Step 4: Mark every actual training entry and preserve one release owner**

在数据导入或模型导入处理完成、确定存在模型和最新数据、即将调用 `executeTraining`/`trainOnLatestData` 前调用 `promoteCurrentTaskToTraining()`。初始操作为 `"staging"` 的空 URL 模型复用路径在 `tryAcquireTask` 中已经置位，不得重复置位。

训练仍在原有 `runAsyncSafe("processImportedResource", release, ...)` 或对应复用路径中同步执行，不能创建嵌套的第二个 release。这样导入任务的原始 `release` 在训练函数返回、失败或 panic 后统一清理 `TrainingRunning` 与 ActiveTask。

若提升失败，记录冲突/持久化错误，停止本次训练并调用原任务 release；HTTP 已响应的异步请求通过失败报告路径处理。

- [ ] **Step 5: Remove historical training state writes and phase gating**

删除所有 `TrainingDone` 和 `Phase1TrainingStarted` 写入。`executeTraining` 成功或失败只生成/上报单次报告，不再写历史完成状态；训练函数返回后由唯一任务 release 立即将 `TrainingRunning=false`。`reportTrainingFailureFromResult` 也删除 `TrainingDone=false`。

删除 `processImportedResource` 中按 `phase` 分支的模型/数据配对门控；训练触发条件只允许是“有最新数据记录且 `ModelImported=true`”。阶段仅继续写入报告和索引需要的上下文，不参与并发或是否触发判断。

不要在训练报告生成或训练结果上报之前释放任务；函数完成报告处理后返回，由 release 统一清理。

- [ ] **Step 6: Cover panic, report failure and release-token cleanup**

保持 `runAsyncSafe` 的 defer 结构只有一个任务 release：

```go
go func() {
	defer release()
	defer func() {
		if r := recover(); r != nil {
			s.handleAsyncPanic(name, r)
		}
	}()
	fn()
}()
```

更新 `handleAsyncPanic` 在清理活动任务时同步设置 `TrainingRunning=false`。由于 panic 处理和外层 release 都可能执行，二者必须依靠 active token 与幂等 release，不能清除后续任务的状态。补充训练报告生成失败、runtimeConfig 失败和 panic 后可重新提交训练的测试。

- [ ] **Step 7: Run concurrency and lifecycle tests**

Run:

```bash
gofmt -w internal/controller/route.go internal/controller/import_processing.go internal/controller/concurrency_test.go internal/controller/route_test.go
/usr/local/go/bin/go test ./internal/controller -run 'TestTrainingRunning|TestConcurrent|TestTask|TestPromote' -count=1
```

Expected: all exclusivity tests pass, including all four phases, sequential rerun, promotion from an import task, normal completion, failure, and panic cleanup.

- [ ] **Step 8: Commit the training lifecycle change**

```bash
git add internal/controller/route.go internal/controller/import_processing.go internal/controller/concurrency_test.go internal/controller/route_test.go
git commit -m "feat(controller): 增加全阶段训练互斥状态"
```

---

### Task 4: Align crash recovery and persistent-state recovery

**Files:**
- Modify: `internal/app/taa/recovery.go:84-107,243-255`
- Modify: `internal/controller/route.go:160-252,823-902`
- Modify: `internal/controller/state_store.go:125-205`
- Test: `internal/app/taa/recovery_test.go`
- Test: `internal/controller/state_store_test.go`
- Test: `internal/controller/taa_state_store_integration_test.go`

- [ ] **Step 1: Add failing recovery assertions**

Extend the existing crash recovery test fixture to initialize:

```go
TrainingRunning: true,
ActiveTask: &controller.ActiveTaskSnapshot{
	Type:   "training",
	Status: "RUNNING",
	TaskID: "crash-training-1",
},
```

After `reconcileCrashRecovery` returns, assert both memory and sealed state have `TrainingRunning == false`, `ActiveTask == nil`, and `CurrentOp == "idle"`.

- [ ] **Step 2: Run recovery tests before implementation**

Run:

```bash
/usr/local/go/bin/go test ./internal/app/taa ./internal/controller -run 'Test.*Recovery|Test.*Persistent|Test.*StateStore' -count=1
```

Expected: compile failures or assertion failures because `TrainingRunning` is not yet integrated into recovery.

- [ ] **Step 3: Restore and seal TrainingRunning**

Ensure `RestoreFromPersistentState` copies `p.TrainingRunning`. Ensure `sealStateLocked` writes `s.TrainingRunning` into the persistent state before sealing. `ActiveTask.Status == "RUNNING"` remains the durable interrupted-task indicator, while `TrainingRunning` is the direct runtime flag.

- [ ] **Step 4: Clear TrainingRunning in every recovery exit**

Use `ResetActiveTask` for circuit-breaker and normal recovery exits, and make that method clear:

```go
s.TrainingRunning = false
s.activeTask = nil
s.ActiveTaskID = ""
s.ActiveRequestID = ""
s.CurrentOp = "idle"
```

If `state == nil` and only a `StateStore` is available, set `pState.TrainingRunning = false` together with `pState.ActiveTask = nil` before sealing.

- [ ] **Step 5: Remove obsolete model/data-state recovery calls**

In model-import recovery, retain `state.UpdateImportState(true, false, activeTask.Phase)` so failed model imports clear `ModelImported`. Remove any attempt to clear deleted data flags. Data index purge, failed result archival, report generation and compensation reporting remain unchanged.

- [ ] **Step 6: Run recovery and persistence tests**

Run:

```bash
gofmt -w internal/app/taa/recovery.go internal/app/taa/recovery_test.go internal/controller/route.go internal/controller/state_store.go internal/controller/state_store_test.go internal/controller/taa_state_store_integration_test.go
/usr/local/go/bin/go test ./internal/app/taa ./internal/controller -run 'Test.*Recovery|Test.*Persistent|Test.*StateStore' -count=1
```

Expected: recovery clears the real-time training state and sealed state without changing model persistence semantics.

- [ ] **Step 7: Commit recovery alignment**

```bash
git add internal/app/taa/recovery.go internal/app/taa/recovery_test.go internal/controller/route.go internal/controller/state_store.go internal/controller/state_store_test.go internal/controller/taa_state_store_integration_test.go
git commit -m "fix(recovery): 恢复训练状态异常收尾"
```

---

### Task 5: Remove stale references and complete regression coverage

**Files:**
- Modify: `internal/controller/handler_test.go`
- Modify: `internal/controller/import_flow_new_test.go`
- Modify: `internal/controller/import_index_test.go`
- Modify: `internal/controller/phase1_reimport_test.go`
- Modify: `internal/controller/security_hardening_test.go`
- Modify: `internal/controller/state_store_test.go`
- Modify: `internal/controller/taa_state_store_integration_test.go`
- Modify: `internal/controller/concurrency_test.go`
- Modify: `internal/app/taa/recovery_test.go`
- Modify: `docs/TAA状态持久化与崩溃自愈设计文档.md` if it names removed fields
- Modify: `docs/taa接口设计文档.md` if it documents removed response keys

- [ ] **Step 1: Find all stale identifiers**

Run:

```bash
rg -n "DataImported|dataImported|TrainingDataImported|trainingDataImported|TrainingDone|trainingDone|Phase1TrainingStarted|phase1TrainingStarted" --glob '*.go' --glob '*.md'
```

Expected after cleanup: no production or test references remain, except historical discussion in the implementation/design documents where the removed field is explicitly described as deleted. Any executable Go reference must be removed.

- [ ] **Step 2: Update tests to assert the new contract**

Replace old assertions with these contract checks:

```go
func assertNoRemovedTrainingFlags(t *testing.T, result map[string]any) {
	t.Helper()
	for _, key := range []string{"dataImported", "trainingDataImported", "trainingDone"} {
		if _, ok := result[key]; ok {
			t.Fatalf("response contains removed key %q: %#v", key, result)
		}
	}
}
```

Use this helper for both health and status responses. For persistent-state tests, marshal/unmarshal and inspect JSON keys rather than referring to removed Go fields.

- [ ] **Step 3: Add all-stage repeatability coverage**

Add a test that sets `ModelImported=true`, installs a valid latest data record and valid runtime configuration, then runs the training entry point twice in each phase after the first run releases `TrainingRunning`. Assert the second run is accepted without a phase transition.

Use a short deterministic command such as:

```go
runtimeConfig := runtimeConfig{Commands: []string{"python3 -c 'from pathlib import Path; Path(\"$OUTPUT_DIR/result.txt\").write_text(\"ok\")'"}}
```

Use the existing test helpers for temporary security directories and wait for `TrainingRunning` to return false before starting the second run.

- [ ] **Step 4: Add cross-phase concurrent rejection coverage**

For each phase, set `TrainingRunning=true` and an active training snapshot, submit a second training-triggering request, and assert HTTP 409. The test must not set or inspect any data completion field.

- [ ] **Step 5: Update documentation contract tables**

In the status API documentation, remove `dataImported`, `trainingDataImported`, and `trainingDone`; document `modelImported` and `trainingRunning`. In the persistence/recovery document, state that the sealed schema is `1.4`, data availability comes from the latest import index record, and `TrainingRunning` is cleared on every training exit.

- [ ] **Step 6: Run package-level regression tests**

Run:

```bash
/usr/local/go/bin/go test ./internal/controller ./internal/app/taa ./pkg/crypto ./pkg/utils -count=1
```

Expected: all selected packages pass with no stale identifier compilation errors.

- [ ] **Step 7: Commit regression and documentation updates**

```bash
git add internal/controller internal/app/taa docs/TAA状态持久化与崩溃自愈设计文档.md docs/taa接口设计文档.md
git commit -m "test(controller): 完善训练状态重构回归覆盖"
```

Only include documentation files if they were actually modified for this contract change.

---

### Task 6: Final verification and clean-scope review

**Files:**
- Verify: all files changed by Tasks 1–5
- Do not modify: existing unrelated `TODO` and `models/audit/research/taa-audit-design.html` changes unless a test explicitly requires them

- [ ] **Step 1: Verify no executable stale references remain**

Run:

```bash
rg -n "DataImported|dataImported|TrainingDataImported|trainingDataImported|TrainingDone|trainingDone|Phase1TrainingStarted|phase1TrainingStarted" --glob '*.go'
```

Expected: no output.

- [ ] **Step 2: Verify formatting and full test suite**

Run:

```bash
gofmt -l internal/controller internal/app/taa pkg/crypto pkg/utils
```

Expected: no output.

Then run:

```bash
git diff --check
/usr/local/go/bin/go test ./...
```

Expected: `git diff --check` exits 0 and every Go package reports `ok` or `[no test files]`.

- [ ] **Step 3: Inspect the final diff scope**

Run:

```bash
git status --short
git diff --stat HEAD~5..HEAD
```

Confirm that implementation commits contain only the approved state-machine changes and their tests/docs. Existing user changes outside this plan remain untouched and are not accidentally staged.

- [ ] **Step 4: Record final verification evidence**

Record the exact `go test ./...` output and the final commit IDs in the completion response. Do not claim completion if any package fails or if stale executable references remain.
