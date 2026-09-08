# Hash-Indexed Import Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/v1/taa/import` store decrypted archives by SM3 hash, keep a persistent `<requestId, taskId, hash>` index, and let `/v1/taa/export` resolve exports from that index instead of phase-only lookup.

**Architecture:** `/v1/taa/import` will download the resource, optionally decrypt `.enc`, compute SM3 on the decrypted archive bytes, and store the archive under a hash-named data directory. The controller will maintain a persistent index that maps `requestId` and `taskId` to a single record containing the hash, the data directory, and the latest result directory. Training stays event-driven per import, but result files and reports move under a `requestId-taskId` result directory derived from the index record. `/v1/taa/export` will resolve the target result directory through the index, validate `requestId` / `taskId` lookup rules, and stream the result archive if it exists.

**Tech Stack:** Go, stdlib filesystem APIs, `taa/crypto` SM3, existing controller tests, existing JSON file helpers.

**Spec:** `docs/taa接口设计文档.md`

## Global Constraints

- `requestId` and `taskId` are 1:1; duplicate `requestId` or duplicate `taskId` must be rejected.
- If both `requestId` and `taskId` are provided to export and they resolve to different records, export must fail.
- `requestId` or `taskId` alone may be used to locate the same unique record.
- Data archives are stored by the SM3 hash of the decrypted compressed package bytes.
- Same hash imports must reuse the existing hash directory.
- Same hash imports still retrain; result directories are organized by `requestId-taskId`.
- Model import remains overwrite-based and unchanged.
- Index state must persist across process restarts.
- Import and export concurrency is allowed; consistency must be preserved with rollback on failure.
- Old data is never deleted by this feature.

---

### Task 1: Add persistent import index storage

**Files:**
- Modify: `internal/controller/route.go:41-120`
- Create: `internal/controller/import_index.go`
- Modify: `internal/controller/import_processing.go:1-40`

**Interfaces:**
- Consumes: `TAAState`, `importRequest`, `requestId`, `taskId`, SM3 hash strings.
- Produces: `ImportIndexStore` with load/save/get/put helpers and a record type that carries `RequestID`, `TaskID`, `Hash`, `DataDir`, and `ResultDir`.

- [ ] **Step 1: Write the failing test**

```go
func TestImportIndexStorePersistsAndRejectsDuplicates(t *testing.T) {
	// create temp index file, write one record, reload it, verify lookup by requestId and taskId.
	// verify duplicate requestId and duplicate taskId are rejected.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/controller -run TestImportIndexStorePersistsAndRejectsDuplicates -v`
Expected: FAIL because the store type and helpers do not exist yet.

- [ ] **Step 3: Write minimal implementation**

```go
type ImportIndexRecord struct {
	RequestID string `json:"requestId"`
	TaskID    string `json:"taskId"`
	Hash      string `json:"hash"`
	DataDir   string `json:"dataDir"`
	ResultDir string `json:"resultDir"`
}

type ImportIndexStore struct {
	mu      sync.RWMutex
	path    string
	byReq   map[string]ImportIndexRecord
	byTask  map[string]ImportIndexRecord
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/controller -run TestImportIndexStorePersistsAndRejectsDuplicates -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controller/import_index.go internal/controller/route.go internal/controller/import_processing.go
git commit -m "feat: 添加导入索引存储"
```

### Task 2: Refactor import flow to hash archive bytes

**Files:**
- Modify: `internal/controller/route.go:320-427,538-643`
- Modify: `internal/controller/import_processing.go:1-320`
- Modify: `internal/controller/handler_test.go:551-866`

**Interfaces:**
- Consumes: `ImportIndexStore`, `ImportIndexRecord`, `downloadToTempFile`, `decryptResourceToTempFile`.
- Produces: hash-based data directory helpers, import dedup/reject behavior, and training result output under `requestId-taskId`.

- [ ] **Step 1: Write the failing test**

```go
func TestImportStoresByHashAndRejectsDuplicateRequestOrTask(t *testing.T) {
	// import same encrypted archive twice with different requestId/taskId, verify same hash dir reused.
	// import with duplicate requestId or duplicate taskId, verify 400/JSON error.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/controller -run TestImportStoresByHashAndRejectsDuplicateRequestOrTask -v`
Expected: FAIL because import still overwrites the shared data directory.

- [ ] **Step 3: Write minimal implementation**

```go
func sm3Hex(data []byte) string {
	h := teecrypto.NewSM3()
	_, _ = h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func dataDirForHash(root, hash string) string {
	return filepath.Join(root, hash)
}

func resultDirForRequestTask(root, requestID, taskID string) string {
	return filepath.Join(root, safeFilenamePart(requestID)+"-"+safeFilenamePart(taskID))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/controller -run TestImportStoresByHashAndRejectsDuplicateRequestOrTask -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controller/route.go internal/controller/import_processing.go internal/controller/handler_test.go
git commit -m "feat: 按哈希重构导入流程"
```

### Task 3: Rewrite export lookup flow

**Files:**
- Modify: `internal/controller/route.go:538-643`
- Modify: `internal/controller/handler_test.go:668-1116`
- Modify: `docs/taa接口设计文档.md:608-705`

**Interfaces:**
- Consumes: `ImportIndexStore` lookup methods.
- Produces: export lookup by requestId/taskId, conflict detection when both disagree, and hash-indexed result streaming.

- [ ] **Step 1: Write the failing test**

```go
func TestExportResolvesByRequestOrTaskFromIndex(t *testing.T) {
	// seed an index record with a requestId/taskId/hash/resultDir
	// verify export succeeds by requestId only, taskId only, and rejects conflicting requestId+taskId.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/controller -run TestExportResolvesByRequestOrTaskFromIndex -v`
Expected: FAIL because export still depends on phase state.

- [ ] **Step 3: Write minimal implementation**

```go
func (s *TAAState) resolveImportRecord(req exportRequest) (ImportIndexRecord, error) {
	// lookup by requestId, then by taskId, enforce same-record rule when both are set.
}

func (s *TAAState) exportResultDir(record ImportIndexRecord) string {
	return record.ResultDir
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/controller -run TestExportResolvesByRequestOrTaskFromIndex -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controller/route.go internal/controller/handler_test.go docs/taa接口设计文档.md
git commit -m "feat: 改造导出索引查询"
```

### Task 4: Update tests and docs for new behavior

**Files:**
- Modify: `internal/controller/handler_test.go`
- Modify: `docs/taa接口设计文档.md`
- Modify: `docs/TAA设计文档.md` if it still describes the old export path behavior

**Interfaces:**
- Consumes: final import/export behavior and the hash/result/index naming rules.
- Produces: coverage for persistence, duplicate rejection, reuse on same hash, and export lookup semantics.

- [ ] **Step 1: Write the failing test**

```go
func TestImportIndexSurvivesRestart(t *testing.T) {
	// create index, save it, reconstruct state, reload it, verify the record is still queryable.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/controller -run TestImportIndexSurvivesRestart -v`
Expected: FAIL until the persistent file load/save path is wired end-to-end.

- [ ] **Step 3: Write minimal implementation**

```go
// update docs with the final rules:
// - data archive hash = SM3(decrypted compressed package bytes)
// - same hash reuses data dir
// - same requestId/taskId rejected
// - export resolves via index
// - result dirs use requestId-taskId
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/controller ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controller/handler_test.go docs/taa接口设计文档.md docs/TAA设计文档.md
git commit -m "docs: 更新哈希索引导入导出说明"
```

## Review checklist

- `/v1/taa/import` no longer overwrites data directories.
- Hash is computed from the decrypted compressed archive bytes.
- Duplicate requestId/taskId imports are rejected.
- Same-hash imports reuse the same data directory.
- Training result output is keyed by requestId-taskId.
- `/v1/taa/export` resolves records through the index and handles requestId/taskId conflicts.
- Index state persists across restarts.
- Old data remains untouched.
