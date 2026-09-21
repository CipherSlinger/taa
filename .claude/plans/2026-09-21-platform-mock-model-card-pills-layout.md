# Platform-Mock Model Card Title and Status Pills Layout Plan

## Work Items
- [x] Task 1: Update CSS Styles (`tools/platform-mock/internal/static/css/components.css`)
  - Define `.card-title-group` with `display: flex; align-items: center; gap: 8px; flex-wrap: wrap;`.
- [x] Task 2: Update HTML Markup (`tools/platform-mock/internal/static/index.html`)
  - In `#card-importModel`, replace the vertically stacked title and pill wrappers with `<div class="card-title-group">`.
  - Position `reportModelImportPill` and `reportAuditPill` side-by-side directly after `<h2>② 下发模型</h2>`.
- [x] Task 3: Update Test Suite (`tools/platform-mock/internal/server_test.go`)
  - Assert that `.card-title-group` exists in `components.css`.
  - Assert that `<h2>② 下发模型</h2>`, `reportModelImportPill`, and `reportAuditPill` are nested within `.card-title-group` in `card-importModel`.
  - Verify all tests pass via `go test ./...`.
- [x] Task 4: Build Verification and Git Commit
  - Build `bin/taa` and `bin/platform-mock`.
  - Execute git commit following Conventional Commits format without AI signatures.
