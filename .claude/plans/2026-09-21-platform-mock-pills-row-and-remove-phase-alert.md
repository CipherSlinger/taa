# Platform-Mock Pills Row and Remove Phase Switch Alert Plan

## Work Items
- [x] Task 1: Update CSS Styles (`tools/platform-mock/internal/static/css/components.css`)
  - Add `.card-pills-row` with `display: inline-flex; align-items: center; gap: 6px; flex-wrap: nowrap; white-space: nowrap; flex-shrink: 0;`.
  - Add `white-space: nowrap;` to `.status-pill` to prevent internal text wrapping.
  - Set `.card-head` `align-items: center;`.
- [x] Task 2: Update HTML Markup (`tools/platform-mock/internal/static/index.html`)
  - In `#card-importModel`, wrap `#reportModelImportPill` and `#reportAuditPill` inside `<div class="card-pills-row">`.
  - Remove `<div id="switchResult" class="test-result"></div>` and `<div id="phaseSwitchDetail" ...>`.
- [x] Task 3: Update JavaScript Logic (`tools/platform-mock/internal/static/js/app.js`)
  - In `quickSwitchPhase`: remove `showResultRunning('switchResult', ...)` and `showResult('switchResult', ...)`.
- [x] Task 4: Update Test Suite (`tools/platform-mock/internal/server_test.go`)
  - Verify `.card-pills-row` CSS class and its presence in `card-importModel`.
  - Verify absence of `id="switchResult"` in `index.html`.
  - Verify all tests pass via `go test ./...`.
- [x] Task 5: Build Verification and Git Commit
  - Build `bin/taa` and `bin/platform-mock`.
  - Execute git commit following Conventional Commits format without AI signatures.
