# Platform-Mock Pills Row and Remove Phase Switch Alert Spec

## 1. Context and Problem Statement
1. **Model Card Status Pills Stacking**:
   - In `#card-importModel`, the two callback status pills (`#reportModelImportPill` and `#reportAuditPill`) were previously placed as direct children in `.card-title-group` alongside `<h2>② 下发模型</h2>`.
   - Because `.card-head` has `display: flex; justify-content: space-between` and the right side holds three action buttons (~260px), in standard 3-column layouts (card width 360px-450px) the title group was constrained to ~150px.
   - With `flex-wrap: wrap`, the two pills wrapped onto separate lines, appearing vertically stacked one over the other rather than side-by-side (`并排展示`).

2. **Intrusive Phase Switch Info Prompt**:
   - When switching execution phases via `.phase-switch-btn` ("1 调试", "2 测试", "3 训练", "4 推理"), `quickSwitchPhase` called `showResultRunning('switchResult', ...)` and `showResult('switchResult', ...)`.
   - This caused `#switchResult` (a `.test-result` box) to expand below the phase switch toolbar, displaying raw request status and response JSON directly on the main page.
   - The user requested this intrusive info popup/prompt to be removed. Phase status is already indicated by `#phaseSwitchDot`, `#phaseSwitchText`, and drawer interaction details (`#phaseSwitchDetailBtn`).

## 2. Technical Design and Solutions

### 2.1 Enforcing Side-by-Side Capsule Display (`.card-pills-row`)
1. Introduce `.card-pills-row` in `tools/platform-mock/internal/static/css/components.css`:
   ```css
   .card-pills-row {
     display: inline-flex;
     align-items: center;
     gap: 6px;
     flex-wrap: nowrap;
     white-space: nowrap;
     flex-shrink: 0;
   }
   ```
2. Wrap `#reportModelImportPill` and `#reportAuditPill` in `.card-pills-row` inside `.card-title-group`:
   ```html
   <div class="card-head">
     <div class="card-title-group">
       <h2 style="margin:0; white-space:nowrap;">② 下发模型</h2>
       <div class="card-pills-row">
         <span id="reportModelImportPill" class="status-pill pending">...</span>
         <span id="reportAuditPill" class="status-pill pending">...</span>
       </div>
     </div>
     <div class="card-head-actions" style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; justify-content:flex-end; margin-left:auto;">
       ...
     </div>
   </div>
   ```
3. Guarantee that the two pills are non-wrapping (`flex-wrap: nowrap`), ensuring they are always horizontally adjacent.
4. On `margin-left: auto` for actions, if the card width cannot hold Title + 2 Pills + 3 Buttons in one line, the actions wrap to the next line on the right, keeping Title + 2 Pills intact side-by-side on the first line.

### 2.2 Removing Phase Switch Popup Alert
1. In `tools/platform-mock/internal/static/js/app.js`:
   - In `quickSwitchPhase(phase)`:
     - Remove `showResultRunning('switchResult', ...)` call.
     - Remove `showResult('switchResult', ok, respText)` call.
     - Remove `showResult('switchResult', false, errMsg)` call.
   - Retain `#phaseSwitchText` updates (`当前阶段: 1 调��`, `切换失败: ...`), `#phaseSwitchDot` updates, and `recordInteraction('switch', ...)` so the user can still view the drawer if needed via `#phaseSwitchDetailBtn`.
2. In `tools/platform-mock/internal/static/index.html`:
   - Remove `<div id="switchResult" class="test-result"></div>` and `<div id="phaseSwitchDetail" ...>`.

## 3. Verification Plan
- Unit tests in `server_test.go`:
  - Assert `.card-pills-row` exists in `components.css`.
  - Assert `#reportModelImportPill` and `#reportAuditPill` are nested inside `.card-pills-row` in `card-importModel`.
  - Assert `switchResult` is not in `index.html` and not invoked in `quickSwitchPhase`.
- Run `go test ./...` to verify all tests pass.
- Build both `taa` and `platform-mock` binaries.
