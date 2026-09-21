# Platform-Mock Model Card Title and Status Pills Layout Spec

## 1. Context and Objective
In `tools/platform-mock`, the Model Dispatch card (`#card-importModel`) displays two asynchronous callback indicators:
- `reportModelImportPill` (Model Import Result Report / 模型导入结果上报)
- `reportAuditPill` (Code Audit Result / 代码审计结果)

Previously, these two status pills were wrapped in separate `<div>` containers stacked vertically underneath `<h2>② 下发模型</h2>`. This increased vertical card padding and created an unbalanced card head.

The goal is to align both status pills side-by-side on the right of the `② 下发模型` card title in a single flexible title row (`.card-title-group`), improving visual density and clarity.

## 2. Component Structure and Layout Design

### 2.1 CSS Layout Rules (`components.css`)
Introduce a `.card-title-group` class to structure card header titles with adjacent tags or pills:
```css
.card-title-group {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
```

### 2.2 Card Header Markup (`index.html`)
Update `#card-importModel` header to use `.card-title-group`:
```html
<div class="card-head">
  <div class="card-title-group">
    <h2>② 下发模型</h2>
    <span id="reportModelImportPill" class="status-pill pending">
      <span id="reportModelImportDot" class="dot pill-dot pending"></span>
      <span id="reportModelImportStatusText">模型导入结果上报</span>
    </span>
    <span id="reportAuditPill" class="status-pill pending">
      <span id="reportAuditDot" class="dot pill-dot pending"></span>
      <span id="reportAuditStatusText">代码审计结果</span>
    </span>
  </div>
  <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; justify-content:flex-end;">
    ...
  </div>
</div>
```

### 2.3 Responsiveness and Accessibility
- `flex-wrap: wrap` ensures that when card width is constrained (e.g., mobile viewports or 3-column grid collapse), pills wrap naturally without overflowing.
- Element IDs, DOM attributes, and JS query selectors (`reportModelImportPill`, `reportAuditPill`, `reportModelImportDot`, `reportAuditDot`) remain strictly preserved.

## 3. Verification Plan
- Unit tests in `server_test.go` will verify:
  - Presence and ordering of `<h2>② 下发模型</h2>`, `#reportModelImportPill`, and `#reportAuditPill` in `#card-importModel`.
  - CSS rule `.card-title-group` defined in `components.css`.
- Run `go test ./...` across the entire workspace.
- Build both `taa` and `platform-mock` binaries.
