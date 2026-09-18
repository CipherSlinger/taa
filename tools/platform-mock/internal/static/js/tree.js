// ── Resource Info Dataset Tree Component (dstree) ──

const RESOURCE_INFO_TIMEOUT_MS = 120000;
let resourceInfoReportData = null;
let resourceInfoTreeExpanded = new Set();
let resourceInfoSelectedNode = null;
let resourceInfoViewMode = 'tree'; // 'tree' | 'raw'
let resourceInfoSearchFilter = '';
let resourceInfoRawResponseText = '';
let isResourceInfoModalOpen = false;

function formatHumanSize(bytes) {
  if (bytes == null || isNaN(bytes)) return '0 B';
  const b = Number(bytes);
  if (b === 0) return '0 B';
  if (b < 1024) return b + ' B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), units.length - 1);
  const val = b / Math.pow(1024, i);
  return `${val >= 10 || i === 0 ? val.toFixed(0) : val.toFixed(1)} ${units[i]}`;
}

function getDstreeFormatInfo(fmt) {
  if (!fmt) return { label: '?', className: 'dstree-fmt-other' };
  const lower = String(fmt).toLowerCase().trim();
  const short = lower.split('/').pop() || lower;
  if (short === 'csv' || short === 'tsv' || lower.includes('csv') || lower.includes('tsv')) {
    return { label: short.toUpperCase(), className: 'dstree-fmt-csv' };
  }
  if (short === 'xlsx' || short === 'xls' || lower.includes('spreadsheet') || lower.includes('excel')) {
    return { label: 'XLSX', className: 'dstree-fmt-xlsx' };
  }
  if (short === 'json' || short === 'jsonl' || lower.includes('json')) {
    return { label: short.toUpperCase(), className: 'dstree-fmt-json' };
  }
  if (short === 'sqlite' || short === 'db' || lower.includes('sqlite')) {
    return { label: 'SQLITE', className: 'dstree-fmt-sqlite' };
  }
  if (short === 'parquet' || lower.includes('parquet')) {
    return { label: 'PARQUET', className: 'dstree-fmt-parquet' };
  }
  if (['png', 'jpeg', 'jpg', 'gif', 'bmp', 'webp', 'svg'].includes(short) || lower.startsWith('image/')) {
    return { label: short.toUpperCase(), className: 'dstree-fmt-image' };
  }
  if (['txt', 'text', 'md', 'markdown', 'log', 'sh', 'py', 'go', 'yaml', 'yml'].includes(short) || lower.startsWith('text/')) {
    return { label: short.toUpperCase(), className: 'dstree-fmt-text' };
  }
  return { label: short.toUpperCase(), className: 'dstree-fmt-other' };
}

function ensureNodePaths(node, parentPath = '') {
  if (!node) return;
  const currentPath = parentPath ? (parentPath === '/' ? `/${node.name}` : `${parentPath}/${node.name}`) : (node.name || '');
  node.path = node.path || currentPath;
  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      ensureNodePaths(child, node.path);
    }
  }
}

function defaultExpandTree(root) {
  resourceInfoTreeExpanded.clear();
  if (!root) return;
  resourceInfoTreeExpanded.add(root.path);
  if (Array.isArray(root.children)) {
    for (const child of root.children) {
      if (child.type === 'dir') {
        resourceInfoTreeExpanded.add(child.path);
      }
    }
  }
}

function expandAllTreeNodes(node = resourceInfoReportData?.tree) {
  if (!node) return;
  if (node.type === 'dir') {
    resourceInfoTreeExpanded.add(node.path);
    if (Array.isArray(node.children)) {
      for (const child of node.children) {
        expandAllTreeNodes(child);
      }
    }
  }
  refreshResourceInfoTreeViews();
}

function collapseAllTreeNodes() {
  resourceInfoTreeExpanded.clear();
  refreshResourceInfoTreeViews();
}

function findNodeByPath(root, path) {
  if (!root) return null;
  if (root.path === path) return root;
  if (Array.isArray(root.children)) {
    for (const child of root.children) {
      const found = findNodeByPath(child, path);
      if (found) return found;
    }
  }
  return null;
}

function nodeMatchesFilter(node, filterText) {
  if (!filterText) return true;
  const q = filterText.toLowerCase().trim();
  if (node.name && node.name.toLowerCase().includes(q)) return true;
  if (node.path && node.path.toLowerCase().includes(q)) return true;
  const fmt = node.fmt || node.format || '';
  if (fmt && fmt.toLowerCase().includes(q)) return true;
  if (node.fields && Array.isArray(node.fields)) {
    for (const f of node.fields) {
      const fn = typeof f === 'object' && f !== null ? `${f.name || ''} ${f.type || ''}` : String(f);
      if (fn.toLowerCase().includes(q)) return true;
    }
  }
  if (node.tables && Array.isArray(node.tables)) {
    for (const t of node.tables) {
      if (t.name && t.name.toLowerCase().includes(q)) return true;
    }
  }
  return false;
}

function subtreeHasMatch(node, filterText) {
  if (!filterText) return true;
  if (nodeMatchesFilter(node, filterText)) return true;
  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      if (subtreeHasMatch(child, filterText)) return true;
    }
  }
  return false;
}

function renderTreeNodeHTML(node, filterText, isModal = false) {
  if (!node) return '';
  const hasSubtreeMatch = subtreeHasMatch(node, filterText);
  if (filterText && !hasSubtreeMatch) {
    return '';
  }

  const isDir = node.type === 'dir';
  const hasFilter = Boolean(filterText && filterText.trim());
  const isOpen = isDir && (hasFilter ? true : resourceInfoTreeExpanded.has(node.path));
  const isSelected = resourceInfoSelectedNode && resourceInfoSelectedNode.path === node.path;
  const fmtInfo = isDir ? null : getDstreeFormatInfo(node.fmt || node.format);
  const isEmpty = !isDir && (node.empty || node.size === 0);
  const sizeText = !isDir ? (node.size_h || formatHumanSize(node.size)) : '';
  const rowCountText = !isDir ? (node.rows != null ? `${node.rows} 行` : (node.count || '')) : '';
  const fileCount = isDir ? (node.file_count != null ? node.file_count : (node.children ? node.children.length : 0)) : 0;

  let html = `<div class="dstree-node" data-path="${escapeHtml(node.path)}">`;
  html += `<div class="dstree-row ${isSelected ? 'selected' : ''}" onclick="onSelectTreeNode('${escapeHtml(node.path)}')">`;

  if (isDir) {
    html += `<span class="dstree-caret" onclick="onToggleTreeNode(event, '${escapeHtml(node.path)}')">${isOpen ? '▾' : '▸'}</span>`;
    html += `<span class="dstree-icon">${isOpen ? '📂' : '📁'}</span>`;
    html += `<span class="dstree-name dstree-dirname">${escapeHtml(node.name)}/</span>`;
    html += `<span class="dstree-meta-dim">(${fileCount} 个文件)</span>`;
  } else {
    html += `<span class="dstree-caret-spacer"></span>`;
    html += `<span class="dstree-icon">📄</span>`;
    html += `<span class="dstree-name">${escapeHtml(node.name)}</span>`;
    html += `<span class="dstree-fmt ${fmtInfo.className}">${escapeHtml(fmtInfo.label)}</span>`;
    if (isEmpty) {
      html += `<span class="dstree-warn-empty">⚠ 空文件</span>`;
    }
    if (node.warning) {
      html += `<span class="dstree-warn-parse" title="${escapeHtml(node.warning)}">⚠ ${escapeHtml(node.warning)}</span>`;
    }
    if (rowCountText) {
      html += `<span class="dstree-count">${escapeHtml(rowCountText)}</span>`;
    }
    if (sizeText) {
      html += `<span class="dstree-meta-dim">${escapeHtml(sizeText)}</span>`;
    }
  }

  html += `</div>`;

  if (!isDir && node.fields && node.fields.length) {
    html += `<div class="dstree-schema-line">`;
    html += `<span class="dstree-schema-label">schema</span>`;
    for (const f of node.fields) {
      const fieldName = typeof f === 'object' && f !== null ? f.name : String(f);
      const fieldType = typeof f === 'object' && f !== null ? f.type : '';
      const chipTitle = fieldType ? `${fieldName}: ${fieldType}` : fieldName;
      html += `<span class="dstree-field-chip" title="${escapeHtml(chipTitle)}">${escapeHtml(fieldName)}${fieldType ? `<span style="opacity:0.75; font-size:10px;">: ${escapeHtml(fieldType)}</span>` : ''}</span>`;
    }
    html += `</div>`;
  }

  if (!isDir && node.tables && node.tables.length) {
    html += `<div class="dstree-schema-line">`;
    html += `<span class="dstree-schema-label">tables</span>`;
    for (const t of node.tables) {
      html += `<span class="dstree-table-chip">${escapeHtml(t.name)} <b>${t.rows != null ? t.rows : 0} 行</b></span>`;
    }
    html += `</div>`;
  }

  if (isDir && isOpen && node.children && node.children.length) {
    html += `<div class="dstree-children">`;
    for (const child of node.children) {
      html += renderTreeNodeHTML(child, filterText, isModal);
    }
    html += `</div>`;
  }

  html += `</div>`;
  return html;
}

function renderTreeDetailHTML(node) {
  if (!node) {
    return `<div style="color:var(--muted); text-align:center; padding:40px 10px;">点击左侧文件或目录查看详情</div>`;
  }

  const isDir = node.type === 'dir';
  const fmtInfo = isDir ? null : getDstreeFormatInfo(node.fmt || node.format);
  const sizeText = !isDir ? (node.size_h || formatHumanSize(node.size)) : '';
  const rawSize = !isDir && node.size != null ? `${node.size.toLocaleString()} 字节` : '';
  const rowCountText = !isDir ? (node.rows != null ? `${node.rows} 行` : (node.count || '')) : '';
  const fileCount = isDir ? (node.file_count != null ? node.file_count : (node.children ? node.children.length : 0)) : 0;

  let html = `
    <div style="display:flex; align-items:center; gap:8px; margin-bottom:12px; padding-bottom:8px; border-bottom:1px solid var(--line);">
      <span style="font-size:20px;">${isDir ? '📁' : '📄'}</span>
      <div style="font-weight:700; font-size:14px; word-break:break-all;">${escapeHtml(node.name)}${isDir ? '/' : ''}</div>
    </div>
    <div style="display:flex; flex-direction:column; gap:8px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px;">
      <div><span class="muted">路径: </span><span style="word-break:break-all; font-weight:600;">${escapeHtml(node.path || '/')}</span></div>
      <div><span class="muted">类型: </span><span>${isDir ? '目录 (dir)' : '文件 (file)'}</span></div>
  `;

  if (!isDir) {
    html += `
      <div><span class="muted">格式: </span><span class="dstree-fmt ${fmtInfo.className}">${escapeHtml(node.fmt || node.format || '未知')}</span></div>
      <div><span class="muted">大小: </span><span>${escapeHtml(sizeText)} ${rawSize ? `(${rawSize})` : ''}</span></div>
      ${rowCountText ? `<div><span class="muted">数据量: </span><span style="color:var(--ok); font-weight:600;">${escapeHtml(rowCountText)}</span></div>` : ''}
      ${node.isObject ? `<div><span class="muted">结构形态: </span><span>JSON Object (键值对象)</span></div>` : ''}
      ${node.warning ? `<div><span class="muted">警告: </span><span style="color:var(--bad); font-weight:600;">${escapeHtml(node.warning)}</span></div>` : ''}
      ${node.size === 0 || node.empty ? `<div><span class="muted">状态: </span><span style="color:#d97706; font-weight:600;">空文件（0 字节）</span></div>` : ''}
    `;
  } else {
    html += `
      <div><span class="muted">文件总数: </span><span style="color:var(--ok); font-weight:600;">${fileCount} 个文件</span></div>
      ${node.children ? `<div><span class="muted">直接子项: </span><span>${node.children.length} 项</span></div>` : ''}
    `;
  }

  html += `</div>`;

  if (!isDir && node.fields && node.fields.length) {
    html += `
      <div style="margin-top:14px;">
        <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--muted); margin-bottom:8px; padding-bottom:4px; border-bottom:1px solid var(--line);">
          Schema 字段定义 (${node.fields.length} 个)
        </div>
        <div style="display:flex; flex-direction:column; gap:4px; max-height:160px; overflow-y:auto; padding-right:2px;">
    `;
    for (const f of node.fields) {
      const fieldName = typeof f === 'object' && f !== null ? f.name : String(f);
      const fieldType = typeof f === 'object' && f !== null ? f.type : '';
      html += `
        <div style="display:flex; justify-content:space-between; align-items:center; background:var(--chip-bg); border:1px solid var(--chip-border); border-radius:4px; padding:2px 8px; font-size:11px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;">
          <span style="color:var(--text); font-weight:600;">${escapeHtml(fieldName)}</span>
          ${fieldType ? `<span class="muted">${escapeHtml(fieldType)}</span>` : ''}
        </div>
      `;
    }
    html += `</div></div>`;
  }

  if (!isDir && node.tables && node.tables.length) {
    html += `
      <div style="margin-top:14px;">
        <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--muted); margin-bottom:8px; padding-bottom:4px; border-bottom:1px solid var(--line);">
          SQLite 表级明细 (${node.tables.length} 张表)
        </div>
        <div style="display:flex; flex-direction:column; gap:4px; max-height:160px; overflow-y:auto; padding-right:2px;">
    `;
    for (const t of node.tables) {
      html += `
        <div class="dstree-table-chip" style="display:flex; justify-content:space-between; align-items:center; padding:3px 8px; font-size:11px;">
          <span>${escapeHtml(t.name)}</span>
          <b>${t.rows != null ? t.rows : 0} 行</b>
        </div>
      `;
    }
    html += `</div></div>`;
  }

  return html;
}

function onToggleTreeNode(e, path) {
  if (e) e.stopPropagation();
  if (resourceInfoTreeExpanded.has(path)) {
    resourceInfoTreeExpanded.delete(path);
  } else {
    resourceInfoTreeExpanded.add(path);
  }
  refreshResourceInfoTreeViews();
}

function onSelectTreeNode(path) {
  const rootNode = resourceInfoReportData?.tree || (resourceInfoReportData?.name ? resourceInfoReportData : null);
  const node = findNodeByPath(rootNode, path);
  if (!node) return;
  resourceInfoSelectedNode = node;
  if (node.type === 'dir') {
    if (resourceInfoTreeExpanded.has(path)) {
      resourceInfoTreeExpanded.delete(path);
    } else {
      resourceInfoTreeExpanded.add(path);
    }
  }
  refreshResourceInfoTreeViews();
}

function onTreeSearchInput(val) {
  resourceInfoSearchFilter = val;
  refreshResourceInfoTreeViews();
}

function switchResourceInfoViewMode(mode) {
  resourceInfoViewMode = mode;
  refreshResourceInfoTreeViews();
}

function renderResourceInfoTreeShell(targetEl, isModal = false) {
  if (!targetEl || !resourceInfoReportData) return;
  const report = resourceInfoReportData;
  const tree = report.tree || (report.name ? report : null);

  let html = `
    <div class="dstree-shell ${isModal ? 'dstree-modal-shell' : ''}">
      <div class="dstree-topbar">
        <div class="dstree-title-area">
          <span style="font-size:16px;">🌳</span>
          <span>${escapeHtml(tree?.name || '数据集')}</span>
          <span class="muted" style="font-weight:normal; font-size:12px;">v${escapeHtml(report.version || '1.0.0')}</span>
        </div>
        <div class="dstree-stats-area">
          <span class="dstree-stat-item"><b>${report.total_files != null ? report.total_files : 0}</b> 个文件</span>
          <span class="dstree-stat-item"><b class="hl">${report.structured_files != null ? report.structured_files : 0}</b> 个结构化</span>
          <span class="dstree-stat-item">${escapeHtml(report.total_size_h || formatHumanSize(report.total_size))}</span>
          ${report.generated_at ? `<span class="dstree-meta-dim">${escapeHtml(report.generated_at)}</span>` : ''}
        </div>
      </div>
  `;

  if (report.checksum) {
    html += `
      <div style="padding:6px 14px; font-size:11px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; background:rgba(127,127,127,.03); border-bottom:1px solid var(--line); display:flex; gap:12px; flex-wrap:wrap; align-items:center;">
        <span class="muted">校验和 (${escapeHtml(report.checksum.algorithm || 'SM3')}):</span>
        <span style="word-break:break-all; color:var(--text); font-weight:600;">${escapeHtml(report.checksum.value)}</span>
        ${report.checksum.size != null ? `<span class="muted">(${formatHumanSize(report.checksum.size)})</span>` : ''}
      </div>
    `;
  }

  if (Array.isArray(report.by_format) && report.by_format.length > 0) {
    html += `
      <div style="padding:6px 14px; font-size:11px; background:rgba(127,127,127,.02); border-bottom:1px solid var(--line); display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
        <span class="muted">格式分布:</span>
    `;
    for (const st of report.by_format) {
      const fmtInfo = getDstreeFormatInfo(st.format);
      html += `<span class="dstree-fmt ${fmtInfo.className}" style="font-size:10px;">${escapeHtml(fmtInfo.label)} ×${st.count}</span>`;
    }
    html += `</div>`;
  }

  html += `
    <div class="dstree-toolbar">
      <div class="dstree-toolbar-group">
        <button type="button" class="secondary dstree-btn-sm" onclick="expandAllTreeNodes()">全部展开</button>
        <button type="button" class="secondary dstree-btn-sm" onclick="collapseAllTreeNodes()">全部折叠</button>
        <div style="display:inline-flex; border:1px solid var(--line); border-radius:6px; overflow:hidden;">
          <button type="button" class="dstree-btn-sm ${resourceInfoViewMode === 'tree' ? 'success' : 'secondary'}" style="border-radius:0;" onclick="switchResourceInfoViewMode('tree')">🌳 目录树</button>
          <button type="button" class="dstree-btn-sm ${resourceInfoViewMode === 'raw' ? 'success' : 'secondary'}" style="border-radius:0;" onclick="switchResourceInfoViewMode('raw')">📄 原始 JSON</button>
        </div>
        <input type="text" placeholder="过滤文件或字段..." value="${escapeHtml(resourceInfoSearchFilter)}" oninput="onTreeSearchInput(this.value)" style="width:150px; padding:3px 8px; font-size:12px; border-radius:6px; margin:0;">
      </div>
      <div class="dstree-legend">
        <span class="dstree-fmt dstree-fmt-csv">CSV</span>
        <span class="dstree-fmt dstree-fmt-xlsx">XLSX</span>
        <span class="dstree-fmt dstree-fmt-json">JSON</span>
        <span class="dstree-fmt dstree-fmt-sqlite">SQLITE</span>
        <span class="dstree-fmt dstree-fmt-parquet">PARQUET</span>
        <span class="dstree-fmt dstree-fmt-image">IMAGE</span>
        <span class="dstree-fmt dstree-fmt-text">TEXT</span>
      </div>
    </div>
  `;

  if (resourceInfoViewMode === 'tree') {
    html += `
      <div class="dstree-body-split">
        <div class="dstree-tree-pane" style="${isModal ? 'max-height: calc(85vh - 200px);' : ''}">
          ${renderTreeNodeHTML(tree, resourceInfoSearchFilter, isModal)}
        </div>
        <aside class="dstree-detail-pane" style="${isModal ? 'width: 320px; max-height: calc(85vh - 200px);' : ''}">
          ${renderTreeDetailHTML(resourceInfoSelectedNode || tree)}
        </aside>
      </div>
    `;
  } else {
    const rawFormatted = resourceInfoRawResponseText || JSON.stringify(report, null, 2);
    html += `
      <div style="padding:12px; overflow:auto; max-height:${isModal ? 'calc(85vh - 200px)' : '480px'}; background:rgba(127,127,127,.03);">
        <div style="display:flex; justify-content:flex-end; margin-bottom:6px;">
          <button type="button" class="secondary dstree-btn-sm" onclick="copyText(resourceInfoRawResponseText || JSON.stringify(resourceInfoReportData, null, 2))">复制 JSON</button>
        </div>
        <pre style="margin:0; font-size:12px; line-height:1.5; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; white-space:pre-wrap; word-break:break-all;">${highlightJSON(rawFormatted)}</pre>
      </div>
    `;
  }

  html += `</div>`;
  targetEl.innerHTML = html;
}

function refreshResourceInfoTreeViews() {
  if (isResourceInfoModalOpen) {
    const modalBody = document.getElementById('resourceInfoModalBody');
    if (modalBody) {
      renderResourceInfoTreeShell(modalBody, true);
    }
  }
}

function openResourceInfoModal() {
  if (!resourceInfoReportData) return;
  isResourceInfoModalOpen = true;
  const modal = document.getElementById('resourceInfoModal');
  const modalBody = document.getElementById('resourceInfoModalBody');
  if (modal && modalBody) {
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    renderResourceInfoTreeShell(modalBody, true);
  }
}

function closeResourceInfoModal() {
  isResourceInfoModalOpen = false;
  const modal = document.getElementById('resourceInfoModal');
  if (modal) {
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
  }
}

function loadSampleResourceTree() {
  const sampleData = {
    version: "1.0.0",
    generated_at: new Date().toISOString(),
    total_files: 17,
    total_size: 18800,
    total_size_h: "18.4KB",
    structured_files: 5,
    checksum: {
      algorithm: "SM3",
      value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      size: 18800
    },
    by_format: [
      { format: "image/png", count: 8, size_sum: 1115 },
      { format: "text/csv", count: 1, size_sum: 119 },
      { format: "spreadsheet/xlsx", count: 1, size_sum: 4916 },
      { format: "database/sqlite", count: 1, size_sum: 12288 },
      { format: "text/jsonl", count: 1, size_sum: 240 },
      { format: "text/json", count: 1, size_sum: 71 },
      { format: "text/plain", count: 4, size_sum: 51 }
    ],
    tree: {
      name: "dataset",
      type: "dir",
      file_count: 17,
      children: [
        {
          name: "annotations",
          type: "dir",
          file_count: 3,
          children: [
            {
              name: "empty.csv",
              type: "file",
              fmt: "csv",
              size: 0,
              size_h: "0B",
              empty: true,
              warning: "空文件"
            },
            {
              name: "train_labels.csv",
              type: "file",
              fmt: "csv",
              size: 119,
              size_h: "119B",
              rows: 4,
              fields: [
                { name: "image", type: "string" },
                { name: "label", type: "int" },
                { name: "bbox", type: "string" }
              ]
            },
            {
              name: "metadata.jsonl",
              type: "file",
              fmt: "jsonl",
              size: 240,
              size_h: "240B",
              rows: 10,
              fields: [
                { name: "id", type: "string" },
                { name: "timestamp", type: "int64" }
              ]
            }
          ]
        },
        {
          name: "images",
          type: "dir",
          file_count: 8,
          children: [
            { name: "cat_001.png", type: "file", fmt: "png", size: 140, size_h: "140B" },
            { name: "cat_002.png", type: "file", fmt: "png", size: 145, size_h: "145B" },
            { name: "dog_001.png", type: "file", fmt: "png", size: 138, size_h: "138B" }
          ]
        },
        {
          name: "tables",
          type: "dir",
          file_count: 2,
          children: [
            {
              name: "stats.xlsx",
              type: "file",
              fmt: "xlsx",
              size: 4916,
              size_h: "4.8KB",
              rows: 120,
              fields: [
                { name: "department", type: "string" },
                { name: "revenue", type: "float64" },
                { name: "headcount", type: "int" }
              ]
            },
            {
              name: "records.db",
              type: "file",
              fmt: "sqlite",
              size: 12288,
              size_h: "12.0KB",
              tables: [
                { name: "users", rows: 50 },
                { name: "logs", rows: 1250 }
              ]
            }
          ]
        }
      ]
    }
  };

  resourceInfoReportData = sampleData;
  resourceInfoRawResponseText = JSON.stringify(sampleData, null, 2);
  ensureNodePaths(resourceInfoReportData.tree, '');
  defaultExpandTree(resourceInfoReportData.tree);
  resourceInfoSelectedNode = resourceInfoReportData.tree;
  const modalBtn = document.getElementById('resourceInfoModalBtn');
  if (modalBtn) modalBtn.disabled = false;
  refreshResourceInfoTreeViews();
  if (typeof recordInteraction === 'function') {
    recordInteraction('resourceInfo', {
      title: '/v1/taa/getResourceInfo 资源信息详情',
      primaryLabel: '返回内容',
      secondaryLabel: '请求体',
      primaryContent: sampleData,
      secondaryContent: { resourceUrl: 'http://example.com/data.tar.gz' },
    });
  }
  if (typeof showResult === 'function') {
    showResult('resourceInfoResult', true, '已加载示例目录树数据（17 个文件，5 个结构化）');
  }
}

async function testGetResourceInfo() {
  if (typeof showResultRunning === 'function') {
    showResultRunning('resourceInfoResult', '正在请求并分析资源...');
  }
  resourceInfoReportData = null;
  resourceInfoRawResponseText = '';
  resourceInfoSelectedNode = null;
  const modalBtn = document.getElementById('resourceInfoModalBtn');
  if (modalBtn) modalBtn.disabled = true;
  const resourceUrl = (document.getElementById('resourceInfoUrl')?.value || '').trim();
  if (typeof recordInteraction === 'function') {
    recordInteraction('resourceInfo', {
      title: '/v1/taa/getResourceInfo 资源信息详情',
      primaryLabel: '返回内容',
      secondaryLabel: '请求体',
      primaryContent: null,
      secondaryContent: { resourceUrl },
    });
  }
  try {
    const r = await postToTAA('/v1/taa/getResourceInfo', { resourceUrl }, RESOURCE_INFO_TIMEOUT_MS);
    const payload = responseResult(r.data);
    let rawText = '';
    let reportObj = null;
    if (typeof payload === 'string') {
      rawText = payload;
      try {
        reportObj = JSON.parse(payload);
      } catch (_) {}
    } else if (payload && typeof payload === 'object') {
      reportObj = payload;
      rawText = JSON.stringify(payload, null, 2);
    }

    if (typeof recordInteraction === 'function') {
      recordInteraction('resourceInfo', { primaryContent: reportObj || rawText || payload });
    }

    if (reportObj && (reportObj.tree || reportObj.name)) {
      resourceInfoReportData = reportObj;
      resourceInfoRawResponseText = rawText || JSON.stringify(reportObj, null, 2);
      const rootNode = reportObj.tree || reportObj;
      ensureNodePaths(rootNode, '');
      defaultExpandTree(rootNode);
      resourceInfoSelectedNode = rootNode;
      const modalBtn = document.getElementById('resourceInfoModalBtn');
      if (modalBtn) modalBtn.disabled = false;
      refreshResourceInfoTreeViews();
      if (typeof showResult === 'function') {
        showResult('resourceInfoResult', true, 'HTTP ' + r.status + ' 资源解析成功（共 ' + (reportObj.total_files || 0) + ' 个文件）');
      }
    } else {
      const rendered = typeof payload === 'string' ? formatJSONText(payload) : JSON.stringify(payload, null, 2);
      if (typeof showResult === 'function') {
        showResult('resourceInfoResult', r.status === 200 && r.data.error === 0, 'HTTP ' + r.status + '\n' + rendered);
      }
    }
  } catch (e) {
    const msg = isAbortLikeError(e)
      ? '请求超时（120s）：资源信息分析较慢，请稍后重试或检查 TAA 是否仍在执行。'
      : '请求失败: ' + e.message + '\n请确认 TAA 服务地址是否正确且服务已启动。';
    if (typeof recordInteraction === 'function') {
      recordInteraction('resourceInfo', { primaryContent: msg });
    }
    if (typeof showResult === 'function') {
      showResult('resourceInfoResult', false, msg);
    }
  }
}
