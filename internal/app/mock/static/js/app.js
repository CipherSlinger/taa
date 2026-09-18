// ── Main Platform-Mock Application Controller ──

// Global State
const resultBodies = {};
const interactionStore = {};
let lastHealthData = null;
let lastRegisterData = null;
let lastReportResData = null;
let reportResHistory = [];
let lastReportModelImportData = null;
let lastReportAuditData = null;
let uploadedFiles = [];
let currentPhase = 1;
let lastPhaseSwitchResp = null;
let lastRegisterModalTitle = '平台注册返回 body';
let lastRegisterModalBody = null;

// DOM Helpers
function text(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value || '-';
}

function area(id, value) {
  const el = document.getElementById(id);
  if (el) el.value = value || '';
}

function genId(prefix) {
  return prefix + '-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
}

function randomizeField(id, prefix) {
  const input = document.getElementById(id);
  if (!input) return '';
  const newId = genId(prefix || 'id');
  input.value = newId;
  input.classList.remove('input-flash-success');
  void input.offsetWidth;
  input.classList.add('input-flash-success');
  setTimeout(() => input.classList.remove('input-flash-success'), 1200);
  return newId;
}

function randomizeImportModelIds() {
  randomizeField('importModelRequestId', 'req-model');
  randomizeField('importModelTaskId', 'task-model');
}

function randomizeImportIds() {
  randomizeField('importRequestId', 'req-data');
  randomizeField('importTaskId', 'task-data');
}

// ── File Upload Formatting & Drag-and-Drop ──
function formatUploadSize(size) {
  const value = Number(size) || 0;
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let scaled = value / 1024;
  let index = 0;
  while (scaled >= 1024 && index < units.length - 1) {
    scaled /= 1024;
    index += 1;
  }
  const t = scaled >= 10 || Number.isInteger(scaled) ? scaled.toFixed(0) : scaled.toFixed(1);
  return `${t} ${units[index]}`;
}

function formatUploadTime(value) {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('zh-CN', { hour12: false });
}

function normalizeUploadedFile(file) {
  if (!file) return null;
  return {
    filename: file.filename || '',
    originalName: file.originalName || file.filename || '',
    size: Number(file.size || 0),
    url: file.url || '',
    uploadedAt: file.uploadedAt || '',
    encrypted: Boolean(file.encrypted),
  };
}

function getFileIcon(filename, encrypted) {
  if (encrypted || (filename && filename.toLowerCase().endsWith('.enc'))) {
    return '🔒';
  }
  const lower = (filename || '').toLowerCase();
  if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz') || lower.endsWith('.tar') || lower.endsWith('.zip') || lower.endsWith('.gz')) {
    return '📦';
  }
  if (lower.endsWith('.py') || lower.endsWith('.sh') || lower.endsWith('.bash')) {
    return '📜';
  }
  if (lower.endsWith('.json') || lower.endsWith('.txt') || lower.endsWith('.csv') || lower.endsWith('.md')) {
    return '📋';
  }
  return '📄';
}

function onUploadItemDragStart(ev, el) {
  const url = decodeURIComponent(el.dataset.url || '');
  if (!url) return;
  ev.dataTransfer.setData('text/plain', url);
  ev.dataTransfer.setData('application/x-resource-url', url);
  ev.dataTransfer.effectAllowed = 'copy';
  el.classList.add('dragging');
  document.querySelectorAll('.drop-zone-card').forEach(card => card.classList.add('drop-hint'));
}

function onUploadItemDragEnd(ev, el) {
  el.classList.remove('dragging');
  document.querySelectorAll('.drop-zone-card').forEach(card => {
    card.classList.remove('drop-hint');
    card.classList.remove('drag-target-hover');
  });
}

function setupResourceUrlDropZones() {
  const dropTargets = [
    { cardId: 'card-importModel', inputId: 'importModelResourceUrl' },
    { cardId: 'card-import', inputId: 'importResourceUrl' },
    { cardId: 'card-resourceInfo', inputId: 'resourceInfoUrl' },
  ];

  dropTargets.forEach(({ cardId, inputId }) => {
    const card = document.getElementById(cardId);
    const input = document.getElementById(inputId);
    if (!card || !input) return;

    card.classList.add('drop-zone-card');

    card.addEventListener('dragover', (ev) => {
      ev.preventDefault();
      ev.dataTransfer.dropEffect = 'copy';
      card.classList.add('drag-target-hover');
    });

    card.addEventListener('dragleave', (ev) => {
      if (!card.contains(ev.relatedTarget)) {
        card.classList.remove('drag-target-hover');
      }
    });

    card.addEventListener('drop', (ev) => {
      ev.preventDefault();
      card.classList.remove('drag-target-hover');
      card.classList.remove('drop-hint');
      const url = ev.dataTransfer.getData('application/x-resource-url') || ev.dataTransfer.getData('text/plain') || '';
      if (url && url.trim()) {
        input.value = url.trim();
        input.classList.remove('input-flash-success');
        void input.offsetWidth;
        input.classList.add('input-flash-success');
        setTimeout(() => input.classList.remove('input-flash-success'), 1200);
      }
    });
  });
}

function renderUploadedFiles(files) {
  uploadedFiles = Array.isArray(files) ? files.slice() : [];
  const countEl = document.getElementById('uploadedFilesCount');
  const listEl = document.getElementById('uploadedFilesList');
  const clearBar = document.getElementById('uploadClearBar');
  if (countEl) countEl.textContent = `${uploadedFiles.length} 个文件`;
  if (clearBar) clearBar.style.display = uploadedFiles.length ? 'flex' : 'none';
  if (!listEl) return;

  if (!uploadedFiles.length) {
    listEl.innerHTML = '<div class="upload-empty">暂无上传文件</div>';
    return;
  }

  listEl.innerHTML = uploadedFiles.map(file => {
    const originalName = escapeHtml(file.originalName || file.filename || '未命名文件');
    const rawFilename = file.filename || '';
    const rawUrl = file.url || '';
    const url = escapeHtml(rawUrl);
    const uploadedAt = escapeHtml(formatUploadTime(file.uploadedAt));
    const size = escapeHtml(formatUploadSize(file.size));
    const isEncrypted = Boolean(file.encrypted || (file.originalName && file.originalName.toLowerCase().endsWith('.enc')) || (file.filename && file.filename.toLowerCase().endsWith('.enc')));
    const icon = getFileIcon(file.originalName || file.filename, isEncrypted);

    return `<div class="upload-item" draggable="true" data-url="${encodeURIComponent(rawUrl)}" ondragstart="onUploadItemDragStart(event, this)" ondragend="onUploadItemDragEnd(event, this)" title="拖拽至右侧卡片自动填入 resourceUrl&#10;文件: ${originalName}&#10;大小: ${size}&#10;时间: ${uploadedAt}&#10;URL: ${url}">` +
      `<div class="upload-item-main">` +
        `<span class="upload-item-icon">${icon}</span>` +
        `<span class="upload-item-name" title="${originalName}">${originalName}</span>` +
      `</div>` +
      `<button type="button" class="upload-item-del" title="删除文件" data-filename="${encodeURIComponent(rawFilename)}" onclick="event.stopPropagation(); deleteUploadedFile(decodeURIComponent(this.dataset.filename))">×</button>` +
    `</div>`;
  }).join('');
}

async function deleteUploadedFile(filename) {
  if (!filename) return;
  if (!confirm(`确认删除文件 ${filename} 吗？`)) return;

  try {
    const res = await fetch('/api/upload/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename }),
    });
    const data = await res.json();
    if (res.status === 200 && data.error === 0) {
      uploadedFiles = uploadedFiles.filter(item => item.filename !== filename);
      renderUploadedFiles(uploadedFiles);
      await refreshUploadedFiles();
    } else {
      alert(`删除失败: ${data.msg || '未知错误'}`);
    }
  } catch (err) {
    alert(`删除失败: ${err.message}`);
  }
}

async function refreshUploadedFiles() {
  try {
    const res = await fetch('/api/uploads', { cache: 'no-store' });
    const data = await res.json();
    const result = responseResult(data);
    renderUploadedFiles((result && result.files) || []);
  } catch (err) {
    if (uploadedFiles.length === 0) {
      const listEl = document.getElementById('uploadedFilesList');
      if (listEl) listEl.innerHTML = `<div class="upload-empty">加载上传历史失败：${escapeHtml(String(err))}</div>`;
      const countEl = document.getElementById('uploadedFilesCount');
      if (countEl) countEl.textContent = '加载失败';
    }
  }
}

async function clearUploadedFiles() {
  showResultRunning('uploadResult', '正在清空上传文件...');
  try {
    const res = await fetch('/api/uploads/reset', { method: 'POST' });
    const data = await res.json();
    if (res.status === 200 && data.error === 0) {
      renderUploadedFiles([]);
      showResult('uploadResult', true, `已清空 ${data.result && typeof data.result.deleted === 'number' ? data.result.deleted : 0} 个文件`);
      await refreshUploadedFiles();
    } else {
      showResult('uploadResult', false, `清空失败: ${data.msg || '未知错误'}`);
    }
  } catch (e) {
    showResult('uploadResult', false, '清空失败: ' + e.message);
  }
}

async function uploadFile() {
  const fileInput = document.getElementById('uploadFile');
  if (!fileInput || !fileInput.files.length) {
    alert('请先选择文件');
    return;
  }
  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append('file', file);

  const encryptSwitch = document.getElementById('uploadEncryptSwitch');
  const isEncrypted = encryptSwitch && encryptSwitch.checked;
  if (isEncrypted) {
    formData.append('encrypt', 'true');
    if (lastRegisterData && lastRegisterData.taaPublicKey) {
      formData.append('publicKey', lastRegisterData.taaPublicKey);
    }
  }

  const uploadMeta = {
    fileName: file.name,
    fileSize: file.size,
    encrypted: isEncrypted,
    publicKey: isEncrypted ? (lastRegisterData && lastRegisterData.taaPublicKey ? '(配置已指定公钥)' : '未提供公钥') : '不加密',
  };
  recordInteraction('upload', {
    title: '文件上传详情 (/api/upload)',
    primaryLabel: '返回内容',
    secondaryLabel: '请求体',
    primaryContent: null,
    secondaryContent: uploadMeta,
    endpoint: '/api/upload',
    reqBody: uploadMeta,
  });

  showResultRunning('uploadResult', isEncrypted ? '正在加密并上传文件...' : '正在上传文件...');
  try {
    const res = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();
    recordInteraction('upload', { primaryContent: data, respBody: data, statusCode: res.status });
    if (res.status === 200 && data.error === 0) {
      const uploaded = normalizeUploadedFile(data.result);
      if (uploaded) {
        renderUploadedFiles([uploaded, ...uploadedFiles.filter(item => item.filename !== uploaded.filename)]);
      }
      const encNote = data.result.encrypted ? ' (已使用 TAA 注册公钥加密)' : '';
      showResult('uploadResult', true, `文件上传成功${encNote}\n\n文件名: ${data.result.originalName}\n保存名: ${data.result.filename}\n大小: ${data.result.size} bytes\nURL: ${data.result.url}`);
      fileInput.value = '';
      await refreshUploadedFiles();
    } else {
      showResult('uploadResult', false, `上传失败: ${data.msg}`);
    }
  } catch (e) {
    recordInteraction('upload', { primaryContent: '上传失败: ' + e.message, respBody: e.message, statusCode: 500 });
    showResult('uploadResult', false, '上传失败: ' + e.message);
  }
}

// ── Result & Drawer Integration ──
const RESULT_TITLES = {
  uploadResult: '文件上传返回',
  importResult: '/v1/taa/import 返回',
  importModelResult: '/v1/taa/importModel 返回',
  resourceInfoResult: '/v1/taa/getResourceInfo 返回',
  switchResult: '/v1/taa/switch 返回',
  attestationResult: '/v1/taa/getAttestation 返回',
};

const RESULT_INTERACTION_KEYS = {
  uploadResult: 'upload',
  importResult: 'import',
  importModelResult: 'importModel',
  resourceInfoResult: 'resourceInfo',
  switchResult: 'switch',
  attestationResult: 'attestation',
};

const HEADER_RESULT_MAPPINGS = {
  uploadResult: {
    btnId: 'uploadBodyBtn',
    boxId: 'uploadStatusBox',
    dotId: 'uploadDot',
    textId: 'uploadStatusText',
  },
  importModelResult: {
    btnId: 'importModelBodyBtn',
    boxId: 'importModelStatusBox',
    dotId: 'importModelDot',
    textId: 'importModelStatusText',
  },
  importResult: {
    btnId: 'importBodyBtn',
    boxId: 'importStatusBox',
    dotId: 'importDot',
    textId: 'importStatusText',
  },
};

function recordInteraction(key, data) {
  if (!interactionStore[key]) {
    interactionStore[key] = {
      title: '接口详情',
      primaryLabel: '返回内容',
      secondaryLabel: '请求体',
      primaryContent: null,
      secondaryContent: null,
      respBody: null,
      reqBody: null,
      statusCode: null,
      badgeType: null,
      badgeData: null,
      badgeBuilder: null,
    };
  }
  if (data && typeof data === 'object') {
    Object.assign(interactionStore[key], data);
  }
}

function renderInteractionBadge(item) {
  if (!item) return '';
  if (typeof item.badgeBuilder === 'function') {
    return item.badgeBuilder(item);
  }

  const badgeType = item.badgeType;
  if (!badgeType) return '';

  const data = item.badgeData != null ? item.badgeData : item.primaryContent;
  const parsedData = (typeof data === 'string') ? parseJSONMaybe(data) : data;
  if (!parsedData || typeof parsedData !== 'object') return '';

  if (badgeType === 'modelImport') {
    const rawBody = parseJSONMaybe(parsedData.rawBody);
    const body = rawBody && typeof rawBody === 'object' ? rawBody : parsedData;
    const checksum = parsedData.checksum || body.checksum;
    if (checksum && typeof checksum === 'object') {
      const algo = checksum.algorithm || 'SM3';
      const size = checksum.size != null ? checksum.size : '-';
      const val = checksum.value || '';
      return '<div style="display:flex; flex-direction:column; gap:4px;">' +
        '<div style="font-weight:700; color:var(--ok);">✓ 模型完整性校验 (checksum)</div>' +
        '<div style="font-size:12px; font-family:monospace; word-break:break-all;">算法: <b>' + escapeHtml(algo) + '</b> | 大小: <b>' + escapeHtml(String(size)) + ' bytes</b></div>' +
        '<div style="font-size:11.5px; font-family:monospace; word-break:break-all; color:var(--muted);">哈希值: ' + escapeHtml(val) + '</div>' +
        '</div>';
    }
  } else if (badgeType === 'audit') {
    const rawBody = parseJSONMaybe(parsedData.rawBody);
    const body = rawBody && typeof rawBody === 'object' ? rawBody : parsedData;
    const reportObj = (body.report && typeof body.report === 'object') ? body.report : (parseJSONMaybe(body.report) || {});
    const stats = parsedData.statistics || (reportObj.conclusion && reportObj.conclusion.statistics);
    const riskLevel = parsedData.riskLevel || parsedData.risk_level || (reportObj.conclusion && reportObj.conclusion.risk_level);
    if (stats) {
      const high = stats.high !== undefined ? stats.high : 0;
      const med = stats.medium !== undefined ? stats.medium : 0;
      const low = stats.low !== undefined ? stats.low : 0;
      const rlUpper = escapeHtml(String(riskLevel || 'UNKNOWN').toUpperCase());
      const rlColor = riskLevel === 'high' ? 'var(--bad)' : (riskLevel === 'medium' ? '#f59e0b' : 'var(--ok)');
      return '<div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">' +
        '<span>风险等级: <strong style="color:' + rlColor + ';">' + rlUpper + '</strong></span>' +
        '<span style="color:var(--muted);">|</span>' +
        '<span style="color:var(--bad); font-weight:600;">高危(high): ' + escapeHtml(String(high)) + '</span>' +
        '<span style="color:var(--muted);">|</span>' +
        '<span style="color:#f59e0b; font-weight:600;">中危(medium): ' + escapeHtml(String(med)) + '</span>' +
        '<span style="color:var(--muted);">|</span>' +
        '<span style="color:#059669; font-weight:600;">低危(low): ' + escapeHtml(String(low)) + '</span>' +
        '</div>';
    }
  }
  return '';
}

function openStoredResult(elId) {
  const key = RESULT_INTERACTION_KEYS[elId];
  if (key) {
    openInteractionDrawer(key, 'primary');
    return;
  }
  openBodyModal(RESULT_TITLES[elId] || '返回 body', resultBodies[elId]);
}

function showResult(elId, ok, text) {
  resultBodies[elId] = text || '';
  const key = RESULT_INTERACTION_KEYS[elId];
  if (key) {
    if (!interactionStore[key] || interactionStore[key].primaryContent == null) {
      recordInteraction(key, { primaryContent: text || '', respBody: text || '' });
    }
  }
  const mapping = HEADER_RESULT_MAPPINGS[elId];
  if (mapping) {
    const box = document.getElementById(mapping.boxId);
    const dot = document.getElementById(mapping.dotId);
    const txt = document.getElementById(mapping.textId);
    const btn = document.getElementById(mapping.btnId);
    if (box) box.style.display = 'inline-flex';
    if (dot) dot.className = 'dot ' + (ok ? 'ok status-pill ok' : 'bad status-pill bad');
    if (txt) txt.textContent = ok ? '请求完成' : '请求失败';
    if (btn) {
      btn.disabled = !text;
      btn.onclick = () => openStoredResult(elId);
    }
  }
  const el = document.getElementById(elId);
  if (el && !mapping) {
    el.style.display = 'block';
    el.className = 'test-result ' + (ok ? 'pass' : 'fail');
    el.innerHTML = '';
    const row = document.createElement('div');
    row.className = 'result-row';
    const state = document.createElement('span');
    state.className = 'result-state';
    state.textContent = ok ? '请求完成' : '请求失败';
    row.appendChild(state);

    const btnGroup = document.createElement('div');
    btnGroup.style.display = 'flex';
    btnGroup.style.gap = '6px';
    btnGroup.style.alignItems = 'center';

    if (elId === 'resourceInfoResult' && ok && typeof resourceInfoReportData !== 'undefined' && resourceInfoReportData) {
      const treeBtn = document.createElement('button');
      treeBtn.type = 'button';
      treeBtn.className = 'success result-body-btn';
      treeBtn.textContent = '查看目录树';
      treeBtn.onclick = () => openResourceInfoModal();
      btnGroup.appendChild(treeBtn);
    }

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'secondary result-body-btn';
    btn.textContent = '查看返回';
    btn.onclick = () => openStoredResult(elId);
    btn.disabled = !text;
    btnGroup.appendChild(btn);

    row.appendChild(btnGroup);

    const note = document.createElement('div');
    note.className = 'result-note';
    if (elId === 'resourceInfoResult' && ok && typeof resourceInfoReportData !== 'undefined' && resourceInfoReportData) {
      note.textContent = '点击“查看目录树”弹窗浏览完整资源结构，点击“查看返回”查看原始数据。';
    } else {
      note.textContent = text ? '完整返回已收起到抽屉中。' : '暂无返回内容。';
    }
    el.appendChild(row);
    el.appendChild(note);
  }
}

function showResultRunning(elId, text) {
  const key = RESULT_INTERACTION_KEYS[elId];
  if (key && interactionStore[key]) {
    interactionStore[key].primaryContent = null;
  }
  const mapping = HEADER_RESULT_MAPPINGS[elId];
  if (mapping) {
    const box = document.getElementById(mapping.boxId);
    const dot = document.getElementById(mapping.dotId);
    const txt = document.getElementById(mapping.textId);
    const btn = document.getElementById(mapping.btnId);
    if (box) box.style.display = 'inline-flex';
    if (dot) dot.className = 'dot status-pill running';
    if (txt) txt.textContent = text || '请求中...';
    if (btn) btn.disabled = true;
  }
  const el = document.getElementById(elId);
  if (el && !mapping) {
    el.style.display = 'block';
    el.className = 'test-result running';
    el.innerHTML = '';
    const row = document.createElement('div');
    row.className = 'result-row';
    const state = document.createElement('span');
    state.className = 'result-state';
    state.textContent = text || '请求中...';
    row.appendChild(state);
    el.appendChild(row);
  }
}

function setHealthState(className, title, labelText, labelColor) {
  const dot = document.getElementById('healthDot');
  const label = document.getElementById('healthLabel');
  const pill = document.getElementById('healthPill');
  if (dot) {
    dot.className = className;
    dot.title = title;
  }
  if (label) {
    label.textContent = labelText;
    label.style.color = labelColor || '';
  }
  if (pill) {
    if (className.includes('ok')) {
      pill.className = 'status-pill ok';
    } else if (className.includes('bad')) {
      pill.className = 'status-pill bad';
    } else if (className.includes('running')) {
      pill.className = 'status-pill running';
    } else {
      pill.className = 'status-pill pending';
    }
  }
}

// ── Dynamic Command & Env Rows ──
function addModelCommandRow(btn) {
  const container = document.getElementById('importModelCommandsList');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'dynamic-input-row';
  row.style.cssText = 'display:flex; gap:6px; align-items:center;';
  row.innerHTML =
    '<input type="text" class="import-model-cmd-input" placeholder="单条命令，如 python3 train.py" style="flex:1; margin:0;">' +
    '<button type="button" class="icon-btn-compact" onclick="addModelCommandRow(this)" title="添加一行" style="padding:4px 8px; font-size:12px;">+</button>' +
    '<button type="button" class="icon-btn-compact danger" onclick="removeModelRow(this)" title="删除此行" style="padding:4px 8px; font-size:12px;">-</button>';
  container.appendChild(row);
}

function addModelEnvRow(btn) {
  const container = document.getElementById('importModelEnvList');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'dynamic-input-row';
  row.style.cssText = 'display:flex; gap:6px; align-items:center;';
  row.innerHTML =
    '<input type="text" class="import-model-env-input" placeholder="KEY=VALUE" style="flex:1; margin:0;">' +
    '<button type="button" class="icon-btn-compact" onclick="addModelEnvRow(this)" title="添加一行" style="padding:4px 8px; font-size:12px;">+</button>' +
    '<button type="button" class="icon-btn-compact danger" onclick="removeModelRow(this)" title="删除此行" style="padding:4px 8px; font-size:12px;">-</button>';
  container.appendChild(row);
}

function removeModelRow(btn) {
  const row = btn?.closest('.dynamic-input-row');
  const container = row?.parentElement;
  if (row && container && container.querySelectorAll('.dynamic-input-row').length > 1) {
    row.remove();
  }
}

function collectModelCommands() {
  const inputs = document.querySelectorAll('.import-model-cmd-input');
  const cmds = [];
  inputs.forEach((input) => {
    const val = (input.value || '').trim();
    if (val) cmds.push(val);
  });
  return cmds;
}

function collectModelEnv() {
  const inputs = document.querySelectorAll('.import-model-env-input');
  const envObj = {};
  inputs.forEach((input) => {
    const raw = (input.value || '').trim();
    if (!raw) return;
    if (raw.startsWith('{') && raw.endsWith('}')) {
      const parsed = parseJSONMaybe(raw);
      if (parsed && typeof parsed === 'object') {
        Object.assign(envObj, parsed);
        return;
      }
    }
    const eqIdx = raw.indexOf('=');
    if (eqIdx !== -1) {
      const k = raw.slice(0, eqIdx).trim();
      const v = raw.slice(eqIdx + 1).trim();
      if (k) envObj[k] = v;
    }
  });
  return Object.keys(envObj).length > 0 ? JSON.stringify(envObj) : '';
}

function buildRuntimeConfig(commands, env) {
  const cmdList = Array.isArray(commands) ? commands : (commands || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const envStr = typeof env === 'string' ? env.trim() : (env ? JSON.stringify(env) : '');
  if (!cmdList.length && !envStr) return '';
  return JSON.stringify({ commands: cmdList, env: envStr });
}

function buildImportBody(resourceUrl, requestId, publicKey, taskId, runtimeConfig) {
  const body = { resourceUrl };
  if (requestId) body.requestId = requestId;
  if (taskId) body.taskId = taskId;
  if (publicKey) body.publicKey = publicKey;
  if (runtimeConfig) body.runtimeConfig = runtimeConfig;
  return body;
}

// ── State Handlers & Renderers ──
function renderRegister(data) {
  lastRegisterData = data || null;
  lastRegisterModalTitle = '平台注册返回 body';
  lastRegisterModalBody = data;
  recordInteraction('register', {
    title: '平台注册详情',
    primaryLabel: '上报内容 (TAA请求体)',
    secondaryLabel: '平台应答',
    primaryContent: data,
    secondaryContent: { code: 0, msg: 'ok', result: { accepted: Boolean(data && data.accepted) } },
    endpoint: '/v1/taa/register',
  });
  const dot = document.getElementById('dot');
  const pill = document.getElementById('registerPill');
  if (dot) dot.className = 'dot';
  const publicKeyBox = document.getElementById('registerPublicKeyBox');
  const publicKeyField = document.getElementById('registerPublicKey');
  if (!data || !data.received) {
    if (pill) pill.className = 'status-pill pending';
    text('statusText', '等待 TAA 注册请求');
    const regBtn = document.getElementById('registerBodyBtn');
    if (regBtn) regBtn.disabled = true;
    if (publicKeyBox) publicKeyBox.hidden = true;
    if (publicKeyField) publicKeyField.value = '';
    return;
  }
  if (dot) dot.className = 'dot ' + (data.accepted ? 'ok status-pill ok' : 'bad status-pill bad');
  if (pill) pill.className = 'status-pill ' + (data.accepted ? 'ok' : 'bad');
  text('statusText', data.accepted ? '已收到注册请求，并已返回 HTTP 200' : '已收到请求，但参数校验失败');
  const regBtn = document.getElementById('registerBodyBtn');
  if (regBtn) regBtn.disabled = false;
  const publicKey = data.accepted ? String(data.taaPublicKey || '').trim() : '';
  if (publicKey) {
    if (publicKeyBox) publicKeyBox.hidden = false;
    if (publicKeyField) publicKeyField.value = publicKey;
  } else {
    if (publicKeyBox) publicKeyBox.hidden = true;
    if (publicKeyField) publicKeyField.value = '';
  }
}

function openRegisterBodyModal() {
  if (lastRegisterModalTitle && lastRegisterModalTitle.includes('/v1/taa/getAttestation')) {
    openInteractionDrawer('attestation', 'primary');
    return;
  }
  const body = lastRegisterModalBody != null ? lastRegisterModalBody : lastRegisterData;
  if (body != null && (!interactionStore['register'] || interactionStore['register'].primaryContent !== body)) {
    recordInteraction('register', {
      title: '平台注册详情',
      primaryLabel: '上报内容 (TAA请求体)',
      secondaryLabel: '平台应答',
      primaryContent: body,
      secondaryContent: { code: 0, msg: 'ok', result: { accepted: Boolean(body && body.accepted) } },
      endpoint: '/v1/taa/register',
    });
  }
  openInteractionDrawer('register', 'primary');
}

async function refreshStatus() {
  try {
    const res = await fetch('/api/register/status', { cache: 'no-store' });
    const data = await res.json();
    renderRegister(responseResult(data));
  } catch (err) {
    text('statusText', '刷新状态失败');
    text('message', String(err));
  }
}

async function resetStatus() {
  await fetch('/api/register/reset', { method: 'POST' });
  await refreshStatus();
}

function buildReportResBodyPreview(data) {
  if (!data || data.received === false) return null;
  const rawBody = parseJSONMaybe(data.rawBody);
  const body = rawBody && typeof rawBody === 'object' ? { ...rawBody } : { ...data };
  delete body.received;
  delete body.accepted;
  delete body.rawBody;
  delete body.history;
  if (Object.prototype.hasOwnProperty.call(body, 'report')) {
    body.report = parseJSONRecursively(body.report);
  }
  return body;
}

function renderReportRes(data) {
  lastReportResData = data || null;
  recordInteraction('reportRes', {
    title: '训练结果上报详情',
    primaryLabel: '上报内容 (TAA请求体)',
    secondaryLabel: '平台应答',
    primaryContent: buildReportResBodyPreview(data),
    secondaryContent: { error: 0, msg: 'ok' },
    endpoint: '/v1/taa/reportRes',
  });
  const dot = document.getElementById('reportResDot');
  if (dot) dot.className = 'dot';
  const reportBtn = document.getElementById('reportResReportBtn');
  const bodyBtn = document.getElementById('reportResBodyBtn');
  renderReportResHistory(data ? (data.history || (data.received ? [data] : [])) : []);
  if (!data || !data.received) {
    text('reportResStatusText', '等待训练结果上报');
    if (reportBtn) reportBtn.disabled = true;
    if (bodyBtn) bodyBtn.disabled = true;
    return;
  }
  if (dot) dot.className = 'dot ' + (data.accepted ? 'ok status-pill ok' : 'bad status-pill bad');
  text('reportResStatusText', data.accepted ? '已收到训练结果上报' : '已收到上报，但参数校验失败');
  if (reportBtn) reportBtn.disabled = false;
  if (bodyBtn) bodyBtn.disabled = false;
}

function renderReportResHistory(history) {
  reportResHistory = Array.isArray(history) ? history.slice() : [];
  const listEl = document.getElementById('reportResList');
  if (!listEl) return;
  if (!reportResHistory.length) {
    listEl.innerHTML = '<div class="upload-empty">暂无上报记录</div>';
    return;
  }
  listEl.innerHTML = reportResHistory.map((item, idx) => {
    const isOk = Boolean(item.accepted && item.code === 0);
    const dotClass = isOk ? 'dot ok status-pill ok' : 'dot bad status-pill bad';
    let timeStr = '-';
    if (item.receivedAt) {
      try {
        const d = new Date(item.receivedAt);
        timeStr = !isNaN(d.getTime()) ? d.toLocaleTimeString() : String(item.receivedAt);
      } catch {
        timeStr = String(item.receivedAt);
      }
    }
    const safeTimeStr = escapeHtml(timeStr);
    const taskId = escapeHtml(item.taskId || '未命名任务');
    const reqId = escapeHtml(item.requestId || '-');
    return `<div class="upload-item" style="cursor:default; padding:6px 10px;" title="requestId: ${reqId}">` +
      `<div class="upload-item-main" style="gap:8px;">` +
        `<span class="${dotClass}" style="margin:0; flex-shrink:0;"></span>` +
        `<span class="upload-item-name" style="font-weight:600;">${taskId}</span>` +
        `<span class="muted" style="font-size:11px; flex-shrink:0;">${safeTimeStr}</span>` +
      `</div>` +
      `<div style="display:flex; gap:6px; flex-shrink:0; align-items:center;">` +
        `<button type="button" class="secondary" style="padding:2px 8px; font-size:11px;" onclick="openReportItemModal(${idx})" title="查看报告">报告</button>` +
        `<button type="button" class="secondary" style="padding:2px 8px; font-size:11px;" onclick="openReportItemPayloadModal(${idx})" title="查看返回">返回</button>` +
        `<button type="button" class="secondary" style="padding:2px 8px; font-size:11px;" onclick="exportReportItem(${idx}, false, this)" title="直接导出结果文件">导出</button>` +
        `<button type="button" class="secondary" style="padding:2px 8px; font-size:11px;" onclick="exportReportItem(${idx}, true, this)" title="导出并解密">导出并解密</button>` +
      `</div>` +
    `</div>`;
  }).join('');
}

function openReportItemModal(idx) {
  const item = reportResHistory[idx];
  if (!item) return;
  let reportContent = item.report;
  if ((reportContent == null || reportContent === '') && item.rawBody) {
    const raw = parseJSONMaybe(item.rawBody);
    if (raw && typeof raw === 'object' && raw.report != null) {
      reportContent = raw.report;
    }
  }
  if (reportContent == null || reportContent === '') {
    openBodyModal(`训练结果报告 (${item.taskId || 'report'})`, '报告内容 (report 字段) 为空。');
    return;
  }
  openBodyModal(`训练结果报告 (${item.taskId || 'report'})`, reportContent);
}

function openReportItemPayloadModal(idx) {
  const item = reportResHistory[idx];
  if (!item) return;
  openBodyModal(`训练结果上报详情 (${item.taskId || 'payload'})`, item.rawBody || JSON.stringify(item, null, 2));
}

function openReportResReportModal() {
  const data = lastReportResData;
  if (!data || !data.received) {
    openBodyModal('训练结果具体报告 (report)', '等待训练结果上报中，暂无报告数据。');
    return;
  }
  let reportContent = data.report;
  if ((reportContent == null || reportContent === '') && data.rawBody) {
    const raw = parseJSONMaybe(data.rawBody);
    if (raw && typeof raw === 'object' && raw.report != null) {
      reportContent = raw.report;
    }
  }
  if (reportContent == null || reportContent === '') {
    openBodyModal('训练结果具体报告 (report)', '已收到训练结果上报，但报告内容 (report 字段) 为空。');
    return;
  }
  openBodyModal('训练结果具体报告 (report)', reportContent);
}

function openReportResBodyModal() {
  openInteractionDrawer('reportRes', 'primary');
}

async function refreshReportResStatus() {
  try {
    const res = await fetch('/api/reportRes/status', { cache: 'no-store' });
    const data = await res.json();
    renderReportRes({ ...responseResult(data), code: data.error, msg: data.msg });
  } catch (err) {
    text('reportResStatusText', '刷新上报状态失败');
  }
}

async function resetReportResStatus() {
  reportResHistory = [];
  renderReportResHistory([]);
  await fetch('/api/reportRes/reset', { method: 'POST' });
  await refreshReportResStatus();
}

function buildReportModelImportBodyPreview(data) {
  if (!data || data.received === false) return null;
  const rawBody = parseJSONMaybe(data.rawBody);
  const body = rawBody && typeof rawBody === 'object' ? { ...rawBody } : { ...data };
  delete body.received;
  delete body.accepted;
  delete body.rawBody;
  const checksum = (data && data.checksum) || body.checksum;
  if (checksum && typeof checksum === 'object') {
    body.checksum = checksum;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'report')) {
    body.report = parseJSONMaybe(body.report);
  }
  return body;
}

function setReportModelImportPending() {
  renderReportModelImport({ received: false, accepted: false });
}

function renderReportModelImport(data) {
  lastReportModelImportData = data || null;
  recordInteraction('reportModelImport', {
    title: '模型导入结果上报详情',
    primaryLabel: '上报内容 (TAA请求体)',
    secondaryLabel: '平台应答',
    primaryContent: buildReportModelImportBodyPreview(data),
    secondaryContent: { error: 0, msg: 'ok' },
    badgeType: 'modelImport',
    badgeData: data,
    endpoint: '/v1/taa/reportModelImport',
  });
  const dot = document.getElementById('reportModelImportDot');
  const bodyBtn = document.getElementById('reportModelImportBodyBtn');
  const pill = document.getElementById('reportModelImportPill');
  if (dot) dot.className = 'dot';
  if (!data || !data.received) {
    if (dot) dot.className = 'dot bad status-pill pending';
    if (pill) pill.className = 'status-pill pending';
    text('reportModelImportStatusText', '模型导入结果上报');
    if (bodyBtn) bodyBtn.disabled = true;
    return;
  }
  if (dot) dot.className = 'dot ' + (data.accepted ? 'ok status-pill ok' : 'bad status-pill bad');
  if (pill) pill.className = 'status-pill ' + (data.accepted ? 'ok' : 'bad');
  text('reportModelImportStatusText', data.accepted ? '模型导入结果上报' : '模型导入结果校验失败');
  if (bodyBtn) bodyBtn.disabled = false;
}

function openReportModelImportBodyModal() {
  openInteractionDrawer('reportModelImport', 'primary');
}

async function refreshReportModelImportStatus() {
  try {
    const res = await fetch('/api/reportModelImport/status', { cache: 'no-store' });
    const data = await res.json();
    renderReportModelImport({ ...responseResult(data), code: data.error, msg: data.msg });
  } catch (err) {
    text('reportModelImportStatusText', '刷新上报状态失败');
  }
}

async function resetReportModelImportStatus() {
  await fetch('/api/reportModelImport/reset', { method: 'POST' }).catch(() => {});
  setReportModelImportPending();
}

function buildReportAuditBodyPreview(data) {
  if (!data || data.received === false) return null;
  const rawBody = parseJSONMaybe(data.rawBody);
  const body = rawBody && typeof rawBody === 'object' ? { ...rawBody } : { ...data };
  delete body.received;
  delete body.accepted;
  delete body.rawBody;
  if (Object.prototype.hasOwnProperty.call(body, 'report')) {
    body.report = parseJSONMaybe(body.report);
  }
  return body;
}

function setReportAuditPending() {
  renderReportAudit({ received: false, accepted: false });
}

function renderReportAudit(data) {
  lastReportAuditData = data || null;
  recordInteraction('reportAudit', {
    title: '代码安全审计结果上报详情',
    primaryLabel: '上报内容 (TAA请求体)',
    secondaryLabel: '平台应答',
    primaryContent: buildReportAuditBodyPreview(data),
    secondaryContent: { error: 0, msg: 'ok' },
    badgeType: 'audit',
    badgeData: data,
    endpoint: '/v1/taa/reportAudit',
  });
  const dot = document.getElementById('reportAuditDot');
  const bodyBtn = document.getElementById('reportAuditBodyBtn');
  const pill = document.getElementById('reportAuditPill');
  if (dot) dot.className = 'dot';
  if (!data || !data.received) {
    if (dot) dot.className = 'dot bad status-pill pending';
    if (pill) pill.className = 'status-pill pending';
    text('reportAuditStatusText', '代码审计结果');
    if (bodyBtn) bodyBtn.disabled = true;
    return;
  }
  if (dot) dot.className = 'dot ' + (data.accepted ? 'ok status-pill ok' : 'bad status-pill bad');
  if (pill) pill.className = 'status-pill ' + (data.accepted ? 'ok' : 'bad');
  text('reportAuditStatusText', data.accepted ? '代码审计结果' : '代码审计结果校验失败');
  if (bodyBtn) bodyBtn.disabled = false;
}

function openReportAuditBodyModal() {
  openInteractionDrawer('reportAudit', 'primary');
}

async function refreshReportAuditStatus() {
  try {
    const res = await fetch('/api/reportAudit/status', { cache: 'no-store' });
    const data = await res.json();
    renderReportAudit({ ...responseResult(data), code: data.error, msg: data.msg });
  } catch (err) {
    text('reportAuditStatusText', '刷新上报状态失败');
  }
}

async function resetReportAuditStatus() {
  await fetch('/api/reportAudit/reset', { method: 'POST' }).catch(() => {});
  setReportAuditPending();
}

function renderReportProgress(result) {
  const percentEl = document.getElementById('reportProgressPercent');
  const barEl = document.getElementById('reportProgressBar');
  if (!result || !result.received) {
    if (percentEl) percentEl.textContent = '0%';
    if (barEl) {
      barEl.style.width = '0%';
      barEl.classList.remove('shimmer', 'active', 'complete');
    }
    return;
  }
  const pctVal = typeof result.percent === 'number' ? result.percent : (typeof result.progress === 'number' ? result.progress : 0);
  const clamped = Math.min(100, Math.max(0, pctVal));
  const pctText = clamped % 1 === 0 ? clamped + '%' : clamped.toFixed(1) + '%';
  if (percentEl) percentEl.textContent = pctText;
  if (barEl) {
    barEl.style.width = clamped + '%';
    if (clamped > 0 && clamped < 100) {
      barEl.classList.add('shimmer', 'active');
      barEl.classList.remove('complete');
    } else if (clamped >= 100) {
      barEl.classList.remove('shimmer', 'active');
      barEl.classList.add('complete');
    } else {
      barEl.classList.remove('shimmer', 'active', 'complete');
    }
  }
}

async function refreshReportProgress() {
  try {
    const res = await fetch('/api/reportProgress/status', { cache: 'no-store' });
    const data = await res.json();
    renderReportProgress(responseResult(data));
  } catch (err) {}
}

async function resetReportProgress() {
  try {
    await fetch('/api/reportProgress/reset', { method: 'POST' });
    await refreshReportProgress();
  } catch (err) {}
}

// ── TAA API Triggers ──
async function testHealth() {
  const btn = document.getElementById('healthResultBtn');
  if (btn) btn.disabled = true;
  setHealthState('dot status-pill running', '检查中', '检查中...', '');
  recordInteraction('health', {
    title: '健康检查 (GET /v1/taa/health)',
    primaryLabel: '返回内容',
    secondaryLabel: '请求体',
    primaryContent: null,
    secondaryContent: '{}',
    endpoint: '/v1/taa/health',
    reqBody: {},
  });
  try {
    const r = await postToTAA('/v1/taa/health', {}, 10000);
    const ok = r.status === 200 && r.data && r.data.error === 0;
    lastHealthData = r.data != null ? r.data : { status: r.status, raw: r };
    setHealthState('dot ' + (ok ? 'ok status-pill ok' : 'bad status-pill bad'), ok ? '连通正常' : '连通异常', ok ? '连通正常' : 'HTTP ' + r.status, ok ? 'var(--ok)' : 'var(--bad)');
    recordInteraction('health', { primaryContent: lastHealthData, respBody: lastHealthData, statusCode: r.status });
  } catch (e) {
    const msg = e.name === 'AbortError'
      ? '请求超时（10s）：TAA 服务响应过慢或不可达。\n请确认：\n1. TAA 服务地址是否正确\n2. TAA 服务是否已启动\n3. 浏览器能否直接访问该地址'
      : '请求失败: ' + e.message + '\n\n可能原因：\n1. TAA 服务地址不正确或服务未启动\n2. 网络不通\n3. 混合内容安全限制';
    lastHealthData = {
      error: -1,
      msg: e.message || '网络请求异常',
      detail: msg,
    };
    setHealthState('dot bad status-pill bad', '不可达', '不可达', 'var(--bad)');
    recordInteraction('health', { primaryContent: lastHealthData, respBody: lastHealthData, statusCode: 500 });
  } finally {
    if (btn) btn.disabled = false;
  }
}

function openHealthResultModal() {
  if (!lastHealthData) {
    recordInteraction('health', {
      title: '健康检查 (GET /v1/taa/health)',
      primaryLabel: '返回内容',
      secondaryLabel: '请求体',
      primaryContent: '暂未执行健康检查，请先点击【检查连通性】。',
      secondaryContent: '{}',
      endpoint: '/v1/taa/health',
    });
  }
  openInteractionDrawer('health', 'primary');
}

async function testImport() {
  showResultRunning('importResult', '正在请求...');
  const importBody = buildImportBody(
    document.getElementById('importResourceUrl').value,
    document.getElementById('importRequestId').value,
    '',
    document.getElementById('importTaskId').value.trim(),
  );
  recordInteraction('import', {
    title: '/v1/taa/import 接口详情',
    primaryLabel: '返回内容',
    secondaryLabel: '请求体',
    primaryContent: null,
    secondaryContent: importBody,
    endpoint: '/v1/taa/import',
    reqBody: importBody,
  });
  try {
    const r = await postToTAA('/v1/taa/import', importBody);
    recordInteraction('import', { primaryContent: formatResp(r), respBody: r.data, statusCode: r.status });
    showResult('importResult', r.status === 200 && r.data.error === 0, formatResp(r));
  } catch (e) {
    recordInteraction('import', { primaryContent: '请求失败: ' + e.message + '\n请确认 TAA 服务地址是否正确且服务已启动。', respBody: e.message, statusCode: 500 });
    showResult('importResult', false, '请求失败: ' + e.message + '\n请确认 TAA 服务地址是否正确且服务已启动。');
  }
}

function onImportModelUsePublicKeyToggle(el) {
  if (el && el.checked) {
    if (!globalKeyPair.publicKey) {
      alert('请先点击上方“创建公私钥”生成密钥对');
      el.checked = false;
    }
  }
}

async function testImportModel() {
  showResultRunning('importModelResult', '正在请求...');
  setReportModelImportPending();
  setReportAuditPending();
  try {
    await fetch('/api/reportModelImport/reset', { method: 'POST' }).catch(() => {});
    await fetch('/api/reportAudit/reset', { method: 'POST' }).catch(() => {});
    const commands = collectModelCommands();
    const env = collectModelEnv();
    const runtimeConfig = buildRuntimeConfig(commands, env);
    const usePubKey = Boolean(document.getElementById('importModelUsePublicKeySwitch') && document.getElementById('importModelUsePublicKeySwitch').checked);
    const pubKey = usePubKey && globalKeyPair.publicKey ? globalKeyPair.publicKey.trim() : '';
    const importModelBody = buildImportBody(
      document.getElementById('importModelResourceUrl').value,
      document.getElementById('importModelRequestId').value,
      pubKey,
      document.getElementById('importModelTaskId').value.trim(),
      runtimeConfig,
    );
    recordInteraction('importModel', {
      title: '/v1/taa/importModel 接口详情',
      primaryLabel: '返回内容',
      secondaryLabel: '请求体',
      primaryContent: null,
      secondaryContent: importModelBody,
      endpoint: '/v1/taa/importModel',
      reqBody: importModelBody,
    });
    const r = await postToTAA('/v1/taa/importModel', importModelBody);
    recordInteraction('importModel', { primaryContent: formatResp(r), respBody: r.data, statusCode: r.status });
    showResult('importModelResult', r.status === 200 && r.data.error === 0, formatResp(r));
  } catch (e) {
    recordInteraction('importModel', { primaryContent: '请求失败: ' + e.message + '\n请确认 TAA 服务地址是否正确且服务已启动。', respBody: e.message, statusCode: 500 });
    showResult('importModelResult', false, '请求失败: ' + e.message + '\n请确认 TAA 服务地址是否正确且服务已启动。');
  }
}

async function testStopTraining() {
  const btn = document.getElementById('stopTrainingBtn');
  const box = document.getElementById('stopTrainingStatusBox');
  const textEl = document.getElementById('stopTrainingStatusText');
  const bodyBtn = document.getElementById('stopTrainingBodyBtn');
  if (btn) btn.disabled = true;
  if (box) {
    box.style.display = 'inline-flex';
    box.style.color = 'var(--text)';
  }
  if (textEl) textEl.textContent = '正在发送中止请求...';
  recordInteraction('stopTraining', {
    title: '/v1/taa/stopTraining 中止训练详情',
    primaryLabel: '返回内容',
    secondaryLabel: '请求体',
    primaryContent: null,
    secondaryContent: '{}',
    endpoint: '/api/taa/stopTraining',
    reqBody: {},
  });
  try {
    const res = await fetch('/api/taa/stopTraining', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    const data = await res.json().catch(() => ({}));
    const ok = res.status === 200 && data.error === 0;
    if (box) {
      box.style.display = 'inline-flex';
      box.style.color = ok ? 'var(--ok)' : 'var(--bad)';
    }
    if (textEl) {
      textEl.textContent = data.msg || (ok ? '训练任务已中止' : `中止失败 (HTTP ${res.status})`);
    }
    recordInteraction('stopTraining', { primaryContent: data, respBody: data, statusCode: res.status });
    if (bodyBtn) bodyBtn.style.display = 'inline-block';
  } catch (err) {
    if (box) {
      box.style.display = 'inline-flex';
      box.style.color = 'var(--bad)';
    }
    if (textEl) textEl.textContent = '请求失败: ' + err.message;
    recordInteraction('stopTraining', { primaryContent: { error: -1, msg: err.message }, respBody: err.message, statusCode: 500 });
    if (bodyBtn) bodyBtn.style.display = 'inline-block';
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function quickSwitchPhase(phase) {
  const phaseNames = { 1: '1 调试', 2: '2 测试', 3: '3 训练', 4: '4 推理' };
  const phaseName = phaseNames[phase] || `阶段 ${phase}`;
  const statusEl = document.getElementById('phaseSwitchText');
  const dotEl = document.getElementById('phaseSwitchDot');
  const detailBtn = document.getElementById('phaseSwitchDetailBtn');
  const detailContent = document.getElementById('phaseSwitchDetailContent');
  const buttons = document.querySelectorAll('.phase-switch-btn[data-phase]');

  buttons.forEach(btn => btn.disabled = true);
  if (dotEl) dotEl.className = 'dot status-pill running';
  if (statusEl) statusEl.textContent = `正在切换至 ${phaseName}...`;
  showResultRunning('switchResult', `正在切换至 ${phaseName}...`);

  const reqBody = { phase: Number(phase) };
  recordInteraction('switch', {
    title: '/v1/taa/switch 阶段切换详情',
    primaryLabel: '返回内容',
    secondaryLabel: '请求体',
    primaryContent: null,
    secondaryContent: reqBody,
    endpoint: '/v1/taa/switch',
    reqBody,
  });

  try {
    const r = await postToTAA('/v1/taa/switch', reqBody);
    lastPhaseSwitchResp = r;
    const ok = r.status === 200 && (r.data?.error === 0 || r.data?.error === undefined);
    if (ok) {
      currentPhase = Number(phase);
      const phaseInput = document.getElementById('switchPhase');
      if (phaseInput) phaseInput.value = currentPhase;
      buttons.forEach(btn => {
        if (Number(btn.dataset.phase) === Number(phase)) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      });
      if (dotEl) dotEl.className = 'dot ok status-pill ok';
      if (statusEl) statusEl.textContent = `当前阶段: ${phaseName}`;
    } else {
      if (dotEl) dotEl.className = 'dot bad status-pill bad';
      const msg = r.data?.msg || `HTTP ${r.status}`;
      if (statusEl) statusEl.textContent = `切换失败: ${msg}`;
    }
    const respText = formatResp(r);
    recordInteraction('switch', { primaryContent: respText, respBody: r.data, statusCode: r.status });
    if (detailBtn) detailBtn.style.display = 'inline-block';
    if (detailContent) detailContent.textContent = respText;
    showResult('switchResult', ok, respText);
  } catch (e) {
    if (dotEl) dotEl.className = 'dot bad status-pill bad';
    if (statusEl) statusEl.textContent = `切换失败: ${e.message}`;
    const errMsg = '请求失败: ' + e.message;
    recordInteraction('switch', { primaryContent: errMsg, respBody: e.message, statusCode: 500 });
    if (detailBtn) detailBtn.style.display = 'inline-block';
    if (detailContent) detailContent.textContent = errMsg;
    showResult('switchResult', false, errMsg);
  } finally {
    buttons.forEach(btn => btn.disabled = false);
  }
}

function togglePhaseSwitchDetail() {
  openInteractionDrawer('switch', 'primary');
}

async function testSwitch(phase) {
  const p = phase !== undefined ? phase : (document.getElementById('switchPhase')?.value || 1);
  return quickSwitchPhase(Number(p));
}

async function detectTAAProxy() {
  const addrInput = document.getElementById('taaAddr');
  const badge = document.getElementById('taaProxyBadge');
  const pill = document.getElementById('taaTargetPill');
  try {
    const res = await fetch('/api/taa-target', { cache: 'no-store' });
    const data = await res.json();
    const payload = responseResult(data);
    if (payload.taaTarget) {
      addrInput.value = location.origin + '/taa';
      if (pill) {
        pill.className = 'status-pill ok';
        pill.style.display = 'inline-flex';
      }
      if (badge) {
        badge.textContent = 'TAA 代理: ' + payload.taaTarget;
        badge.style.color = 'var(--ok)';
      }
    } else {
      addrInput.value = 'http://127.0.0.1:6001';
      if (pill) {
        pill.className = 'status-pill pending';
        pill.style.display = 'inline-flex';
      }
      if (badge) {
        badge.textContent = '未检测到 TAA Pod，请手动填写 TAA 地址';
        badge.style.color = 'var(--bad)';
      }
    }
  } catch {
    addrInput.value = 'http://127.0.0.1:6001';
    if (pill) {
      pill.className = 'status-pill bad';
      pill.style.display = 'inline-flex';
    }
    if (badge) {
      badge.textContent = '检测失败，请手动填写 TAA 地址';
      badge.style.color = 'var(--bad)';
    }
  }
}

// ── Application Lifecycle Bootstrapping ──
document.addEventListener('DOMContentLoaded', () => {
  detectTAAProxy();
  setupResourceUrlDropZones();
  refreshUploadedFiles();
  refreshStatus();
  refreshReportResStatus();
  setReportModelImportPending();
  refreshReportModelImportStatus();
  setReportAuditPending();
  refreshReportAuditStatus();
  refreshReportProgress();
  fetchModelLogs();
  fetchTaaLogs();

  // Start unified Visibility-aware Polling Manager
  PollingManager.start();
});
