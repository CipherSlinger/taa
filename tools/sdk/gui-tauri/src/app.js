// ─── Tauri API Wrapper ─────────────────────────────────────────────
const tauri = window.__TAURI__ || {};
const invoke = tauri.core?.invoke || (async () => { throw new Error('Tauri invoke unavailable'); });
const listen = tauri.event?.listen || (async () => () => {});

// Custom context menu for PEM textareas
const contextMenu = document.createElement('div');
contextMenu.id = 'customContextMenu';
contextMenu.style.cssText = `
  position: fixed;
  display: none;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(0, 0, 0, 0.1);
  border-radius: 8px;
  box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15), 0 2px 4px rgba(0, 0, 0, 0.1);
  z-index: 10000;
  padding: 6px;
  min-width: 140px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
`;

const pasteItem = document.createElement('div');
pasteItem.innerHTML = `
  <span style="display: inline-block; width: 20px; text-align: center; margin-right: 8px;">📋</span>
  <span>粘贴</span>
`;
pasteItem.style.cssText = `
  padding: 10px 16px;
  cursor: pointer;
  border-radius: 6px;
  transition: background 0.15s ease;
  font-size: 14px;
  color: #333;
  user-select: none;
`;
pasteItem.onmouseover = () => {
  pasteItem.style.background = 'rgba(0, 120, 212, 0.1)';
  pasteItem.style.color = '#0078d4';
};
pasteItem.onmouseout = () => {
  pasteItem.style.background = '';
  pasteItem.style.color = '#333';
};
contextMenu.appendChild(pasteItem);
document.body.appendChild(contextMenu);

let currentTextarea = null;

// Disable right-click context menu (except for PEM textareas)
document.addEventListener('contextmenu', (e) => {
  e.preventDefault();

  // Check if right-click is on a PEM textarea
  if (e.target.tagName === 'TEXTAREA' && (e.target.id === 'publicKey' || e.target.id === 'privateKey')) {
    currentTextarea = e.target;
    contextMenu.style.display = 'block';
    contextMenu.style.left = e.clientX + 'px';
    contextMenu.style.top = e.clientY + 'px';

    // Ensure menu stays within viewport
    const rect = contextMenu.getBoundingClientRect();
    if (rect.right > window.innerWidth) {
      contextMenu.style.left = (e.clientX - rect.width) + 'px';
    }
    if (rect.bottom > window.innerHeight) {
      contextMenu.style.top = (e.clientY - rect.height) + 'px';
    }
  } else {
    contextMenu.style.display = 'none';
  }

  return false;
});

// Hide context menu when clicking elsewhere
document.addEventListener('click', () => {
  contextMenu.style.display = 'none';
});

// Paste action
pasteItem.addEventListener('click', async () => {
  if (currentTextarea) {
    try {
      const text = await navigator.clipboard.readText();
      currentTextarea.value += text;
      currentTextarea.dispatchEvent(new Event('input'));
      setStatus('已粘贴到' + (currentTextarea.id === 'publicKey' ? '公钥' : '私钥'), 'success');
    } catch (err) {
      setStatus('粘贴失败: ' + err, 'error');
    }
  }
  contextMenu.style.display = 'none';
});

const api = {
  openFile: (options) => invoke('pick_file', {
    filters: options?.filters?.map(f => ({ name: f.name, extensions: f.extensions })),
  }),
  openFolder: () => invoke('pick_folder'),
  saveFile: (options) => invoke('save_file', {
    defaultName: options?.defaultName,
    filters: options?.filters?.map(f => ({ name: f.name, extensions: f.extensions })),
  }),
  readFile: (path) => invoke('read_file', { path }),
  writeFile: (path, content) => invoke('write_file', { path, content }),
  genKey: () => invoke('gen_key', { memory: true }),
  validatePublicKey: (pem) => invoke('validate_public_key', { pem }),
  validatePrivateKey: (pem) => invoke('validate_private_key', { pem }),
  encrypt: ({ inputPath, publicKey }) =>
    invoke('encrypt_file', { inputPath, publicKey }),
  decrypt: ({ inputPath, privateKey }) =>
    invoke('decrypt_file', { inputPath, privateKey }),
  saveOutput: ({ tempPath, outputPath }) =>
    invoke('save_output', { tempPath, outputPath }),
  verify: ({ reportPath, verifyChain }) =>
    invoke('verify_report', { reportPath, verifyChain }),
};

// ─── DOM References ────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

const tabBtns = document.querySelectorAll('.nav-btn');
const tabCrypto = $('tab-crypto');
const tabAttestation = $('tab-attestation');

const publicKeyEl = $('publicKey');
const privateKeyEl = $('privateKey');
const genKeyBtn = $('genKeyBtn');
const savePubBtn = $('savePubBtn');
const savePrvBtn = $('savePrvBtn');
const importPubBtn = $('importPubBtn');
const importPrvBtn = $('importPrvBtn');
const copyPubBtn = $('copyPubBtn');
const copyPrvBtn = $('copyPrvBtn');

const dropZone = $('dropZone');
const fileInfo = $('fileInfo');
const fileIcon = $('fileIcon');
const fileName = $('fileName');
const fileSize = $('fileSize');
const browseBtn = $('browseBtn');
const browseFolderBtn = $('browseFolderBtn');
const clearFileBtn = $('clearFileBtn');
const encryptBtn = $('encryptBtn');
const decryptBtn = $('decryptBtn');

const reportFileInput = $('reportFileInput');
const reportBrowseBtn = $('reportBrowseBtn');
const verifyChainCheck = $('verifyChainCheck');
const verifyBtn = $('verifyBtn');
const attestationTable = $('attestationTable');

const progressFill = document.querySelector('.progress-fill');
const progressBar = document.querySelector('.progress-bar');
const statusBar = document.querySelector('.status-bar');
const statusMsg = document.querySelector('.status-msg');
const saveBtn = $('saveBtn');

// Cached DOM refs for key state (never change)
const pubKeyRow = publicKeyEl.closest('.key-row');
const pubBadge = pubKeyRow?.querySelector('.key-badge');
const prvKeyRow = privateKeyEl.closest('.key-row');
const prvBadge = prvKeyRow?.querySelector('.key-badge');

// Cached verdict banner child refs
const verdictBanner = $('verdictBanner');
const verdictIcon = verdictBanner?.querySelector('.verdict-icon');
const verdictTitle = verdictBanner?.querySelector('.verdict-title');
const verdictDetail = verdictBanner?.querySelector('.verdict-detail');

// ─── State ─────────────────────────────────────────────────────────
let selectedFile = null;
let selectedFolder = null;
let outputPath = null;
let publicKeyValid = false;
let privateKeyValid = false;
let pendingTempPath = null;
let pendingIsArchive = false;
const saveOutputBtn = $('saveOutputBtn');
const fileOutput = $('fileOutput');

window.addEventListener('error', (e) => {
  try {
    setStatus('脚本错误: ' + (e?.message || '未知错误'), 'error');
  } catch {}
});

window.addEventListener('unhandledrejection', (e) => {
  try {
    setStatus('脚本异常: ' + (e?.reason?.message || e?.reason || '未知错误'), 'error');
  } catch {}
});

// ─── Shared Constants ──────────────────────────────────────────────
const PEM_FILTERS = [
  { name: 'PEM Files', extensions: ['pem'] },
  { name: 'All Files', extensions: ['*'] },
];

// ─── Helpers ───────────────────────────────────────────────────────

function basename(p) {
  return p.split(/[\\/]/).pop();
}

function setStatus(msg, type) {
  statusMsg.textContent = (type === 'success' ? '✓ ' : type === 'error' ? '✗ ' : '') + msg;
  statusMsg.className = 'status-msg';
  // Slide-in animation on every status change
  void statusMsg.offsetWidth;
  statusMsg.classList.add('status-enter');
  statusMsg.addEventListener('animationend', () => statusMsg.classList.remove('status-enter'), { once: true });
  if (type) {
    // Force reflow to restart animation
    void statusMsg.offsetWidth;
    statusMsg.classList.add(type);
    // Flash status bar on completion
    if (statusBar && (type === 'success' || type === 'error')) {
      statusBar.classList.remove('completion-flash');
      void statusBar.offsetWidth;
      statusBar.classList.add('completion-flash');
      statusBar.addEventListener('animationend', () => statusBar.classList.remove('completion-flash'), { once: true });
    }
  }
}

function setProgress(pct) {
  progressFill.classList.remove('indeterminate', 'active');
  if (pct === 'busy') {
    progressFill.classList.add('indeterminate', 'active');
    progressBar?.classList.add('active', 'working');
    statusBar?.classList.add('processing');
  } else if (pct && pct > 0) {
    progressFill.classList.add('active');
    progressBar?.classList.add('active');
    progressBar?.classList.remove('working');
    progressFill.style.width = pct + '%';
  } else {
    progressFill.style.width = '0%';
    progressBar?.classList.remove('active', 'working');
    statusBar?.classList.remove('processing');
  }
}

function clearProgress() {
  // Brief completion celebration before clearing
  progressFill.classList.remove('indeterminate', 'active');
  progressFill.classList.add('complete');
  progressFill.style.width = '100%';
  progressBar?.classList.add('complete');

  setTimeout(() => {
    progressFill.classList.remove('complete');
    progressBar?.classList.remove('active', 'working', 'complete');
    statusBar?.classList.remove('processing');
    progressFill.style.width = '0%';
  }, 600);
}

function disableButtons(disabled, btns) {
  btns.forEach((b) => (b.disabled = disabled));
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// ─── SVG Icon Helpers ───────────────────────────────────────────────
const S = 'width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"';
const fileSvg = `<svg ${S}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
const folderSvg = `<svg ${S}><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`;

const fileIconMap = {
  pdf: `<svg ${S}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="15" x2="15" y2="15"/></svg>`,
  image: `<svg ${S}><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`,
  archive: `<svg ${S}><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>`,
  key: `<svg ${S}><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/></svg>`,
  lock: `<svg ${S}><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  code: `<svg ${S}><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
  text: `<svg ${S}><line x1="17" y1="10" x2="3" y2="10"/><line x1="21" y1="6" x2="3" y2="6"/><line x1="21" y1="14" x2="3" y2="14"/><line x1="17" y1="18" x2="3" y2="18"/></svg>`,
};

// Extension → category lookup (O(1), no array allocation per call)
const extCategory = {
  jpg:'image', jpeg:'image', png:'image', gif:'image', bmp:'image', svg:'image', ico:'image',
  zip:'archive', rar:'archive', '7z':'archive', tar:'archive', gz:'archive',
  pem:'key', key:'key', crt:'key', cer:'key', p12:'key', pfx:'key',
  enc:'lock',
  go:'code', rs:'code', py:'code', java:'code', js:'code', ts:'code',
  c:'code', cpp:'code', h:'code', rb:'code', sh:'code', bat:'code',
  txt:'text', md:'text', log:'text', csv:'text',
  pdf:'pdf',
};

function getFileIcon(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  return fileIconMap[extCategory[ext]] || fileSvg;
}

// History SVG icons (16x16, thinner stroke)
const H = 'width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
const historyIcons = {
  genkey: `<svg ${H}><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/><line x1="7" y1="21" x2="7" y2="15"/><line x1="4" y1="18" x2="10" y2="18"/></svg>`,
  paste: `<svg ${H}><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  save: `<svg ${H}><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>`,
  import: `<svg ${H}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>`,
  encrypt: `<svg ${H}><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  decrypt: `<svg ${H}><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>`,
  verify: `<svg ${H}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`,
};

// Map icon keys to history color classes
const historyColorMap = { genkey: 'hi-generate', encrypt: 'hi-encrypt', decrypt: 'hi-decrypt', verify: 'hi-decrypt' };

function addHistory(iconKey, text) {
  const historyList = $('historyList');
  if (!historyList) return;

  const empty = historyList.querySelector('.history-empty');
  if (empty) empty.remove();

  const now = new Date();
  const timeStr = now.getHours().toString().padStart(2, '0') + ':' +
                  now.getMinutes().toString().padStart(2, '0') + ':' +
                  now.getSeconds().toString().padStart(2, '0');

  const colorClass = historyColorMap[iconKey] || '';
  const icon = historyIcons[iconKey] || '';

  const item = document.createElement('div');
  item.className = 'history-item history-new';
  item.innerHTML = '<span class="history-icon ' + colorClass + '">' + icon + '</span>' +
                   '<span class="history-text">' + text + '</span>' +
                   '<span class="history-time">' + timeStr + '</span>';

  historyList.insertBefore(item, historyList.firstChild);
  item.addEventListener('animationend', () => item.classList.remove('history-new'), { once: true });

  while (historyList.children.length > 50) {
    historyList.removeChild(historyList.lastChild);
  }

  // Update history count badge
  const countEl = $('historyCount');
  if (countEl) {
    const count = historyList.querySelectorAll('.history-item').length;
    countEl.textContent = count > 0 ? count : '';
    if (count > 0) {
      countEl.classList.remove('count-pop', 'count-pulse');
      void countEl.offsetWidth;
      countEl.classList.add('count-pop', 'count-pulse');
      countEl.addEventListener('animationend', () => countEl.classList.remove('count-pulse'), { once: true });
    }
  }

  // Pulse history header when collapsed and new item added
  const historyPanel = $('historyPanel');
  if (historyPanel && historyPanel.classList.contains('collapsed')) {
    const header = $('historyHeader');
    if (header) {
      header.classList.remove('history-pulse');
      void header.offsetWidth;
      header.classList.add('history-pulse');
      header.addEventListener('animationend', () => header.classList.remove('history-pulse'), { once: true });
    }
  }
}

const cryptoBtns = [genKeyBtn, savePubBtn, savePrvBtn, importPubBtn, importPrvBtn, browseBtn, browseFolderBtn, encryptBtn, decryptBtn];

// ─── Tab Switching ─────────────────────────────────────────────────

tabBtns.forEach((btn) => {
  btn.addEventListener('click', () => {
    if (btn.classList.contains('active')) return;
    tabBtns.forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.dataset.tab;
    // Add entering animation to the target tab
    const entering = target === 'crypto' ? tabCrypto : tabAttestation;
    entering.classList.remove('tab-entering');
    void entering.offsetWidth;
    tabCrypto.classList.toggle('active', target === 'crypto');
    tabAttestation.classList.toggle('active', target === 'attestation');
    entering.classList.add('tab-entering');
    entering.addEventListener('animationend', () => entering.classList.remove('tab-entering'), { once: true });
  });
});

// ─── Ctrl Key Shortcut Preview ──────────────────────────────────────
const shortcutBar = document.querySelector('.shortcut-bar');
document.addEventListener('keydown', (e) => {
  if ((e.key === 'Control' || e.key === 'Meta') && shortcutBar) {
    shortcutBar.classList.add('ctrl-held');
  }
});
document.addEventListener('keyup', (e) => {
  if ((e.key === 'Control' || e.key === 'Meta') && shortcutBar) {
    shortcutBar.classList.remove('ctrl-held');
  }
});

// ─── Keyboard Shortcuts ─────────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey)) return;

  // Visual feedback: flash the shortcut kbd
  function flashKbd(key) {
    const shortcutBar = document.querySelector('.shortcut-bar');
    if (!shortcutBar) return;
    const kbds = shortcutBar.querySelectorAll('kbd');
    kbds.forEach(kbd => {
      if (kbd.textContent.trim().toLowerCase() === key.toLowerCase()) {
        kbd.classList.remove('kbd-flash');
        void kbd.offsetWidth;
        kbd.classList.add('kbd-flash');
        kbd.addEventListener('animationend', () => kbd.classList.remove('kbd-flash'), { once: true });
      }
    });
  }

  // Flash the button that was triggered by shortcut
  function flashBtnShortcut(btnEl) {
    if (!btnEl) return;
    btnEl.classList.remove('btn-shortcut-flash');
    void btnEl.offsetWidth;
    btnEl.classList.add('btn-shortcut-flash');
    btnEl.addEventListener('animationend', () => btnEl.classList.remove('btn-shortcut-flash'), { once: true });
  }

  switch (e.key.toLowerCase()) {
    case 'g':
      e.preventDefault();
      flashKbd('G');
      flashBtnShortcut(genKeyBtn);
      if (!genKeyBtn.disabled) genKeyBtn.click();
      break;
    case 'e':
      e.preventDefault();
      flashKbd('E');
      flashBtnShortcut(encryptBtn);
      if (!encryptBtn.disabled) encryptBtn.click();
      break;
    case 'd':
      e.preventDefault();
      flashKbd('D');
      flashBtnShortcut(decryptBtn);
      if (!decryptBtn.disabled) decryptBtn.click();
      break;
  }
});

// ─── Key Management ────────────────────────────────────────────────

genKeyBtn.addEventListener('click', async () => {
  setProgress('busy');
  setStatus('正在生成密钥对...');
  disableButtons(true, cryptoBtns);
  genKeyBtn.classList.add('generating');

  try {
    const result = await api.genKey();
    if (result && result.publicKey && result.privateKey) {
      publicKeyEl.value = result.publicKey;
      privateKeyEl.value = result.privateKey;
      onKeyInput(publicKeyEl, pubKeyRow, pubBadge);
      onKeyInput(privateKeyEl, prvKeyRow, prvBadge);
      doValidatePublicKey();
      doValidatePrivateKey();
      setStatus('密钥对已生成并加载', 'success');
      addHistory('genkey', '生成 SM2 密钥对');
      flashCard(genKeyBtn.closest('.card'));
      genKeyBtn.classList.remove('genkey-complete');
      void genKeyBtn.offsetWidth;
      genKeyBtn.classList.add('genkey-complete');
      genKeyBtn.addEventListener('animationend', () => genKeyBtn.classList.remove('genkey-complete'), { once: true });
    }
  } catch (err) {
    console.error('[genkey] failed:', err);
    setStatus('生成密钥失败: ' + err, 'error');
  } finally {
    genKeyBtn.classList.remove('generating');
    clearProgress();
    disableButtons(false, cryptoBtns);
  }
});

// ─── Copy Handlers ──────────────────────────────────────────────────
function flashToolBtn(btnEl, className) {
  btnEl.classList.remove(className);
  void btnEl.offsetWidth;
  btnEl.classList.add(className);
  btnEl.addEventListener('animationend', () => btnEl.classList.remove(className), { once: true });
}

function bindCopy(btnEl, textareaEl, label) {
  btnEl.addEventListener('click', async () => {
    const pem = textareaEl.value.trim();
    if (!pem) { setStatus(label + '为空', 'error'); return; }
    try {
      await navigator.clipboard.writeText(pem);
      setStatus(label + '已复制', 'success');
      flashToolBtn(btnEl, 'btn-tool-copied');
      // Temporarily change tooltip to "已复制!"
      const origTooltip = btnEl.getAttribute('data-tooltip');
      btnEl.setAttribute('data-tooltip', '已复制 ✓');
      setTimeout(() => btnEl.setAttribute('data-tooltip', origTooltip), 1500);
    } catch (err) {
      setStatus('复制失败: ' + err, 'error');
    }
  });
}

bindCopy(copyPubBtn, publicKeyEl, '公钥');
bindCopy(copyPrvBtn, privateKeyEl, '私钥');

// ─── Save Handlers ──────────────────────────────────────────────────
async function saveKey(textareaEl, defaultName, label, btnEl) {
  const pem = textareaEl.value.trim();
  if (!pem) { setStatus(label + '为空', 'error'); return; }
  const filePath = await api.saveFile({ defaultName, filters: PEM_FILTERS });
  if (!filePath) return;

  setProgress('busy');
  try {
    await api.writeFile(filePath, pem);
    setStatus(label + '已保存 → ' + filePath, 'success');
    addHistory('save', '保存' + label + ' → ' + basename(filePath));
    if (btnEl) flashToolBtn(btnEl, 'btn-tool-saved');
  } catch (err) {
    setStatus('保存' + label + '失败: ' + err, 'error');
  } finally { clearProgress(); }
}

savePubBtn.addEventListener('click', () => saveKey(publicKeyEl, 'public.pem', '公钥', savePubBtn));
savePrvBtn.addEventListener('click', () => saveKey(privateKeyEl, 'private.pem', '私钥', savePrvBtn));

// ─── Import Handlers ────────────────────────────────────────────────
async function importKey(textareaEl, label, keyRow, badge, btnEl) {
  const filePath = await api.openFile({ filters: PEM_FILTERS });
  if (!filePath) return;

  setProgress('busy');
  setStatus('正在导入' + label + '...');
  try {
    const content = await api.readFile(filePath);
    textareaEl.value = content;
    onKeyInput(textareaEl, keyRow, badge);
    setStatus(label + '已导入', 'success');
    addHistory('import', '导入' + label + ' ← ' + basename(filePath));
    flashCard(textareaEl.closest('.card'));
    if (btnEl) flashToolBtn(btnEl, 'btn-tool-imported');
  } catch (err) {
    setStatus('导入' + label + '失败: ' + err, 'error');
  } finally { clearProgress(); }
}

importPubBtn.addEventListener('click', () => importKey(publicKeyEl, '公钥', pubKeyRow, pubBadge, importPubBtn));
importPrvBtn.addEventListener('click', () => importKey(privateKeyEl, '私钥', prvKeyRow, prvBadge, importPrvBtn));

// ─── Paste Animation on Textareas ──────────────────────────────────
[publicKeyEl, privateKeyEl].forEach((ta) => {
  ta.addEventListener('paste', () => {
    ta.classList.remove('paste-flash');
    void ta.offsetWidth;
    ta.classList.add('paste-flash');
    ta.addEventListener('animationend', () => ta.classList.remove('paste-flash'), { once: true });
  });
  // Card border glow when textarea is focused
  ta.addEventListener('focus', () => {
    const keyRow = ta.closest('.key-row');
    if (keyRow) keyRow.classList.add('textarea-focused');
  });
  ta.addEventListener('blur', () => {
    const keyRow = ta.closest('.key-row');
    if (keyRow) keyRow.classList.remove('textarea-focused');
  });
});

// ─── File Selection & Drag-Drop ────────────────────────────────────

function showFileInfo(path, isFolder) {
  const dropHint = dropZone.querySelector('.drop-hint');
  dropHint.classList.add('hidden');
  fileInfo.classList.remove('hidden', 'file-info-enter', 'file-enter');
  void fileInfo.offsetWidth;
  fileInfo.classList.add('file-info-enter', 'file-enter');
  fileInfo.addEventListener('animationend', () => { fileInfo.classList.remove('file-info-enter', 'file-enter'); }, { once: true });
  dropZone.classList.add('file-selected');

  fileIcon.innerHTML = isFolder ? folderSvg : getFileIcon(path);
  fileName.textContent = basename(path);
  fileSize.textContent = isFolder ? '文件夹' : '文件';

  // Stagger animation on file name + size
  const fileDetails = fileInfo.querySelector('.file-details');
  if (fileDetails) {
    fileDetails.classList.remove('details-enter');
    void fileDetails.offsetWidth;
    fileDetails.classList.add('details-enter');
    fileDetails.addEventListener('animationend', () => fileDetails.classList.remove('details-enter'), { once: true });
  }

  // Bounce animation on file icon
  fileIcon.classList.remove('file-icon-bounce');
  void fileIcon.offsetWidth; // force reflow to restart animation
  fileIcon.classList.add('file-icon-bounce');
  fileIcon.addEventListener('animationend', () => fileIcon.classList.remove('file-icon-bounce'), { once: true });
}

function clearFileSelection() {
  selectedFile = null;
  selectedFolder = null;
  outputPath = null;
  fileInfo.classList.add('hidden');
  fileInfo.classList.remove('file-info-enter', 'file-enter', 'file-info-exit');
  fileOutput.classList.add('hidden');
  fileOutput.textContent = '';
  dropZone.classList.remove('file-selected');
  dropZone.querySelector('.drop-hint').classList.remove('hidden');
  setStatus('就绪');
}

browseBtn.addEventListener('click', async () => {
  const filePath = await api.openFile({});
  if (!filePath) return;
  selectedFile = filePath;
  selectedFolder = null;
  showFileInfo(filePath, false);
  setStatus('已选择文件: ' + basename(filePath));
});

browseFolderBtn.addEventListener('click', async () => {
  const folderPath = await api.openFolder();
  if (!folderPath) return;
  selectedFolder = folderPath;
  selectedFile = null;
  showFileInfo(folderPath, true);
  setStatus('已选择文件夹: ' + basename(folderPath));
});

clearFileBtn.addEventListener('click', clearFileSelection);

// Save output from temp file
saveOutputBtn.addEventListener('click', async () => {
  if (!pendingTempPath) {
    setStatus('没有待保存的结果，请先执行加密或解密', 'error');
    return;
  }
  const inputPath = selectedFile || selectedFolder;
  const inputName = inputPath ? basename(inputPath) : 'output';

  // Determine default name and filters based on operation type
  let defaultName, filters;
  if (pendingIsArchive) {
    // Decrypted folder archive
    defaultName = inputName.endsWith('.enc') ? inputName.slice(0, -4) : inputName + '.decrypted';
    filters = [{ name: 'All Files', extensions: ['*'] }];
  } else if (inputName.endsWith('.enc')) {
    // Decrypting a .enc file
    defaultName = inputName.slice(0, -4);
    filters = [{ name: 'All Files', extensions: ['*'] }];
  } else {
    // Encrypting a file
    defaultName = inputName + '.enc';
    filters = [{ name: 'Encrypted Files', extensions: ['enc'] }, { name: 'All Files', extensions: ['*'] }];
  }

  const outPath = await api.saveFile({ defaultName, filters });
  if (!outPath) return;

  setProgress('busy');
  setStatus('正在保存...');
  try {
    await api.saveOutput({ tempPath: pendingTempPath, outputPath: outPath });
    setStatus('已保存 → ' + outPath, 'success');
    addHistory('save', '保存 → ' + basename(outPath));
    pendingTempPath = null;
    saveOutputBtn.classList.add('hidden');
    fileOutput.textContent = '→ ' + basename(outPath);
    fileOutput.classList.remove('hidden');
  } catch (err) {
    setStatus('保存失败: ' + err, 'error');
  } finally {
    clearProgress();
  }
});

// Drag and drop
async function logDragDrop(message) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] ${message}\n`;
  try {
    await invoke('append_log', { message: logEntry });
  } catch (err) {
    console.error('Failed to write log:', err);
  }
}

function applyDroppedFile(file) {
  const filePath = file.path || file.name;
  if (!filePath) {
    setStatus('拖拽文件无法识别', 'error');
    return;
  }

  selectedFile = file.path || filePath;
  selectedFolder = null;
  showFileInfo(selectedFile, false);
  fileSize.textContent = formatBytes(file.size || 0);
  setStatus('已选择文件: ' + (file.name || basename(filePath)), 'success');
}

function wireDragDropListeners() {
  const markDragover = () => dropZone.classList.add('dragover');
  const clearDragover = () => dropZone.classList.remove('dragover');

  // Keep only lightweight DOM feedback here.
  document.addEventListener('dragenter', (e) => {
    e.preventDefault();
    markDragover();
  }, true);

  document.addEventListener('dragover', (e) => {
    e.preventDefault();
    markDragover();
  }, true);

  document.addEventListener('dragleave', (e) => {
    if (e.target === document || e.target === document.body || e.target === dropZone) {
      clearDragover();
    }
  }, true);

  setStatus('就绪');
}

async function initNativeDragDrop() {
  const getCurrentWindow = tauri.window?.getCurrentWindow;
  if (typeof getCurrentWindow !== 'function') {
    setStatus('拖拽API不可用', 'error');
    return;
  }

  try {
    const appWindow = getCurrentWindow();
    if (!appWindow?.onDragDropEvent) {
      setStatus('拖拽监听不可用', 'error');
      return;
    }

    await appWindow.onDragDropEvent((event) => {
      const payload = event?.payload || {};
      const type = payload.type || event?.type || 'unknown';
      const paths = payload.paths || event?.paths || [];
      logDragDrop(`[native ${type}] paths=${JSON.stringify(paths)}`).catch(() => {});

      if (type === 'enter' || type === 'over') {
        dropZone.classList.add('dragover');
        setStatus('检测到拖拽文件...');
        return;
      }

      if (type === 'leave' || type === 'cancelled') {
        dropZone.classList.remove('dragover');
        return;
      }

      if (type === 'drop') {
        dropZone.classList.remove('dragover');
        if (paths.length > 0) {
          const filePath = paths[0];
          applyDroppedFile({ path: filePath, name: basename(filePath), size: 0 });
          setStatus('已选择文件: ' + basename(filePath), 'success');
        } else {
          setStatus('拖拽未获取到文件路径', 'error');
        }
      }
    });

    await logDragDrop('native drag-drop listener registered');
  } catch (err) {
    setStatus('拖拽初始化失败: ' + err, 'error');
  }
}

wireDragDropListeners();
initNativeDragDrop().catch((err) => setStatus('拖拽初始化失败: ' + err, 'error'));
logDragDrop('app.js loaded').catch(() => {});

// ─── Live PEM Validation ───────────────────────────────────────────

let pubValidateTimer = null;
let prvValidateTimer = null;

async function doValidatePublicKey() {
  const pem = publicKeyEl.value.trim();
  if (!pem || !pem.includes('-----BEGIN')) {
    publicKeyValid = false;
    pubKeyRow?.classList.remove('loaded', 'invalid');
    return;
  }
  try {
    const result = await api.validatePublicKey(pem);
    const valid = result.valid;
    publicKeyValid = valid;
    if (pubKeyRow) {
      pubKeyRow.classList.toggle('loaded', valid);
      pubKeyRow.classList.toggle('invalid', !valid);
    }
    if (!valid) {
      const errMsg = result.error || '未知错误';
      setStatus('公钥格式无效: ' + errMsg, 'error');
      console.error('[validatePublicKey] Error:', errMsg);
    } else {
      setStatus('公钥格式验证通过', 'success');
    }
  } catch (err) {
    publicKeyValid = false;
    pubKeyRow?.classList.add('invalid');
    pubKeyRow?.classList.remove('loaded');
    console.error('[validatePublicKey] Exception:', err);
  }
}

async function doValidatePrivateKey() {
  const pem = privateKeyEl.value.trim();
  if (!pem || !pem.includes('-----BEGIN')) {
    privateKeyValid = false;
    prvKeyRow?.classList.remove('loaded', 'invalid');
    return;
  }
  try {
    const result = await api.validatePrivateKey(pem);
    const valid = result.valid;
    privateKeyValid = valid;
    if (prvKeyRow) {
      prvKeyRow.classList.toggle('loaded', valid);
      prvKeyRow.classList.toggle('invalid', !valid);
    }
    if (!valid) {
      const errMsg = result.error || '未知错误';
      setStatus('私钥格式无效: ' + errMsg, 'error');
      console.error('[validatePrivateKey] Error:', errMsg);
    } else {
      setStatus('私钥格式验证通过', 'success');
    }
  } catch (err) {
    privateKeyValid = false;
    prvKeyRow?.classList.add('invalid');
    prvKeyRow?.classList.remove('loaded');
    console.error('[validatePrivateKey] Exception:', err);
  }
}

function scheduleValidatePublicKey() {
  clearTimeout(pubValidateTimer);
  pubValidateTimer = setTimeout(doValidatePublicKey, 500);
}

function scheduleValidatePrivateKey() {
  clearTimeout(prvValidateTimer);
  prvValidateTimer = setTimeout(doValidatePrivateKey, 500);
}

// ─── Encrypt ───────────────────────────────────────────────────────

encryptBtn.addEventListener('click', async () => {
  const inputPath = selectedFile || selectedFolder;
  const pubKey = publicKeyEl.value.trim();
  if (!inputPath) { setStatus('请先选择要加密的文件或文件夹', 'error'); return; }
  if (!pubKey) { setStatus('请先导入或粘贴公钥', 'error'); return; }
  if (!publicKeyValid) { setStatus('公钥格式无效，请先修正公钥 PEM', 'error'); return; }

  const encryptCard = encryptBtn.closest('.card');
  setProgress('busy');
  setStatus('正在加密...');
  disableButtons(true, cryptoBtns);
  encryptBtn.classList.add('btn-loading', 'processing-glow');
  encryptCard?.classList.add('processing', 'card-active-operation');
  try {
    const result = await api.encrypt({ inputPath, publicKey: pubKey });
    pendingTempPath = result.tempPath;
    pendingIsArchive = result.isArchive;
    setStatus('加密完成，请点击保存按钮选择输出路径', 'success');
    addHistory('encrypt', '加密: ' + basename(inputPath) + ' (' + result.outputSize + ' bytes)');
    flashCard(encryptCard);
    flashBtnSuccess(encryptBtn);
    saveOutputBtn.classList.remove('hidden');
  } catch (err) {
    setStatus('加密失败: ' + err, 'error');
    shakeCard(encryptCard);
  } finally {
    clearProgress();
    disableButtons(false, cryptoBtns);
    encryptBtn.classList.remove('btn-loading', 'processing-glow');
    encryptCard?.classList.remove('processing', 'card-active-operation');
  }
});

// ─── Decrypt ───────────────────────────────────────────────────────

decryptBtn.addEventListener('click', async () => {
  const inputPath = selectedFile || selectedFolder;
  const privKey = privateKeyEl.value.trim();
  if (!inputPath) { setStatus('请先选择要解密的文件', 'error'); return; }
  if (!privKey) { setStatus('请先导入或粘贴私钥', 'error'); return; }
  if (!privateKeyValid) { setStatus('私钥格式无效，请先修正私钥 PEM', 'error'); return; }

  const decryptCard = decryptBtn.closest('.card');
  setProgress('busy');
  setStatus('正在解密...');
  disableButtons(true, cryptoBtns);
  decryptBtn.classList.add('btn-loading', 'processing-glow');
  decryptCard?.classList.add('processing', 'card-active-operation');
  try {
    const result = await api.decrypt({ inputPath, privateKey: privKey });
    pendingTempPath = result.tempPath || result.tempDir;
    pendingIsArchive = result.isArchive;
    setStatus('解密完成，请点击保存按钮选择输出路径', 'success');
    addHistory('decrypt', '解密: ' + basename(inputPath) + ' (' + result.outputSize + ' bytes)');
    flashCard(decryptCard);
    flashBtnSuccess(decryptBtn);
    saveOutputBtn.classList.remove('hidden');
  } catch (err) {
    setStatus('解密失败: ' + err, 'error');
    shakeCard(decryptCard);
  } finally {
    clearProgress();
    disableButtons(false, cryptoBtns);
    decryptBtn.classList.remove('btn-loading', 'processing-glow');
    decryptCard?.classList.remove('processing', 'card-active-operation');
  }
});

// ─── Attestation ───────────────────────────────────────────────────

reportBrowseBtn.addEventListener('click', async () => {
  const filePath = await api.openFile({
    filters: [
      { name: 'Attestation Reports', extensions: ['bin', 'csv', 'dat'] },
      { name: 'All Files', extensions: ['*'] },
    ],
  });
  if (!filePath) return;
  reportFileInput.value = filePath;
  reportFileInput.classList.add('has-file');
  // Animate input when file path appears
  reportFileInput.classList.remove('input-file-landed');
  void reportFileInput.offsetWidth;
  reportFileInput.classList.add('input-file-landed');
  reportFileInput.addEventListener('animationend', () => reportFileInput.classList.remove('input-file-landed'), { once: true });
  setStatus('已选择报告: ' + basename(filePath));
});

verifyBtn.addEventListener('click', async () => {
  const reportPath = reportFileInput.value.trim();
  if (!reportPath) { setStatus('请先选择报告文件', 'error'); return; }

  setProgress('busy');
  setStatus('正在验证远程报告...');
  verifyBtn.disabled = true;
  verifyBtn.classList.add('btn-loading');
  try {
    const result = await api.verify({ reportPath, verifyChain: verifyChainCheck.checked });
    populateAttestationTable(result);
    if (result && result.error) {
      setStatus('验证完成（有警告）: ' + result.error, 'error');
      showVerdictBanner(false, '验证有警告', result.error);
      flashVerifyResult('fail');
    } else {
      setStatus('报告验证完成', 'success');
      addHistory('verify', '验证报告: ' + basename(reportPath));
      showVerdictBanner(true, '验证通过', '远程报告验证成功');
      flashVerifyResult('success');
    }
  } catch (err) {
    setStatus('验证失败: ' + err, 'error');
    flashVerifyResult('fail');
  } finally {
    clearProgress();
    verifyBtn.disabled = false;
    verifyBtn.classList.remove('btn-loading');
  }
});

// ─── History Panel Toggle ───────────────────────────────────────────
const historyHeader = $('historyHeader');
if (historyHeader) {
  historyHeader.addEventListener('click', () => {
    const panel = $('historyPanel');
    if (panel) panel.classList.toggle('collapsed');
  });
}

// ─── Card Flash Animation ───────────────────────────────────────────
function flashCard(cardEl) {
  if (!cardEl) return;
  cardEl.classList.remove('card-flash', 'card-flash-success');
  void cardEl.offsetWidth; // Force reflow
  cardEl.classList.add('card-flash', 'card-flash-success');
  cardEl.addEventListener('animationend', () => {
    cardEl.classList.remove('card-flash', 'card-flash-success');
  }, { once: true });
}

function shakeCard(cardEl) {
  if (!cardEl) return;
  cardEl.classList.remove('card-shake-error');
  void cardEl.offsetWidth;
  cardEl.classList.add('card-shake-error');
  cardEl.addEventListener('animationend', () => {
    cardEl.classList.remove('card-shake-error');
  }, { once: true });
}

function flashBtnSuccess(btnEl) {
  if (!btnEl) return;
  btnEl.classList.remove('btn-success-flash');
  void btnEl.offsetWidth;
  btnEl.classList.add('btn-success-flash');
  btnEl.addEventListener('animationend', () => {
    btnEl.classList.remove('btn-success-flash');
  }, { once: true });
}

function flashVerifyResult(result) {
  if (!verifyBtn) return;
  const cls = result === 'success' ? 'verify-success' : 'verify-fail';
  verifyBtn.classList.remove('verify-success', 'verify-fail');
  void verifyBtn.offsetWidth;
  verifyBtn.classList.add(cls);
  verifyBtn.addEventListener('animationend', () => verifyBtn.classList.remove(cls), { once: true });
}

// ─── Button Ripple Effect ───────────────────────────────────────────
function addRippleEffect(btnEl) {
  btnEl.addEventListener('click', function(e) {
    if (btnEl.disabled) return;
    const rect = btnEl.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = e.clientX - rect.left - size / 2;
    const y = e.clientY - rect.top - size / 2;

    const ripple = document.createElement('span');
    ripple.className = 'btn-ripple';
    ripple.style.width = ripple.style.height = size + 'px';
    ripple.style.left = x + 'px';
    ripple.style.top = y + 'px';

    btnEl.appendChild(ripple);
    ripple.addEventListener('animationend', () => ripple.remove());
  });
}

// Add ripple to main action buttons
[encryptBtn, decryptBtn, verifyBtn].forEach(addRippleEffect);


// ─── Verdict Banner ─────────────────────────────────────────────────
function showVerdictBanner(pass, title, detail) {
  if (!verdictBanner) return;
  verdictBanner.classList.remove('hidden', 'verdict-pass', 'verdict-fail', 'verdict-enter');
  verdictBanner.classList.add(pass ? 'verdict-pass' : 'verdict-fail');
  void verdictBanner.offsetWidth;
  verdictBanner.classList.add('verdict-enter');
  verdictBanner.addEventListener('animationend', () => verdictBanner.classList.remove('verdict-enter'), { once: true });

  if (verdictIcon) verdictIcon.innerHTML = pass ? '<polyline points="20 6 9 17 4 12"/>' : '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>';
  if (verdictTitle) verdictTitle.textContent = title;
  if (verdictDetail) verdictDetail.textContent = detail;
}

// ─── Key State Detection ────────────────────────────────────────────
function checkKeyLoaded(textareaEl) {
  const val = textareaEl.value.trim();
  return val.includes('-----BEGIN') && val.includes('-----END');
}

function onKeyInput(textareaEl, keyRow, badge) {
  const loaded = checkKeyLoaded(textareaEl);
  const wasLoaded = keyRow?.classList.contains('loaded');
  if (keyRow) keyRow.classList.toggle('loaded', loaded);
  if (badge) {
    badge.classList.remove('public-loaded', 'private-loaded');
    if (loaded) {
      if (keyRow.classList.contains('public')) badge.classList.add('public-loaded');
      else badge.classList.add('private-loaded');
      // Pulse badge when key first detected
      if (!wasLoaded) {
        badge.classList.remove('badge-pulse');
        void badge.offsetWidth;
        badge.classList.add('badge-pulse');
        badge.addEventListener('animationend', () => badge.classList.remove('badge-pulse'), { once: true });
      }
    }
  }
  // Update textarea count
  const val = textareaEl.value;
  const counter = keyRow?.querySelector('.textarea-count');
  if (counter) {
    const lines = val ? countLines(val) : 0;
    const newText = val.length + ' 字符 · ' + lines + ' 行';
    if (counter.textContent !== newText) {
      counter.textContent = newText;
      counter.classList.remove('count-update');
      void counter.offsetWidth;
      counter.classList.add('count-update');
    }
  }
}

function countLines(val) {
  let n = 1;
  for (let i = 0; i < val.length; i++) if (val[i] === '\n') n++;
  return n;
}

// Single merged input listener per textarea (key state + char count + validation)
publicKeyEl.addEventListener('input', () => {
  onKeyInput(publicKeyEl, pubKeyRow, pubBadge);
  scheduleValidatePublicKey();
});
privateKeyEl.addEventListener('input', () => {
  onKeyInput(privateKeyEl, prvKeyRow, prvBadge);
  scheduleValidatePrivateKey();
});

// Init key state + textarea counters
function initTextarea(textareaEl, keyRow, badge) {
  onKeyInput(textareaEl, keyRow, badge);
  const counter = document.createElement('div');
  counter.className = 'textarea-count';
  if (keyRow) keyRow.appendChild(counter);
}

initTextarea(publicKeyEl, pubKeyRow, pubBadge);
initTextarea(privateKeyEl, prvKeyRow, prvBadge);

// ─── Shortcut Hints ─────────────────────────────────────────────────
function addShortcutHint(btnId, shortcut) {
  const btn = $(btnId);
  if (!btn) return;
  const hint = document.createElement('span');
  hint.className = 'shortcut-hint';
  hint.textContent = shortcut;
  btn.appendChild(hint);
}
addShortcutHint('genKeyBtn', 'Ctrl+G');
addShortcutHint('encryptBtn', 'Ctrl+E');
addShortcutHint('decryptBtn', 'Ctrl+D');

// ─── Attestation Table Wrap Scroll Shadow ──────────────────────────
const attTableWrap = document.querySelector('.att-table-wrap');
if (attTableWrap) {
  attTableWrap.addEventListener('scroll', () => {
    const thead = attTableWrap.querySelector('thead');
    if (thead) {
      thead.classList.toggle('scrolled', attTableWrap.scrollTop > 2);
    }
  });
}

// ─── Attestation Field Dictionary ───────────────────────────────────
const ATT_FIELDS = [
  ['报告文件', '要验证的远程报告文件路径'],
  ['报告长度', '报告文件总字节数'],
  ['PUBKEY_DIGEST (0x000)', '平台公钥摘要，用于标识对应的平台密钥'],
  ['ID (0x020)', '虚拟机唯一标识符（VM ID）'],
  ['Version (0x030)', '报告版本号，标识固件或固件兼容版本'],
  ['USERDATA (0x040)', '用户自定义数据，通常用于绑定会话或挑战值'],
  ['MNONCE (0x080)', '测量随机数，用于防止重放攻击'],
  ['DIGEST (0x090)', '虚拟机的度量摘要（固件/内核的哈希值）'],
  ['POLICY (0x0B0)', '安全策略位掩码，控制调试权限、内存加密等安全选项'],
  ['SIG_USAGE (0x0B4)', '签名用途标识，说明签名的使用场景'],
  ['SIG_ALGO (0x0B8)', '签名算法标识，如 SM2、RSA 等'],
  ['ANONCE (0x0BC)', '认证随机数，与签名绑定的防重放值'],
  ['Signature (0x0C0)', '报告签名值，由 PEK 对报告内容签名生成'],
  ['PEK_CERT (0x150)', '平台endorsement密钥（PEK）证书数据大小'],
  ['CHIP_ID (0x974)', '芯片唯一标识符，标识物理硬件'],
  ['Reserved2 (0x9B4)', '保留字段，当前未使用'],
  ['MAC (0x9D4)', '消息认证码，用于校验报告完整性'],
  ['报告签名', 'PEK 对报告内容的签名验证结果'],
  ['PEK PubKeyUsage', 'PEK 证书中公钥的用途标识'],
  ['PEK Sig1Usage', 'PEK 证书中签名 1 的用途标识'],
  ['PEK Sig2Usage', 'PEK 证书中签名 2 的用途标识'],
  ['PEK CurveID', 'PEK 公钥使用的椭圆曲线标识（如 SM2P256）'],
  ['PEK UserID', 'PEK 证书中公钥的用户标识（文本）'],
  ['PEK UserID Hex', 'PEK 证书中公钥的用户标识（十六进制）'],
  ['PEK QX', 'PEK 公钥的 X 坐标（椭圆曲线上的点）'],
  ['PEK QY', 'PEK 公钥的 Y 坐标（椭圆曲线上的点）'],
];

const ATT_CHAIN_FIELDS = [
  ['证书来源', '证书链获取方式：远程下载或本地缓存'],
  ['HRK URL', 'Hygon 根密钥（HRK）证书的下载地址'],
  ['HSK/CEK URL', 'HSK 和 CEK 证书的下载地址'],
  ['下载说明', '证书下载过程的备注信息'],
  ['HRK KeyUsage', 'Hygon 根密钥的用途标识'],
  ['HRK UserID', 'HRK 证书的用户标识'],
  ['HRK QX', 'HRK 公钥 X 坐标'],
  ['HRK QY', 'HRK 公钥 Y 坐标'],
  ['HRK 自签名', 'HRK 证书自签名验证结果（根证书应自签名通过）'],
  ['HSK KeyUsage', 'Hygon 签名密钥的用途标识'],
  ['HSK UserID', 'HSK 证书的用户标识'],
  ['HSK QX', 'HSK 公钥 X 坐标'],
  ['HSK QY', 'HSK 公钥 Y 坐标'],
  ['HSK HRK签名', 'HSK 由 HRK 签名的验证结果'],
  ['CEK KeyUsage', '芯片背书密钥的用途标识'],
  ['CEK UserID', 'CEK 证书的用户标识'],
  ['CEK QX', 'CEK 公钥 X 坐标'],
  ['CEK QY', 'CEK 公钥 Y 坐标'],
  ['CEK HSK签名', 'CEK 由 HSK 签名的验证结果'],
  ['PEK CEK签名', 'PEK 由 CEK 签名的验证结果（芯片级信任链终点）'],
  ['证书链完整性', 'HRK→HSK→CEK→PEK 完整信任链验证结果'],
];

// Build tooltip map
const attTooltipMap = new Map();
for (const [name, desc] of ATT_FIELDS) attTooltipMap.set(name, desc);
for (const [name, desc] of ATT_CHAIN_FIELDS) attTooltipMap.set(name, desc);

// Pre-fill attestation table on load
(function initAttestationTable() {
  const tbody = attestationTable.querySelector('tbody');
  tbody.innerHTML = '';
  for (const [name, desc] of ATT_FIELDS) {
    const tr = document.createElement('tr');
    tr.title = desc;
    tr.innerHTML = `<td>${name}</td><td class="att-val">—</td>`;
    tbody.appendChild(tr);
  }
})();

// ─── Attestation Table ──────────────────────────────────────────────
function populateAttestationTable(result) {
  const tbody = attestationTable.querySelector('tbody');

  if (!result || !result.fields) {
    tbody.querySelectorAll('.att-val').forEach(td => td.textContent = '—');
    return;
  }

  // Build a map of pre-filled rows by field name
  const prefilled = new Map();
  tbody.querySelectorAll('tr').forEach(tr => {
    const cells = tr.querySelectorAll('td');
    if (cells.length === 2) {
      prefilled.set(cells[0].textContent.trim(), cells[1]);
    }
  });

  // Remove any previously appended dynamic rows
  tbody.querySelectorAll('.att-dynamic').forEach(tr => tr.remove());

  let rowIndex = 0;
  for (const field of result.fields) {
    if (field.separator) {
      const tr = document.createElement('tr');
      tr.className = 'separator att-dynamic';
      tr.innerHTML = '<td colspan="2"></td>';
      tbody.appendChild(tr);
      continue;
    }

    const valCell = prefilled.get(field.name);
    if (valCell) {
      valCell.textContent = field.value;
      valCell.classList.remove('att-updated');
      void valCell.offsetWidth;
      valCell.classList.add('att-updated');
      valCell.addEventListener('animationend', () => valCell.classList.remove('att-updated'), { once: true });
    } else {
      // Append new row with tooltip
      const tip = attTooltipMap.get(field.name) || '';
      const tr = document.createElement('tr');
      tr.className = 'att-dynamic row-enter';
      tr.title = tip;
      tr.style.animationDelay = (rowIndex * 0.04) + 's';
      tr.innerHTML = `<td>${field.name}</td><td class="att-val">${field.value}</td>`;
      tbody.appendChild(tr);
      tr.addEventListener('animationend', () => { tr.classList.remove('row-enter'); tr.style.animationDelay = ''; }, { once: true });
    }
    rowIndex++;
  }

  const resultsHeader = document.querySelector('.results-header');
  if (resultsHeader) {
    resultsHeader.classList.remove('results-visible');
    void resultsHeader.offsetWidth;
    resultsHeader.classList.add('results-visible');
  }
}

// ─── Verification Flow Animation ───────────────────────────────────
const flowOverlay = $('flowOverlay');
const showFlowBtn = $('showFlowBtn');
const flowClose = $('flowClose');
const flowViz = $('flowViz');
const flowProgressFill = $('flowProgressFill');
const flowProgressText = $('flowProgress');
const flowPrevBtn = $('flowPrev');
const flowNextBtn = $('flowNext');

const FLOW_STEPS = [
  {
    title: '读取报告二进制文件',
    render: () => `
      <p class="flow-desc">Hygon CSV 远程证明报告是一个固定长度的二进制文件，总大小为 <b>2548 字节 (0x9F4)</b>。</p>
      <div class="flow-block highlight">
        <div class="flow-block-label">报告文件</div>
        <div class="flow-block-content">
          文件大小: 2548 bytes (0x9F4)<br>
          格式: Hygon CSV Attestation Report<br>
          结构: 固定偏移量的二进制字段布局
        </div>
      </div>
      <p class="flow-note">手动验证时，使用 xxd 或 hexdump 查看报告原始字节。</p>`
  },
  {
    title: '读取 ANonce 解密密钥',
    render: () => `
      <p class="flow-desc">报告偏移量 <b>0x0BC</b> 处存储了 ANonce（4 字节），它是报告中多个字段的 XOR 解密密钥。部分敏感字段在写入报告时被 ANonce 掩码保护。</p>
      <div class="flow-block highlight">
        <div class="flow-block-label">ANonce (0x0BC, 4 bytes)</div>
        <div class="flow-block-content">
          <span class="offset">偏移 0x0BC</span>: 读取 4 字节 little-endian uint32
        </div>
      </div>
      <div class="flow-xor-diagram">
        <div class="flow-xor-row">
          <div class="flow-xor-cell flow-xor-label">原始字节</div>
          <div class="flow-xor-cell flow-xor-byte">A3</div>
          <div class="flow-xor-cell flow-xor-byte">7F</div>
          <div class="flow-xor-cell flow-xor-byte">02</div>
          <div class="flow-xor-cell flow-xor-byte">E1</div>
          <div class="flow-xor-cell flow-xor-byte">B8</div>
          <div class="flow-xor-cell flow-xor-byte">4D</div>
          <div class="flow-xor-cell flow-xor-byte">96</div>
          <div class="flow-xor-cell flow-xor-byte">C5</div>
          <div class="flow-xor-dots">…</div>
        </div>
        <div class="flow-xor-row flow-xor-op-row">
          <div class="flow-xor-cell flow-xor-label flow-xor-op-label">XOR</div>
          <div class="flow-xor-cell flow-xor-op">5A</div>
          <div class="flow-xor-cell flow-xor-op">5A</div>
          <div class="flow-xor-cell flow-xor-op">5A</div>
          <div class="flow-xor-cell flow-xor-op">5A</div>
          <div class="flow-xor-cell flow-xor-op">5A</div>
          <div class="flow-xor-cell flow-xor-op">5A</div>
          <div class="flow-xor-cell flow-xor-op">5A</div>
          <div class="flow-xor-cell flow-xor-op">5A</div>
          <div class="flow-xor-dots"></div>
        </div>
        <div class="flow-xor-divider"></div>
        <div class="flow-xor-row">
          <div class="flow-xor-cell flow-xor-label flow-xor-result-label">真实值</div>
          <div class="flow-xor-cell flow-xor-result">F9</div>
          <div class="flow-xor-cell flow-xor-result">25</div>
          <div class="flow-xor-cell flow-xor-result">58</div>
          <div class="flow-xor-cell flow-xor-result">BB</div>
          <div class="flow-xor-cell flow-xor-result">E2</div>
          <div class="flow-xor-cell flow-xor-result">17</div>
          <div class="flow-xor-cell flow-xor-result">CC</div>
          <div class="flow-xor-cell flow-xor-result">9F</div>
          <div class="flow-xor-dots">…</div>
        </div>
      </div>
      <p class="flow-note">每 4 字节为一组，与 ANonce (0x5A5A5A5A 示例) 做逐字 XOR 运算。</p>`
  },
  {
    title: '提取报告字段',
    render: () => {
      const fields = [
        ['0x000', 'PUBKEY_DIGEST', '32B', '平台公钥摘要', false],
        ['0x020', 'VM ID', '16B', '虚拟机标识', false],
        ['0x030', 'Version', '16B', '报告版本', false],
        ['0x040', 'USERDATA', '64B', '用户自定义数据', true],
        ['0x080', 'MNONCE', '16B', '度量随机数', true],
        ['0x090', 'DIGEST', '32B', '度量摘要', true],
        ['0x0B0', 'POLICY', '4B', '安全策略', true],
        ['0x0B4', 'SIG_USAGE', '4B', '签名用途', true],
        ['0x0B8', 'SIG_ALGO', '4B', '签名算法', true],
        ['0x0BC', 'ANonce', '4B', 'XOR 解密密钥', false],
        ['0x0C0', 'Signature', '144B', 'SM2 签名 (R+S)', false],
        ['0x150', 'PEK 证书', '2084B', '平台背书密钥证书', true],
        ['0x974', 'CHIP_ID', '64B', '芯片序列号', true],
        ['0x9B4', 'Reserved2', '32B', '保留字段', false],
        ['0x9D4', 'MAC', '32B', '消息认证码', false],
      ];
      let rows = fields.map(([off, name, size, desc, masked]) =>
        `<tr class="${masked ? 'f-masked' : 'f-plain'}"><td class="f-off">${off}</td><td class="f-name">${name}</td><td class="f-size">${size}</td><td class="f-desc">${desc}</td><td class="f-tag">${masked ? '⊕ XOR' : '直接'}</td></tr>`
      ).join('');
      return `
      <p class="flow-desc">按偏移量顺序提取报告中所有字段。<span class="f-tag-legend f-masked-tag">⊕ XOR 解密</span> 表示需要 ANonce 解密，<span class="f-tag-legend f-plain-tag">直接</span> 表示直接读取。</p>
      <div class="flow-field-table-wrap">
        <table class="flow-field-table"><thead><tr><th>偏移</th><th>字段</th><th>长度</th><th>说明</th><th>读取</th></tr></thead><tbody>${rows}</tbody></table>
      </div>`;
    }
  },
  {
    title: '解析 PEK 证书结构',
    render: () => `
      <p class="flow-desc">PEK (Platform Endorsement Key) 证书位于报告偏移 <b>0x150</b> 处，大小 <b>2084 字节 (0x824)</b>。它是 CSV 格式的证书，包含 SM2 公钥和签名。</p>
      <div class="flow-block highlight">
        <div class="flow-block-label">PEK 证书内部结构</div>
        <div class="flow-block-content">
          <span class="offset">+0x008</span> <span class="val">PubKeyUsage</span> (4B) — 应为 0x1002 (PEK)<br>
          <span class="offset">+0x010</span> <span class="val">公钥区域</span> — SM2 椭圆曲线公钥<br>
          &nbsp;&nbsp;<span class="offset">+0x014</span> CurveID = 0x3 (SM2P256)<br>
          &nbsp;&nbsp;<span class="offset">+0x018</span> QX (32B) — 公钥 X 坐标<br>
          &nbsp;&nbsp;<span class="offset">+0x060</span> QY (32B) — 公钥 Y 坐标<br>
          &nbsp;&nbsp;<span class="offset">+0x0A8</span> UserID — 签名者标识<br>
          <span class="offset">+0x414</span> <span class="val">Sig1Usage</span> (4B)<br>
          <span class="offset">+0x41C</span> <span class="val">Sig1</span> (签名 R+S)<br>
          <span class="offset">+0x61C</span> <span class="val">Sig2Usage</span> (4B)<br>
          <span class="offset">+0x624</span> <span class="val">Sig2</span> (签名 R+S)
        </div>
      </div>`
  },
  {
    title: '提取 PEK 公钥 (QX, QY, UserID)',
    render: () => `
      <p class="flow-desc">从 PEK 证书中提取 SM2 公钥。SM2 是国密椭圆曲线算法，公钥由曲线上的点 (QX, QY) 和签名者标识 (UserID) 组成。注意 Hygon 的字节序是<b>小端序 (reversed)</b>，需要反转后使用。</p>
      <div class="flow-block highlight">
        <div class="flow-block-label">提取 SM2 公钥</div>
        <div class="flow-block-content">
          CurveID = <span class="val">0x3</span> → SM2P256 曲线<br><br>
          QX = <span class="val">reverse(证书[0x018 : 0x038])</span> → 32字节大整数<br>
          QY = <span class="val">reverse(证书[0x060 : 0x080])</span> → 32字节大整数<br><br>
          UserID = <span class="val">证书[0x0A8]</span> — SM2 签名验证所需的标识字符串<br><br>
          <span class="fn">SM2PubKey</span> = { X: QX, Y: QY }
        </div>
      </div>
      <p class="flow-note">手动操作时，可用 openssl ec 命令解析 SM2 公钥参数。</p>`
  },
  {
    title: '提取报告签名 (R, S)',
    render: () => `
      <p class="flow-desc">报告签名位于偏移 <b>0x0C0</b>，长度 144 字节。其中有效签名数据是 SM2 签名的两个分量 R 和 S，各 32 字节，同样是小端序。</p>
      <div class="flow-block highlight">
        <div class="flow-block-label">报告签名 (0x0C0)</div>
        <div class="flow-block-content">
          R = <span class="val">reverse(报告[0x0C0 : 0x0E0])</span> → 32字节大整数<br>
          S = <span class="val">reverse(报告[0x108 : 0x128])</span> → 32字节大整数<br><br>
          <span class="fn">Signature</span> = (R, S)
        </div>
      </div>
      <div class="flow-arrow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg></div>
      <p class="flow-desc">接下来将使用 PEK 公钥和 (R, S) 签名验证报告数据完整性。</p>`
  },
  {
    title: 'SM2 签名验证',
    render: () => `
      <p class="flow-desc">验证的核心：使用 SM2 算法确认报告前 <b>0xB4 (180) 字节</b>数据由 PEK 私钥签名，未被篡改。</p>
      <div class="flow-verify-center">
        <div class="flow-verify-fn">
          <span class="fn">SM2_Verify</span> ( pubKey, userID, message, sig )
        </div>
        <div class="flow-verify-params">
          <div class="flow-vp-item">
            <span class="vp-label">pubKey</span>
            <span class="vp-eq">=</span>
            <span class="vp-val">PEK.{ QX, QY }</span>
          </div>
          <div class="flow-vp-item">
            <span class="vp-label">userID</span>
            <span class="vp-eq">=</span>
            <span class="vp-val">PEK.UserID</span>
          </div>
          <div class="flow-vp-item">
            <span class="vp-label">message</span>
            <span class="vp-eq">=</span>
            <span class="vp-val">报告[ 0x000 : 0x0B4 ]<span class="vp-note">前180字节</span></span>
          </div>
          <div class="flow-vp-item">
            <span class="vp-label">sig</span>
            <span class="vp-eq">=</span>
            <span class="vp-val">( R, S )<span class="vp-note">签名分量</span></span>
          </div>
        </div>
        <div class="flow-verify-divider"></div>
        <div class="flow-verify-results">
          <div class="flow-vr-item"><span class="result-ok">✓ 通过</span><span class="vr-desc">报告完整，来自合法 TEE 平台</span></div>
          <div class="flow-vr-item"><span class="result-fail">✗ 失败</span><span class="vr-desc">报告被篡改或来源不可信</span></div>
        </div>
      </div>
      <p class="flow-note">手动验证可使用 GmSSL 或 OpenSSL SM2 模块。</p>`
  },
  {
    title: '获取芯片 ID 构造证书下载 URL',
    render: () => `
      <p class="flow-desc">从解密后的 CHIP_ID 字段提取芯片序列号（ASCII 文本），用它构造 Hygon 证书服务器的下载 URL。</p>
      <div class="flow-block">
        <div class="flow-block-label">CHIP_ID (0x974, 64 bytes, XOR解密后)</div>
        <div class="flow-block-content">
          chip_id = <span class="val">"HYGONxxxxxxx"</span> — ASCII 芯片序列号<br>
          去除尾部 \\x00 和空白
        </div>
      </div>
      <div class="flow-arrow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg></div>
      <div class="flow-block highlight">
        <div class="flow-block-label">证书下载 URL</div>
        <div class="flow-block-content">
          HRK = <span class="val">https://cert.hygon.cn/hrk</span><br>
          HSK/CEK = <span class="val">https://cert.hygon.cn/hsk_cek?snumber={chip_id}</span>
        </div>
      </div>`
  },
  {
    title: '下载证书链 (HRK + HSK/CEK)',
    render: () => `
      <p class="flow-desc">从 Hygon 证书服务器下载两个证书文件。</p>
      <div class="flow-block highlight">
        <div class="flow-block-label">HRK 根证书 (832 bytes / 0x340)</div>
        <div class="flow-block-content">
          来源: https://cert.hygon.cn/hrk<br>
          类型: Hygon Root Key — 信任链的根<br>
          KeyUsage: <span class="val">0x0000</span> (HRK)
        </div>
      </div>
      <div class="flow-block highlight">
        <div class="flow-block-label">HSK/CEK 证书包 (2924 bytes / 0xB6C)</div>
        <div class="flow-block-content">
          来源: https://cert.hygon.cn/hsk_cek?snumber={chip_id}<br>
          包含两个证书:<br>
          &nbsp;&nbsp;<span class="val">HSK</span> (前832字节) — Hygon Signing Key, KeyUsage: 0x0013<br>
          &nbsp;&nbsp;<span class="val">CEK</span> (后2084字节) — Chip Endorsement Key, PubKeyUsage: 0x1004
        </div>
      </div>`
  },
  {
    title: '验证证书链 (HRK → HSK → CEK → PEK)',
    render: () => `
      <p class="flow-desc">证书链验证是逐级进行的：每一级证书的公钥用来验证下一级证书的签名。这构成了从 Hygon 根密钥到具体芯片 PEK 的完整信任链。</p>
      <div class="flow-chain">
        <div class="flow-cert done">
          <div class="flow-cert-name">HRK</div>
          <div class="flow-cert-desc">根密钥<br>自签名验证 ✓</div>
        </div>
        <div class="flow-cert-arrow done">→</div>
        <div class="flow-cert done">
          <div class="flow-cert-name">HSK</div>
          <div class="flow-cert-desc">签名密钥<br>HRK签名验证 ✓</div>
        </div>
        <div class="flow-cert-arrow done">→</div>
        <div class="flow-cert active">
          <div class="flow-cert-name">CEK</div>
          <div class="flow-cert-desc">芯片背书密钥<br>HSK签名验证</div>
        </div>
        <div class="flow-cert-arrow">→</div>
        <div class="flow-cert">
          <div class="flow-cert-name">PEK</div>
          <div class="flow-cert-desc">平台背书密钥<br>CEK签名验证</div>
        </div>
      </div>
      <div class="flow-verify-box active">
        <div class="flow-block-label">逐级 SM2 签名验证</div>
        <div class="flow-verify-formula">
          ① <span class="fn">SM2_Verify</span>(<span class="op">HRK.PubKey</span>, HRK_data, HRK_Sig) → <span class="result-ok">自签名 ✓</span><br>
          ② <span class="fn">SM2_Verify</span>(<span class="op">HRK.PubKey</span>, HSK_data, HSK_Sig) → <span class="result-ok">HRK签HSK ✓</span><br>
          ③ <span class="fn">SM2_Verify</span>(<span class="op">HSK.PubKey</span>, CEK_data, CEK_Sig1) → <span class="result-ok">HSK签CEK ✓</span><br>
          ④ <span class="fn">SM2_Verify</span>(<span class="op">CEK.PubKey</span>, PEK_data, PEK_Sig1) → <span class="result-ok">CEK签PEK ✓</span>
        </div>
      </div>`
  },
  {
    title: '验证 KeyUsage 标识',
    render: () => `
      <p class="flow-desc">除了签名验证，还需检查每个证书的 KeyUsage 字段是否正确，确保证书没有被错误使用或替换。</p>
      <div class="flow-block">
        <div class="flow-block-label">KeyUsage 校验</div>
        <div class="flow-block-content">
          <span class="val">HRK</span> KeyUsage = <span class="offset">0x0000</span> → Hygon Root Key ✓<br>
          <span class="val">HSK</span> KeyUsage = <span class="offset">0x0013</span> → Hygon Signing Key ✓<br>
          <span class="val">CEK</span> PubKeyUsage = <span class="offset">0x1004</span> → Chip Endorsement Key ✓<br>
          <span class="val">CEK</span> Sig1Usage = <span class="offset">0x0013</span> → 签名者是 HSK ✓<br>
          <span class="val">CEK</span> Sig2Usage = <span class="offset">0x1000</span> → Invalid (未使用) ✓<br>
          <span class="val">PEK</span> PubKeyUsage = <span class="offset">0x1002</span> → Platform Endorsement Key ✓
        </div>
      </div>
      <p class="flow-note">任何一个 KeyUsage 不匹配都会导致验证失败，防止证书类型混淆攻击。</p>`
  },
  {
    title: '验证完成：信任链建立',
    render: () => `
      <div class="flow-final">
        <div class="flow-final-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        </div>
        <div class="flow-final-title">验证完成：远程平台可信</div>
        <div class="flow-final-desc">
          通过以上步骤，建立了从 Hygon 根密钥 (HRK) 到芯片 PEK 的完整信任链：<br><br>
          <b>HRK</b> (Hygon 信任根) → <b>HSK</b> (签名权威) → <b>CEK</b> (芯片级背书) → <b>PEK</b> (平台级背书)<br><br>
          报告签名由 PEK 验证通过，证明报告数据来自真实的 Hygon TEE 平台且未被篡改。<br><br>
          <span style="color:var(--text-tertiary)">手动验证工具: GmSSL、OpenSSL SM2 模块、或 Hygon 官方验证工具。</span>
        </div>
      </div>`
  }
];

let flowCurrent = 0;

function renderFlowStep(idx) {
  if (!flowViz || idx < 0 || idx >= FLOW_STEPS.length) return;
  flowCurrent = idx;
  const step = FLOW_STEPS[idx];
  flowViz.innerHTML = `<div class="flow-viz-inner"><div class="flow-title">${step.title}</div>${step.render()}</div>`;
  if (flowProgressFill) flowProgressFill.style.width = ((idx + 1) / FLOW_STEPS.length * 100) + '%';
  if (flowProgressText) flowProgressText.textContent = (idx + 1) + ' / ' + FLOW_STEPS.length;
}

function flowNext() {
  if (flowCurrent < FLOW_STEPS.length - 1) renderFlowStep(flowCurrent + 1);
  else stopFlowAuto();
}

function flowPrev() {
  if (flowCurrent > 0) renderFlowStep(flowCurrent - 1);
}

function openFlow() {
  if (!flowOverlay) return;
  flowOverlay.classList.remove('hidden');
  flowCurrent = 0;
  renderFlowStep(0);
}

function closeFlow() {
  if (!flowOverlay) return;
  flowOverlay.classList.add('hidden');
}

if (showFlowBtn) showFlowBtn.addEventListener('click', openFlow);
if (flowClose) flowClose.addEventListener('click', closeFlow);
if (flowPrevBtn) flowPrevBtn.addEventListener('click', flowPrev);
if (flowNextBtn) flowNextBtn.addEventListener('click', flowNext);
if (flowOverlay) flowOverlay.addEventListener('click', (e) => {
  if (e.target === flowOverlay) closeFlow();
});
