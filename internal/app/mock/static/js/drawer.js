// ── Slide-over Drawer & Syntax Highlighting & cURL Generation ──

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Micro JSON Syntax Highlighter: colorizes keys, strings, numbers, booleans, and nulls.
 * Sanitizes all input with escapeHtml before parsing.
 */
function highlightJSON(jsonStr) {
  if (typeof jsonStr !== 'string') {
    try {
      jsonStr = JSON.stringify(jsonStr, null, 2);
    } catch (_) {
      jsonStr = String(jsonStr);
    }
  }
  const safe = escapeHtml(jsonStr);
  return safe.replace(
    /("(?:\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    function (match) {
      let cls = 'hl-num';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'hl-key';
        } else {
          cls = 'hl-str';
        }
      } else if (/true|false/.test(match)) {
        cls = 'hl-bool';
      } else if (/null/.test(match)) {
        cls = 'hl-null';
      }
      return '<span class="' + cls + '">' + match + '</span>';
    }
  );
}

function parseJSONRecursively(val) {
  if (typeof val !== 'string') return val;
  const trimmed = val.trim();
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      const parsed = JSON.parse(trimmed);
      if (typeof parsed === 'object' && parsed !== null) {
        for (const k in parsed) {
          parsed[k] = parseJSONRecursively(parsed[k]);
        }
      }
      return parsed;
    } catch (_) {
      return val;
    }
  }
  return val;
}

let currentDrawerInteractionKey = null;
let currentDrawerActiveTab = 'primary';
let currentDrawerBody = '';

function formatModalBody(body) {
  if (body == null) return '';
  if (typeof body === 'object') {
    try {
      return JSON.stringify(body, null, 2);
    } catch (_) {
      return String(body);
    }
  }
  const str = String(body).trim();
  if ((str.startsWith('{') && str.endsWith('}')) || (str.startsWith('[') && str.endsWith(']'))) {
    try {
      const parsed = parseJSONRecursively(str);
      return JSON.stringify(parsed, null, 2);
    } catch (_) {
      return str;
    }
  }
  return str;
}

function buildCurlCommand(item) {
  if (!item) return '';
  const method = (item.method || 'POST').toUpperCase();
  const baseTaa = (typeof getTaaAddr === 'function') ? getTaaAddr() : '';
  const url = item.url || (baseTaa + (item.endpoint || ''));
  const lines = [`curl -X ${method} "${url}"`];
  lines.push('  -H "Content-Type: application/json"');
  if (item.reqHeaders && typeof item.reqHeaders === 'object') {
    for (const [k, v] of Object.entries(item.reqHeaders)) {
      if (k.toLowerCase() !== 'content-type') {
        lines.push(`  -H "${k}: ${v}"`);
      }
    }
  }
  if (item.reqBody != null && method !== 'GET' && method !== 'HEAD') {
    let bodyStr = '';
    if (typeof item.reqBody === 'string') {
      bodyStr = item.reqBody;
    } else {
      try {
        bodyStr = JSON.stringify(item.reqBody);
      } catch (_) {
        bodyStr = String(item.reqBody);
      }
    }
    // Escape single quotes for bash
    const escaped = bodyStr.replace(/'/g, `'\\''`);
    lines.push(`  -d '${escaped}'`);
  }
  return lines.join(' \\\n');
}

function openInteractionDrawer(key, preferredTab = 'primary') {
  currentDrawerInteractionKey = key;
  currentDrawerActiveTab = preferredTab;
  const item = (typeof interactionStore !== 'undefined' && interactionStore[key]) ? interactionStore[key] : null;

  const drawer = document.getElementById('appDrawer');
  const titleEl = document.getElementById('drawerTitle') || document.getElementById('bodyModalTitle');
  const badgeEl = document.getElementById('drawerBadge') || document.getElementById('bodyModalBadge');
  const curlBtn = document.getElementById('drawerCurlBtn');

  if (titleEl) {
    titleEl.textContent = item?.title || '接口交互详情';
  }
  if (badgeEl) {
    if (item) {
      badgeEl.innerHTML = renderInteractionBadge(item);
      badgeEl.style.display = 'inline-flex';
    } else {
      badgeEl.style.display = 'none';
    }
  }
  if (curlBtn) {
    curlBtn.style.display = (item && (item.endpoint || item.url)) ? 'inline-flex' : 'none';
  }

  switchDrawerTab(preferredTab);

  if (drawer) {
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
  } else {
    const legacyModal = document.getElementById('bodyModal');
    if (legacyModal) {
      legacyModal.classList.add('open');
      legacyModal.setAttribute('aria-hidden', 'false');
    }
  }
}

function closeDrawer() {
  const drawer = document.getElementById('appDrawer');
  if (drawer) {
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
  }
  const legacyModal = document.getElementById('bodyModal');
  if (legacyModal) {
    legacyModal.classList.remove('open');
    legacyModal.setAttribute('aria-hidden', 'true');
  }
}

function switchDrawerTab(tabType) {
  currentDrawerActiveTab = tabType;
  const primaryTabBtn = document.getElementById('drawerTabPrimary') || document.getElementById('modalTabPrimary');
  const secondaryTabBtn = document.getElementById('drawerTabSecondary') || document.getElementById('modalTabSecondary');
  const codeEl = document.getElementById('drawerCode') || document.getElementById('bodyModalContent');

  if (primaryTabBtn && secondaryTabBtn) {
    if (tabType === 'primary') {
      primaryTabBtn.classList.add('active');
      secondaryTabBtn.classList.remove('active');
    } else {
      primaryTabBtn.classList.remove('active');
      secondaryTabBtn.classList.add('active');
    }
  }

  const item = (typeof interactionStore !== 'undefined' && currentDrawerInteractionKey) ? interactionStore[currentDrawerInteractionKey] : null;
  let content = '';
  const isSecondary = (tabType === 'secondary');
  const defaultEmptyMsg = isSecondary ? '/* 尚未发送请求体 */' : '/* 暂无返回内容 */';

  if (!item) {
    content = defaultEmptyMsg;
  } else {
    const rawVal = isSecondary ? item.reqBody : item.respBody;
    if (rawVal == null || rawVal === '') {
      content = defaultEmptyMsg;
    } else {
      content = formatModalBody(rawVal);
    }
  }

  currentDrawerBody = content;
  if (codeEl) {
    codeEl.innerHTML = highlightJSON(content);
  }
}

// Aliases for backward compatibility
function openInteractionModal(key, preferredTab = 'primary') {
  openInteractionDrawer(key, preferredTab);
}
function closeBodyModal() {
  closeDrawer();
}
function switchModalTab(tabType) {
  switchDrawerTab(tabType);
}
function openBodyModal(title, body) {
  const codeEl = document.getElementById('drawerCode') || document.getElementById('bodyModalContent');
  const titleEl = document.getElementById('drawerTitle') || document.getElementById('bodyModalTitle');
  const badgeEl = document.getElementById('drawerBadge') || document.getElementById('bodyModalBadge');
  const tabsBar = document.getElementById('drawerTabsBar') || document.getElementById('modalTabsBar');

  if (titleEl) titleEl.textContent = title || '返回内容';
  if (badgeEl) badgeEl.style.display = 'none';
  if (tabsBar) tabsBar.style.display = 'none';

  currentDrawerBody = formatModalBody(body);
  if (codeEl) {
    codeEl.innerHTML = highlightJSON(currentDrawerBody);
  }

  const drawer = document.getElementById('appDrawer');
  if (drawer) {
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
  } else {
    const legacyModal = document.getElementById('bodyModal');
    if (legacyModal) {
      legacyModal.classList.add('open');
      legacyModal.setAttribute('aria-hidden', 'false');
    }
  }
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {}
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  ta.style.top = '-9999px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch (_) {}
  document.body.removeChild(ta);
  return ok;
}

async function copyBodyModal(btn) {
  const success = await copyText(currentDrawerBody);
  if (btn) {
    const originalText = btn.textContent;
    btn.textContent = success ? '已复制!' : '复制失败';
    setTimeout(() => {
      btn.textContent = originalText;
    }, 1500);
  }
}

async function copyCurlCommand(btn) {
  const item = (typeof interactionStore !== 'undefined' && currentDrawerInteractionKey) ? interactionStore[currentDrawerInteractionKey] : null;
  if (!item) return;
  const curlCmd = buildCurlCommand(item);
  const success = await copyText(curlCmd);
  if (btn) {
    const originalText = btn.textContent;
    btn.textContent = success ? '已复制 cURL!' : '复制失败';
    setTimeout(() => {
      btn.textContent = originalText;
    }, 1500);
  }
}

// Global keydown handler for Escape to close drawer
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeDrawer();
  }
});
