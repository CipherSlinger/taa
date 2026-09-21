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
let currentDrawerViewMode = 'visual';

function getAuditReportFromInteraction(item, tabType) {
  if (!item || tabType !== 'primary') return null;
  const content = item.primaryContent != null ? item.primaryContent : item.respBody;
  if (!content) return null;
  if (typeof content === 'object') {
    if (content.report) return content.report;
    if (content.conclusion || content.file_reports) return content;
  }
  if (typeof content === 'string') {
    try {
      const parsed = JSON.parse(content);
      if (parsed && typeof parsed === 'object') {
        if (parsed.report) return parsed.report;
        if (parsed.conclusion || parsed.file_reports) return parsed;
      }
    } catch (_) {}
  }
  return null;
}

function toggleDrawerViewMode() {
  currentDrawerViewMode = (currentDrawerViewMode === 'visual') ? 'json' : 'visual';
  switchDrawerTab(currentDrawerActiveTab);
}
window.toggleDrawerViewMode = toggleDrawerViewMode;

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
  currentDrawerViewMode = 'visual';
  const item = (typeof interactionStore !== 'undefined' && interactionStore[key]) ? interactionStore[key] : null;

  const drawer = document.getElementById('appDrawer');
  const titleEl = document.getElementById('drawerTitle') || document.getElementById('bodyModalTitle');
  const badgeEl = document.getElementById('drawerBadge') || document.getElementById('bodyModalBadge');
  const curlBtn = document.getElementById('drawerCurlBtn');
  const primaryTabBtn = document.getElementById('drawerTabPrimary') || document.getElementById('modalTabPrimary');
  const secondaryTabBtn = document.getElementById('drawerTabSecondary') || document.getElementById('modalTabSecondary');

  if (titleEl) {
    titleEl.textContent = item?.title || '接口交互详情';
  }
  if (primaryTabBtn) {
    primaryTabBtn.textContent = (item && item.primaryLabel) ? item.primaryLabel : '返回内容';
  }
  if (secondaryTabBtn) {
    secondaryTabBtn.textContent = (item && item.secondaryLabel) ? item.secondaryLabel : '请求体';
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
  const visualContainer = document.getElementById('drawerVisualContainer');
  const viewModeBtn = document.getElementById('drawerViewModeBtn');
  const viewModeText = document.getElementById('drawerViewModeText');

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
    const rawVal = isSecondary ? (item.secondaryContent != null ? item.secondaryContent : item.reqBody) : (item.primaryContent != null ? item.primaryContent : item.respBody);
    if (rawVal == null || rawVal === '') {
      content = defaultEmptyMsg;
    } else {
      content = formatModalBody(rawVal);
    }
  }

  currentDrawerBody = content;

  const auditReport = (currentDrawerInteractionKey === 'reportAudit' || getAuditReportFromInteraction(item, tabType)) && typeof renderAuditDashboard === 'function' ? getAuditReportFromInteraction(item, tabType) : null;

  if (auditReport && viewModeBtn && visualContainer && codeEl) {
    viewModeBtn.style.display = 'inline-flex';
    if (currentDrawerViewMode === 'visual') {
      if (viewModeText) viewModeText.textContent = '原始 JSON';
      visualContainer.innerHTML = renderAuditDashboard(auditReport);
      visualContainer.style.display = 'block';
      codeEl.style.display = 'none';
    } else {
      if (viewModeText) viewModeText.textContent = '可视化视图';
      visualContainer.style.display = 'none';
      codeEl.style.display = 'block';
      codeEl.innerHTML = highlightJSON(content);
    }
  } else {
    if (viewModeBtn) viewModeBtn.style.display = 'none';
    if (visualContainer) visualContainer.style.display = 'none';
    if (codeEl) {
      codeEl.style.display = 'block';
      codeEl.innerHTML = highlightJSON(content);
    }
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
  if (typeof showToast === 'function') {
    if (success) {
      showToast({ type: 'success', title: '复制成功', message: '已复制到剪贴板' });
    } else {
      showToast({ type: 'error', title: '复制失败', message: '未能写入剪贴板' });
    }
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
  if (typeof showToast === 'function') {
    if (success) {
      showToast({ type: 'success', title: 'cURL 复制成功', message: '已复制 cURL 命令到剪贴板' });
    } else {
      showToast({ type: 'error', title: '复制失败', message: '未能写入剪贴板' });
    }
  }
}

// Global keydown handler for Escape to close drawer & modals
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeDrawer();
    if (typeof closeTaaPublicKeyModal === 'function') {
      closeTaaPublicKeyModal();
    }
  }
});
