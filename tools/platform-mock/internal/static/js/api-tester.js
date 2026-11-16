// ── API tester ──
//
// One dropdown, one editable body and one generated curl command. TAA accepts
// only {dockerId?, cipher, sign}: the business JSON is SM2-sealed and signed,
// so a plaintext body cannot succeed. The browser cannot run SM2, so the mock
// seals the body through /api/crypto/envelope and the command carries the
// finished envelope. The keys doing the sealing are shown and editable, and
// the request goes straight to the instance's own address - through the mock's
// /taa proxy the envelope would be sealed a second time.
//
// Only platform→TAA business routes are listed. The callbacks TAA sends
// (register, report*, *Log) are sealed envelopes the mock opens with the
// instance's registered key, so a hand-written body cannot reproduce them.

const API_TESTER_ENDPOINTS = [
  {
    path: '/v1/taa/health',
    label: '健康检查',
    body: () => ({}),
    note: '返回阶段、端口与模型状态。控制台用它判断实例是否可达。',
  },
  {
    path: '/v1/taa/status',
    label: '运行状态',
    body: () => ({}),
    note: '返回阶段、当前任务与资源目录。',
  },
  {
    path: '/v1/taa/switch',
    label: '阶段切换',
    body: () => ({ phase: 3 }),
    note: 'phase：1 调试 / 2 测试 / 3 训练 / 4 推理。有任务、导入或审计在跑时会被拒绝。',
  },
  {
    path: '/v1/taa/getAttestation',
    label: '远程证明报告',
    body: () => ({ requestId: genId('req-attest') }),
    note: '返回 base64 报告与解析后的字段；helper 调用需要数秒，45s 超时。',
  },
  {
    path: '/v1/taa/getResourceInfo',
    label: '查询资源',
    body: () => ({ resourceUrl: 'http://example.com/data.tar.gz' }),
    note: '按 resourceUrl 查询导入记录。',
  },
  {
    path: '/v1/taa/import',
    label: '下发数据',
    body: () => ({
      resourceUrl: 'http://example.com/data.tar.gz',
      requestId: genId('req-data'),
      taskId: genId('task-data'),
    }),
    note: '平台下发数据包；requestId / taskId 是后续导出和结果上报要用的标识。',
  },
  {
    path: '/v1/taa/importModel',
    label: '下发模型',
    body: () => ({
      resourceUrl: 'http://example.com/model.tar.gz',
      requestId: genId('req-model'),
      taskId: genId('task-model'),
      runtimeConfig: JSON.stringify({
        commands: ['python3 train.py -b TransMUF -g cpu -bc 16 -e 30 -d _dkd -s 128'],
        env: 'CUDA_VISIBLE_DEVICES=0',
      }),
    }),
    note: 'runtimeConfig 是 JSON 字符串而不是对象，TAA 会再解析一次；导入后异步触发代码审计。',
  },
  {
    path: '/v1/taa/export',
    label: '导出结果',
    body: () => ({ requestId: genId('req-data'), taskId: genId('task-data') }),
    note: '响应是文件字节（加密时为 .enc），不是 JSON；需要时可给 curl 加 -o 保存。',
  },
  {
    path: '/v1/taa/stopTraining',
    label: '中止训练',
    body: () => ({}),
    note: '中止当前训练任务；没有任务在跑时返回错误码。',
  },
];

function apiTesterSelected() {
  const sel = document.getElementById('apiTesterEndpoint');
  if (!sel) return API_TESTER_ENDPOINTS[0];
  return API_TESTER_ENDPOINTS.find((e) => e.path === sel.value) || API_TESTER_ENDPOINTS[0];
}

// The target address follows the selected instance's direct address until the
// operator edits the field; after that it is theirs and the async resolution
// must not overwrite it.
let apiTesterBaseAuto = true;

// apiTesterDefaultBase is the instance's own TAA address. The console calls TAA
// through the mock's /taa proxy when one is registered, but a sealed body must
// not go through it: the proxy seals again, and TAA then opens a double
// envelope. Falls back to the page host, then to the loopback default.
function apiTesterDefaultBase() {
  const id = typeof currentDockerId === 'function' ? currentDockerId() : '';
  const direct = id && typeof instanceTargets !== 'undefined' ? instanceTargets[id] : '';
  if (direct) return direct.replace(/\/+$/, '');
  const current = typeof getTaaAddr === 'function' ? getTaaAddr() : '';
  if (current && !/\/taa$/.test(current)) return current;
  return typeof defaultTaaAddr === 'function' ? defaultTaaAddr() : location.origin;
}

function apiTesterOnBaseInput() {
  apiTesterBaseAuto = false;
  apiTesterRender();
}

function apiTesterBaseValue() {
  const input = document.getElementById('apiTesterBase');
  return (input && input.value ? input.value : '').trim().replace(/\/+$/, '');
}

function apiTesterUsingProxy() {
  return /\/taa$/.test(apiTesterBaseValue());
}

function apiTesterUrl() {
  return apiTesterBaseValue() + apiTesterSelected().path;
}

// shellQuote wraps a value in single quotes, closing and reopening around any
// single quote inside it. JSON bodies normally have none, but a user-pasted string
// field can.
function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

// ── Envelope key boxes ──
//
// Both boxes are prefilled from the mock's own key material. An empty side is
// filled in by the server from the same keystore, so clearing one box does not
// break the command; clearing both falls back to the mock's registered key,
// which is exactly what the console itself uses.
let apiTesterKeysAuto = true;

// apiTesterDockerId is the instance the card is sealing for. The console's own
// selection resolves asynchronously, so the card reads the instance list once at
// startup and remembers the default; afterwards the console's selection wins.
let apiTesterDockerId = '';

function apiTesterSelectedDockerId() {
  const id = typeof currentDockerId === 'function' ? currentDockerId() : '';
  return id || apiTesterDockerId;
}

function apiTesterKeyValue(id) {
  const el = document.getElementById(id);
  return el ? el.value : '';
}

function apiTesterOnKeyInput() {
  apiTesterKeysAuto = false;
  apiTesterScheduleSeal();
}

function apiTesterApplyKeys(result) {
  const priv = document.getElementById('apiTesterPlatformPriv');
  const pub = document.getElementById('apiTesterTaaPub');
  const id = document.getElementById('apiTesterIdentity');
  if (priv) priv.value = result.platformPrivateKey || '';
  if (pub) pub.value = result.taaPublicKeyHex || '';
  if (id) id.value = result.identity || '';
  apiTesterKeysAuto = true;
}

async function apiTesterLoadKeys() {
  const id = apiTesterSelectedDockerId();
  const url = id ? '/api/crypto/envelope?dockerId=' + encodeURIComponent(id) : '/api/crypto/envelope';
  try {
    const res = await fetch(url, { cache: 'no-store' });
    const payload = await res.json();
    if (!payload || payload.error !== 0) return;
    apiTesterApplyKeys(payload.result || {});
    apiTesterScheduleSeal();
  } catch (_) {
    // Leave whatever is in the boxes; the seal call reports the real problem.
  }
}

function apiTesterReloadKeys() {
  apiTesterLoadKeys();
}

// apiTesterBootstrap resolves the instance this card seals for without waiting
// for the console's 5s poll. Both the direct target and the TAA key belong to
// that instance, and until the first poll finishes the console has no selection
// at all - sealing then would use the legacy key and target the page host.
async function apiTesterBootstrap() {
  try {
    const res = await fetch('/api/instances', { cache: 'no-store' });
    const payload = await res.json();
    const result = (payload && payload.result) || {};
    const list = result.instances || [];
    list.forEach((item) => {
      if (item.dockerId) instanceTargets[item.dockerId] = item.taaTarget || '';
    });
    const id = result.defaultDockerId || (list[0] && list[0].dockerId) || '';
    if (id) apiTesterDockerId = id;
    if (id && apiTesterBaseAuto) {
      const direct = (instanceTargets[id] || '').replace(/\/+$/, '');
      const input = document.getElementById('apiTesterBase');
      if (direct && input) input.value = direct;
    }
  } catch (_) {
    // The console's own poll is the fallback; leave the page-host default.
  }
  if (apiTesterKeysAuto) apiTesterLoadKeys();
}

// ── Sealing ──
//
// Sealing is asynchronous and runs on every edit, so its result can arrive
// after newer input. A sequence number drops stale replies; a short debounce
// keeps one keystroke from queueing a request.
let apiTesterSealSeq = 0;
let apiTesterSealTimer = null;
let apiTesterSealed = { pending: false, body: '', error: '', usedKeystore: false, partial: false };

// apiTesterOnBodyInput runs on every keystroke: the old envelope no longer
// matches the visible body, so it is dropped at once (copy goes unavailable)
// and a debounced seal rebuilds it.
function apiTesterOnBodyInput() {
  apiTesterSealed = { pending: true, body: '', error: '', usedKeystore: false, partial: false };
  apiTesterRender();
  apiTesterScheduleSeal();
}

function apiTesterScheduleSeal() {
  if (apiTesterSealTimer) clearTimeout(apiTesterSealTimer);
  apiTesterSealTimer = setTimeout(apiTesterSeal, 200);
}

async function apiTesterSeal() {
  apiTesterSealTimer = null;
  const bodyEl = document.getElementById('apiTesterBody');
  const raw = bodyEl ? bodyEl.value : '';
  const seq = ++apiTesterSealSeq;

  if (raw.trim() === '') {
    apiTesterSealed = { pending: false, body: '', error: '请求体为空', usedKeystore: false, partial: false };
    apiTesterRender();
    return;
  }
  let plaintext;
  try {
    plaintext = JSON.stringify(JSON.parse(raw));
  } catch (_) {
    apiTesterSealed = { pending: false, body: '', error: '请求体不是合法 JSON', usedKeystore: false, partial: false };
    apiTesterRender();
    return;
  }

  apiTesterSealed = { pending: true, body: '', error: '', usedKeystore: false, partial: false };
  apiTesterRender();

  const dockerId = apiTesterSelectedDockerId();
  const request = {
    dockerId: dockerId,
    plaintext: plaintext,
    platformPrivateKey: apiTesterKeyValue('apiTesterPlatformPriv').trim(),
    taaPublicKeyHex: apiTesterKeyValue('apiTesterTaaPub').trim(),
    identity: apiTesterKeyValue('apiTesterIdentity'),
  };
  try {
    const res = await fetch('/api/crypto/envelope', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    const payload = await res.json();
    if (seq !== apiTesterSealSeq) return;
    if (!payload || payload.error !== 0) {
      apiTesterSealed = { pending: false, body: '', error: (payload && payload.msg) || ('HTTP ' + res.status), usedKeystore: false, partial: false };
    } else {
      const result = payload.result || {};
      // One empty box plus one filled box means the server completed the pair
      // from the keystore; the note must say so rather than claim both keys
      // came from the form.
      const partial = !request.platformPrivateKey !== !request.taaPublicKeyHex;
      apiTesterSealed = { pending: false, body: result.body || '', error: '', usedKeystore: !!result.usedKeystore, partial: partial };
    }
  } catch (err) {
    if (seq !== apiTesterSealSeq) return;
    apiTesterSealed = { pending: false, body: '', error: '封装信封失败: ' + err.message, usedKeystore: false, partial: false };
  }
  apiTesterRender();
}

function apiTesterCurlText() {
  if (!apiTesterSealed.body) {
    const why = apiTesterSealed.pending ? '正在封装信封…' : '无法生成信封：' + (apiTesterSealed.error || '未知原因');
    return { text: '# ' + why, sealed: false };
  }
  const lines = [
    "curl -sS -X POST '" + apiTesterUrl() + "'",
    "  -H 'Content-Type: application/json'",
    '  --data-raw ' + shellQuote(apiTesterSealed.body),
  ];
  return { text: lines.join(' \\\n'), sealed: true };
}

function apiTesterRender() {
  const curl = document.getElementById('apiTesterCurl');
  if (!curl) return;
  const { text, sealed } = apiTesterCurlText();
  curl.textContent = text;

  const copyBtn = document.getElementById('apiTesterCopyBtn');
  if (copyBtn) {
    copyBtn.disabled = !sealed;
    copyBtn.title = sealed ? '' : '信封尚未生成';
  }

  const ep = apiTesterSelected();
  const note = document.getElementById('apiTesterNote');
  if (note) {
    const parts = [ep.note];
    if (sealed) {
      if (apiTesterSealed.usedKeystore) {
        parts.push('请求体已用 mock 注册密钥封装成信封（cipher + sign）。');
      } else if (apiTesterSealed.partial) {
        parts.push('请求体已封装成信封（cipher + sign）；留空的一侧由 mock 现有密钥补齐。');
      } else {
        parts.push('请求体已用上方填写的平台私钥与 TAA 公钥封装成信封（cipher + sign）。');
      }
      if (apiTesterUsingProxy()) {
        parts.push('目标地址是 mock 的 /taa 代理，它会再封装一次——请改成该实例的直连地址。');
      }
    } else if (apiTesterSealed.pending) {
      parts.push('正在封装信封…');
    } else {
      parts.push(apiTesterSealed.error || '');
    }
    note.textContent = parts.filter(Boolean).join(' ');
    note.classList.toggle('is-warn', !sealed || apiTesterUsingProxy());
  }
}

function apiTesterSelectEndpoint() {
  const ep = apiTesterSelected();
  const body = document.getElementById('apiTesterBody');
  if (body) body.value = JSON.stringify(ep.body(), null, 2);
  apiTesterScheduleSeal();
}

function apiTesterResetBody() {
  apiTesterSelectEndpoint();
}

function apiTesterUseDirectTarget() {
  const input = document.getElementById('apiTesterBase');
  if (input) input.value = apiTesterDefaultBase();
  apiTesterBaseAuto = true;
  apiTesterRender();
}

async function apiTesterCopy() {
  const curl = document.getElementById('apiTesterCurl');
  if (!curl || !apiTesterSealed.body) return;
  const text = curl.textContent || '';
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    // The clipboard API is unavailable outside a secure context; a selection and
    // execCommand still reaches the clipboard from a user gesture.
    const helper = document.createElement('textarea');
    helper.value = text;
    helper.style.position = 'fixed';
    helper.style.opacity = '0';
    document.body.appendChild(helper);
    helper.select();
    try {
      document.execCommand('copy');
    } catch (__) {
      if (typeof showToast === 'function') showToast({ type: 'error', title: '复制失败', message: '浏览器不允许写入剪贴板，请手动选中命令' });
      document.body.removeChild(helper);
      return;
    }
    document.body.removeChild(helper);
  }
  if (typeof showToast === 'function') {
    showToast({ type: 'success', title: '已复制', message: 'curl 命令已复制到剪贴板' });
  }
}

function apiTesterInit() {
  const sel = document.getElementById('apiTesterEndpoint');
  if (!sel) return;
  sel.innerHTML = '';
  API_TESTER_ENDPOINTS.forEach((ep) => {
    const opt = document.createElement('option');
    opt.value = ep.path;
    opt.textContent = ep.label + ' · ' + ep.path;
    sel.appendChild(opt);
  });
  const base = document.getElementById('apiTesterBase');
  if (base && !base.value) base.value = apiTesterDefaultBase();
  apiTesterSelectEndpoint();
  apiTesterBootstrap();

  // The console's target resolves after its first status poll, and it changes
  // when another instance is selected. Follow it while the field is untouched.
  // Only a change of the resolved direct target reloads the keys: the event
  // fires on every poll, and the keys only move when an instance registers.
  let lastAutoBase = apiTesterDefaultBase();
  window.addEventListener('taa-addr-change', () => {
    const next = apiTesterDefaultBase();
    const moved = next !== lastAutoBase;
    lastAutoBase = next;
    if (apiTesterBaseAuto) {
      const input = document.getElementById('apiTesterBase');
      if (input) input.value = next;
    }
    if (moved && apiTesterKeysAuto) apiTesterLoadKeys();
    apiTesterRender();
  });

  // The envelope is sealed for one instance: its dockerId selects the
  // registered TAA key, so a selection change reloads the keys and reseals.
  // Deferred one turn because the selector's own handler updates
  // currentDockerId, and listener order is not guaranteed.
  const instance = document.getElementById('instanceSelect');
  if (instance) instance.addEventListener('change', () => {
    setTimeout(() => {
      apiTesterDockerId = instance.value;
      if (apiTesterBaseAuto && base) base.value = apiTesterDefaultBase();
      if (apiTesterKeysAuto) {
        apiTesterLoadKeys();
      } else {
        apiTesterScheduleSeal();
      }
    }, 0);
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', apiTesterInit);
} else {
  apiTesterInit();
}
