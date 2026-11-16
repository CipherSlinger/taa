// ── API tester ──
//
// One dropdown, one editable body and one generated curl command. The command is
// built from exactly what the console would send: same path, same JSON body, same
// target address. Bodies are compacted with JSON.stringify so the copied command
// stays a single line the shell can read.
//
// Only platform→TAA business routes are listed. TAA seals every one of them, and
// the mock's /taa proxy is what makes a plaintext curl possible; the callbacks
// TAA sends (register, report*, *Log) are sealed envelopes the mock opens with
// the instance's registered key, so a hand-written body cannot reproduce them.

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

// The target address follows the console's target until the operator edits the
// field; after that it is theirs and the async resolution must not overwrite it.
let apiTesterBaseAuto = true;

function apiTesterDefaultBase() {
  // The console calls TAA through this mock's /taa proxy whenever an instance is
  // registered. With none registered there is no address to follow, and the
  // proxy path is still the only one a plaintext command can use.
  const target = typeof getTaaAddr === 'function' ? getTaaAddr() : '';
  return target || location.origin + '/taa';
}

function apiTesterOnBaseInput() {
  apiTesterBaseAuto = false;
  apiTesterRender();
}

function apiTesterBaseValue() {
  const input = document.getElementById('apiTesterBase');
  return (input && input.value ? input.value : '').trim().replace(/\/+$/, '');
}

// apiTesterUsingProxy reports whether the command goes through the mock's /taa
// proxy. That path seals plaintext for TAA and is the only one a copied command
// can use; a direct TAA address would need an envelope the shell cannot build.
function apiTesterUsingProxy() {
  return /\/taa$/.test(apiTesterBaseValue());
}

function apiTesterUrl() {
  const url = apiTesterBaseValue() + apiTesterSelected().path;
  if (!apiTesterUsingProxy()) return url;
  const dockerId = typeof currentDockerId === 'function' ? currentDockerId() : '';
  if (!dockerId) return url;
  return url + '?dockerId=' + encodeURIComponent(dockerId);
}

// shellQuote wraps a value in single quotes, closing and reopening around any
// single quote inside it. JSON bodies normally have none, but a user-pasted string
// field can.
function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

function apiTesterCurlText() {
  const bodyEl = document.getElementById('apiTesterBody');
  const raw = bodyEl ? bodyEl.value : '';
  let body = '{}';
  let bodyError = false;
  if (raw.trim() !== '') {
    try {
      body = JSON.stringify(JSON.parse(raw));
    } catch (_) {
      body = raw.trim();
      bodyError = true;
    }
  }
  const lines = [
    "curl -sS -X POST '" + apiTesterUrl() + "'",
    "  -H 'Content-Type: application/json'",
    '  --data-raw ' + shellQuote(body),
  ];
  return { text: lines.join(' \\\n'), bodyError };
}

function apiTesterRender() {
  const curl = document.getElementById('apiTesterCurl');
  if (!curl) return;
  const { text, bodyError } = apiTesterCurlText();
  curl.textContent = text;

  const ep = apiTesterSelected();
  const note = document.getElementById('apiTesterNote');
  if (note) {
    const seal = apiTesterUsingProxy()
      ? '当前经 mock 的 /taa 反向代理：代理用该实例注册的 SM2 公钥把明文请求封装成信封，响应也会解封。'
      : '当前是直连地址：TAA 只接受 SM2/SM4 信封，明文请求会被拒绝（请求缺少 cipher/sign）。改成 ' + location.origin + '/taa 才能直接跑。';
    const bodyState = bodyError ? ' 请求体不是合法 JSON，已按原样嵌入。' : '';
    note.textContent = ep.note + ' ' + seal + bodyState;
    note.classList.toggle('is-warn', bodyError || !apiTesterUsingProxy());
  }
}

function apiTesterSelectEndpoint() {
  const ep = apiTesterSelected();
  const body = document.getElementById('apiTesterBody');
  if (body) body.value = JSON.stringify(ep.body(), null, 2);
  apiTesterRender();
}

function apiTesterResetBody() {
  apiTesterSelectEndpoint();
}

function apiTesterUseConsoleTarget() {
  const input = document.getElementById('apiTesterBase');
  if (input) input.value = apiTesterDefaultBase();
  apiTesterBaseAuto = true;
  apiTesterRender();
}

async function apiTesterCopy() {
  const curl = document.getElementById('apiTesterCurl');
  if (!curl) return;
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

  // The console's target resolves after its first status poll, and it changes
  // when another instance is selected. Follow it while the field is untouched.
  window.addEventListener('taa-addr-change', (event) => {
    if (!apiTesterBaseAuto) return;
    const input = document.getElementById('apiTesterBase');
    if (!input) return;
    input.value = (event.detail && event.detail.addr) || apiTesterDefaultBase();
    apiTesterRender();
  });

  // The generated URL carries the selected instance's dockerId, so a selection
  // change has to regenerate the command.
  const instance = document.getElementById('instanceSelect');
  if (instance) instance.addEventListener('change', () => {
    if (apiTesterBaseAuto && base) base.value = apiTesterDefaultBase();
    apiTesterRender();
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', apiTesterInit);
} else {
  apiTesterInit();
}
