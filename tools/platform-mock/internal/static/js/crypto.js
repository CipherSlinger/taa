// ── Cryptographic Utilities & Key Management ──

let globalKeyPair = {
  publicKey: null,
  privateKey: null,
  createdAt: null,
};

// loadGlobalKeyPair reads the platform SM2 key pair the mock already holds. The
// mock generates and persists that pair at startup, so the console only displays
// it - loading the page never mints a key, because a fresh pair on every reload
// would silently break every running TAA's envelopes.
async function loadGlobalKeyPair() {
  try {
    const resp = await fetch('/api/crypto/generate-key', { method: 'GET' });
    const data = await resp.json();
    if (!resp.ok || data.error !== 0) {
      throw new Error(data.msg || '读取密钥对失败');
    }
    globalKeyPair = {
      publicKey: data.result.publicKey,
      privateKey: data.result.privateKey,
      publicKeyHex: data.result.publicKeyHex || '',
      createdAt: null,
    };
    showGlobalKeyPairActive();
    return true;
  } catch (err) {
    console.warn('读取平台密钥对失败:', err);
    return false;
  }
}

// showGlobalKeyPairActive swaps the "create" button for the view/regenerate
// group once a pair is on screen.
function showGlobalKeyPairActive() {
  const activeGroup = document.getElementById('globalKeyPairActiveGroup');
  const createBtn = document.getElementById('createGlobalKeyPairBtn');
  if (activeGroup) activeGroup.style.display = 'inline-flex';
  if (createBtn) createBtn.style.display = 'none';
}

// regenerateGlobalKeyPair rotates the platform pair: a new one is generated and
// written over the persisted key file. Every running TAA has cached the old
// public key, so the operator has to confirm and then reconfigure and restart
// each instance with the new PLATFORM_PUBLIC_KEY.
async function regenerateGlobalKeyPair(btn) {
  if (!confirm('重新生成会覆盖已落盘的平台 SM2 密钥对。\n\n所有正在运行的 TAA 都缓存了旧公钥，轮换后必须用新的 PLATFORM_PUBLIC_KEY 重新配置并重启，否则其信封将无法解密。\n\n确认重新生成？')) {
    return;
  }
  const origText = btn ? btn.textContent : '';
  if (btn) {
    btn.disabled = true;
  }
  try {
    const resp = await fetch('/api/crypto/generate-key', { method: 'POST' });
    const data = await resp.json();
    if (!resp.ok || data.error !== 0) {
      throw new Error(data.msg || '重新生成密钥对失败');
    }
    globalKeyPair = {
      publicKey: data.result.publicKey,
      privateKey: data.result.privateKey,
      publicKeyHex: data.result.publicKeyHex || '',
      createdAt: new Date().toISOString(),
    };
    showGlobalKeyPairActive();

    // Automatically fill into importModel if switch is enabled
    const switchEl = document.getElementById('importModelUsePublicKeySwitch');
    if (switchEl && switchEl.checked && typeof onImportModelUsePublicKeyToggle === 'function') {
      onImportModelUsePublicKeyToggle(switchEl);
    }

    if (typeof openBodyModal === 'function') {
      openBodyModal(
        '已重新生成并覆盖平台 SM2 密钥对',
        `公钥 (Public Key):\n${globalKeyPair.publicKey}\n\nPLATFORM_PUBLIC_KEY (hex):\n${globalKeyPair.publicKeyHex}\n\n所有 TAA 实例需重新配置此公钥并重启。\n\n生成时间: ${globalKeyPair.createdAt}`
      );
    }
  } catch (err) {
    alert('重新生成密钥对失败: ' + err.message);
  } finally {
    if (btn) {
      btn.textContent = origText;
      btn.disabled = false;
    }
  }
}

// initGlobalKeyPair runs once per console load. The pair is already persisted by
// the mock at startup, so this only reads it back into the page.
function initGlobalKeyPair() {
  return loadGlobalKeyPair();
}

function openGlobalPublicKeyModal() {
  if (!globalKeyPair.publicKey) {
    alert('尚未读取到平台公钥，请刷新页面');
    return;
  }
  openBodyModal('平台 SM2 公钥 (Public Key)', globalKeyPair.publicKey);
}

function openGlobalPrivateKeyModal() {
  if (!globalKeyPair.privateKey) {
    alert('尚未读取到平台私钥，请刷新页面');
    return;
  }
  openBodyModal('平台 SM2 私钥 (Private Key)', globalKeyPair.privateKey);
}

async function copyRegisterPublicKey(btnEl) {
  const area = document.getElementById('registerPublicKey');
  if (!area || !area.value) return;
  const ok = await copyText(area.value);
  if (typeof showToast === 'function') {
    if (ok) {
      showToast({ type: 'success', title: '公钥已复制', message: 'TAA 注册公钥已复制到剪贴板' });
    } else {
      showToast({ type: 'error', title: '复制失败', message: '未能写入剪贴板' });
    }
  }
  if (btnEl) {
    const copySvg = btnEl.querySelector('.copy-icon');
    const checkSvg = btnEl.querySelector('.check-icon');
    if (copySvg && checkSvg) {
      copySvg.style.display = 'none';
      checkSvg.style.display = 'inline-block';
      btnEl.classList.add('copied');
      setTimeout(() => {
        copySvg.style.display = 'inline-block';
        checkSvg.style.display = 'none';
        btnEl.classList.remove('copied');
      }, 1500);
    }
  }
}

let _lastAttestationBase64 = null;
let _lastAttestationValues = null;
// The instance the held report belongs to. The report is one value in the page,
// so only that row may offer to save or inspect it.
let _lastAttestationOwner = '';

function base64ToUint8Array(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function testGetAttestation() {
  if (typeof randomizeField === 'function') {
    randomizeField('attestRequestId', 'req-attest');
  }
  if (typeof showResultRunning === 'function') {
    showResultRunning('attestationResult', '正在请求远程证明报告（helper 可能需要数秒）...');
  }
  const statusEl = document.getElementById('statusText');
  if (statusEl) statusEl.textContent = '正在获取远程证明报告...';
  const dot = document.getElementById('dot');
  if (dot) dot.className = 'dot';
  _lastAttestationBase64 = null;
  _lastAttestationValues = null;
  _lastAttestationOwner = '';
  const reqIdEl = document.getElementById('attestRequestId');
  const body = { requestId: reqIdEl ? reqIdEl.value : 'req-mock-attest-001' };

  if (typeof recordInteraction === 'function') {
    recordInteraction('attestation', {
      title: '/v1/taa/getAttestation 远程证明详情',
      primaryLabel: '返回内容',
      secondaryLabel: '请求体',
      primaryContent: null,
      secondaryContent: body,
      endpoint: '/v1/taa/getAttestation',
      reqBody: body,
    });
  }

  try {
    const res = await taaFetch('/v1/taa/getAttestation', body, 45000);
    const data = await res.json().catch(() => ({}));
    const payload = responseResult(data);
    const ok = res.status === 200 && data.error === 0 && !!payload.attestation;
    const attB64 = payload.attestation || '';
    const attValues = payload.attestationValues || '';
    let binaryLen = 0;
    try { binaryLen = atob(attB64).length; } catch {}

    let display = { ...data, result: { ...payload } };
    if (attB64.length > 80) {
      display.result.attestation = attB64.slice(0, 80) + '...(' + attB64.length + ' chars, decoded=' + binaryLen + ' bytes)';
    }
    if (attValues) {
      try { display.result.attestationValues = JSON.parse(attValues); } catch {}
    }
    const displayText = 'HTTP ' + res.status + '\n' + JSON.stringify(display, null, 2);

    if (ok) {
      _lastAttestationBase64 = attB64;
      _lastAttestationValues = attValues;
      // The report belongs to the instance that answered, so its row is the one
      // that gains 保存报告 / 查看返回.
      _lastAttestationOwner = typeof currentDockerId === 'function' ? currentDockerId() : '';
    }
    if (typeof lastRegisterModalTitle !== 'undefined') {
      lastRegisterModalTitle = '/v1/taa/getAttestation 返回 body';
      lastRegisterModalBody = displayText;
    }
    if (statusEl) statusEl.textContent = ok ? '已获取远程证明报告 (HTTP ' + res.status + ')' : '获取远程证明报告失败';
    if (dot) dot.className = 'dot ' + (ok ? 'ok' : 'bad');
    if (typeof recordInteraction === 'function') {
      recordInteraction('attestation', {
        primaryContent: displayText,
        respBody: displayText,
        statusCode: res.status,
      });
    }
    if (typeof showResult === 'function') {
      showResult('attestationResult', ok, displayText);
    }
  } catch (e) {
    let msg;
    if (e.name === 'AbortError') {
      msg = '请求超时（45s）：attestation helper 可能挂起。\n\n请检查 TAA 容器内日志：\n  kubectl exec <pod> -- tail /tmp/taa.log\n\n常见原因：\n1. /dev/csv-guest 设备不可用\n2. attestation helper 二进制无法执行\n3. ioctl 调用阻塞';
    } else if (e.message && (e.message.includes('Failed to fetch') || e.message.includes('NetworkError'))) {
      msg = '网络请求失败: Failed to fetch\n\n请先用上方 /v1/taa/health 接口确认基础连通性。\n\n如 health 通过但本接口失败，说明 attestation helper 有问题。\n如 health 也失败，请检查：\n1. TAA 地址是否正确\n2. 是否部署了最新版本\n3. 浏览器控制台 (F12) 查看具体错误';
    } else {
      msg = '请求失败: ' + (e.message || String(e));
    }
    if (typeof lastRegisterModalTitle !== 'undefined') {
      lastRegisterModalTitle = '/v1/taa/getAttestation 请求失败';
      lastRegisterModalBody = msg;
    }
    if (statusEl) statusEl.textContent = '获取远程证明报告失败';
    if (dot) dot.className = 'dot bad';
    if (typeof recordInteraction === 'function') {
      recordInteraction('attestation', {
        primaryContent: msg,
        respBody: msg,
        statusCode: 500,
      });
    }
    if (typeof showResult === 'function') {
      showResult('attestationResult', false, msg);
    }
  }
  // The owning row gains or loses 保存报告 / 查看返回 with this result.
  if (typeof renderInstanceList === 'function') renderInstanceList();
}

function saveAttestationReport() {
  if (!_lastAttestationBase64) {
    alert('没有可保存的报告，请先点击"获取证明报告"获取报告');
    return;
  }
  const bytes = base64ToUint8Array(_lastAttestationBase64);
  downloadBlob(new Blob([bytes], { type: 'application/octet-stream' }), 'report.cert', 0);
  if (_lastAttestationValues) {
    downloadBlob(new Blob([_lastAttestationValues], { type: 'application/json' }), 'attestation-values.json', 0);
  }
}

async function exportReportItem(idx, shouldDecrypt, btn) {
  const item = (typeof reportResHistory !== 'undefined') ? reportResHistory[idx] : null;
  if (!item) return;

  const taskId = (item.taskId || '').trim();
  const requestId = (item.requestId || '').trim();

  if (shouldDecrypt) {
    const privKey = (globalKeyPair.privateKey || '').trim();
    if (!privKey) {
      alert('已开启解密，但尚未生成解密私钥，请先点击上方“创建公私钥”生成密钥对');
      return;
    }
  }

  const origText = btn ? btn.textContent : '';
  if (btn) {
    btn.disabled = true;
    btn.textContent = shouldDecrypt ? '解密中...' : '导出中...';
  }

  try {
    const body = {};
    if (taskId) body.taskId = taskId;
    if (requestId) body.requestId = requestId;

    if (typeof recordInteraction === 'function') {
      recordInteraction('export', {
        title: `/v1/taa/export 导出结果详情 (${taskId || 'task'})`,
        primaryLabel: '返回内容',
        secondaryLabel: '请求体',
        primaryContent: null,
        secondaryContent: body,
        endpoint: '/v1/taa/export',
        reqBody: body,
      });
    }

    const r = await postToTAAFile('/v1/taa/export', body);
    if (r.status === 200 && r.blob) {
      const isEncrypted = Boolean(r.encrypted || (r.filename && r.filename.toLowerCase().endsWith('.enc')));

      if (shouldDecrypt) {
        if (!isEncrypted) {
          downloadBlob(r.blob, r.filename || 'export.zip');
          const plainText = `HTTP 200\n提示: 响应结果为明文（未加密，无需解密），已直接保存原文件: ${r.filename || 'export.zip'}`;
          if (typeof recordInteraction === 'function') {
            recordInteraction('export', { primaryContent: plainText, respBody: plainText, statusCode: 200 });
          }
          alert(`提示: 响应结果为明文（无需解密），已保存原文件: ${r.filename || 'export.zip'}`);
          return;
        }

        const formData = new FormData();
        formData.append('privateKey', globalKeyPair.privateKey.trim());
        formData.append('file', r.blob, r.filename || 'export.enc');

        const decRes = await fetch('/api/crypto/decrypt', {
          method: 'POST',
          body: formData,
        });

        if (!decRes.ok) {
          const errData = await decRes.json().catch(() => ({}));
          const decErrMsg = `解密失败: ${errData.msg || 'HTTP ' + decRes.status}`;
          if (typeof recordInteraction === 'function') {
            recordInteraction('export', { primaryContent: decErrMsg, respBody: decErrMsg, statusCode: decRes.status });
          }
          alert(decErrMsg);
          return;
        }

        const decBlob = await decRes.blob();
        let saveFilename = r.filename || 'export.zip.enc';
        if (saveFilename.toLowerCase().endsWith('.enc')) {
          saveFilename = saveFilename.slice(0, -4);
        } else {
          saveFilename = saveFilename + '.dec';
        }

        downloadBlob(decBlob, saveFilename);
        const decSuccessText = `HTTP 200\n已成功解密并保存结果文件: ${saveFilename}`;
        if (typeof recordInteraction === 'function') {
          recordInteraction('export', { primaryContent: decSuccessText, respBody: decSuccessText, statusCode: 200 });
        }
      } else {
        downloadBlob(r.blob, r.filename || 'export.zip');
        const rawText = `HTTP 200\n已直接返回并保存原文件: ${r.filename || 'export.zip'}`;
        if (typeof recordInteraction === 'function') {
          recordInteraction('export', { primaryContent: rawText, respBody: rawText, statusCode: 200 });
        }
      }
    } else {
      const errMsg = `导出失败: ${(r.data && r.data.msg) || ('HTTP ' + r.status)}`;
      if (typeof recordInteraction === 'function') {
        recordInteraction('export', { primaryContent: errMsg, respBody: errMsg, statusCode: r.status });
      }
      alert(errMsg);
    }
  } catch (err) {
    if (typeof recordInteraction === 'function') {
      recordInteraction('export', { primaryContent: '导出异常: ' + err.message, respBody: err.message, statusCode: 500 });
    }
    alert(`导出异常: ${err.message}`);
  } finally {
    if (btn) {
      btn.textContent = origText;
      btn.disabled = false;
    }
  }
}
