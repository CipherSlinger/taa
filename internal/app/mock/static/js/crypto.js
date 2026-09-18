// ── Cryptographic Utilities & Key Management ──

let globalKeyPair = {
  publicKey: null,
  privateKey: null,
  createdAt: null,
};

async function generateGlobalKeyPair(btn) {
  const origText = btn ? btn.textContent : '';
  if (btn) {
    btn.disabled = true;
    btn.textContent = '生成中...';
  }
  try {
    const resp = await fetch('/api/crypto/generate-key', { method: 'POST' });
    const data = await resp.json();
    if (!resp.ok || data.error !== 0) {
      throw new Error(data.msg || '生成密钥对失败');
    }
    globalKeyPair = {
      publicKey: data.result.publicKey,
      privateKey: data.result.privateKey,
      createdAt: new Date().toISOString(),
    };

    const activeGroup = document.getElementById('globalKeyPairActiveGroup');
    const createBtn = document.getElementById('createGlobalKeyPairBtn');
    if (activeGroup) activeGroup.style.display = 'inline-flex';
    if (createBtn) createBtn.style.display = 'none';

    // Automatically fill into importModel if switch is enabled
    const switchEl = document.getElementById('importModelUsePublicKeySwitch');
    if (switchEl && switchEl.checked && typeof onImportModelUsePublicKeyToggle === 'function') {
      onImportModelUsePublicKeyToggle(switchEl);
    }

    if (typeof openBodyModal === 'function') {
      openBodyModal(
        '已生成新 SM2 密钥对',
        `公钥 (Public Key):\n${globalKeyPair.publicKey}\n\n私钥 (Private Key):\n${globalKeyPair.privateKey}\n\n生成时间: ${globalKeyPair.createdAt}`
      );
    }
  } catch (err) {
    alert('生成密钥对失败: ' + err.message);
  } finally {
    if (btn) {
      btn.textContent = origText;
      btn.disabled = false;
    }
  }
}

function openGlobalPublicKeyModal() {
  if (!globalKeyPair.publicKey) {
    alert('尚未生成公钥，请先点击“创建公私钥”');
    return;
  }
  openBodyModal('全局 SM2 公钥 (Public Key)', globalKeyPair.publicKey);
}

function openGlobalPrivateKeyModal() {
  if (!globalKeyPair.privateKey) {
    alert('尚未生成私钥，请先点击“创建公私钥”');
    return;
  }
  openBodyModal('全局 SM2 私钥 (Private Key)', globalKeyPair.privateKey);
}

async function copyRegisterPublicKey(btnEl) {
  const area = document.getElementById('registerPublicKey');
  if (!area || !area.value) return;
  const ok = await copyText(area.value);
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
  const saveBtn = document.getElementById('saveReportBtn');
  if (saveBtn) saveBtn.disabled = true;
  _lastAttestationBase64 = null;
  _lastAttestationValues = null;
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
      if (saveBtn) saveBtn.disabled = false;
    }
    if (typeof lastRegisterModalTitle !== 'undefined') {
      lastRegisterModalTitle = '/v1/taa/getAttestation 返回 body';
      lastRegisterModalBody = displayText;
    }
    const regBodyBtn = document.getElementById('registerBodyBtn');
    if (regBodyBtn) regBodyBtn.disabled = false;
    const attestBtn = document.getElementById('attestationBodyBtn');
    if (attestBtn) attestBtn.style.display = 'inline-block';
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
    const regBodyBtn = document.getElementById('registerBodyBtn');
    if (regBodyBtn) regBodyBtn.disabled = false;
    const attestBtn = document.getElementById('attestationBodyBtn');
    if (attestBtn) attestBtn.style.display = 'inline-block';
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
}

function saveAttestationReport() {
  if (!_lastAttestationBase64) {
    alert('没有可保存的报告，请先点击"获取远程证明报告"获取报告');
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
          downloadBlob(r.blob, r.filename || 'export.tar.gz');
          const plainText = `HTTP 200\n提示: 响应结果为明文（未加密，无需解密），已直接保存原文件: ${r.filename || 'export.tar.gz'}`;
          if (typeof recordInteraction === 'function') {
            recordInteraction('export', { primaryContent: plainText, respBody: plainText, statusCode: 200 });
          }
          alert(`提示: 响应结果为明文（无需解密），已保存原文件: ${r.filename || 'export.tar.gz'}`);
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
        let saveFilename = r.filename || 'export.tar.gz.enc';
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
        downloadBlob(r.blob, r.filename || 'export.tar.gz');
        const rawText = `HTTP 200\n已直接返回并保存原文件: ${r.filename || 'export.tar.gz'}`;
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
