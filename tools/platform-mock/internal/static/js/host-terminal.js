// Host terminal for the API-tester tab.
//
// The mock runs on the host that can reach the TAA Pod, so "run the curl
// command" means "run it there". This panel opens a shell on that machine over
// a WebSocket and renders it with xterm.js. The shell is a child of the mock
// process, not an SSH session, and it is gated by the same console session as
// the audit and TEE-LLM tabs — so an expired session asks for the password here
// instead of failing as a bare socket error.
//
// Everything here is presentation: the server owns the PTY, the process tree and
// the session check.
(function () {
  'use strict';

  var TERMINAL_PATH = '/api/host/terminal';
  var FAILED_CLOSE = new Set([1006, 1008, 1011]);
  var state = {
    term: null,
    fit: null,
    socket: null,
    opened: false,
    resizing: false,
    loginBusy: false,
  };

  function byId(id) { return document.getElementById(id); }

  function setStatus(text, kind) {
    var el = byId('hostTerminalState');
    if (!el) return;
    el.textContent = text;
    el.dataset.state = kind || 'idle';
  }

  function setHint(text) {
    var el = byId('hostTerminalHint');
    if (el) el.textContent = text || '';
  }

  function showLoginForm(show, message) {
    var form = byId('hostTerminalLoginForm');
    if (form) form.hidden = !show;
    var err = byId('hostTerminalLoginError');
    if (err) err.textContent = message || '';
    if (show) {
      var pwd = byId('hostTerminalPassword');
      if (pwd) { pwd.value = ''; pwd.focus(); }
    }
  }

  function syncButtons() {
    var connect = byId('hostTerminalConnectBtn');
    var disconnect = byId('hostTerminalDisconnectBtn');
    var connected = !!state.socket;
    if (connect) {
      connect.disabled = connected || state.opened;
      connect.textContent = state.opened ? '已连接' : '连接';
    }
    if (disconnect) disconnect.disabled = !connected;
  }

  // ensureTerminal builds the xterm instance on first use. It is deferred
  // because the API-tester tab starts hidden, and a terminal created inside a
  // display:none container measures as zero cells.
  function ensureTerminal() {
    if (state.term) return true;
    if (typeof window.Terminal !== 'function' || typeof window.FitAddon !== 'object') {
      setStatus('组件缺失', 'error');
      setHint('终端组件（xterm.js）未加载，请刷新页面后重试。');
      return false;
    }
    var host = byId('hostTerminalScreen');
    if (!host) return false;

    var term = new window.Terminal({
      cursorBlink: true,
      convertEol: false,
      scrollback: 5000,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      fontSize: 12.5,
      lineHeight: 1.25,
      theme: {
        background: '#090d16',
        foreground: '#e2e8f0',
        cursor: '#93c5fd',
        selectionBackground: '#334155',
      },
    });
    var fit = new window.FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(host);
    state.term = term;
    state.fit = fit;

    term.onData(function (data) {
      sendFrame({ type: 'input', data: data });
    });

    // A size change has to reach the shell or a full-width program (an editor,
    // `top`) draws for the old geometry. The observer covers the tab becoming
    // visible as well, which is when the first real measurement is possible.
    if (typeof ResizeObserver === 'function') {
      var observer = new ResizeObserver(function () { fitTerminal(); });
      observer.observe(host);
    }
    window.addEventListener('resize', fitTerminal);
    return true;
  }

  function fitTerminal() {
    if (!state.fit || !state.term || state.resizing) return;
    var host = byId('hostTerminalScreen');
    if (!host || host.offsetParent === null) return;
    state.resizing = true;
    try {
      state.fit.fit();
    } catch (_) {
      // A zero-sized measurement throws inside the addon; the next visible pass
      // fixes it.
    } finally {
      state.resizing = false;
    }
    sendFrame({ type: 'resize', cols: state.term.cols, rows: state.term.rows });
  }

  function sendFrame(frame) {
    var socket = state.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    socket.send(JSON.stringify(frame));
  }

  function writeLine(text) {
    if (!state.term) return;
    state.term.write(text.replace(/\r?\n/g, '\r\n'));
  }

  function socketURL() {
    var scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return scheme + '//' + location.host + TERMINAL_PATH;
  }

  // sessionIsLive asks the console whether the cookie still works. A WebSocket
  // handshake that fails with 401 cannot be read from the browser, so the only
  // honest way to distinguish "signed out" from "server down" is to ask first.
  function sessionIsLive() {
    return fetch('/api/console/session', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (res) { return res.json().catch(function () { return null; }); })
      .then(function (data) {
        var payload = data && (data.result || data);
        return !!(payload && payload.authenticated);
      })
      .catch(function () { return false; });
  }

  function hostTerminalConnect() {
    if (state.socket) return;
    if (!ensureTerminal()) return;
    setStatus('连接中…', 'loading');
    setHint('正在连接宿主机 shell…');
    showLoginForm(false);

    sessionIsLive().then(function (live) {
      if (!live) {
        setStatus('未登录', 'error');
        setHint('宿主机终端需要控制台登录后才能打开。');
        showLoginForm(true, '');
        return;
      }
      openSocket();
    });
  }

  function openSocket() {
    var socket;
    try {
      socket = new WebSocket(socketURL());
    } catch (err) {
      setStatus('连接失败', 'error');
      setHint('无法打开终端连接：' + (err && err.message ? err.message : err));
      return;
    }
    state.socket = socket;
    state.opened = false;
    syncButtons();

    socket.onopen = function () {
      state.opened = true;
      setStatus('已连接', 'ok');
      setHint('连接已建立。命令直接在本机执行，当前用户即运行 mock 的用户。');
      syncButtons();
      fitTerminal();
      if (state.term) state.term.focus();
    };

    socket.onmessage = function (event) {
      var msg;
      try { msg = JSON.parse(event.data); } catch (_) { return; }
      if (!msg || typeof msg.type !== 'string') return;
      if (msg.type === 'output') {
        if (state.term) state.term.write(msg.data || '');
        return;
      }
      if (msg.type === 'exit') {
        var code = typeof msg.code === 'number' ? msg.code : 0;
        writeLine('\r\n[终端已退出，退出码 ' + code + ']');
        if (msg.message) writeLine('\r\n' + msg.message);
        setStatus('已退出', 'idle');
        showLoginForm(false);
      }
    };

    socket.onerror = function () {
      // A close event always follows; the message is reported there where the
      // close code is available.
    };

    socket.onclose = function (event) {
      state.socket = null;
      state.opened = false;
      syncButtons();
      if (event && event.code === 1008) {
        setStatus('未登录', 'error');
        showLoginForm(true, '会话已过期，请重新登录');
        return;
      }
      if (event && FAILED_CLOSE.has(event.code)) {
        setStatus('连接中断', 'error');
        setHint('与宿主机终端的连接已断开（' + event.code + '）。可点“连接”重试。');
      }
    };
  }

  function hostTerminalDisconnect() {
    var socket = state.socket;
    if (!socket) return;
    state.socket = null;
    syncButtons();
    setStatus('已断开', 'idle');
    try { socket.close(1000, 'operator disconnected'); } catch (_) {}
    writeLine('\r\n[已断开连接]');
  }

  function hostTerminalClear() {
    if (state.term) state.term.clear();
  }

  // hostTerminalLogin reuses the console's own login endpoint: the terminal has
  // no credentials of its own, and a second password store would be one more
  // thing to keep in sync with the console.
  function hostTerminalLogin(event) {
    if (event && event.preventDefault) event.preventDefault();
    if (state.loginBusy) return;
    var userEl = byId('hostTerminalUser');
    var pwdEl = byId('hostTerminalPassword');
    var username = userEl ? userEl.value.trim() : '';
    var password = pwdEl ? pwdEl.value : '';
    if (!username || !password) {
      showLoginForm(true, '请输入用户名和口令');
      return;
    }
    state.loginBusy = true;
    var btn = byId('hostTerminalLoginBtn');
    if (btn) btn.disabled = true;

    fetch('/api/console/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password }),
    })
      .then(function (res) {
        return res.json().catch(function () { return null; }).then(function (data) {
          return { ok: res.ok, status: res.status, data: data };
        });
      })
      .then(function (res) {
        if (res.ok) {
          if (pwdEl) pwdEl.value = '';
          showLoginForm(false);
          setHint('登录成功，正在连接宿主机 shell…');
          openSocket();
          return;
        }
        var payload = res.data || {};
        var msg = payload.error || payload.msg || ('登录失败（HTTP ' + res.status + '）');
        showLoginForm(true, msg);
      })
      .catch(function () {
        showLoginForm(true, '无法连接服务器，请稍后重试');
      })
      .finally(function () {
        state.loginBusy = false;
        if (btn) btn.disabled = false;
      });
  }

  // The terminal is created lazily, so a first visit that never opens it costs
  // nothing. When the API tab is selected the container has a size, and the
  // size has to be pushed then rather than at creation time.
  function hostTerminalOnTabShown() {
    if (state.term) setTimeout(fitTerminal, 0);
  }

  function init() {
    syncButtons();
  }

  window.hostTerminalConnect = hostTerminalConnect;
  window.hostTerminalDisconnect = hostTerminalDisconnect;
  window.hostTerminalClear = hostTerminalClear;
  window.hostTerminalLogin = hostTerminalLogin;
  window.hostTerminalOnTabShown = hostTerminalOnTabShown;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();