// Host terminal for the API-tester tab.
//
// The mock runs on the host that can reach the TAA Pod, so "run the curl
// command" means "run it there". This panel opens a shell on that machine over
// a WebSocket and renders it with xterm.js. The shell is a child of the mock
// process, not an SSH session, and it has no console login of its own: the tab
// is already part of the page the operator is using, so connecting is one click.
//
// Everything here is presentation: the server owns the PTY and the process tree.
(function () {
  'use strict';

  var TERMINAL_PATH = '/api/host/terminal';
  var FAILED_CLOSE = new Set([1006, 1011]);
  var state = {
    term: null,
    fit: null,
    socket: null,
    opened: false,
    resizing: false,
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

  function hostTerminalConnect() {
    if (state.socket) return;
    if (!ensureTerminal()) return;
    setStatus('连接中…', 'loading');
    setHint('正在连接宿主机 shell…');
    openSocket();
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
  window.hostTerminalOnTabShown = hostTerminalOnTabShown;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();