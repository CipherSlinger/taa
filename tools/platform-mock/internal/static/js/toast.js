// ── Global Toast Notification Manager ──
(function (global) {
  let container = null;

  function ensureContainer() {
    if (!container || !document.body.contains(container)) {
      container = document.getElementById('toastContainer');
      if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container';
        document.body.appendChild(container);
      }
    }
    return container;
  }

  function getIcon(type) {
    switch (type) {
      case 'success':
        return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      case 'error':
        return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
      case 'warning':
        return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
      default:
        return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }
  }

  function showToast(options) {
    const opts = typeof options === 'string' ? { message: options } : (options || {});
    const type = opts.type || 'info';
    const title = opts.title || (type === 'success' ? '操作成功' : (type === 'error' ? '操作失败' : (type === 'warning' ? '警告提示' : '系统提示')));
    const message = opts.message || '';
    const duration = typeof opts.duration === 'number' ? opts.duration : 3200;

    const cont = ensureContainer();
    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;

    toast.innerHTML = `
      <div class="toast-icon-wrap">${getIcon(type)}</div>
      <div class="toast-body">
        <div class="toast-title">${title}</div>
        ${message ? `<div class="toast-msg">${message}</div>` : ''}
      </div>
      <button type="button" class="toast-close" aria-label="Close">&times;</button>
      <div class="toast-progress" style="animation-duration: ${duration}ms;"></div>
    `;

    const closeBtn = toast.querySelector('.toast-close');
    let timer = null;

    function removeToast() {
      if (timer) clearTimeout(timer);
      toast.classList.remove('toast-show');
      toast.classList.add('toast-hide');
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 260);
    }

    if (closeBtn) closeBtn.onclick = removeToast;
    if (duration > 0) timer = setTimeout(removeToast, duration);

    cont.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('toast-show'));
  }

  global.Toast = { show: showToast };
  global.showToast = showToast;
})(window);
