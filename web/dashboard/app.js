const API = '/api';

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });

  if (response.status === 401) {
    window.location.href = '/ui/login.html';
    throw new Error('unauthorized');
  }

  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      message = data.error || message;
    } catch (_) {}
    throw new Error(message);
  }

  if (response.status === 204) {
    return null;
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

function showMessage(id, text, isError = false) {
  const node = document.getElementById(id);
  if (!node) return;
  node.textContent = text;
  node.classList.remove('hidden');
  node.classList.toggle('error', isError);
  node.classList.toggle('message', !isError);
}

async function requireAuth() {
  try {
    return await api('/auth/me');
  } catch (err) {
    window.location.href = '/ui/login.html';
    throw err;
  }
}

function bindLogout() {
  const button = document.getElementById('logout-btn');
  if (!button) return;
  button.addEventListener('click', async () => {
    await api('/auth/logout', { method: 'POST' });
    window.location.href = '/ui/login.html';
  });
}

function renderCurrentUser(user) {
  const node = document.getElementById('current-user');
  if (node) {
    node.textContent = `${user.display_name} (${user.role})`;
  }
  document.querySelectorAll('[data-role="admin"]').forEach((el) => {
    if (user.role !== 'admin') {
      el.classList.add('hidden');
    }
  });
}

function renderStats(stats) {
  const grid = document.getElementById('stats-grid');
  if (!grid) return;
  const cards = [
    ['Всего соединений', stats.total_connections],
    ['MTProto', stats.mtproto_connections],
    ['Fallback', stats.fallback_connections],
    ['Domain fronted', stats.domain_fronted ?? 0],
    ['Replay blocked', stats.replay_blocked ?? 0],
    ['TLS handshakes', stats.tls_handshakes],
    ['Фрагментаций', stats.fragmented_writes],
    ['DRS записей', stats.drs_writes ?? 0],
    ['dd записей', stats.dd_writes ?? 0],
    ['Backend failover', stats.backend_failovers ?? 0],
    ['Bytes → backend', stats.bytes_to_backend],
    ['Bytes ← backend', stats.bytes_from_backend],
  ];
  grid.innerHTML = cards.map(([label, value]) => `
    <div class="stat-card">
      <span class="muted">${label}</span>
      <strong>${value}</strong>
    </div>
  `).join('');
}

async function initLoginPage() {
  try {
    const user = await api('/auth/me');
    if (user) {
      window.location.href = '/ui/dashboard.html';
      return;
    }
  } catch (_) {}

  const form = document.getElementById('login-form');
  const error = document.getElementById('login-error');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    try {
      await api('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          username: data.get('username'),
          password: data.get('password'),
        }),
      });
      window.location.href = '/ui/dashboard.html';
    } catch (err) {
      error.textContent = err.message;
      error.classList.remove('hidden');
    }
  });
}

async function initDashboardPage() {
  const user = await requireAuth();
  renderCurrentUser(user);
  bindLogout();

  const [stats, summary, full] = await Promise.all([
    api('/stats'),
    api('/config'),
    user.role === 'viewer' ? Promise.resolve(null) : api('/config/full'),
  ]);

  renderStats(stats);

  try {
    const proxy = await api('/proxy-link');
    const linkInput = document.getElementById('proxy-link');
    if (linkInput && proxy?.link) {
      linkInput.value = proxy.link;
      const qrImg = document.getElementById('proxy-qr');
      if (qrImg) {
        qrImg.src = `${API}/proxy-link/qr`;
      }
      document.getElementById('copy-proxy-link')?.addEventListener('click', async () => {
        await navigator.clipboard.writeText(proxy.link);
        showMessage('dashboard-message', 'Ссылка скопирована');
      });
    }
  } catch (_) {}

  if (full) {
    const mtprotoForm = document.getElementById('mtproto-form');
    mtprotoForm.secret.value = full.mtproto.secret;
    mtprotoForm.backend.value = full.mtproto.backend;
    mtprotoForm.fake_domain.value = full.tls.fake_domain;

    const fragForm = document.getElementById('fragmentation-form');
    fragForm.enabled.checked = full.fragmentation.enabled;
    fragForm.chunk_sizes.value = full.fragmentation.chunk_sizes.join(',');
    fragForm.delay_ms.value = full.fragmentation.delay_ms;

    if (user.role === 'viewer') {
      mtprotoForm.querySelectorAll('input,button').forEach((el) => { el.disabled = true; });
      fragForm.querySelectorAll('input,button').forEach((el) => { el.disabled = true; });
      document.getElementById('reload-btn').disabled = true;
    }
  }

  document.getElementById('reload-btn').addEventListener('click', async () => {
    try {
      await api('/config/reload', { method: 'POST' });
      showMessage('dashboard-message', 'Конфигурация перезагружена');
    } catch (err) {
      showMessage('dashboard-message', err.message, true);
    }
  });

  document.getElementById('mtproto-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.target;
    try {
      await api('/config/mtproto', {
        method: 'PUT',
        body: JSON.stringify({
          secret: form.secret.value,
          backend: form.backend.value,
          fake_domain: form.fake_domain.value,
        }),
      });
      showMessage('dashboard-message', 'MTProto настройки сохранены');
    } catch (err) {
      showMessage('dashboard-message', err.message, true);
    }
  });

  document.getElementById('fragmentation-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.target;
    const chunkSizes = form.chunk_sizes.value
      .split(',')
      .map((value) => Number(value.trim()))
      .filter((value) => Number.isFinite(value) && value > 0);
    try {
      await api('/config/fragmentation', {
        method: 'PUT',
        body: JSON.stringify({
          enabled: form.enabled.checked,
          chunk_sizes: chunkSizes,
          delay_ms: Number(form.delay_ms.value || 0),
        }),
      });
      showMessage('dashboard-message', 'Фрагментация сохранена');
    } catch (err) {
      showMessage('dashboard-message', err.message, true);
    }
  });

  if (summary) {
    document.title = `StealthGate — ${summary.listen}`;
  }
}

async function initUsersPage() {
  const user = await requireAuth();
  if (user.role !== 'admin') {
    window.location.href = '/ui/dashboard.html';
    return;
  }
  renderCurrentUser(user);
  bindLogout();

  async function loadUsers() {
    const users = await api('/users');
    const tbody = document.getElementById('users-table');
    tbody.innerHTML = users.map((item) => `
      <tr>
        <td>${item.username}</td>
        <td>${item.display_name}</td>
        <td>${item.role}</td>
        <td>
          ${item.username === user.username ? '' : `<button class="btn danger" data-delete="${item.username}">Удалить</button>`}
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('[data-delete]').forEach((button) => {
      button.addEventListener('click', async () => {
        const username = button.getAttribute('data-delete');
        try {
          await api(`/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
          await loadUsers();
          showMessage('users-message', `Пользователь ${username} удалён`);
        } catch (err) {
          showMessage('users-message', err.message, true);
        }
      });
    });
  }

  document.getElementById('create-user-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.target;
    const data = new FormData(form);
    try {
      await api('/users', {
        method: 'POST',
        body: JSON.stringify({
          username: data.get('username'),
          display_name: data.get('display_name'),
          password: data.get('password'),
          role: data.get('role'),
        }),
      });
      form.reset();
      await loadUsers();
      showMessage('users-message', 'Пользователь создан');
    } catch (err) {
      showMessage('users-message', err.message, true);
    }
  });

  await loadUsers();
}

window.initLoginPage = initLoginPage;
window.initDashboardPage = initDashboardPage;
window.initUsersPage = initUsersPage;
