(function () {
  const API = '/api/v1';
  let accessToken = null; // kept in memory only (never localStorage)
  const $ = (id) => document.getElementById(id);

  function show(title, status, data) {
    $('out').textContent = `${title}\nHTTP ${status}\n\n${JSON.stringify(data, null, 2)}`;
  }

  function setStatus(user) {
    $('status').textContent = user ? `${user.email} (${user.role})` : 'Not logged in';
  }

  async function call(method, path, body, useAuth) {
    const headers = { 'Content-Type': 'application/json' };
    if (useAuth && accessToken) headers.Authorization = 'Bearer ' + accessToken;
    const res = await fetch(API + path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = {};
    try { data = await res.json(); } catch (e) { /* no body */ }
    return { status: res.status, data };
  }

  function storeSession(r) {
    if (r.status === 200 && r.data.accessToken) {
      accessToken = r.data.accessToken;
      setStatus(r.data.user);
    } else if (r.status === 401) {
      accessToken = null;
      setStatus(null);
    }
  }

  $('btn-login').addEventListener('click', async () => {
    const r = await call('POST', '/auth/login', { email: $('email').value, password: $('password').value });
    storeSession(r);
    show('POST /auth/login', r.status, r.data);
  });

  $('btn-register').addEventListener('click', async () => {
    const r = await call('POST', '/auth/register', { name: $('name').value, email: $('email').value, password: $('password').value });
    show('POST /auth/register', r.status, r.data);
  });

  $('btn-refresh').addEventListener('click', async () => {
    const r = await call('POST', '/auth/refresh');
    storeSession(r);
    show('POST /auth/refresh (rotates the cookie)', r.status, r.data);
  });

  $('btn-logout').addEventListener('click', async () => {
    const r = await call('POST', '/auth/logout');
    accessToken = null;
    setStatus(null);
    show('POST /auth/logout', r.status, r.data);
  });

  $('btn-profile').addEventListener('click', async () => {
    const r = await call('GET', '/employee/profile', null, true);
    show('GET /employee/profile', r.status, r.data);
  });

  $('btn-users').addEventListener('click', async () => {
    const r = await call('GET', '/users', null, true);
    show('GET /users', r.status, r.data);
  });

  $('btn-payroll').addEventListener('click', async () => {
    const r = await call('POST', '/payroll/approve', {
      employeeId: $('employeeId').value,
      amount: Number($('amount').value),
      period: new Date().toISOString().slice(0, 7),
    }, true);
    show('POST /payroll/approve', r.status, r.data);
  });

  $('btn-delete').addEventListener('click', async () => {
    const r = await call('DELETE', '/users/' + encodeURIComponent($('deleteId').value), null, true);
    show('DELETE /users/:id', r.status, r.data);
  });

  // After OAuth redirect (or page reload) try to restore the session from the refresh cookie
  (async function init() {
    const params = new URLSearchParams(location.search);
    if (params.get('error')) show('OAuth error', 400, { error: params.get('error') });
    const r = await call('POST', '/auth/refresh');
    storeSession(r);
    if (params.get('oauth') === 'success') show('OAuth login complete', r.status, r.data);
    if (params.has('oauth') || params.has('error')) history.replaceState(null, '', '/');
  })();
})();
