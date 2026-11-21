import { createApp } from '../../test-api/src/app.js';

/** Starts an isolated benchmark API instance on an ephemeral port. */
export async function startApi(overrides = {}) {
  const app = createApp({ jwtSecret: 'test-secret', tokenTtlSeconds: 600, benchmarkMode: true, ...overrides });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  async function request(method, path, { token, body } = {}) {
    const headers = {};
    if (token) headers.authorization = `Bearer ${token}`;
    if (body !== undefined) headers['content-type'] = 'application/json';
    const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON body */ }
    return { status: res.status, body: json };
  }

  const passwords = { admin: 'Admin#2026', alice: 'Alice#2026', bob: 'Bob#2026', guest: 'Guest#2026' };
  async function login(username) {
    const r = await request('POST', '/api/auth/login', { body: { username, password: passwords[username] } });
    if (r.status !== 200) throw new Error(`login failed for ${username}: ${r.status}`);
    return r.body.token;
  }

  return { base, app, request, login, close: () => new Promise((r) => server.close(r)) };
}
