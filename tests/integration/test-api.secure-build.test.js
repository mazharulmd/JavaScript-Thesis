/**
 * Authorization regression tests of the PATCHED build (FLAWS=none).
 *
 * These tests document the correct access-control behaviour the benchmark is built
 * around, including the "true negative" response patterns that are legitimate even
 * though they return a 2xx status. They validate the benchmark's secure baseline.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { startApi } from '../fixtures/server.js';

const spec = parse(readFileSync(new URL('../../test-api/openapi.yaml', import.meta.url), 'utf8'));
let api;
let t; // tokens by account
before(async () => {
  api = await startApi({ flaws: 'none' });
  t = { admin: await api.login('admin'), alice: await api.login('alice'), bob: await api.login('bob'), guest: await api.login('guest') };
});
after(async () => { await api.close(); });

test('every operation that requires authentication rejects requests without credentials', async () => {
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(item)) {
      if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) continue;
      const isPublic = Array.isArray(op.security) && op.security.length === 0;
      if (isPublic) continue;
      const concrete = path.replace(/\{[^}]+\}/g, '1');
      const r = await api.request(method.toUpperCase(), concrete, { body: method === 'get' || method === 'delete' ? undefined : {} });
      assert.equal(r.status, 401, `${method.toUpperCase()} ${path} should require authentication`);
    }
  }
});

test('object level: users can access their own objects', async () => {
  assert.equal((await api.request('GET', '/api/users/2', { token: t.alice })).status, 200);
  assert.equal((await api.request('GET', '/api/orders/1003', { token: t.alice })).status, 200);
  assert.equal((await api.request('GET', '/api/invoices/7003', { token: t.alice })).status, 200);
  assert.equal((await api.request('GET', '/api/devices/dev-002-a/readings', { token: t.alice })).status, 200);
});

test("object level: another user's objects are denied", async () => {
  const cases = [
    ['GET', '/api/users/3', 403],
    ['PATCH', '/api/users/3', 403, { displayName: 'x' }],
    ['GET', '/api/profiles/3', 403],
    ['GET', '/api/orders/1005', 404],
    ['PUT', '/api/orders/1005', 404, { shippingAddress: 'x' }],
    ['GET', '/api/invoices/7005', 403],
    ['GET', '/api/documents/doc-3-private', 403],
    ['PATCH', '/api/documents/doc-3-private', 403, { title: 'x' }],
    ['GET', '/api/devices/dev-003-a', 404],
    ['GET', '/api/devices/dev-003-a/readings', 404],
    ['POST', '/api/devices/dev-003-a/readings', 404, { value: 1 }],
    ['DELETE', '/api/devices/dev-003-a', 403],
  ];
  for (const [method, path, expected, body] of cases) {
    const r = await api.request(method, path, { token: t.alice, body });
    assert.equal(r.status, expected, `${method} ${path}`);
  }
});

test('administrators bypass object ownership', async () => {
  assert.equal((await api.request('GET', '/api/orders/1005', { token: t.admin })).status, 200);
  assert.equal((await api.request('GET', '/api/documents/doc-3-private', { token: t.admin })).status, 200);
});

test('function level: admin-only functions are denied to users and guests', async () => {
  const cases = [
    ['GET', '/api/admin/users'],
    ['POST', '/api/admin/users', { username: 'n', email: 'n@x.test', password: 'p' }],
    ['PUT', '/api/admin/users/5/role', { role: 'guest' }],
    ['GET', '/api/admin/stats'],
    ['POST', '/api/admin/announcements', { title: 't', message: 'm' }],
    ['POST', '/api/admin/backups'],
    ['POST', '/api/products', { sku: 'S', name: 'n', price: 1 }],
    ['PUT', '/api/products/501', { sku: 'S', name: 'n', price: 1 }],
  ];
  for (const who of ['alice', 'guest']) {
    for (const [method, path, body] of cases) {
      const r = await api.request(method, path, { token: t[who], body });
      assert.equal(r.status, 403, `${who}: ${method} ${path}`);
    }
  }
  assert.equal((await api.request('GET', '/api/admin/stats', { token: t.admin })).status, 200);
});

test('function level: read-only guests cannot create objects', async () => {
  assert.equal((await api.request('POST', '/api/orders', { token: t.guest, body: { sku: 'SKU-501', quantity: 1, shippingAddress: 'x' } })).status, 403);
  assert.equal((await api.request('POST', '/api/documents', { token: t.guest, body: { title: 't', content: 'c' } })).status, 403);
  assert.equal((await api.request('POST', '/api/devices', { token: t.guest, body: { name: 'n', type: 'smart-plug' } })).status, 403);
});

// ---- True-negative patterns: correct behaviour that still returns 2xx -------------------

test('TN pattern: public documents of other users are readable (200, owner is someone else)', async () => {
  const r = await api.request('GET', '/api/documents/doc-3-public', { token: t.alice });
  assert.equal(r.status, 200);
  assert.equal(r.body.ownerId, 3);
  assert.equal(r.body.visibility, 'public');
});

test("TN pattern: account summary ignores the path id and returns the caller's own data", async () => {
  const r = await api.request('GET', '/api/accounts/3/summary', { token: t.alice });
  assert.equal(r.status, 200);
  assert.equal(r.body.accountId, 2);
});

test('TN pattern: soft denial on document deletion (200, success=false, nothing deleted)', async () => {
  const r = await api.request('DELETE', '/api/documents/doc-3-private', { token: t.alice });
  assert.equal(r.status, 200);
  assert.equal(r.body.success, false);
  assert.equal((await api.request('GET', '/api/documents/doc-3-private', { token: t.bob })).status, 200);
});

test("TN pattern: device config change is accepted (202) but not applied for non-owners", async () => {
  const r = await api.request('PUT', '/api/devices/dev-003-a/config', { token: t.alice, body: { samplingIntervalSec: 5, label: 'changed-by-alice' } });
  assert.equal(r.status, 202);
  const owner = await api.request('GET', '/api/devices/dev-003-a', { token: t.bob });
  assert.equal(owner.body.config.label, 'default');
});

test('TN pattern: admin reports are role-filtered (200, empty self scope)', async () => {
  const r = await api.request('GET', '/api/admin/reports', { token: t.alice });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { scope: 'self', reports: [] });
  const a = await api.request('GET', '/api/admin/reports', { token: t.admin });
  assert.equal(a.body.scope, 'global');
  assert.ok(a.body.reports.length > 0);
});

test('TN pattern: audit log soft denial (200, success=false)', async () => {
  const r = await api.request('GET', '/api/admin/audit-logs', { token: t.alice });
  assert.equal(r.status, 200);
  assert.equal(r.body.success, false);
  assert.equal(r.body.logs, undefined);
});
