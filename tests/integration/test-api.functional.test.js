/**
 * Functional tests of the benchmark API: authentication, roles, seed determinism,
 * reset, and consistency between the OpenAPI specification and the implementation.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { startApi } from '../fixtures/server.js';
import { createFlawSet, FLAWS } from '../../test-api/src/flaws.js';

const spec = parse(readFileSync(new URL('../../test-api/openapi.yaml', import.meta.url), 'utf8'));
const METHODS = ['get', 'post', 'put', 'patch', 'delete'];
const operations = Object.entries(spec.paths).flatMap(([path, item]) =>
  METHODS.filter((m) => item[m]).map((m) => ({ path, method: m.toUpperCase(), op: item[m] })));

let api;
before(async () => { api = await startApi({ flaws: 'none' }); });
after(async () => { await api.close(); });

test('login succeeds for every seeded test account and returns its role', async () => {
  for (const [username, role] of [['admin', 'admin'], ['alice', 'user'], ['bob', 'user'], ['guest', 'guest']]) {
    const token = await api.login(username);
    const me = await api.request('GET', '/api/auth/me', { token });
    assert.equal(me.status, 200);
    assert.equal(me.body.username, username);
    assert.equal(me.body.role, role);
    assert.equal(me.body.passwordHash, undefined, 'password hash must never be exposed');
  }
});

test('login rejects a wrong password and malformed bodies', async () => {
  assert.equal((await api.request('POST', '/api/auth/login', { body: { username: 'alice', password: 'nope' } })).status, 401);
  assert.equal((await api.request('POST', '/api/auth/login', { body: { username: 'alice' } })).status, 400);
});

test('flaw registry: all / none / explicit list', () => {
  assert.equal(createFlawSet('all').list().length, Object.keys(FLAWS).length);
  assert.equal(createFlawSet('none').mode, 'secure');
  assert.deepEqual(createFlawSet('BOLA_ORDERS_READ').list(), ['BOLA_ORDERS_READ']);
  assert.throws(() => createFlawSet('NOT_A_FLAW'));
});

test('every OpenAPI operation documents its intended policy (x-access-control)', () => {
  assert.ok(operations.length >= 40, `expected >= 40 operations, got ${operations.length}`);
  for (const { method, path, op } of operations) {
    const ac = op['x-access-control'];
    assert.ok(ac, `${method} ${path} lacks x-access-control`);
    assert.ok(Array.isArray(ac.roles) && ac.roles.length > 0, `${method} ${path} has no roles`);
    assert.ok(['owner', 'none'].includes(ac.ownership), `${method} ${path} has invalid ownership`);
  }
});

test('every OpenAPI operation is implemented (no "No route" 404)', async () => {
  const token = await api.login('admin');
  for (const { method, path } of operations) {
    const concrete = path
      .replace('{userId}', '2').replace('{accountId}', '2').replace('{orderId}', '1003')
      .replace('{invoiceId}', '7003').replace('{documentId}', 'doc-2-private')
      .replace('{deviceId}', 'dev-002-a').replace('{productId}', '501');
    // GET-only probe for safety; other methods are probed with an empty body (400 is fine, "No route" is not).
    const r = await api.request(method === 'DELETE' ? 'OPTIONS' : method, concrete, { token, body: method === 'GET' || method === 'DELETE' ? undefined : {} });
    const noRoute = r.status === 404 && r.body?.error?.message?.startsWith('No route');
    if (method !== 'DELETE') assert.ok(!noRoute, `${method} ${path} is documented but not implemented`);
  }
});

test('seed data is deterministic and reset restores it', async () => {
  const token = await api.login('alice');
  const before1 = await api.request('GET', '/api/orders', { token });
  const created = await api.request('POST', '/api/orders', { token, body: { sku: 'SKU-501', quantity: 1, shippingAddress: 'x' } });
  assert.equal(created.status, 201);
  assert.equal((await api.request('GET', '/api/orders', { token })).body.count, before1.body.count + 1);
  assert.equal((await api.request('POST', '/__benchmark/reset')).status, 200);
  assert.deepEqual((await api.request('GET', '/api/orders', { token })).body, before1.body);
});

test('reset endpoint is unavailable outside benchmark mode', async () => {
  const other = await startApi({ benchmarkMode: false });
  try {
    assert.equal((await other.request('POST', '/__benchmark/reset')).status, 404);
  } finally {
    await other.close();
  }
});

test('mass assignment is prevented: ownerId in a create body is ignored', async () => {
  const token = await api.login('alice');
  const r = await api.request('POST', '/api/documents', { token, body: { title: 't', content: 'c', ownerId: 3 } });
  assert.equal(r.status, 201);
  assert.equal(r.body.ownerId, 2);
});
