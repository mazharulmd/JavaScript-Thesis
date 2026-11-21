import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse } from 'yaml';
import { readFileSync } from 'node:fs';
import { loadSpec, listOperations, deref, resolveRef, fillPath, specServer } from '../../cli-tool/src/parser/openapi.js';
import { sampleFromSchema } from '../../cli-tool/src/utils/sample.js';
import { normalizeConfig, validateConfig, assertTargetAllowed, loadConfig } from '../../cli-tool/src/config/load-config.js';
import { resolvePolicy, policyMatrix, matchRule } from '../../cli-tool/src/config/policy.js';
import { getPath, readJwtClaims } from '../../cli-tool/src/utils/object-path.js';
import { createHttpClient } from '../../cli-tool/src/utils/http.js';
import { authHeaders } from '../../cli-tool/src/authentication/session.js';

const SPEC = new URL('../../test-api/openapi.yaml', import.meta.url).pathname;
const VAMPI = new URL('../../benchmarks/vampi/openapi3.yml', import.meta.url).pathname;
const CFG = new URL('../../cli-tool/config/example.config.yaml', import.meta.url).pathname;
const VCFG = new URL('../../benchmarks/vampi/vampi.config.yaml', import.meta.url).pathname;

test('parser: every operation of the benchmark spec is listed with params, security and policy', () => {
  const ops = listOperations(loadSpec(SPEC));
  assert.equal(ops.length, 47);
  const getOrder = ops.find((o) => o.id === 'GET /api/orders/{orderId}');
  assert.deepEqual(getOrder.pathParams, ['orderId']);
  assert.equal(getOrder.requiresAuth, true);
  assert.equal(getOrder.accessControl.ownership, 'owner');
  assert.equal(ops.find((o) => o.id === 'POST /api/auth/login').isPublic, true);
  const createOrder = ops.find((o) => o.id === 'POST /api/orders');
  assert.deepEqual(createOrder.requestBody.schema.required, ['sku', 'quantity', 'shippingAddress']);
  assert.ok(!JSON.stringify(createOrder).includes('$ref'), 'request body schema must be dereferenced');
});

test('parser: works on a third-party spec (VAmPI) and rejects Swagger 2.0', () => {
  const ops = listOperations(loadSpec(VAMPI));
  assert.equal(ops.length, 14);
  assert.equal(ops.filter((o) => o.requiresAuth).length, 6);
  assert.throws(() => listOperations({ swagger: '2.0', paths: {} }), /OpenAPI 3/);
});

test('parser: $ref resolution, cycles and path filling', () => {
  const doc = { openapi: '3.0.0', paths: {}, components: { schemas: { A: { properties: { b: { $ref: '#/components/schemas/A' } } } } } };
  assert.ok(resolveRef(doc, '#/components/schemas/A'));
  assert.throws(() => resolveRef(doc, 'other.yaml#/x'));
  const d = deref(doc, { $ref: '#/components/schemas/A' });
  assert.deepEqual(d.properties.b, { $circular: '#/components/schemas/A' });
  assert.equal(fillPath('/a/{x}/b/{y}', { x: 1, y: 'p q' }), '/a/1/b/p%20q');
  assert.throws(() => fillPath('/a/{x}', {}));
  assert.equal(specServer(loadSpec(SPEC)), 'http://localhost:3000');
});

test('sample bodies satisfy the schema basics and skip readOnly fields', () => {
  const ops = listOperations(loadSpec(SPEC));
  const order = sampleFromSchema(ops.find((o) => o.id === 'POST /api/orders').requestBody.schema);
  assert.deepEqual(Object.keys(order).sort(), ['note', 'quantity', 'shippingAddress', 'sku']);
  assert.equal(order.quantity, 1);
  const user = sampleFromSchema(ops.find((o) => o.id === 'POST /api/admin/users').requestBody.schema, { uniqueSuffix: 'r1' });
  assert.equal(user.username, 'temp-user-r1');
  assert.equal(user.email, 'temp-user-r1@bench.local');
  assert.equal(sampleFromSchema({ type: 'integer', minimum: 5, maximum: 9 }), 5);
  assert.equal(sampleFromSchema({ type: 'string', format: 'uuid' }), '00000000-0000-4000-8000-000000000000');
  assert.deepEqual(sampleFromSchema({ type: 'object', properties: { id: { type: 'integer', readOnly: true }, n: { type: 'string', enum: ['a', 'b'] } } }), { n: 'a' });
});

test('config: example configs are valid; missing secrets and single-role setups are reported', () => {
  assert.deepEqual(validateConfig(loadConfig(CFG)), []);
  assert.deepEqual(validateConfig(loadConfig(VCFG)), []);
  const cfg = normalizeConfig({ auth: { login: { path: '/login', tokenPath: 't' } }, accounts: [{ name: 'a', role: 'user', passwordEnv: 'NOPE_NOT_SET' }, { name: 'a', role: 'user', password: 'x' }] }, {});
  const problems = validateConfig(cfg);
  assert.ok(problems.some((p) => p.includes('NOPE_NOT_SET')));
  assert.ok(problems.some((p) => p.includes('duplicated')));
  assert.ok(problems.some((p) => p.includes('two different roles')));
  assert.ok(!JSON.stringify(problems).includes('"x"'), 'secrets must not be echoed');
});

test('config: passwords are read from environment variables', () => {
  const cfg = normalizeConfig({ accounts: [{ name: 'a', role: 'r', passwordEnv: 'PW' }] }, { PW: 's3cret' });
  assert.equal(cfg.accounts[0].password, 's3cret');
});

test('safety: only allow-listed hosts can be targeted', () => {
  assert.ok(assertTargetAllowed('http://localhost:3000', ['localhost']));
  assert.ok(assertTargetAllowed('http://[::1]:3000', ['::1']));
  assert.throws(() => assertTargetAllowed('https://example.com', ['localhost', '127.0.0.1']), /not in allowedHosts/);
});

test('policy: config rules override the spec, including operations the spec declares public', () => {
  const ops = listOperations(loadSpec(VAMPI));
  const cfg = loadConfig(VCFG);
  const debug = ops.find((o) => o.id === 'GET /users/v1/_debug');
  assert.equal(debug.isPublic, true);
  const p = resolvePolicy(debug, cfg);
  assert.deepEqual(p.roles, ['admin']);
  assert.equal(p.overridesPublic, true);
  const row = policyMatrix(ops, cfg).find((r) => r.operation === 'GET /users/v1/_debug');
  assert.equal(row.user, 'no');
  assert.equal(row.admin, 'yes');
  assert.equal(resolvePolicy(ops.find((o) => o.id === 'GET /books/v1/{book_title}'), cfg).ownership, 'owner');
});

test('policy: rule globs', () => {
  assert.ok(matchRule({ path: '/api/admin/**' }, { method: 'GET', path: '/api/admin/users/{userId}/role' }));
  assert.ok(matchRule({ path: '/api/*/x', methods: ['post'] }, { method: 'POST', path: '/api/a/x' }));
  assert.ok(!matchRule({ path: '/api/*/x', methods: ['GET'] }, { method: 'POST', path: '/api/a/x' }));
  assert.ok(!matchRule({ path: '/api/*' }, { method: 'GET', path: '/api/a/b' }));
});

test('policy: the benchmark spec yields the documented role restrictions', () => {
  const ops = listOperations(loadSpec(SPEC));
  const m = policyMatrix(ops, loadConfig(CFG));
  const row = (id) => m.find((r) => r.operation === id);
  assert.deepEqual([row('GET /api/admin/stats').admin, row('GET /api/admin/stats').user, row('GET /api/admin/stats').guest], ['yes', 'no', 'no']);
  assert.equal(row('POST /api/orders').guest, 'no');
  assert.equal(row('GET /api/products').public, true);
});

test('utils: object paths and JWT claim reading', () => {
  assert.equal(getPath({ a: { b: [{ c: 7 }] } }, 'a.b.0.c'), 7);
  assert.equal(getPath({ a: 1 }, 'a.b.c'), undefined);
  const token = `x.${Buffer.from(JSON.stringify({ sub: '42' })).toString('base64url')}.y`;
  assert.equal(readJwtClaims(token).sub, '42');
  assert.equal(readJwtClaims('garbage'), null);
  assert.deepEqual(authHeaders({ auth: { header: 'Authorization', scheme: 'Bearer' } }, { token: 't' }), { Authorization: 'Bearer t' });
});

test('http client: counts requests, enforces the budget and parses JSON', async () => {
  const fakeFetch = async () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } });
  const http = createHttpClient({ baseUrl: 'http://localhost:1', maxRequests: 2, fetchImpl: fakeFetch });
  const r = await http.request('GET', '/x', { query: { a: 1 } });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true });
  assert.equal(r.request.url, 'http://localhost:1/x?a=1');
  await http.request('GET', '/y');
  assert.equal(http.count, 2);
  await assert.rejects(http.request('GET', '/z'), /budget exhausted/);
});
