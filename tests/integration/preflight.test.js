import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startApi } from '../fixtures/server.js';
import { runPreflight } from '../../cli-tool/src/preflight.js';

const SPEC = new URL('../../test-api/openapi.yaml', import.meta.url).pathname;
const CFG = new URL('../../cli-tool/config/example.config.yaml', import.meta.url).pathname;
let api;
before(async () => { api = await startApi(); });
after(async () => { await api.close(); });

test('preflight logs in all accounts against a live benchmark and sends only login requests', async () => {
  const r = await runPreflight({ spec: SPEC, config: CFG, target: api.base });
  assert.equal(r.exitCode, 0, r.problems.join('; '));
  assert.deepEqual(r.accounts.map((a) => [a.name, a.identity, a.ok]), [['admin', '1', true], ['alice', '2', true], ['bob', '3', true], ['guest', '4', true]]);
  assert.equal(r.requests, 4);
  assert.ok(r.accounts.every((a) => a.token === '[obtained]'), 'tokens must not appear in the preflight result');
  assert.equal(r.inventory.operations, 47);
});

test('preflight reports a failed login with exit code 3', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'bac-pf-'));
  const bad = readFileSync(CFG, 'utf8').replace('password: "Bob#2026"', 'password: "wrong"');
  writeFileSync(join(dir, 'c.yaml'), bad);
  const r = await runPreflight({ spec: SPEC, config: join(dir, 'c.yaml'), target: api.base });
  assert.equal(r.exitCode, 3);
  assert.match(r.problems[0], /login failed for: bob/);
});

test('preflight refuses a target outside allowedHosts without sending requests', async () => {
  const r = await runPreflight({ spec: SPEC, config: CFG, target: 'https://example.com' });
  assert.equal(r.exitCode, 2);
  assert.match(r.problems[0], /not in allowedHosts/);
  assert.equal(r.requests, undefined);
});
