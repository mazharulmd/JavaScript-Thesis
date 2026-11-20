import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse } from 'yaml';
import { templateMatchers, matchTemplate, convertZapReport } from '../../evaluation/adapters/zap.js';
import { compareRuns, writeComparison, detectedKeys } from '../../evaluation/compare.js';
import { groupedBarChart } from '../../evaluation/chart.js';

const spec = parse(readFileSync(new URL('../../test-api/openapi.yaml', import.meta.url), 'utf8'));
const gt = JSON.parse(readFileSync(new URL('../../test-api/ground-truth.json', import.meta.url), 'utf8'));

test('URL paths are mapped to the most specific OpenAPI template', () => {
  const m = templateMatchers(spec);
  assert.equal(matchTemplate(m, '/api/orders/1005'), '/api/orders/{orderId}');
  assert.equal(matchTemplate(m, '/api/orders'), '/api/orders');
  assert.equal(matchTemplate(m, '/api/devices/dev-002-a/readings'), '/api/devices/{deviceId}/readings');
  assert.equal(matchTemplate(m, '/api/admin/users/7/role'), '/api/admin/users/{userId}/role');
  assert.equal(matchTemplate(m, '/nope'), null);
});

test('ZAP adapter maps access-control CWEs and keeps other alerts out of scope', () => {
  const zap = { '@version': 'test', site: [{ '@name': 'http://localhost:3000', alerts: [
    { pluginid: '1', alert: 'Some authz issue', cweid: '639', riskcode: '3', confidence: '3', instances: [{ uri: 'http://localhost:3000/api/orders/1005', method: 'GET' }] },
    { pluginid: '2', alert: 'Missing header', cweid: '693', riskcode: '1', confidence: '2', instances: [{ uri: 'http://localhost:3000/api/orders', method: 'GET' }] },
    { pluginid: '3', alert: 'Generic authz', cweid: '285', riskcode: '2', confidence: '2', instances: [{ uri: 'http://localhost:3000/api/admin/stats', method: 'GET' }] },
  ] }] };
  const doc = convertZapReport(zap, spec);
  assert.equal(doc.findings.length, 2);
  assert.deepEqual(doc.findings.map((f) => [f.category, f.path, f.status]), [
    ['BOLA', '/api/orders/{orderId}', 'confirmed'],
    ['BFLA', '/api/admin/stats', 'potential'],
  ]);
  assert.equal(doc.outOfScope.length, 1);
});

test('compareRuns scores runs at both thresholds', () => {
  const doc = { meta: { tool: 't' }, findings: [
    { id: 'a', category: 'BOLA', method: 'GET', path: '/api/orders/{orderId}', status: 'confirmed', severity: 'high' }, // TP
    { id: 'b', category: 'BOLA', method: 'GET', path: '/api/documents/{documentId}', status: 'potential', severity: 'high' }, // FP at loose threshold
  ] };
  const r = compareRuns(gt, [{ name: 'X', doc }]).results[0];
  assert.equal(r.metrics.confirmed.BOLA.tp, 1);
  assert.equal(r.metrics.confirmed.BOLA.fp, 0);
  assert.equal(r.metrics['confirmed+potential'].BOLA.fp, 1);
  assert.equal(r.metrics.confirmed.PRIMARY.fn, gt.cases.filter((c) => c.vulnerable && ['BOLA', 'BFLA'].includes(c.category)).length - 1);
  assert.equal(detectedKeys(doc, ['confirmed']).size, 1);
});

test('a run with no findings has undefined precision and zero recall', () => {
  const r = compareRuns(gt, [{ name: 'Empty', doc: { meta: { tool: 'e' }, findings: [] } }]).results[0];
  assert.equal(r.metrics.confirmed.OVERALL.precision, null);
  assert.equal(r.metrics.confirmed.OVERALL.recall, 0);
  assert.equal(r.metrics.confirmed.OVERALL.falsePositiveRate, 0);
});

test('writeComparison writes all artefacts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bac-cmp-'));
  writeComparison(gt, [{ name: 'Empty', doc: { meta: { tool: 'e' }, findings: [] } }], dir);
  for (const f of ['metrics.json', 'metrics.csv', 'per-case.csv', 'comparison.md', 'chart-primary.svg']) assert.ok(existsSync(join(dir, f)), f);
  assert.match(readFileSync(join(dir, 'comparison.md'), 'utf8'), /n\/a/);
});

test('chart refuses more than three series (validated palette slots)', () => {
  const s = { name: 's', values: [0.5, null, 1, 0] };
  assert.match(groupedBarChart({ title: 't', groups: ['a', 'b', 'c', 'd'], series: [s] }), /^<svg/);
  assert.throws(() => groupedBarChart({ title: 't', groups: ['a'], series: [s, s, s, s] }));
});
