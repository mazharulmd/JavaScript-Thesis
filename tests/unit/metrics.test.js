import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ratio, confusionMatrix, computeMetrics, metricsByCategory, caseKey, fmt } from '../../evaluation/metrics.js';

const cases = [
  { id: 'C1', method: 'GET', path: '/a/{id}', category: 'BOLA', vulnerable: true },
  { id: 'C2', method: 'GET', path: '/b/{id}', category: 'BOLA', vulnerable: false },
  { id: 'C3', method: 'POST', path: '/admin/x', category: 'BFLA', vulnerable: true },
  { id: 'C4', method: 'GET', path: '/admin/y', category: 'BFLA', vulnerable: false },
  { id: 'C5', method: 'GET', path: '/excluded', category: 'BFLA', vulnerable: true, applicable: false },
];

test('ratio returns null for a zero denominator', () => {
  assert.equal(ratio(1, 0), null);
  assert.equal(ratio(1, 4), 0.25);
});

test('confusion matrix counts TP/FP/TN/FN and skips non-applicable cases', () => {
  const detected = [caseKey(cases[0]), caseKey(cases[1])];
  const m = confusionMatrix(cases, detected);
  assert.deepEqual({ tp: m.tp, fp: m.fp, tn: m.tn, fn: m.fn }, { tp: 1, fp: 1, tn: 1, fn: 1 });
  assert.equal(m.perCase.length, 4);
});

test('findings that match no ground-truth case count as false positives', () => {
  const m = confusionMatrix(cases, ['GET /unknown BOLA']);
  assert.equal(m.fp, 1);
  assert.deepEqual(m.unlisted, ['GET /unknown BOLA']);
});

test('computeMetrics: standard values', () => {
  const r = computeMetrics({ tp: 8, fp: 2, tn: 18, fn: 2 });
  assert.equal(r.precision, 0.8);
  assert.equal(r.recall, 0.8);
  assert.ok(Math.abs(r.f1 - 0.8) < 1e-12);
  assert.equal(r.falsePositiveRate, 0.1);
});

test('computeMetrics: zero denominators are reported as null with notes', () => {
  const r = computeMetrics({ tp: 0, fp: 0, tn: 5, fn: 3 });
  assert.equal(r.precision, null);
  assert.equal(r.recall, 0);
  assert.equal(r.f1, null);
  assert.equal(r.falsePositiveRate, 0);
  assert.ok(r.notes.some((n) => n.startsWith('precision undefined')));
});

test('computeMetrics: precision and recall both zero gives F1 = 0', () => {
  const r = computeMetrics({ tp: 0, fp: 3, tn: 1, fn: 2 });
  assert.equal(r.precision, 0);
  assert.equal(r.recall, 0);
  assert.equal(r.f1, 0);
});

test('metricsByCategory produces per-category and overall rows', () => {
  const rows = metricsByCategory(cases, [caseKey(cases[0]), caseKey(cases[2])]);
  assert.equal(rows.BOLA.tp, 1);
  assert.equal(rows.BFLA.tp, 1);
  assert.equal(rows.OVERALL.tp, 2);
  assert.equal(rows.OVERALL.fp, 0);
  assert.equal(rows.OVERALL.precision, 1);
});

test('fmt renders null as n/a', () => {
  assert.equal(fmt(null), 'n/a');
  assert.equal(fmt(0.12345), '0.123');
});
