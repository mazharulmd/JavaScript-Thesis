import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { buildGroundTruth, VULNERABLE } from '../../evaluation/build-ground-truth.js';
import { FLAWS } from '../../test-api/src/flaws.js';

const spec = parse(readFileSync(new URL('../../test-api/openapi.yaml', import.meta.url), 'utf8'));
const onDisk = JSON.parse(readFileSync(new URL('../../test-api/ground-truth.json', import.meta.url), 'utf8'));

test('every injected flaw has exactly one vulnerable ground-truth case and vice versa', () => {
  const flawIds = VULNERABLE.map((v) => v.flawId).sort();
  assert.deepEqual(flawIds, Object.keys(FLAWS).sort());
  assert.equal(new Set(flawIds).size, flawIds.length);
  assert.equal(onDisk.cases.filter((c) => c.vulnerable).length, Object.keys(FLAWS).length);
});

test('committed ground-truth.json is up to date with the spec and the labels', () => {
  assert.deepEqual(onDisk, buildGroundTruth(spec));
});

test('case ids and keys are unique', () => {
  const ids = onDisk.cases.map((c) => c.id);
  const keys = onDisk.cases.map((c) => `${c.method} ${c.path} ${c.category}`);
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(new Set(keys).size, keys.length);
});

test('patched-build ground truth contains no vulnerable case', () => {
  const secure = buildGroundTruth(spec, { secure: true });
  assert.equal(secure.cases.filter((c) => c.vulnerable).length, 0);
  assert.ok(secure.cases.every((c) => c.applicable !== false));
});

test('vulnerable cases are never excluded from scoring', () => {
  assert.ok(onDisk.cases.filter((c) => c.vulnerable).every((c) => c.applicable !== false));
});
