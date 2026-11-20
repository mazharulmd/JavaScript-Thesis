import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';

const spec = parse(readFileSync(new URL('../../benchmarks/vampi/openapi3.yml', import.meta.url), 'utf8'));
const load = (f) => JSON.parse(readFileSync(new URL(`../../benchmarks/vampi/${f}`, import.meta.url), 'utf8'));

for (const file of ['ground-truth.json', 'ground-truth.secure.json']) {
  test(`VAmPI ${file}: every case refers to an operation in VAmPI's spec`, () => {
    for (const c of load(file).cases) {
      assert.ok(spec.paths[c.path]?.[c.method.toLowerCase()], `${c.method} ${c.path} not in VAmPI spec`);
    }
  });
  test(`VAmPI ${file}: auth cases exist exactly for bearer-protected operations`, () => {
    const bearer = Object.entries(spec.paths).flatMap(([p, item]) => Object.entries(item)
      .filter(([, op]) => Array.isArray(op?.security) && op.security.some((s) => 'bearerAuth' in s))
      .map(([m]) => `${m.toUpperCase()} ${p}`)).sort();
    const authOps = [...new Set(load(file).cases.filter((c) => c.category === 'AUTH_MISSING').map((c) => `${c.method} ${c.path}`))].sort();
    assert.deepEqual(authOps, bearer);
  });
}

test('VAmPI patched mode differs from vulnerable mode only where the source switches on `vuln`', () => {
  const v = load('ground-truth.json').cases;
  const s = load('ground-truth.secure.json').cases;
  const changed = v.filter((c, i) => c.vulnerable !== s[i].vulnerable).map((c) => `${c.method} ${c.path}`);
  assert.deepEqual(changed.sort(), ['GET /books/v1/{book_title}', 'PUT /users/v1/{username}/password']);
});
