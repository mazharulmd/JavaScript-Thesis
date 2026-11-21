import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { startApi } from '../fixtures/server.js';
import { runScan, evaluatePlan } from '../../cli-tool/src/engine/index.js';
import { validateFindingsDocument, exceedsThreshold } from '../../cli-tool/src/reporting/index.js';
import { checkRegression } from '../../evaluation/check-regression.js';

const SPEC = new URL('../../test-api/openapi.yaml', import.meta.url).pathname;
const CONFIG = new URL('../../cli-tool/config/example.config.yaml', import.meta.url).pathname;
const GT = JSON.parse(readFileSync(new URL('../../test-api/ground-truth.json', import.meta.url), 'utf8'));

test('vulnerable build: ownership-differential achieves 100% recall and 0 FPs while status-only raises FPs on the same requests', async () => {
  const api = await startApi({ flaws: 'all' });
  try {
    const scan = await runScan({
      spec: SPEC,
      config: CONFIG,
      target: api.base,
      statusOnly: false,
      env: { ...process.env, JWT_SECRET: 'test-secret' },
    });
    assert.equal(scan.ok, true);
    assert.deepEqual(validateFindingsDocument(scan.document), []);
    assert.ok(scan.document.meta.requests > 0);
    assert.ok(scan.document.meta.durationMs >= 0);

    const primary = checkRegression(GT, scan.document, { minRecall: 1, maxFp: 0, scope: 'PRIMARY' });
    assert.deepEqual(primary.problems, [], `PRIMARY regression: ${primary.problems.join('; ')}`);

    const overall = checkRegression(GT, scan.document, { minRecall: 1, maxFp: 0, scope: 'OVERALL' });
    assert.deepEqual(overall.problems, [], `OVERALL regression: ${overall.problems.join('; ')}`);

    // Evaluate the exact same execution trace with the status-only oracle (RQ2)
    const statusDoc = evaluatePlan(scan.plan, scan.executions, scan.cfg, scan.document.meta, { statusOnly: true });
    const statusReg = checkRegression(GT, statusDoc, { minRecall: 1, maxFp: 0, scope: 'PRIMARY' });
    assert.ok(statusReg.metrics.fp > 0, 'status-only oracle must raise false positives on the true-negative patterns');
  } finally {
    await api.close();
  }
});

test('patched build (FLAWS=none): produces no confirmed high-severity findings', async () => {
  const api = await startApi({ flaws: 'none' });
  try {
    const scan = await runScan({
      spec: SPEC,
      config: CONFIG,
      target: api.base,
      statusOnly: false,
      env: { ...process.env, JWT_SECRET: 'test-secret' },
    });
    assert.equal(scan.ok, true);
    assert.deepEqual(validateFindingsDocument(scan.document), []);
    assert.equal(exceedsThreshold(scan.document, 'high'), false);
    assert.equal(scan.document.findings.filter((f) => f.status === 'confirmed').length, 0);
  } finally {
    await api.close();
  }
});
