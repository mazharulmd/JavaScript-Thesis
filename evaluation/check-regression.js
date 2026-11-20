#!/usr/bin/env node
/**
 * CI regression check: scores a findings document against the ground truth and fails
 * (exit 1) when detection quality drops below the configured floors.
 *
 * Usage: node evaluation/check-regression.js --ground-truth <gt.json> --findings <f.json>
 *          [--min-recall 1.0] [--max-fp 0] [--scope PRIMARY|SECONDARY|OVERALL]
 */
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { compareRuns } from './compare.js';
import { fmt } from './metrics.js';

export function checkRegression(gt, doc, { minRecall = 1, maxFp = 0, scope = 'OVERALL' } = {}) {
  const m = compareRuns(gt, [{ name: 'run', doc }]).results[0].metrics.confirmed[scope];
  const problems = [];
  if (m.recall !== null && m.recall < minRecall) problems.push(`recall ${fmt(m.recall)} < ${minRecall}`);
  if (m.fp > maxFp) problems.push(`false positives ${m.fp} > ${maxFp}`);
  return { metrics: m, problems };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { values } = parseArgs({ options: {
    'ground-truth': { type: 'string' }, findings: { type: 'string' },
    'min-recall': { type: 'string', default: '1' }, 'max-fp': { type: 'string', default: '0' }, scope: { type: 'string', default: 'OVERALL' },
  } });
  if (!values['ground-truth'] || !values.findings) {
    console.error('Usage: check-regression.js --ground-truth <gt.json> --findings <findings.json> [--min-recall R] [--max-fp N] [--scope S]');
    process.exit(2);
  }
  const { metrics: m, problems } = checkRegression(
    JSON.parse(readFileSync(values['ground-truth'], 'utf8')),
    JSON.parse(readFileSync(values.findings, 'utf8')),
    { minRecall: Number(values['min-recall']), maxFp: Number(values['max-fp']), scope: values.scope },
  );
  console.log(`${values.scope}: TP=${m.tp} FP=${m.fp} TN=${m.tn} FN=${m.fn} precision=${fmt(m.precision)} recall=${fmt(m.recall)} FPR=${fmt(m.falsePositiveRate)}`);
  if (problems.length) {
    console.error(`REGRESSION: ${problems.join('; ')}`);
    process.exit(1);
  }
  console.log('Detection quality within the configured floors.');
}
