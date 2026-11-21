#!/usr/bin/env node
/**
 * Builds docs/dashboard/index.html: a single self-contained results dashboard.
 *
 * Browsers cannot fetch local files over file://, so this script reads the archived
 * experiment results from the repository and inlines them as JSON into the page
 * template (docs/dashboard/template.html). Nothing is typed in by hand: every number
 * on the dashboard comes from evaluation/results/, test-api/ or benchmarks/.
 *
 * Usage: node docs/dashboard/build.js
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FLAWS } from '../../test-api/src/flaws.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const rel = (p) => join(ROOT, p);
const json = (p) => JSON.parse(readFileSync(rel(p), 'utf8'));

/** Minimal CSV parser (handles quoted fields). */
function csv(p) {
  const text = readFileSync(rel(p), 'utf8').trim();
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    const out = [];
    let cur = '';
    let q = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (q) {
        if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (ch === '"') q = false; else cur += ch;
      } else if (ch === '"') q = true;
      else if (ch === ',') { out.push(cur); cur = ''; } else cur += ch;
    }
    out.push(cur);
    rows.push(out);
  }
  const [head, ...body] = rows;
  return body.map((r) => Object.fromEntries(head.map((h, i) => [h, r[i]])));
}

const SCOPES = ['OVERALL', 'PRIMARY', 'SECONDARY', 'BOLA', 'BFLA'];
const APPROACHES = ['Role-aware', 'Status-only', 'OWASP ZAP'];

function experiment(id, title, dir, gtPath, experiments) {
  const m = json(`${dir}/metrics.json`);
  const perCaseRows = csv(`${dir}/per-case.csv`);
  const gt = json(gtPath);
  const gtById = new Map(gt.cases.map((c) => [c.id, c]));
  const runs = m.results.map((r) => {
    const scopes = {};
    for (const s of SCOPES) {
      const v = r.metrics.confirmed[s];
      if (v) scopes[s] = { tp: v.tp, fp: v.fp, tn: v.tn, fn: v.fn, precision: v.precision, recall: v.recall, f1: v.f1, fpr: v.falsePositiveRate };
    }
    // Split false positives: on scored true-negative cases vs. findings that match no scored case
    // (e.g. narrower auth categories on operations excluded by the root-cause rule).
    const fpScored = perCaseRows.filter((c) => c.vulnerable === 'false' && c[r.name] !== 'not reported').length;
    const fpUnlisted = r.metrics.confirmed.OVERALL.fp - fpScored;
    return {
      name: r.name, tool: r.tool, mode: r.mode, durationMs: r.durationMs, requests: r.requests, findings: r.findings,
      sameAtLooseThreshold: JSON.stringify(r.metrics.confirmed) === JSON.stringify(r.metrics['confirmed+potential']),
      scopes, fpScored, fpUnlisted,
    };
  });
  const cases = perCaseRows.map((c) => {
    const g = gtById.get(c.case_id) || {};
    return {
      id: c.case_id, category: c.category, method: c.method, path: c.path, vulnerable: c.vulnerable === 'true',
      notes: g.notes || '', flawId: g.flawId || null,
      results: Object.fromEntries(APPROACHES.map((a) => [a, c[a] !== 'not reported'])),
    };
  });
  return { id, title, experiments, groundTruth: m.groundTruth, runs, cases };
}

const benchmark = experiment('benchmark', 'Benchmark API (vulnerable build)',
  'evaluation/results/2026-11-21-scanner-test-api/comparison', 'test-api/ground-truth.json', 'E1 · E3 · E4');
const vampi = experiment('vampi', 'VAmPI (vulnerable mode)',
  'evaluation/results/2026-11-21-scanner-vampi/comparison', 'benchmarks/vampi/ground-truth.json', 'E2 · E5');

// RQ3 timing
const timing = csv('evaluation/results/2026-11-21-scanner-test-api/rq3-timing.csv')
  .map((r) => ({ run: Number(r.run), requests: Number(r.requests), durationMs: Number(r.durationMs) }));
const d = timing.map((t) => t.durationMs);
const mean = d.reduce((a, b) => a + b, 0) / d.length;
const sd = Math.sqrt(d.reduce((a, b) => a + (b - mean) ** 2, 0) / d.length);

// Injected flaws, joined with the ground-truth case and per-approach detection on the benchmark
const gt = json('test-api/ground-truth.json');
const benchCase = new Map(benchmark.cases.map((c) => [c.id, c]));
const flaws = Object.entries(FLAWS).map(([id, description]) => {
  const c = gt.cases.find((x) => x.flawId === id);
  return {
    id, description, category: c?.category, method: c?.method, path: c?.path, kind: c?.kind || '',
    caseId: c?.id, detected: benchCase.get(c?.id)?.results || {},
  };
});

const trueNegativePatterns = gt.cases
  .filter((c) => !c.vulnerable && (c.notes || '').startsWith('True-negative pattern'))
  .map((c) => ({ id: c.id, method: c.method, path: c.path, category: c.category, notes: c.notes.replace('True-negative pattern. ', '') }));

const summaryOf = (g) => ({ benchmark: g.benchmark, build: g.build, totals: g.totals, summary: g.summary });
const groundTruth = {
  categories: gt.categories,
  sets: [
    { label: 'Benchmark, vulnerable build', ...summaryOf(gt) },
    { label: 'Benchmark, patched build', ...summaryOf(json('test-api/ground-truth.secure.json')) },
    { label: 'VAmPI, vulnerable mode', ...summaryOf(json('benchmarks/vampi/ground-truth.json')) },
    { label: 'VAmPI, patched mode', ...summaryOf(json('benchmarks/vampi/ground-truth.secure.json')) },
  ],
};

// Patched-build sanity runs
const patchedBench = json('evaluation/results/2026-11-21-scanner-test-api/role-aware-patched-findings.json');
const patchedVampi = json('evaluation/results/2026-11-21-scanner-vampi/comparison-patched/metrics.json');
const zapPatched = json('evaluation/results/2026-11-20-zap-test-api/patched/metrics/metrics.json');
const patched = [
  { target: 'Benchmark API, patched build', approach: 'Role-aware', findings: patchedBench.findings.length, requests: patchedBench.meta.requests, durationMs: patchedBench.meta.durationMs, note: 'No findings on the build with every flaw switched off.' },
  { target: 'VAmPI, patched mode', approach: 'Role-aware', findings: patchedVampi.results[0].findings, requests: patchedVampi.results[0].requests, durationMs: patchedVampi.results[0].durationMs, note: 'One true positive: VAmPI leaves the unauthenticated /users/v1/_debug endpoint open in both modes.' },
  { target: 'Benchmark API, patched build', approach: 'OWASP ZAP', findings: zapPatched.results[0].findings, requests: null, durationMs: zapPatched.results[0].durationMs, note: 'No access-control findings.' },
];

// Experiment status, read from evaluation/README.md
const expRows = [];
let inside = false;
for (const line of readFileSync(rel('evaluation/README.md'), 'utf8').split('\n')) {
  if (line.startsWith('| ID ')) { inside = true; continue; }
  if (!inside) continue;
  if (!line.startsWith('|')) break;
  if (/^\|[-\s|:]+\|$/.test(line)) continue;
  const [id, description, status] = line.slice(1, -1).split('|').map((s) => s.trim().replace(/\*\*|`/g, ''));
  expRows.push({ id, description, status });
}

let commit = 'unknown';
try { commit = execSync('git log -1 --format=%h -- evaluation/results test-api benchmarks', { cwd: ROOT }).toString().trim(); } catch { /* not a git checkout */ }

const data = {
  generated: new Date().toISOString().slice(0, 10),
  commit,
  experiments: [benchmark, vampi],
  rq3: { timing, mean, sd, requests: timing[0].requests, target: 'localhost (Docker), benchmark reset between runs' },
  flaws, trueNegativePatterns, groundTruth, patched, experimentStatus: expRows,
};

const template = readFileSync(join(HERE, 'template.html'), 'utf8');
const payload = JSON.stringify(data).replace(/</g, '\\u003c');
if (!template.includes('/*__DATA__*/')) throw new Error('template.html is missing the /*__DATA__*/ placeholder');
const html = template.replace('/*__DATA__*/null', payload);
writeFileSync(join(HERE, 'index.html'), html);
console.log(`Wrote docs/dashboard/index.html (${(html.length / 1024).toFixed(0)} KB, input data last changed in commit ${commit})`);
