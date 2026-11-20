#!/usr/bin/env node
/**
 * Compares one or more detection runs against a ground-truth manifest.
 *
 * Every run is a findings document (docs/FINDINGS-FORMAT.md). External tools are first
 * converted with an adapter (e.g. evaluation/adapters/zap.js).
 *
 * Two decision thresholds are always reported:
 *   - "confirmed"            only findings with status = confirmed count as detections
 *   - "confirmed+potential"  potential findings count as well
 *
 * Usage:
 *   node evaluation/compare.js --ground-truth test-api/ground-truth.json \
 *        --run "OWASP ZAP=evaluation/results/x/zap-findings.json" [--run "Name=file.json" ...] \
 *        --out evaluation/results/<experiment-id>
 *
 * Outputs (in --out): metrics.json, metrics.csv, per-case.csv, comparison.md, chart-*.svg
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { caseKey, metricsReport, fmt, GROUPS } from './metrics.js';
import { groupedBarChart } from './chart.js';

const THRESHOLDS = { confirmed: ['confirmed'], 'confirmed+potential': ['confirmed', 'potential'] };
const ROW_ORDER = ['PRIMARY', 'BOLA', 'BFLA', 'SECONDARY', ...GROUPS.SECONDARY, 'OVERALL'];

export function detectedKeys(doc, statuses) {
  return new Set((doc.findings ?? []).filter((f) => statuses.includes(f.status)).map(caseKey));
}

/** Fraction of scored cases for which the run recorded an executed test (needs doc.tests). */
export function coverage(doc, cases) {
  if (!Array.isArray(doc.tests) || doc.tests.length === 0) return null;
  const tested = new Set(doc.tests.filter((t) => t.verdict !== 'skipped').map(caseKey));
  const scored = cases.filter((c) => c.applicable !== false);
  return scored.filter((c) => tested.has(caseKey(c))).length / scored.length;
}

export function compareRuns(groundTruth, runs) {
  const cases = groundTruth.cases;
  const results = runs.map(({ name, doc }) => {
    const byThreshold = {};
    for (const [label, statuses] of Object.entries(THRESHOLDS)) byThreshold[label] = metricsReport(cases, detectedKeys(doc, statuses));
    return {
      name,
      tool: doc.meta?.tool ?? name,
      mode: doc.meta?.mode ?? null,
      durationMs: doc.meta?.durationMs ?? null,
      requests: doc.meta?.requests ?? null,
      findings: (doc.findings ?? []).length,
      coverage: coverage(doc, cases),
      metrics: byThreshold,
      perCase: Object.fromEntries(cases.filter((c) => c.applicable !== false).map((c) => {
        const k = caseKey(c);
        const conf = detectedKeys(doc, THRESHOLDS.confirmed).has(k);
        const pot = detectedKeys(doc, THRESHOLDS['confirmed+potential']).has(k);
        return [c.id, conf ? 'confirmed' : pot ? 'potential' : 'not reported'];
      })),
    };
  });
  return { groundTruth: { benchmark: groundTruth.benchmark, build: groundTruth.build, totals: groundTruth.totals }, results };
}

function markdown(report) {
  const lines = [];
  lines.push(`# Detection comparison: ${report.groundTruth.benchmark}`, '');
  lines.push(`Ground truth: ${report.groundTruth.build}; ${report.groundTruth.totals.scored} scored cases (${report.groundTruth.totals.vulnerable} vulnerable).`, '');
  lines.push('| Run | Tool | Findings | Requests | Duration (s) | Case coverage |', '|---|---|---:|---:|---:|---:|');
  for (const r of report.results) {
    lines.push(`| ${r.name} | ${r.tool} | ${r.findings} | ${r.requests ?? 'n/a'} | ${r.durationMs === null ? 'n/a' : (r.durationMs / 1000).toFixed(2)} | ${r.coverage === null ? 'n/a' : `${(r.coverage * 100).toFixed(1)}%`} |`);
  }
  for (const threshold of Object.keys(THRESHOLDS)) {
    lines.push('', `## Threshold: ${threshold}`, '');
    lines.push('| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |', '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|');
    for (const scope of ROW_ORDER) {
      for (const r of report.results) {
        const m = r.metrics[threshold][scope];
        if (!m) continue;
        lines.push(`| ${scope} | ${r.name} | ${m.tp} | ${m.fp} | ${m.tn} | ${m.fn} | ${fmt(m.precision)} | ${fmt(m.recall)} | ${fmt(m.f1)} | ${fmt(m.falsePositiveRate)} |`);
      }
    }
  }
  lines.push('', '`n/a` = undefined because the denominator is zero (see evaluation/metrics.js).', '');
  return lines.join('\n');
}

function csvMetrics(report) {
  const rows = [['run', 'threshold', 'scope', 'tp', 'fp', 'tn', 'fn', 'precision', 'recall', 'f1', 'fpr']];
  for (const r of report.results) {
    for (const [threshold, scopes] of Object.entries(r.metrics)) {
      for (const scope of ROW_ORDER) {
        const m = scopes[scope];
        if (!m) continue;
        rows.push([r.name, threshold, scope, m.tp, m.fp, m.tn, m.fn, m.precision ?? '', m.recall ?? '', m.f1 ?? '', m.falsePositiveRate ?? '']);
      }
    }
  }
  return rows.map((row) => row.map((v) => (/[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : v)).join(',')).join('\n') + '\n';
}

function csvPerCase(groundTruth, report) {
  const header = ['case_id', 'category', 'method', 'path', 'vulnerable', ...report.results.map((r) => r.name)];
  const rows = [header];
  for (const c of groundTruth.cases.filter((x) => x.applicable !== false)) {
    rows.push([c.id, c.category, c.method, c.path, c.vulnerable, ...report.results.map((r) => r.perCase[c.id])]);
  }
  return rows.map((row) => row.map((v) => (/[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : v)).join(',')).join('\n') + '\n';
}

export function writeComparison(groundTruth, runs, outDir) {
  const report = compareRuns(groundTruth, runs);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'metrics.json'), `${JSON.stringify(report, null, 2)}\n`);
  writeFileSync(join(outDir, 'metrics.csv'), csvMetrics(report));
  writeFileSync(join(outDir, 'per-case.csv'), csvPerCase(groundTruth, report));
  writeFileSync(join(outDir, 'comparison.md'), markdown(report));
  if (report.results.length <= 3) {
    for (const scope of ['PRIMARY', 'SECONDARY', 'OVERALL']) {
      const svg = groupedBarChart({
        title: `${scope === 'PRIMARY' ? 'BOLA + BFLA' : scope === 'SECONDARY' ? 'Authentication / JWT' : 'All categories'}: detection quality`,
        subtitle: `Threshold: confirmed findings · ${groundTruth.build} · higher is better except FPR`,
        groups: ['Precision', 'Recall', 'F1', 'FPR'],
        series: report.results.map((r) => {
          const m = r.metrics.confirmed[scope];
          return { name: r.name, values: [m?.precision ?? null, m?.recall ?? null, m?.f1 ?? null, m?.falsePositiveRate ?? null] };
        }),
      });
      writeFileSync(join(outDir, `chart-${scope.toLowerCase()}.svg`), svg);
    }
  }
  return report;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { values } = parseArgs({ options: { 'ground-truth': { type: 'string' }, run: { type: 'string', multiple: true }, out: { type: 'string' } } });
  if (!values['ground-truth'] || !values.run?.length || !values.out) {
    console.error('Usage: compare.js --ground-truth <gt.json> --run "Name=findings.json" [--run ...] --out <dir>');
    process.exit(2);
  }
  const gt = JSON.parse(readFileSync(values['ground-truth'], 'utf8'));
  const runs = values.run.map((spec) => {
    const i = spec.indexOf('=');
    if (i < 1) throw new Error(`--run must be "Name=file.json", got ${spec}`);
    return { name: spec.slice(0, i), doc: JSON.parse(readFileSync(spec.slice(i + 1), 'utf8')) };
  });
  writeComparison(gt, runs, values.out);
  console.log(readFileSync(join(values.out, 'comparison.md'), 'utf8'));
}
