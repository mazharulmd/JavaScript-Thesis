#!/usr/bin/env node
/**
 * Builds docs/webapp/index.html: a self-contained, interactive explainer of the
 * role-aware broken-access-control testing tool, aimed at a non-expert reader.
 *
 * Browsers cannot fetch local files over file://, so (exactly like
 * docs/dashboard/build.js) this script reads the archived experiment results and
 * benchmark definitions from the repository and inlines them as a single JSON blob
 * into the page template (docs/webapp/template.html). Nothing on the page is typed
 * in by hand: every number, request, response and verdict comes from
 * evaluation/results/, test-api/ or cli-tool/config/.
 *
 * This is a STATIC VIEWER. It does not run a scan; it visualises results that were
 * already computed and committed under evaluation/results/2026-11-21-scanner-*.
 *
 * Usage: node docs/webapp/build.js
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
const text = (p) => readFileSync(rel(p), 'utf8');

/** Minimal CSV parser (handles simple quoted fields). */
function csv(p) {
  const raw = text(p).trim();
  const rows = [];
  for (const line of raw.split(/\r?\n/)) {
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

// ---------------------------------------------------------------------------
// OpenAPI policy map: parse the single-line `x-access-control` flow objects out
// of test-api/openapi.yaml, keyed by "METHOD path". Indentation is fixed in the
// spec: paths at 2 spaces, methods at 4, x-access-control at 6.
// ---------------------------------------------------------------------------
function parsePolicy(s) {
  const inner = s.trim().replace(/^\{/, '').replace(/\}$/, '');
  const roles = (inner.match(/roles:\s*\[([^\]]*)\]/) || [])[1] || '';
  const get = (k) => {
    const m = inner.match(new RegExp(`${k}:\\s*([^,\\]]+?)(?:,|$)`));
    return m ? m[1].trim() : null;
  };
  return {
    roles: roles.split(',').map((x) => x.trim()).filter(Boolean),
    ownership: get('ownership'),
    ownerField: get('ownerField'),
    resource: get('resource'),
  };
}
function buildPolicyMap() {
  const map = {};
  let path = null;
  let method = null;
  for (const line of text('test-api/openapi.yaml').split('\n')) {
    const pm = line.match(/^ {2}(\/\S+):\s*$/);
    if (pm) { path = pm[1]; method = null; continue; }
    const mm = line.match(/^ {4}(get|post|put|patch|delete):\s*$/);
    if (mm) { method = mm[1].toUpperCase(); continue; }
    const xm = line.match(/^ {6}x-access-control:\s*(\{.*\})\s*$/);
    if (xm && path && method) map[`${method} ${path}`] = parsePolicy(xm[1]);
  }
  return map;
}

// ---------------------------------------------------------------------------
// Load archived scanner results (benchmark, vulnerable build)
// ---------------------------------------------------------------------------
const BENCH = 'evaluation/results/2026-11-21-scanner-test-api';
const VAMPI = 'evaluation/results/2026-11-21-scanner-vampi';

const roleAware = json(`${BENCH}/role-aware-findings.json`);
const statusOnly = json(`${BENCH}/status-only-findings.json`);
const metrics = json(`${BENCH}/comparison/metrics.json`);
const perCaseRows = csv(`${BENCH}/comparison/per-case.csv`);
const gt = json('test-api/ground-truth.json');
const policyMap = buildPolicyMap();

const findingKey = (f) => `${f.method} ${f.path}`;
// The walkthrough is framed around "Alice", and several endpoints have one
// finding per attacker (alice, guest, ...). Prefer the alice-attacker finding so
// the narrative and the quoted evidence agree; fall back to the first match.
function indexFindings(list) {
  const m = new Map();
  for (const f of list) {
    const k = findingKey(f);
    const cur = m.get(k);
    if (!cur || (f.attacker && f.attacker.account === 'alice' && (!cur.attacker || cur.attacker.account !== 'alice'))) m.set(k, f);
  }
  return m;
}
const roleAwareBy = indexFindings(roleAware.findings);
const statusOnlyBy = indexFindings(statusOnly.findings);
const perCaseByTriple = new Map(perCaseRows.map((c) => [`${c.category} ${c.method} ${c.path}`, c]));
const gtByTriple = new Map(gt.cases.map((c) => [`${c.category} ${c.method} ${c.path}`, c]));

const SCOPES = ['OVERALL', 'BOLA', 'BFLA', 'AUTH_MISSING', 'AUTH_INVALID_TOKEN', 'JWT_SIGNATURE', 'JWT_NONE_ALG', 'JWT_EXPIRED'];
const APPROACHES = ['Role-aware', 'Status-only', 'OWASP ZAP'];

// ---------------------------------------------------------------------------
// OVERVIEW: headline numbers, straight from metrics.json OVERALL (confirmed).
// ---------------------------------------------------------------------------
const headline = metrics.results.map((r) => {
  const o = r.metrics.confirmed.OVERALL;
  return {
    approach: r.name,
    mode: r.mode,
    precision: o.precision,
    recall: o.recall,
    f1: o.f1,
    fpr: o.falsePositiveRate,
    tp: o.tp, fp: o.fp, tn: o.tn, fn: o.fn,
    detected: o.tp,
    requests: r.requests,
    durationMs: r.durationMs,
    findings: r.findings,
  };
});

// Flaw family counts, derived from the ground-truth categories of the 20 flaws.
const flawFamilies = {};
for (const [id] of Object.entries(FLAWS)) {
  const c = gt.cases.find((x) => x.flawId === id);
  const fam = c ? c.category : 'other';
  flawFamilies[fam] = (flawFamilies[fam] || 0) + 1;
}

const accounts = [
  { name: 'admin', role: 'admin', can: 'Everything; ownership is bypassed for admins.' },
  { name: 'alice', role: 'user', can: 'Read and change only the objects Alice owns.' },
  { name: 'bob', role: 'user', can: 'Read and change only the objects Bob owns.' },
  { name: 'guest', role: 'guest', can: 'Authenticated but read-only; may not create or delete.' },
];

// ---------------------------------------------------------------------------
// HOW IT WORKS: a curated, ordered set of concrete examples. Each one is
// resolved against the archived findings / per-case / ground truth / spec, so
// every request, response and verdict is real data, not hand-written.
//
// `source` says which oracle's run carries the shared request/response for this
// example. Both oracles send the SAME request; when one of them does not raise a
// finding (a correct denial) its run has no evidence to quote, so we take the
// request/response from the run that did, and label each oracle's decision from
// the per-case verdict table.
// ---------------------------------------------------------------------------
const WALKTHROUGH = [
  {
    id: 'orders-bola',
    title: "Alice reads Bob's order",
    tagline: 'A real BOLA. Both oracles correctly flag it.',
    category: 'BOLA', method: 'GET', path: '/api/orders/{orderId}',
    source: 'role-aware',
    plain: "Alice is logged in as an ordinary user. She asks for an order that belongs to Bob. The server hands it over — including Bob's shipping address.",
  },
  {
    id: 'documents-public',
    title: 'A public handbook',
    tagline: 'Looks identical over HTTP, but is allowed by design. Status-only trips; role-aware holds.',
    category: 'BOLA', method: 'GET', path: '/api/documents/{documentId}',
    source: 'status-only',
    plain: "Alice asks for a document owned by Bob. It comes back with HTTP 200 — but the object says visibility: public. It is meant to be readable by anyone.",
  },
  {
    id: 'accounts-summary',
    title: 'The ignored path id',
    tagline: 'A 200 that never leaked anything. Status-only trips; role-aware holds.',
    category: 'BOLA', method: 'GET', path: '/api/accounts/{accountId}/summary',
    source: 'status-only',
    plain: "Alice asks for account 3's summary (Bob's). The server ignores the id in the URL and returns Alice's OWN summary (accountId: 2). No data crossed the owner boundary.",
  },
  {
    id: 'documents-delete',
    title: 'A soft denial',
    tagline: 'A 200 that actually refused. Status-only trips; role-aware holds.',
    category: 'BOLA', method: 'DELETE', path: '/api/documents/{documentId}',
    source: 'status-only',
    plain: "Alice tries to delete Bob's document. The server answers HTTP 200 — but the body says success: false and nothing was deleted.",
  },
  {
    id: 'admin-reports',
    title: 'A role-filtered view',
    tagline: 'A 200 scoped down to nothing. Status-only trips; role-aware holds.',
    category: 'BFLA', method: 'GET', path: '/api/admin/reports',
    source: 'status-only',
    plain: 'Alice (a non-admin) calls an admin reports endpoint. She gets HTTP 200, but the body is scope: "self" with an empty report list — the admin data is withheld.',
  },
  {
    id: 'admin-users',
    title: 'A non-admin lists every account',
    tagline: 'A real BFLA. Both oracles correctly flag it.',
    category: 'BFLA', method: 'GET', path: '/api/admin/users',
    source: 'role-aware',
    plain: 'Alice (a non-admin) calls the admin-only "list all users" endpoint. The full account list comes back — a function-level authorization failure.',
  },
];

function redactResponseBody(body) {
  return body; // archived findings are already redacted by the reporting module
}

const walkthrough = WALKTHROUGH.map((w) => {
  const key = `${w.method} ${w.path}`;
  const triple = `${w.category} ${w.method} ${w.path}`;
  const pc = perCaseByTriple.get(triple) || {};
  const gtc = gtByTriple.get(triple) || {};
  const src = w.source === 'role-aware' ? roleAwareBy.get(key) : statusOnlyBy.get(key);
  const ra = roleAwareBy.get(key);
  const so = statusOnlyBy.get(key);
  if (!src) throw new Error(`walkthrough ${w.id}: no finding for ${key}`);

  const vulnerable = gtc.vulnerable === true;
  const soFlagged = pc['Status-only'] && pc['Status-only'] !== 'not reported';
  const raFlagged = pc['Role-aware'] && pc['Role-aware'] !== 'not reported';

  // Human-readable reasons, sourced from the finding `observed` text and the
  // ground-truth notes (both committed in the repo).
  const soReason = soFlagged
    ? (so ? so.observed : 'Response had a 2xx status, so the status-only oracle reported it.')
    : 'Response was not 2xx, so the status-only oracle did not report it.';
  const raReason = raFlagged
    ? (ra ? ra.observed : 'The ownership-differential oracle confirmed a policy violation.')
    : (gtc.notes ? gtc.notes.replace(/^True-negative pattern\.\s*/, '') : 'The ownership-differential oracle saw no owner-boundary violation.');

  return {
    id: w.id, title: w.title, tagline: w.tagline, plain: w.plain,
    category: w.category, method: w.method, path: w.path,
    policy: policyMap[key] || null,
    attacker: src.attacker || { account: 'alice', role: 'user' },
    victim: src.victim || null,
    resource: src.resource || null,
    groundTruth: { vulnerable, notes: gtc.notes || '' },
    request: src.evidence.request,
    response: { status: src.evidence.response.status, body: redactResponseBody(src.evidence.response.body) },
    statusOnly: {
      decision: soFlagged ? 'flag' : 'allow',
      correct: soFlagged === vulnerable,
      confidence: so ? so.confidence : null,
      reason: soReason,
    },
    roleAware: {
      decision: raFlagged ? 'flag' : 'allow',
      correct: raFlagged === vulnerable,
      confidence: ra ? ra.confidence : null,
      reason: raReason,
    },
  };
});

// ---------------------------------------------------------------------------
// RESULTS: per-approach metric scopes + the per-case detection grid + RQ3.
// ---------------------------------------------------------------------------
function runsFor(m, rows) {
  return m.results.map((r) => {
    const scopes = {};
    for (const s of SCOPES) {
      const v = r.metrics.confirmed[s];
      if (v) scopes[s] = { tp: v.tp, fp: v.fp, tn: v.tn, fn: v.fn, precision: v.precision, recall: v.recall, f1: v.f1, fpr: v.falsePositiveRate };
    }
    const fpScored = rows.filter((c) => c.vulnerable === 'false' && c[r.name] && c[r.name] !== 'not reported').length;
    const fpUnlisted = r.metrics.confirmed.OVERALL.fp - fpScored;
    return {
      name: r.name, tool: r.tool, mode: r.mode,
      durationMs: r.durationMs, requests: r.requests, findings: r.findings,
      scopes, fpScored, fpUnlisted,
    };
  });
}

const cases = perCaseRows.map((c) => {
  const g = gtByTriple.get(`${c.category} ${c.method} ${c.path}`) || {};
  return {
    id: c.case_id, category: c.category, method: c.method, path: c.path,
    vulnerable: c.vulnerable === 'true',
    notes: g.notes || '', flawId: g.flawId || null,
    results: Object.fromEntries(APPROACHES.map((a) => [a, c[a] !== 'not reported'])),
  };
});

// VAmPI (vulnerable mode) — used for the external-benchmark note.
const vampiMetrics = json(`${VAMPI}/comparison/metrics.json`);
const vampiRole = vampiMetrics.results.find((r) => r.name === 'Role-aware');
const vampi = {
  groundTruth: vampiMetrics.groundTruth,
  roleAware: {
    precision: vampiRole.metrics.confirmed.OVERALL.precision,
    recall: vampiRole.metrics.confirmed.OVERALL.recall,
    f1: vampiRole.metrics.confirmed.OVERALL.f1,
    fpr: vampiRole.metrics.confirmed.OVERALL.falsePositiveRate,
    tp: vampiRole.metrics.confirmed.OVERALL.tp,
    fn: vampiRole.metrics.confirmed.OVERALL.fn,
  },
};

// RQ3 timing
const timing = csv(`${BENCH}/rq3-timing.csv`).map((r) => ({ run: Number(r.run), requests: Number(r.requests), durationMs: Number(r.durationMs) }));
const d = timing.map((t) => t.durationMs);
const mean = d.reduce((a, b) => a + b, 0) / d.length;
const sd = Math.sqrt(d.reduce((a, b) => a + (b - mean) ** 2, 0) / d.length);

// ---------------------------------------------------------------------------
// EXPLORE FINDINGS: the role-aware run's findings, trimmed for the table.
// ---------------------------------------------------------------------------
const findings = roleAware.findings.map((f) => ({
  id: f.id, category: f.category, method: f.method, path: f.path,
  severity: f.severity, status: f.status, confidence: f.confidence,
  attacker: f.attacker || null, victim: f.victim || null,
  expected: f.expected || '', observed: f.observed || '',
  resource: f.resource || null,
  request: f.evidence ? f.evidence.request : null,
  response: f.evidence ? { status: f.evidence.response.status, body: f.evidence.response.body } : null,
}));

// Injected flaws joined with per-approach detection on the benchmark.
const caseById = new Map(cases.map((c) => [c.id, c]));
const flaws = Object.entries(FLAWS).map(([id, description]) => {
  const c = gt.cases.find((x) => x.flawId === id);
  return {
    id, description,
    category: c?.category, method: c?.method, path: c?.path,
    detected: c ? (caseById.get(c.id)?.results || {}) : {},
  };
});

const trueNegativePatterns = gt.cases
  .filter((c) => !c.vulnerable && (c.notes || '').startsWith('True-negative pattern'))
  .map((c) => ({ method: c.method, path: c.path, category: c.category, notes: c.notes.replace('True-negative pattern. ', '') }));

let commit = 'unknown';
try { commit = execSync('git log -1 --format=%h -- evaluation/results test-api benchmarks cli-tool/config', { cwd: ROOT }).toString().trim(); } catch { /* not a git checkout */ }

const data = {
  generated: new Date().toISOString().slice(0, 10),
  commit,
  overview: {
    totals: metrics.groundTruth.totals,
    categories: gt.categories,
    flawFamilies,
    headline,
    requests: roleAware.meta.requests,
    durationMean: Math.round(mean),
  },
  accounts,
  walkthrough,
  results: {
    benchmark: { groundTruth: metrics.groundTruth, runs: runsFor(metrics, perCaseRows), cases },
    vampi,
    rq3: { timing, mean, sd, requests: timing[0].requests },
  },
  findings,
  flaws,
  trueNegativePatterns,
  meta: {
    roleAware: roleAware.meta,
    statusOnly: statusOnly.meta,
    sources: [
      'evaluation/results/2026-11-21-scanner-test-api/role-aware-findings.json',
      'evaluation/results/2026-11-21-scanner-test-api/status-only-findings.json',
      'evaluation/results/2026-11-21-scanner-test-api/comparison/metrics.json',
      'evaluation/results/2026-11-21-scanner-test-api/comparison/per-case.csv',
      'evaluation/results/2026-11-21-scanner-test-api/rq3-timing.csv',
      'evaluation/results/2026-11-21-scanner-vampi/comparison/metrics.json',
      'test-api/ground-truth.json',
      'test-api/openapi.yaml',
      'test-api/src/flaws.js',
      'cli-tool/config/example.config.yaml',
    ],
  },
};

const template = text('docs/webapp/template.html');
if (!template.includes('/*__DATA__*/null')) throw new Error('template.html is missing the /*__DATA__*/null placeholder');
const payload = JSON.stringify(data).replace(/</g, '\\u003c');
const html = template.replace('/*__DATA__*/null', payload);
writeFileSync(join(HERE, 'index.html'), html);
console.log(`Wrote docs/webapp/index.html (${(html.length / 1024).toFixed(0)} KB, ${findings.length} findings, ${walkthrough.length} walkthrough steps, data commit ${commit})`);
