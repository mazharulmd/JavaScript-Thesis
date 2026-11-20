#!/usr/bin/env node
/**
 * Builds test-api/ground-truth.json.
 *
 * The ground truth is defined by the benchmark DESIGN, independently of any scanner:
 *  1. VULNERABLE: the hand-labelled list below (one entry per injected flaw, see test-api/src/flaws.js).
 *  2. APPLICABILITY RULES decide which (operation, category) pairs are scored at all:
 *     - BOLA   : operations whose intended policy has ownership = owner
 *     - BFLA   : non-public operations whose intended roles exclude at least one role
 *                and that have no ownership rule (function-level restriction)
 *     - AUTH_* / JWT_* : every operation that requires authentication
 *  3. Every applicable pair that is not in the vulnerable list is a SECURE case (true negative).
 *  4. ROOT-CAUSE RULE: on an operation where a broader authentication flaw exists, the narrower
 *     categories are marked applicable=false (excluded from scoring), because they would only
 *     re-count the same root cause:
 *       AUTH_MISSING      excludes AUTH_INVALID_TOKEN, JWT_SIGNATURE, JWT_NONE_ALG, JWT_EXPIRED
 *       AUTH_INVALID_TOKEN excludes JWT_SIGNATURE, JWT_NONE_ALG, JWT_EXPIRED
 *       JWT_SIGNATURE     excludes JWT_NONE_ALG
 *
 * In the patched build (FLAWS=none) every case is secure; use --secure to emit that variant.
 *
 * Usage: node evaluation/build-ground-truth.js [--secure] [--out <file>]
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { parse } from 'yaml';

const ROOT = new URL('../', import.meta.url);
const ALL_ROLES = ['admin', 'user', 'guest'];
const AUTH_CATEGORIES = ['AUTH_MISSING', 'AUTH_INVALID_TOKEN', 'JWT_SIGNATURE', 'JWT_NONE_ALG', 'JWT_EXPIRED'];
const SUBSUMES = {
  AUTH_MISSING: ['AUTH_INVALID_TOKEN', 'JWT_SIGNATURE', 'JWT_NONE_ALG', 'JWT_EXPIRED'],
  AUTH_INVALID_TOKEN: ['JWT_SIGNATURE', 'JWT_NONE_ALG', 'JWT_EXPIRED'],
  JWT_SIGNATURE: ['JWT_NONE_ALG'],
};

/** Hand-labelled vulnerable cases (one per injected flaw). */
export const VULNERABLE = [
  { category: 'BOLA', method: 'GET', path: '/api/users/{userId}', flawId: 'BOLA_USERS_READ', kind: 'read', attackers: ['user→user', 'guest→user'] },
  { category: 'BOLA', method: 'PATCH', path: '/api/users/{userId}', flawId: 'BOLA_USERS_WRITE', kind: 'write', attackers: ['user→user', 'guest→user'] },
  { category: 'BOLA', method: 'GET', path: '/api/orders/{orderId}', flawId: 'BOLA_ORDERS_READ', kind: 'read', attackers: ['user→user', 'guest→user'] },
  { category: 'BOLA', method: 'DELETE', path: '/api/orders/{orderId}', flawId: 'BOLA_ORDERS_DELETE', kind: 'delete', attackers: ['user→user', 'guest→user'] },
  { category: 'BOLA', method: 'GET', path: '/api/invoices/{invoiceId}', flawId: 'BOLA_INVOICES_READ', kind: 'read', attackers: ['user→user', 'guest→user'], notes: 'Ownership is nested at data.invoice.billing.accountId.' },
  { category: 'BOLA', method: 'PATCH', path: '/api/documents/{documentId}', flawId: 'BOLA_DOCUMENTS_WRITE', kind: 'write', attackers: ['user→user', 'guest→user'] },
  { category: 'BOLA', method: 'GET', path: '/api/devices/{deviceId}/readings', flawId: 'BOLA_READINGS_READ', kind: 'read', attackers: ['user→user', 'guest→user'], notes: 'The response carries no owner identifier.' },
  { category: 'BOLA', method: 'POST', path: '/api/devices/{deviceId}/readings', flawId: 'BOLA_READINGS_WRITE', kind: 'write', attackers: ['user→user', 'guest→user'] },
  { category: 'BFLA', method: 'GET', path: '/api/admin/users', flawId: 'BFLA_ADMIN_USERS_LIST', kind: 'read', attackers: ['user', 'guest'] },
  { category: 'BFLA', method: 'DELETE', path: '/api/admin/users/{userId}', flawId: 'BFLA_ADMIN_USERS_DELETE', kind: 'delete', attackers: ['user', 'guest'] },
  { category: 'BFLA', method: 'POST', path: '/api/admin/announcements', flawId: 'BFLA_ANNOUNCEMENTS_CREATE', kind: 'write', attackers: ['user', 'guest'] },
  { category: 'BFLA', method: 'POST', path: '/api/admin/backups', flawId: 'BFLA_BACKUPS_CREATE', kind: 'write', attackers: ['user', 'guest'] },
  { category: 'BFLA', method: 'POST', path: '/api/products', flawId: 'BFLA_PRODUCTS_CREATE', kind: 'write', attackers: ['user', 'guest'] },
  { category: 'BFLA', method: 'POST', path: '/api/documents', flawId: 'BFLA_DOCUMENTS_CREATE_GUEST', kind: 'write', attackers: ['guest'] },
  { category: 'AUTH_MISSING', method: 'GET', path: '/api/system/diagnostics', flawId: 'AUTH_MISSING_DIAGNOSTICS', kind: 'read' },
  { category: 'AUTH_MISSING', method: 'POST', path: '/api/support/tickets', flawId: 'AUTH_MISSING_TICKETS', kind: 'write' },
  { category: 'AUTH_INVALID_TOKEN', method: 'GET', path: '/api/analytics/summary', flawId: 'AUTH_INVALID_ANALYTICS', kind: 'read' },
  { category: 'JWT_SIGNATURE', method: 'GET', path: '/api/messages', flawId: 'JWT_SIGNATURE_MESSAGES', kind: 'read' },
  { category: 'JWT_NONE_ALG', method: 'GET', path: '/api/notifications', flawId: 'JWT_NONE_NOTIFICATIONS', kind: 'read' },
  { category: 'JWT_EXPIRED', method: 'GET', path: '/api/sessions', flawId: 'JWT_EXPIRED_SESSIONS', kind: 'read' },
];

/** Notes for secure cases whose correct behaviour includes a 2xx response. */
const TN_PATTERNS = {
  'GET /api/documents/{documentId} BOLA': 'Public documents of other users are readable by design (200).',
  'GET /api/accounts/{accountId}/summary BOLA': "Path id is ignored; the caller's own summary is returned (200).",
  'DELETE /api/documents/{documentId} BOLA': 'Soft denial: 200 {success:false}, nothing deleted.',
  'PUT /api/devices/{deviceId}/config BOLA': 'Accepted with 202 for everybody, applied only for the owner.',
  'GET /api/admin/reports BFLA': 'Role-filtered view: non-admins get 200 {scope:"self", reports:[]}.',
  'GET /api/admin/audit-logs BFLA': 'Soft denial: 200 {success:false}.',
};

function expectedBehaviour(category, ac) {
  switch (category) {
    case 'BOLA': return 'Only the owner of the addressed object (or an administrator) may perform the operation.';
    case 'BFLA': return `Only roles [${ac.roles.join(', ')}] may invoke the function.`;
    case 'AUTH_MISSING': return 'Requests without credentials are rejected (401).';
    case 'AUTH_INVALID_TOKEN': return 'Malformed bearer tokens are rejected (401).';
    case 'JWT_SIGNATURE': return 'Tokens with an invalid signature are rejected (401).';
    case 'JWT_NONE_ALG': return 'Unsigned tokens (alg none) are rejected (401).';
    case 'JWT_EXPIRED': return 'Expired tokens are rejected (401).';
    default: return '';
  }
}

export function buildGroundTruth(spec, { secure = false } = {}) {
  const vulnByKey = new Map(VULNERABLE.map((v) => [`${v.method} ${v.path} ${v.category}`, v]));
  const cases = [];
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
      const op = item[method];
      if (!op) continue;
      const M = method.toUpperCase();
      const ac = op['x-access-control'];
      const isPublic = Array.isArray(op.security) && op.security.length === 0;
      const categories = [];
      if (ac.ownership === 'owner') categories.push('BOLA');
      if (!isPublic && ac.ownership === 'none' && ALL_ROLES.some((r) => !ac.roles.includes(r))) categories.push('BFLA');
      if (!isPublic) categories.push(...AUTH_CATEGORIES);

      // Root-cause exclusions on this operation
      const excluded = new Map();
      for (const [broad, narrower] of Object.entries(SUBSUMES)) {
        if (!secure && vulnByKey.has(`${M} ${path} ${broad}`)) for (const n of narrower) excluded.set(n, broad);
      }

      for (const category of categories) {
        const key = `${M} ${path} ${category}`;
        const v = secure ? undefined : vulnByKey.get(key);
        const c = {
          method: M,
          path,
          category,
          vulnerable: !!v,
          operationId: op.operationId,
          expected: expectedBehaviour(category, ac),
        };
        if (v) {
          c.flawId = v.flawId;
          c.kind = v.kind;
          if (v.attackers) c.attackers = v.attackers;
        }
        if (excluded.has(category)) {
          c.applicable = false;
          c.notes = `Excluded from scoring: subsumed by ${excluded.get(category)} on the same operation (root-cause rule).`;
        }
        if (TN_PATTERNS[key]) c.notes = `True-negative pattern. ${TN_PATTERNS[key]}`;
        if (v?.notes) c.notes = v.notes;
        cases.push(c);
      }
    }
  }
  const order = ['BOLA', 'BFLA', ...AUTH_CATEGORIES];
  cases.sort((a, b) => order.indexOf(a.category) - order.indexOf(b.category) || a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  const counters = {};
  for (const c of cases) {
    counters[c.category] = (counters[c.category] ?? 0) + 1;
    c.id = `GT-${c.category}-${String(counters[c.category]).padStart(3, '0')}`;
  }
  // put id first for readability
  const ordered = cases.map(({ id, ...rest }) => ({ id, ...rest }));

  // Sanity: every hand-labelled vulnerable case must exist among the applicable cases.
  if (!secure) {
    for (const key of vulnByKey.keys()) {
      if (!ordered.some((c) => `${c.method} ${c.path} ${c.category}` === key && c.vulnerable)) {
        throw new Error(`Vulnerable case not applicable under the rules: ${key}`);
      }
    }
  }

  const scored = ordered.filter((c) => c.applicable !== false);
  const summary = {};
  for (const c of scored) {
    summary[c.category] ??= { vulnerable: 0, secure: 0 };
    summary[c.category][c.vulnerable ? 'vulnerable' : 'secure'] += 1;
  }
  return {
    benchmark: 'BAC Benchmark API (test-api)',
    build: secure ? 'patched (FLAWS=none)' : 'vulnerable (FLAWS=all)',
    specVersion: spec.info.version,
    generatedBy: 'evaluation/build-ground-truth.js (hand-labelled vulnerable list + documented applicability rules)',
    unit: 'One case = (HTTP method, OpenAPI path template, category). A tool detects a case if at least one finding maps to it.',
    categories: order,
    summary,
    totals: { cases: ordered.length, scored: scored.length, excluded: ordered.length - scored.length, vulnerable: scored.filter((c) => c.vulnerable).length },
    cases: ordered,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const secure = process.argv.includes('--secure');
  const outIdx = process.argv.indexOf('--out');
  const out = outIdx > -1 ? process.argv[outIdx + 1] : new URL(secure ? 'test-api/ground-truth.secure.json' : 'test-api/ground-truth.json', ROOT);
  const spec = parse(readFileSync(new URL('test-api/openapi.yaml', ROOT), 'utf8'));
  const gt = buildGroundTruth(spec, { secure });
  writeFileSync(out, `${JSON.stringify(gt, null, 2)}\n`);
  console.log(`Wrote ${out}`);
  console.log(JSON.stringify({ totals: gt.totals, summary: gt.summary }, null, 2));
}
