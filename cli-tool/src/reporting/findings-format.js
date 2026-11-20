/**
 * The findings format: the contract between detectors (the role-aware scanner, the
 * status-code-only baseline, or external tools via adapters) and the reporting and
 * evaluation pipeline. See docs/FINDINGS-FORMAT.md.
 */
export const FORMAT_VERSION = '1.0';
export const CATEGORIES = ['BOLA', 'BFLA', 'AUTH_MISSING', 'AUTH_INVALID_TOKEN', 'JWT_SIGNATURE', 'JWT_NONE_ALG', 'JWT_EXPIRED'];
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const STATUSES = ['confirmed', 'potential', 'inconclusive'];
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

/**
 * Validates a findings document. Returns a list of human-readable problems (empty = valid).
 */
export function validateFindingsDocument(doc) {
  const problems = [];
  if (!doc || typeof doc !== 'object') return ['document must be a JSON object'];
  if (!doc.meta || typeof doc.meta !== 'object') problems.push('meta is required');
  else {
    if (typeof doc.meta.tool !== 'string') problems.push('meta.tool must be a string');
    if (doc.meta.formatVersion !== undefined && doc.meta.formatVersion !== FORMAT_VERSION) problems.push(`meta.formatVersion must be ${FORMAT_VERSION}`);
  }
  if (!Array.isArray(doc.findings)) {
    problems.push('findings must be an array');
    return problems;
  }
  const ids = new Set();
  doc.findings.forEach((f, i) => {
    const at = `findings[${i}]`;
    if (typeof f.id !== 'string' || !f.id) problems.push(`${at}.id is required`);
    else if (ids.has(f.id)) problems.push(`${at}.id "${f.id}" is duplicated`);
    else ids.add(f.id);
    if (!CATEGORIES.includes(f.category)) problems.push(`${at}.category must be one of ${CATEGORIES.join(', ')}`);
    if (!METHODS.includes(f.method)) problems.push(`${at}.method is invalid`);
    if (typeof f.path !== 'string' || !f.path.startsWith('/')) problems.push(`${at}.path must be an OpenAPI path template`);
    if (!SEVERITIES.includes(f.severity)) problems.push(`${at}.severity must be one of ${SEVERITIES.join(', ')}`);
    if (!STATUSES.includes(f.status)) problems.push(`${at}.status must be one of ${STATUSES.join(', ')}`);
    if (f.confidence !== undefined && !(typeof f.confidence === 'number' && f.confidence >= 0 && f.confidence <= 1)) problems.push(`${at}.confidence must be a number in [0, 1]`);
  });
  return problems;
}

/** Summary statistics used by both report formats. */
export function summarize(doc) {
  const findings = doc.findings ?? [];
  const by = (key, values) => Object.fromEntries(values.map((v) => [v, findings.filter((f) => f[key] === v).length]));
  const tests = Array.isArray(doc.tests) ? doc.tests : [];
  const endpoints = new Set([...findings, ...tests].map((x) => `${x.method} ${x.path}`));
  return {
    totalFindings: findings.length,
    byStatus: by('status', STATUSES),
    bySeverity: by('severity', SEVERITIES),
    byCategory: by('category', CATEGORIES),
    confirmedBySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.status === 'confirmed' && f.severity === s).length])),
    endpointsTested: doc.meta?.endpointsTested ?? endpoints.size,
    totalRequests: doc.meta?.requests ?? null,
    testsExecuted: tests.length || null,
    durationMs: doc.meta?.durationMs ?? null,
  };
}

/** True when there is at least one confirmed finding at or above `threshold` severity. */
export function exceedsThreshold(doc, threshold = 'high') {
  if (threshold === 'none') return false;
  const limit = SEVERITIES.indexOf(threshold);
  if (limit < 0) throw new Error(`Unknown severity threshold: ${threshold}`);
  return (doc.findings ?? []).some((f) => f.status === 'confirmed' && SEVERITIES.indexOf(f.severity) <= limit);
}
