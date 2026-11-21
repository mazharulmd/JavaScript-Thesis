/**
 * Removes credentials from report evidence. Reports are meant to be shared (CI artifacts,
 * thesis appendices), so tokens, passwords and secrets must never appear in them.
 */
const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'x-api-key', 'proxy-authorization']);
const SENSITIVE_KEYS = /^(password|passwd|secret|token|access_?token|refresh_?token|auth_?token|api_?key|client_?secret|jwt)$/i;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;

export function redactString(s) {
  return typeof s === 'string' ? s.replace(JWT_PATTERN, '[REDACTED-JWT]') : s;
}

export function redactHeaders(headers = {}) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (SENSITIVE_HEADERS.has(k.toLowerCase())) {
      const scheme = typeof v === 'string' && /^\w+\s/.test(v) ? `${v.split(/\s/)[0]} ` : '';
      out[k] = `${scheme}[REDACTED]`;
    } else out[k] = redactString(v);
  }
  return out;
}

/** Deep-redacts a JSON value: sensitive keys are masked, embedded JWTs are replaced. */
export function redactValue(value, depth = 0) {
  if (depth > 50) return '[TRUNCATED]';
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = SENSITIVE_KEYS.test(k) && v != null ? '[REDACTED]' : redactValue(v, depth + 1);
    return out;
  }
  return value;
}

/** Redacts a complete findings document (evidence requests/responses included). */
export function redactDocument(doc) {
  const copy = redactValue(structuredClone(doc));
  for (const f of copy.findings ?? []) {
    for (const ex of [f.evidence?.request, f.evidence?.response, ...(f.evidence?.exchanges ?? []).flatMap((e) => [e.request, e.response])]) {
      if (ex?.headers) ex.headers = redactHeaders(ex.headers);
    }
  }
  return copy;
}

/** Truncates large bodies so reports stay readable. */
export function truncate(text, max = 4000) {
  if (typeof text !== 'string' || text.length <= max) return text;
  return `${text.slice(0, max)}\n… [truncated ${text.length - max} characters]`;
}
