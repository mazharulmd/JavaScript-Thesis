/**
 * Minimal body validation helper (keeps the benchmark dependency-free).
 * rules: { field: { type: 'string'|'number'|'integer'|'boolean', required?, enum?, maxLength?, min?, max? } }
 */
export function validateBody(body, rules, { partial = false } = {}) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return 'Request body must be a JSON object';
  const errors = [];
  for (const [field, rule] of Object.entries(rules)) {
    const value = body[field];
    if (value === undefined || value === null) {
      if (rule.required && !partial) errors.push(`${field} is required`);
      continue;
    }
    if (rule.type === 'integer' ? !Number.isInteger(value) : typeof value !== rule.type) {
      errors.push(`${field} must be of type ${rule.type}`);
      continue;
    }
    if (rule.enum && !rule.enum.includes(value)) errors.push(`${field} must be one of ${rule.enum.join(', ')}`);
    if (rule.maxLength && String(value).length > rule.maxLength) errors.push(`${field} is too long`);
    if (rule.min !== undefined && value < rule.min) errors.push(`${field} must be >= ${rule.min}`);
    if (rule.max !== undefined && value > rule.max) errors.push(`${field} must be <= ${rule.max}`);
  }
  if (partial && !Object.keys(rules).some((f) => body[f] !== undefined)) errors.push('No updatable field supplied');
  return errors.length ? errors.join('; ') : null;
}

/** Copies only whitelisted fields (prevents mass assignment of ownerId, role, id ...). */
export function pick(body, fields) {
  const out = {};
  for (const f of fields) if (body[f] !== undefined) out[f] = body[f];
  return out;
}
