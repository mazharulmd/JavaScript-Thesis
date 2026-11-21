/**
 * Determines the intended access-control policy of an operation.
 * Precedence: configuration accessRules > spec x-access-control > none.
 * Rule paths support "*" (one segment) and "**" (any remainder), e.g. "/api/admin/**".
 */
function globToRegExp(glob) {
  const escaped = glob.replace(/[.+?^$()|[\]\\]/g, '\\$&').replace(/\{[^}]+\}/g, '[^/]+');
  return new RegExp(`^${escaped.replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]+').replace(/\u0000/g, '.*')}$`);
}

export function matchRule(rule, op) {
  const methods = (rule.methods ?? ['*']).map((m) => m.toUpperCase());
  return (methods.includes('*') || methods.includes(op.method)) && (rule.path === op.path || globToRegExp(rule.path).test(op.path));
}

export function resolvePolicy(op, cfg) {
  const rule = (cfg.accessRules ?? []).find((r) => matchRule(r, op));
  // A configuration rule overrides the spec, including an operation the spec declares public.
  if (rule) return { roles: rule.roles ?? null, ownership: rule.ownership ?? 'none', ownerField: rule.ownerField, source: 'config', overridesPublic: op.isPublic && !!(rule.roles || rule.ownership === 'owner') };
  if (op.accessControl) {
    const ac = op.accessControl;
    return { roles: ac.roles ?? null, ownership: ac.ownership ?? 'none', ownerField: ac.ownerField, publicWhen: ac.publicWhen, source: 'spec' };
  }
  return { roles: null, ownership: 'none', source: 'none' };
}

/** Policy matrix: for every operation, which configured roles the policy allows. */
export function policyMatrix(operations, cfg) {
  const roles = [...new Set(cfg.accounts.map((a) => a.role))];
  return operations.map((op) => {
    const p = resolvePolicy(op, cfg);
    const effectivelyPublic = op.isPublic && !p.overridesPublic;
    const allowed = Object.fromEntries(roles.map((r) => [r, effectivelyPublic || !p.roles ? 'yes' : p.roles.includes(r) ? 'yes' : 'no']));
    return { operation: op.id, public: effectivelyPublic, ownership: p.ownership, source: p.source, ...allowed };
  });
}
