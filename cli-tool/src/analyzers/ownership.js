import { getPath } from '../utils/object-path.js';

/**
 * Extracts ownership identifiers from an arbitrary JSON response body.
 * Supports both dotted paths (via getPath) and recursive nested-key scanning.
 */
export function extractOwnership(value, ownershipFields = [], extraFields = []) {
  const allFields = [...new Set([...(ownershipFields ?? []), ...(extraFields ?? [])].filter(Boolean))];
  const dotted = allFields.filter((f) => f.includes('.'));
  const simple = new Set(allFields.filter((f) => !f.includes('.')));
  const matches = [];
  const seenPaths = new Set();

  for (const path of dotted) {
    const val = getPath(value, path);
    if (isPrimitiveId(val)) {
      seenPaths.add(path);
      matches.push({ path, field: path, value: String(val) });
    }
  }

  function walk(node, path, depth) {
    if (depth > 32 || node === null || node === undefined || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) walk(node[i], `${path}.${i}`, depth + 1);
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      const nextPath = path ? `${path}.${k}` : k;
      if (simple.has(k) && isPrimitiveId(v) && !seenPaths.has(nextPath)) {
        seenPaths.add(nextPath);
        matches.push({ path: nextPath, field: k, value: String(v) });
      }
      if (v && typeof v === 'object') walk(v, nextPath, depth + 1);
    }
  }

  walk(value, '', 0);
  const ids = [...new Set(matches.map((m) => m.value))];
  return { matches, ids };
}

function isPrimitiveId(val) {
  return (typeof val === 'string' && val.length > 0) || (typeof val === 'number' && Number.isFinite(val));
}

/**
 * Returns true when the response body matches any configured public indicator
 * (e.g. { field: 'visibility', equals: 'public' }), either at root or nested.
 */
export function matchesPublicIndicator(value, publicIndicators = []) {
  if (!Array.isArray(publicIndicators) || publicIndicators.length === 0 || !value || typeof value !== 'object') {
    return false;
  }
  for (const ind of publicIndicators) {
    if (!ind?.field) continue;
    if (ind.field.includes('.')) {
      if (getPath(value, ind.field) === ind.equals) return true;
      continue;
    }
    if (findKeyEquals(value, ind.field, ind.equals, 0)) return true;
  }
  return false;
}

function findKeyEquals(node, key, expected, depth) {
  if (depth > 16 || !node || typeof node !== 'object') return false;
  if (Array.isArray(node)) return node.some((item) => findKeyEquals(item, key, expected, depth + 1));
  if (key in node && node[key] === expected) return true;
  return Object.values(node).some((v) => v && typeof v === 'object' && findKeyEquals(v, key, expected, depth + 1));
}

/** Detects 2xx "soft denial" payloads such as { success: false, error: "..." }. */
export function isSoftDenial(res) {
  if (!res?.isJson || !res.body || typeof res.body !== 'object' || Array.isArray(res.body)) return false;
  return res.body.success === false || res.body.ok === false || res.body.allowed === false;
}

/**
 * Detects role-filtered views where a non-privileged caller receives a self-scoped
 * or empty collection while a privileged baseline receives a global/non-empty one.
 */
export function isRoleFilteredEmptyView(attackerRes, baselineRes) {
  if (!attackerRes?.isJson || !baselineRes?.isJson) return false;
  const a = attackerRes.body;
  const b = baselineRes.body;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) || Array.isArray(b)) return false;
  if (a.scope === 'self' && b.scope && b.scope !== 'self') return true;
  const aArrays = Object.entries(a).filter(([, v]) => Array.isArray(v));
  const bArrays = Object.entries(b).filter(([, v]) => Array.isArray(v));
  if (aArrays.length > 0 && bArrays.length > 0) {
    const allAttackerEmpty = aArrays.every(([, v]) => v.length === 0);
    const anyBaselineNonEmpty = bArrays.some(([, v]) => v.length > 0);
    if (allAttackerEmpty && anyBaselineNonEmpty) return true;
  }
  return false;
}

/** Structural JSON equality for comparing pre/post state and baseline responses. */
export function deepEqual(a, b) {
  if (Object.is(a, b)) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  const keysA = Object.keys(a);
  const keysB = Object.keys(b);
  if (keysA.length !== keysB.length) return false;
  return keysA.every((k) => Object.hasOwn(b, k) && deepEqual(a[k], b[k]));
}
