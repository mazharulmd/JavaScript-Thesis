import { authHeaders } from '../authentication/session.js';
import { sampleFromSchema } from '../utils/sample.js';
import { extractOwnership, matchesPublicIndicator } from '../analyzers/ownership.js';

/**
 * Selects the primary roles/sessions used for cross-user and cross-role testing.
 */
export function selectActors(cfg, sessions) {
  const valid = sessions.filter((s) => s.ok);
  const roleLevel = (role) => cfg.roles?.[role]?.level ?? 0;
  const bypasses = (role) => !!cfg.roles?.[role]?.bypassOwnership;

  const nonBypass = valid.filter((s) => !bypasses(s.role));
  const byRole = new Map();
  for (const s of valid) {
    if (!byRole.has(s.role)) byRole.set(s.role, []);
    byRole.get(s.role).push(s);
  }

  // Prefer a role with >= 2 accounts for cross-user BOLA testing (e.g. alice & bob).
  let userSessions = [];
  for (const list of byRole.values()) {
    if (list.length >= 2 && !bypasses(list[0].role)) {
      userSessions = list;
      break;
    }
  }
  if (!userSessions.length) userSessions = nonBypass;

  const attacker = userSessions[0] ?? valid[0] ?? null;
  const victim = userSessions[1] ?? userSessions[0] ?? null;
  const admin = valid.find((s) => bypasses(s.role)) ?? [...valid].sort((a, b) => roleLevel(b.role) - roleLevel(a.role))[0] ?? null;
  const guest = valid.find((s) => s !== attacker && s !== victim && !bypasses(s.role) && roleLevel(s.role) < roleLevel(attacker?.role)) ?? null;

  return { valid, byRole, attacker, victim, admin, guest };
}

function extractItems(body) {
  if (Array.isArray(body)) return body;
  if (!body || typeof body !== 'object') return [];
  for (const v of Object.values(body)) {
    if (Array.isArray(v)) return v;
  }
  return [];
}

function extractItemId(item, paramName) {
  if (!item || typeof item !== 'object') return null;
  if (item[paramName] !== undefined && item[paramName] !== null) return item[paramName];
  for (const k of ['id', '_id', 'uuid']) {
    if (item[k] !== undefined && item[k] !== null) return item[k];
  }
  return null;
}

/**
 * Discovers existing objects owned by `victim` from collection GET endpoints,
 * plus identity-derived IDs for user/account path parameters.
 */
export async function discoverObjects(http, cfg, operations, sessions, actors) {
  const byPrefix = new Map(); // collectionPath -> Array<{ item, idByParam, isPublic }>
  const collectionGets = operations.filter((op) => op.method === 'GET' && op.pathParams.length === 0);

  if (actors.victim) {
    for (const op of collectionGets) {
      let res;
      try {
        res = await http.request('GET', op.path, { headers: authHeaders(cfg, actors.victim) });
      } catch {
        continue;
      }
      if (res.status < 200 || res.status >= 300 || !res.isJson) continue;
      const items = extractItems(res.body);
      if (!items.length) continue;

      const records = [];
      for (const item of items) {
        if (!item || typeof item !== 'object') continue;
        const { ids } = extractOwnership(item, cfg.ownership?.fields);
        const victimId = actors.victim.identity != null ? String(actors.victim.identity) : null;
        if (ids.length > 0 && victimId && !ids.includes(victimId)) continue;
        records.push({
          item,
          isPublic: matchesPublicIndicator(item, cfg.ownership?.publicIndicators),
        });
      }
      if (records.length) byPrefix.set(op.path, records);
    }
  }

  return { byPrefix };
}

/**
 * Resolves target path parameter sets for an operation.
 * Returns an array of { pathParams, creatorOp } objects.
 * For DELETE operations, returns a creatorOp so the executor creates a fresh object first.
 */
export function resolveTargetsForOperation(op, operations, cfg, discovery, actors, { isBfla = false } = {}) {
  if (op.pathParams.length === 0) return [{ pathParams: {}, creatorOp: null }];

  // Never delete seeded objects: locate a POST creator on the collection prefix.
  if (op.method === 'DELETE') {
    const collectionPath = op.path.replace(/\/\{[^}]+\}$/, '');
    const creatorOp = operations.find((o) => o.method === 'POST' && o.path === collectionPath);
    if (!creatorOp) return [];
    const ownerSession = isBfla ? actors.admin : actors.victim;
    if (!ownerSession) return [];
    return [{ pathParams: null, creatorOp, ownerSession }];
  }

  const param = op.pathParams[0];
  // Check matching collection GET prefixes (longest prefix first).
  const prefixes = [...discovery.byPrefix.keys()]
    .filter((p) => op.path === p || op.path.startsWith(`${p}/`))
    .sort((a, b) => b.length - a.length);

  for (const prefix of prefixes) {
    const records = discovery.byPrefix.get(prefix);
    const chosen = [];
    const privateRec = records.find((r) => !r.isPublic);
    const publicRec = records.find((r) => r.isPublic);
    if (privateRec) chosen.push(privateRec);
    if (publicRec && op.method === 'GET') chosen.push(publicRec);
    if (!chosen.length && records[0]) chosen.push(records[0]);

    const targets = [];
    for (const rec of chosen) {
      const id = extractItemId(rec.item, param);
      if (id !== null) targets.push({ pathParams: { [param]: id }, creatorOp: null });
    }
    if (targets.length) return targets;
  }

  // Identity-based path parameters (e.g. /api/users/{userId}, /api/accounts/{accountId}/summary)
  const targetSession = isBfla ? (actors.guest ?? actors.victim) : actors.victim;
  if (targetSession?.identity != null && /^(user|account|profile|member)id$/i.test(param)) {
    return [{ pathParams: { [param]: targetSession.identity }, creatorOp: null }];
  }
  if (targetSession?.identity != null && param === 'username') {
    return [{ pathParams: { [param]: targetSession.identity }, creatorOp: null }];
  }

  // Fallback: OpenAPI parameter example
  const paramMeta = op.parameters.find((p) => p.name === param);
  if (paramMeta?.example !== undefined) {
    return [{ pathParams: { [param]: paramMeta.example }, creatorOp: null }];
  }

  return [];
}

/**
 * Creates a disposable object via `creatorOp` as `ownerSession` and extracts its ID.
 */
export async function createDisposableTarget(http, cfg, creatorOp, ownerSession, paramName, uniqueSuffix) {
  const body = creatorOp.requestBody?.schema
    ? sampleFromSchema(creatorOp.requestBody.schema, { uniqueSuffix })
    : undefined;
  const res = await http.request(creatorOp.method, creatorOp.path, {
    headers: authHeaders(cfg, ownerSession),
    body,
  });
  if (res.status < 200 || res.status >= 300 || !res.isJson) return null;
  const id = extractItemId(res.body, paramName) ?? extractItemId(res.body?.data, paramName);
  if (id === null) return null;
  return { [paramName]: id };
}
