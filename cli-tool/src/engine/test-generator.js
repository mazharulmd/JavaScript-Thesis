import { fillPath } from '../parser/openapi.js';
import { resolvePolicy } from '../config/policy.js';
import { authHeaders } from '../authentication/session.js';
import { sampleFromSchema } from '../utils/sample.js';
import { buildAuthProbes } from '../detectors/auth-tests.js';
import { resolveTargetsForOperation, createDisposableTarget } from './discovery.js';

function findVerifyOp(op, operations) {
  const exact = operations.find((o) => o.method === 'GET' && o.path === op.path);
  if (exact) return exact;
  const parentPath = op.path.replace(/\/[^/{}]+$/, '');
  if (parentPath && parentPath !== op.path) {
    return operations.find((o) => o.method === 'GET' && o.path === parentPath) ?? null;
  }
  return null;
}

function buildBody(op, uniqueSuffix) {
  if (!op.requestBody?.schema) return undefined;
  return sampleFromSchema(op.requestBody.schema, { uniqueSuffix });
}

/**
 * Generates a deterministic, oracle-independent test plan from the OpenAPI spec,
 * configuration, and discovered objects. Both oracles evaluate the exact same requests.
 */
export function generateTestPlan(operations, cfg, discovery, actors) {
  const plan = [];
  const configuredRoles = [...new Set(cfg.accounts.map((a) => a.role))];
  let seq = 0;

  for (const op of operations) {
    const policy = resolvePolicy(op, cfg);
    const effectivelyPublic = op.isPublic && !policy.overridesPublic;

    // 1. BOLA (cross-user / ownership) tests
    if (policy.ownership === 'owner' && op.pathParams.length > 0 && actors.victim) {
      const targets = resolveTargetsForOperation(op, operations, cfg, discovery, actors, { isBfla: false });
      const attackers = [actors.attacker, actors.guest].filter((a) => a && a.name !== actors.victim.name);
      const verifyOp = findVerifyOp(op, operations);

      for (const target of targets) {
        for (const attacker of attackers) {
          // If the operation's role policy already forbids this attacker's role, BFLA covers it;
          // however, testing BOLA for allowed non-owner users (and guest if allowed) is primary.
          if (Array.isArray(policy.roles) && !policy.roles.includes(attacker.role)) continue;
          seq += 1;
          const probeMarker = `bac-probe-${seq}`;
          plan.push({
            id: `T-${seq}`,
            category: 'BOLA',
            operation: op,
            policy,
            attacker: { account: attacker.name, role: attacker.role, identity: attacker.identity, session: attacker },
            victim: { account: actors.victim.name, role: actors.victim.role, identity: actors.victim.identity, session: actors.victim },
            target,
            body: buildBody(op, probeMarker),
            probeMarker,
            baselineOp: op.method === 'GET' ? op : null,
            verifyOp: ['POST', 'PUT', 'PATCH', 'DELETE'].includes(op.method) ? verifyOp : null,
            expected: 'Only the owner of the addressed object (or an administrator) may perform the operation.',
          });
        }
      }
    }

    // 2. BFLA (cross-role) tests
    if (!effectivelyPublic && Array.isArray(policy.roles)) {
      const disallowedRoles = configuredRoles.filter((r) => !policy.roles.includes(r));
      if (disallowedRoles.length > 0) {
        const permittedRole = policy.roles.find((r) => actors.byRole.has(r));
        const baselineSession = permittedRole ? actors.byRole.get(permittedRole)[0] : null;
        const targets = resolveTargetsForOperation(op, operations, cfg, discovery, actors, { isBfla: true });

        for (const target of targets) {
          for (const role of disallowedRoles) {
            const attacker = actors.byRole.get(role)?.[0];
            if (!attacker) continue;
            seq += 1;
            const probeMarker = `bac-probe-${seq}`;
            plan.push({
              id: `T-${seq}`,
              category: 'BFLA',
              operation: op,
              policy,
              attacker: { account: attacker.name, role: attacker.role, identity: attacker.identity, session: attacker },
              victim: null,
              baselineSession,
              target,
              body: buildBody(op, probeMarker),
              probeMarker,
              baselineOp: op.method === 'GET' && baselineSession ? op : null,
              verifyOp: null,
              expected: `Only roles [${policy.roles.join(', ')}] may invoke ${op.id}.`,
            });
          }
        }
      }
    }

    // 3. Secondary Authentication / JWT tests
    if (op.requiresAuth && actors.attacker) {
      const targets = op.pathParams.length > 0
        ? resolveTargetsForOperation(op, operations, cfg, discovery, actors, { isBfla: false })
        : [{ pathParams: {}, creatorOp: null }];
      const target = targets[0] ?? {
        pathParams: Object.fromEntries(op.pathParams.map((p) => [p, actors.attacker.identity ?? '1'])),
        creatorOp: null,
      };
      // Never send unauthenticated DELETE against seeded data if no creator exists
      if (op.method === 'DELETE' && !target.creatorOp) continue;

      const probes = buildAuthProbes(cfg, actors.attacker);
      for (const probe of probes) {
        seq += 1;
        plan.push({
          id: `T-${seq}`,
          category: probe.category,
          operation: op,
          policy,
          attacker: { account: 'unauthenticated', role: 'anonymous', identity: null, session: null },
          victim: null,
          target,
          authHeadersOverride: probe.headers,
          skipReason: probe.skipReason,
          body: buildBody(op, `bac-auth-${seq}`),
          baselineOp: null,
          verifyOp: null,
          expected: probe.expected,
        });
      }
    }
  }

  return plan;
}

/**
 * Executes a generated test plan against the target using the provided HTTP client.
 * Captures attacker responses, owner baselines, and pre/post state reads.
 */
export async function executeTestPlan(http, cfg, plan) {
  const executions = new Map();
  const baselineCache = new Map();

  for (const tc of plan) {
    if (tc.skipReason) {
      executions.set(tc.id, { skipReason: tc.skipReason });
      continue;
    }

    try {
      let pathParams = tc.target.pathParams;
      if (tc.target.creatorOp) {
        const paramName = tc.operation.pathParams[0];
        pathParams = await createDisposableTarget(
          http,
          cfg,
          tc.target.creatorOp,
          tc.target.ownerSession,
          paramName,
          tc.id.toLowerCase(),
        );
        if (!pathParams) {
          executions.set(tc.id, { skipReason: 'could not create disposable target for DELETE' });
          continue;
        }
      }

      const concretePath = tc.operation.pathParams.length > 0
        ? fillPath(tc.operation.path, pathParams)
        : tc.operation.path;

      // Baseline read (for BOLA GET without owner IDs, or BFLA GET role-filtered views)
      let ownerBaselineRes = null;
      const baseSession = tc.category === 'BOLA' ? tc.victim?.session : tc.baselineSession;
      if (tc.baselineOp && baseSession) {
        const cacheKey = `${baseSession.name}:${tc.baselineOp.method}:${concretePath}`;
        if (baselineCache.has(cacheKey)) {
          ownerBaselineRes = baselineCache.get(cacheKey);
        } else {
          ownerBaselineRes = await http.request(tc.baselineOp.method, concretePath, {
            headers: authHeaders(cfg, baseSession),
          });
          baselineCache.set(cacheKey, ownerBaselineRes);
        }
      }

      // Pre-write state read (for BOLA PUT/PATCH/POST state verification)
      let ownerBeforeRes = null;
      if (tc.verifyOp && tc.victim?.session && tc.operation.method !== 'DELETE') {
        const verifyPath = fillPath(tc.verifyOp.path, pathParams);
        ownerBeforeRes = await http.request(tc.verifyOp.method, verifyPath, {
          headers: authHeaders(cfg, tc.victim.session),
        });
      }

      // Attacker request
      const headers = tc.authHeadersOverride !== undefined
        ? tc.authHeadersOverride
        : authHeaders(cfg, tc.attacker.session);

      const attackerRes = await http.request(tc.operation.method, concretePath, {
        headers,
        body: tc.body,
      });

      // Post-write/delete state read (only needed if attacker got 2xx)
      let ownerAfterRes = null;
      if (tc.verifyOp && tc.victim?.session && attackerRes.status >= 200 && attackerRes.status < 300) {
        const verifyPath = fillPath(tc.verifyOp.path, pathParams);
        ownerAfterRes = await http.request(tc.verifyOp.method, verifyPath, {
          headers: authHeaders(cfg, tc.victim.session),
        });
      }

      executions.set(tc.id, {
        pathParams,
        concretePath,
        attackerRes,
        ownerBaselineRes,
        ownerBeforeRes,
        ownerAfterRes,
      });
    } catch (err) {
      if (String(err.message).includes('Request budget exhausted')) {
        executions.set(tc.id, { skipReason: err.message });
        break;
      }
      executions.set(tc.id, { skipReason: err.cause?.code ?? err.message });
    }
  }

  return executions;
}
