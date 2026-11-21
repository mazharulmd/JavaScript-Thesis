import {
  extractOwnership,
  matchesPublicIndicator,
  isSoftDenial,
  isRoleFilteredEmptyView,
  deepEqual,
} from './ownership.js';

/**
 * Ownership-differential oracle (default).
 *
 * Classifies each executed test from:
 *  - HTTP status & soft-denial payloads ({ success: false })
 *  - Public resource indicators (config.ownership.publicIndicators)
 *  - Nested ownership identifiers (config.ownership.fields + policy.ownerField)
 *  - Comparison against the legitimate owner's / permitted role's baseline
 *  - Pre/post state verification via owner re-read on write and delete operations
 */
export function evaluateOwnershipDifferential(testCase, exec, cfg) {
  if (!exec?.attackerRes) {
    return { verdict: 'skipped', reason: exec?.skipReason ?? 'not executed' };
  }

  const res = exec.attackerRes;
  const s = res.status;
  if (s < 200 || s >= 300) {
    return { verdict: 'denied', observed: `HTTP ${s}` };
  }

  if (isSoftDenial(res)) {
    return { verdict: 'denied', observed: `HTTP ${s} soft denial (${JSON.stringify(res.body)})` };
  }

  if (testCase.category === 'BOLA') {
    return evaluateBola(testCase, exec, cfg);
  }

  if (testCase.category === 'BFLA') {
    if (isRoleFilteredEmptyView(res, exec.ownerBaselineRes)) {
      return { verdict: 'denied', observed: `HTTP ${s} role-filtered empty/self view` };
    }
    return {
      verdict: 'vulnerable',
      status: 'confirmed',
      confidence: 0.95,
      expected: testCase.expected,
      observed: `HTTP ${s} allowed disallowed role "${testCase.attacker?.role}"`,
    };
  }

  // Secondary auth / JWT categories
  return {
    verdict: 'vulnerable',
    status: 'confirmed',
    confidence: 0.95,
    expected: testCase.expected,
    observed: `HTTP ${s} accepted request (${testCase.category})`,
  };
}

function evaluateBola(testCase, exec, cfg) {
  const res = exec.attackerRes;
  const s = res.status;

  if (matchesPublicIndicator(res.body, cfg.ownership?.publicIndicators)) {
    return { verdict: 'denied', observed: `HTTP ${s} public resource (matches publicIndicators)` };
  }

  const method = testCase.operation.method;
  const victimId = testCase.victim?.identity != null ? String(testCase.victim.identity) : null;
  const attackerId = testCase.attacker?.identity != null ? String(testCase.attacker.identity) : null;
  const extraFields = testCase.policy?.ownerField ? [testCase.policy.ownerField] : [];

  if (method === 'GET' || method === 'HEAD') {
    const { ids } = extractOwnership(res.body, cfg.ownership?.fields, extraFields);
    if (ids.length > 0) {
      if (attackerId && ids.includes(attackerId) && (!victimId || !ids.includes(victimId))) {
        return {
          verdict: 'denied',
          observed: `HTTP ${s} returned caller's own identity (${attackerId}); path ID ignored`,
        };
      }
      if (victimId && ids.includes(victimId)) {
        return {
          verdict: 'vulnerable',
          status: 'confirmed',
          confidence: 0.95,
          expected: testCase.expected,
          observed: `HTTP ${s} returned victim's (${victimId}) object to ${testCase.attacker?.account}`,
        };
      }
    }

    // Response carries no owner identifier (e.g. sensor readings): compare with owner baseline.
    const base = exec.ownerBaselineRes;
    if (base && base.status >= 200 && base.status < 300) {
      if (deepEqual(res.body, base.body) || sharesNonEmptyContent(res.body, base.body)) {
        return {
          verdict: 'vulnerable',
          status: 'confirmed',
          confidence: 0.9,
          expected: testCase.expected,
          observed: `HTTP ${s} response matches victim owner's baseline response`,
        };
      }
    }

    return {
      verdict: 'potential',
      status: 'potential',
      confidence: 0.5,
      expected: testCase.expected,
      observed: `HTTP ${s} returned without matching owner identifier or baseline`,
    };
  }

  // Write / delete operations: verify actual state change via owner re-read.
  if (method === 'DELETE') {
    if (exec.ownerAfterRes) {
      if (exec.ownerAfterRes.status === 404 || exec.ownerAfterRes.status === 410) {
        return {
          verdict: 'vulnerable',
          status: 'confirmed',
          confidence: 0.98,
          expected: testCase.expected,
          observed: `HTTP ${s} deleted victim's resource (verified ${exec.ownerAfterRes.status} on owner re-read)`,
        };
      }
      if (exec.ownerAfterRes.status >= 200 && exec.ownerAfterRes.status < 300) {
        return {
          verdict: 'denied',
          observed: `HTTP ${s} returned, but owner re-read confirmed resource still exists`,
        };
      }
    }
    return {
      verdict: 'potential',
      status: 'potential',
      confidence: 0.6,
      expected: testCase.expected,
      observed: `HTTP ${s} on DELETE without owner re-read verification`,
    };
  }

  // POST / PUT / PATCH state verification
  if (exec.ownerAfterRes && exec.ownerAfterRes.status >= 200 && exec.ownerAfterRes.status < 300) {
    if (testCase.probeMarker) {
      const afterText = JSON.stringify(exec.ownerAfterRes.body ?? '');
      const beforeText = JSON.stringify(exec.ownerBeforeRes?.body ?? '');
      if (afterText.includes(testCase.probeMarker) && !beforeText.includes(testCase.probeMarker)) {
        return {
          verdict: 'vulnerable',
          status: 'confirmed',
          confidence: 0.95,
          expected: testCase.expected,
          observed: `HTTP ${s} mutation persisted (probe marker verified on owner re-read)`,
        };
      }
    }
    if (exec.ownerBeforeRes && !deepEqual(exec.ownerBeforeRes.body, exec.ownerAfterRes.body)) {
      return {
        verdict: 'vulnerable',
        status: 'confirmed',
        confidence: 0.9,
        expected: testCase.expected,
        observed: `HTTP ${s} changed victim's resource state (verified on owner re-read)`,
      };
    }
    if (exec.ownerBeforeRes && deepEqual(exec.ownerBeforeRes.body, exec.ownerAfterRes.body)) {
      return {
        verdict: 'denied',
        observed: `HTTP ${s} accepted, but owner re-read confirmed resource state was unchanged`,
      };
    }
  }

  const { ids } = extractOwnership(res.body, cfg.ownership?.fields, extraFields);
  if (victimId && ids.includes(victimId)) {
    return {
      verdict: 'vulnerable',
      status: 'confirmed',
      confidence: 0.85,
      expected: testCase.expected,
      observed: `HTTP ${s} returned victim's (${victimId}) ownership identifier after write`,
    };
  }

  return {
    verdict: 'potential',
    status: 'potential',
    confidence: 0.5,
    expected: testCase.expected,
    observed: `HTTP ${s} on ${method} without conclusive owner state verification`,
  };
}

function sharesNonEmptyContent(a, b) {
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  for (const [k, v] of Object.entries(a)) {
    if (Array.isArray(v) && v.length > 0 && Array.isArray(b[k]) && deepEqual(v, b[k])) return true;
  }
  return false;
}
