import { loadSpec, listOperations, specServer } from '../parser/openapi.js';
import { loadConfig, validateConfig, assertTargetAllowed } from '../config/load-config.js';
import { createHttpClient } from '../utils/http.js';
import { loginAll } from '../authentication/session.js';
import { evaluateStatusOnly } from '../analyzers/status-oracle.js';
import { evaluateOwnershipDifferential } from '../analyzers/ownership-oracle.js';
import { selectActors, discoverObjects } from './discovery.js';
import { generateTestPlan, executeTestPlan } from './test-generator.js';

// Inverse of the ground-truth SUBSUMES map (evaluation/build-ground-truth.js, decision D6):
// a narrower authentication category is not reported on an operation where a broader
// category is already confirmed, so one root cause is not counted several times.
// JWT_NONE_ALG is subsumed by JWT_SIGNATURE (a decode-only endpoint that ignores the
// signature also ignores the alg header), matching the manifest's exclusions.
const AUTH_BROADER_CATEGORIES = {
  AUTH_INVALID_TOKEN: ['AUTH_MISSING'],
  JWT_SIGNATURE: ['AUTH_MISSING', 'AUTH_INVALID_TOKEN'],
  JWT_NONE_ALG: ['AUTH_MISSING', 'AUTH_INVALID_TOKEN', 'JWT_SIGNATURE'],
  JWT_EXPIRED: ['AUTH_MISSING', 'AUTH_INVALID_TOKEN'],
};

function severityFor(category, method) {
  if (category === 'AUTH_MISSING' || category === 'JWT_SIGNATURE' || category === 'JWT_NONE_ALG') return 'critical';
  if (category === 'BOLA' && method === 'DELETE') return 'critical';
  if (category === 'BOLA' || category === 'BFLA' || category === 'AUTH_INVALID_TOKEN') return 'high';
  return 'medium';
}

/**
 * Evaluates an executed test plan using either the ownership-differential oracle
 * or the status-only baseline oracle, producing a Findings Document (v1.0).
 */
export function evaluatePlan(plan, executions, cfg, meta, { statusOnly = false } = {}) {
  const oracle = statusOnly ? evaluateStatusOnly : evaluateOwnershipDifferential;
  const findings = [];
  const tests = [];
  const confirmedAuthByOp = new Map(); // "METHOD /path" -> Set<category>
  let findingSeq = 0;

  for (const tc of plan) {
    const exec = executions.get(tc.id) ?? { skipReason: 'not executed' };
    const verdictObj = oracle(tc, exec, cfg);
    const opKey = `${tc.operation.method} ${tc.operation.path}`;

    // Root-cause rule (D6) for ownership-differential oracle:
    // if a broader auth flaw is already confirmed on this operation, narrower auth categories are non-applicable.
    if (!statusOnly && verdictObj.verdict === 'vulnerable' && verdictObj.status === 'confirmed') {
      const broader = AUTH_BROADER_CATEGORIES[tc.category];
      if (broader) {
        const seen = confirmedAuthByOp.get(opKey);
        if (seen && broader.some((b) => seen.has(b))) {
          tests.push({ method: tc.operation.method, path: tc.operation.path, category: tc.category, verdict: 'skipped' });
          continue;
        }
      }
      if (!confirmedAuthByOp.has(opKey)) confirmedAuthByOp.set(opKey, new Set());
      confirmedAuthByOp.get(opKey).add(tc.category);
    }

    tests.push({
      method: tc.operation.method,
      path: tc.operation.path,
      category: tc.category,
      verdict: verdictObj.verdict,
    });

    if (verdictObj.verdict === 'vulnerable' || verdictObj.verdict === 'potential') {
      findingSeq += 1;
      const finding = {
        id: `F-${String(findingSeq).padStart(4, '0')}`,
        category: tc.category,
        method: tc.operation.method,
        path: tc.operation.path,
        severity: severityFor(tc.category, tc.operation.method),
        status: verdictObj.status,
        confidence: verdictObj.confidence,
        attacker: tc.attacker ? { account: tc.attacker.account, role: tc.attacker.role } : undefined,
        victim: tc.victim ? { account: tc.victim.account, role: tc.victim.role } : undefined,
        expected: verdictObj.expected ?? tc.expected,
        observed: verdictObj.observed,
        timestamp: new Date().toISOString(),
        evidence: {
          notes: [verdictObj.observed],
          request: exec.attackerRes?.request,
          response: exec.attackerRes
            ? { status: exec.attackerRes.status, headers: exec.attackerRes.headers, body: exec.attackerRes.body }
            : undefined,
        },
      };
      if (exec.pathParams && Object.keys(exec.pathParams).length > 0) {
        finding.resource = exec.pathParams;
      }
      findings.push(finding);
    }
  }

  const endpointsTested = new Set(tests.filter((t) => t.verdict !== 'skipped').map((t) => `${t.method} ${t.path}`)).size;
  return {
    meta: {
      tool: 'bac-scanner',
      version: '1.0.0',
      formatVersion: '1.0',
      mode: statusOnly ? 'status-only' : 'ownership-differential',
      endpointsTested,
      ...meta,
    },
    findings,
    tests,
  };
}

/**
 * Full scan entrypoint: validates inputs, enforces allowedHosts, logs in accounts,
 * discovers objects, runs the shared test plan, and evaluates with the chosen oracle.
 */
export async function runScan({
  spec: specPath,
  config: configPath,
  target: targetOverride,
  statusOnly = false,
  env = process.env,
  http: customHttp,
}) {
  let doc;
  let cfg;
  try {
    doc = loadSpec(specPath);
    cfg = loadConfig(configPath, env);
  } catch (err) {
    return { ok: false, exitCode: 2, problems: [err.message] };
  }

  const problems = validateConfig(cfg);
  const target = targetOverride ?? cfg.target ?? specServer(doc);
  if (!target) problems.push('no target: set target in the config, pass --target, or declare servers[0] in the spec');
  if (problems.length) return { ok: false, exitCode: 2, problems };

  try {
    assertTargetAllowed(target, cfg.allowedHosts);
  } catch (err) {
    return { ok: false, exitCode: 2, problems: [err.message] };
  }

  const http = customHttp ?? createHttpClient({
    baseUrl: target,
    timeoutMs: cfg.scan.requestTimeoutMs,
    delayMs: cfg.scan.delayMs,
    maxRequests: cfg.scan.maxRequests,
  });

  const startedAt = new Date().toISOString();
  const t0 = performance.now();

  let sessions;
  try {
    sessions = await loginAll(http, cfg);
  } catch (err) {
    return { ok: false, exitCode: 3, problems: [`target not reachable: ${err.cause?.code ?? err.message}`] };
  }
  const failed = sessions.filter((s) => !s.ok);
  if (failed.length) {
    return { ok: false, exitCode: 3, problems: [`login failed for: ${failed.map((s) => s.name).join(', ')}`] };
  }

  const operations = listOperations(doc);
  const actors = selectActors(cfg, sessions);
  const discovery = await discoverObjects(http, cfg, operations, sessions, actors);
  const plan = generateTestPlan(operations, cfg, discovery, actors);
  const executions = await executeTestPlan(http, cfg, plan);

  const finishedAt = new Date().toISOString();
  const durationMs = Math.round(performance.now() - t0);

  const findingsDoc = evaluatePlan(
    plan,
    executions,
    cfg,
    {
      target,
      spec: specPath,
      scanId: startedAt.replace(/[:.]/g, '-'),
      startedAt,
      finishedAt,
      durationMs,
      requests: http.count,
    },
    { statusOnly },
  );

  return { ok: true, exitCode: 0, document: findingsDoc, plan, executions, cfg };
}
