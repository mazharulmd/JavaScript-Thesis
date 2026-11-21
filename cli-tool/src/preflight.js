import { loadSpec, listOperations, specServer } from './parser/openapi.js';
import { loadConfig, validateConfig, assertTargetAllowed } from './config/load-config.js';
import { policyMatrix, resolvePolicy } from './config/policy.js';
import { createHttpClient } from './utils/http.js';
import { loginAll } from './authentication/session.js';

/**
 * Pre-scan check. Validates the inputs, enforces the host allowlist, logs in each account
 * and summarises what a scan would cover. The only requests sent are the login requests.
 */
export async function runPreflight({ spec: specPath, config: configPath, target: targetOverride, env = process.env }) {
  const result = { ok: false, exitCode: 2, problems: [] };
  let doc;
  let cfg;
  try {
    doc = loadSpec(specPath);
    cfg = loadConfig(configPath, env);
  } catch (err) {
    result.problems.push(err.message);
    return result;
  }
  const problems = validateConfig(cfg);
  const target = targetOverride ?? cfg.target ?? specServer(doc);
  if (!target) problems.push('no target: set target in the config, pass --target, or declare servers[0] in the spec');
  if (problems.length) {
    result.problems = problems;
    return result;
  }
  try {
    assertTargetAllowed(target, cfg.allowedHosts);
  } catch (err) {
    result.problems.push(err.message);
    return result;
  }

  const operations = listOperations(doc);
  const withPolicy = operations.map((op) => ({ op, policy: resolvePolicy(op, cfg) }));
  result.target = target;
  result.inventory = {
    operations: operations.length,
    requiresAuth: operations.filter((o) => o.requiresAuth).length,
    public: operations.filter((o) => o.isPublic).length,
    withPathParameters: operations.filter((o) => o.pathParams.length).length,
    policyFromSpec: withPolicy.filter((x) => x.policy.source === 'spec').length,
    policyFromConfig: withPolicy.filter((x) => x.policy.source === 'config').length,
    withoutPolicy: withPolicy.filter((x) => x.policy.source === 'none' && x.op.requiresAuth).length,
    ownerOnly: withPolicy.filter((x) => x.policy.ownership === 'owner').length,
    roleRestricted: withPolicy.filter((x) => (!x.op.isPublic || x.policy.overridesPublic) && Array.isArray(x.policy.roles) && [...new Set(cfg.accounts.map((a) => a.role))].some((r) => !x.policy.roles.includes(r))).length,
  };
  result.matrix = policyMatrix(operations, cfg);

  const http = createHttpClient({ baseUrl: target, timeoutMs: cfg.scan.requestTimeoutMs, delayMs: cfg.scan.delayMs, maxRequests: cfg.scan.maxRequests });
  let sessions;
  try {
    sessions = await loginAll(http, cfg);
  } catch (err) {
    result.problems.push(`target not reachable: ${err.cause?.code ?? err.message}`);
    result.exitCode = 3;
    return result;
  }
  result.accounts = sessions.map(({ token, ...s }) => ({ ...s, token: token ? '[obtained]' : undefined }));
  result.requests = http.count;
  const failed = sessions.filter((s) => !s.ok);
  if (failed.length) {
    result.problems.push(`login failed for: ${failed.map((s) => s.name).join(', ')}`);
    result.exitCode = 3;
    return result;
  }
  const identities = sessions.map((s) => s.identity);
  if (identities.some((i) => i === null)) result.warnings = ['some accounts have no identity; set auth.login.identityPath or account.identity'];
  else if (new Set(identities).size !== identities.length) result.warnings = ['two accounts share the same identity; cross-user tests need distinct users'];
  result.ok = true;
  result.exitCode = 0;
  return result;
}

export function printPreflight(r) {
  if (r.problems.length) {
    console.error(`Preflight FAILED:\n - ${r.problems.join('\n - ')}`);
    if (r.accounts) console.table(r.accounts.map(({ name, role, ok, status }) => ({ name, role, ok, status })));
    return;
  }
  console.log(`Target: ${r.target}`);
  console.log('Operation inventory:');
  console.table(r.inventory);
  console.log('Accounts:');
  console.table(r.accounts.map(({ name, role, identity, ok, via }) => ({ name, role, identity, ok, via })));
  console.log('Intended policy per operation (from spec x-access-control or config accessRules):');
  console.table(r.matrix);
  for (const w of r.warnings ?? []) console.warn(`warning: ${w}`);
  console.log(`Preflight OK (${r.requests} login requests sent).`);
}
