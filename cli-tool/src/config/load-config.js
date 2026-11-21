import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

/**
 * Scanner configuration: target, accounts and roles, login procedure, ownership hints,
 * access rules (for specs without x-access-control) and request limits.
 * See config/example.config.yaml for a documented example.
 */
export const DEFAULTS = Object.freeze({
  allowedHosts: ['localhost', '127.0.0.1', '::1'],
  auth: { header: 'Authorization', scheme: 'Bearer' },
  ownership: { fields: ['ownerId', 'userId', 'accountId', 'createdBy', 'owner'], publicIndicators: [] },
  accessRules: [],
  scan: { requestTimeoutMs: 5000, delayMs: 0, maxRequests: 5000 },
});

export function loadConfig(path, env = process.env) {
  const text = readFileSync(path, 'utf8');
  const raw = path.endsWith('.json') ? JSON.parse(text) : parseYaml(text);
  return normalizeConfig(raw, env);
}

/** Applies defaults and resolves secrets from environment variables (never logged). */
export function normalizeConfig(raw, env = process.env) {
  const cfg = {
    ...raw,
    allowedHosts: raw?.allowedHosts ?? [...DEFAULTS.allowedHosts],
    auth: { ...DEFAULTS.auth, ...(raw?.auth ?? {}) },
    ownership: { ...DEFAULTS.ownership, ...(raw?.ownership ?? {}) },
    accessRules: raw?.accessRules ?? [],
    scan: { ...DEFAULTS.scan, ...(raw?.scan ?? {}) },
    roles: raw?.roles ?? {},
  };
  cfg.accounts = (raw?.accounts ?? []).map((a) => {
    const account = { ...a };
    if (a.passwordEnv) account.password = env[a.passwordEnv];
    if (a.tokenEnv) account.token = env[a.tokenEnv];
    return account;
  });
  return cfg;
}

/** Returns a list of configuration problems (empty list = valid). Secrets are never echoed. */
export function validateConfig(cfg) {
  const problems = [];
  if (!cfg || typeof cfg !== 'object') return ['configuration must be an object'];
  if (cfg.target !== undefined) {
    try { new URL(cfg.target); } catch { problems.push('target must be an absolute URL'); }
  }
  if (!Array.isArray(cfg.allowedHosts) || cfg.allowedHosts.length === 0) problems.push('allowedHosts must be a non-empty list');
  if (!Array.isArray(cfg.accounts) || cfg.accounts.length < 2) problems.push('at least two accounts are required for cross-user and cross-role testing');
  const names = new Set();
  for (const [i, a] of (cfg.accounts ?? []).entries()) {
    const at = `accounts[${i}]`;
    if (!a.name) problems.push(`${at}.name is required`);
    else if (names.has(a.name)) problems.push(`${at}.name "${a.name}" is duplicated`);
    names.add(a.name);
    if (!a.role) problems.push(`${at}.role is required`);
    else if (Object.keys(cfg.roles).length && !(a.role in cfg.roles)) problems.push(`${at}.role "${a.role}" is not defined under roles`);
    const hasLogin = !!cfg.auth?.login;
    if (!a.token && !hasLogin) problems.push(`${at}: either auth.login or a static token (token/tokenEnv) is required`);
    if (hasLogin && !a.token && (a.password === undefined || a.password === '')) {
      problems.push(`${at}: password is missing${a.passwordEnv ? ` (environment variable ${a.passwordEnv} is not set)` : ''}`);
    }
  }
  const roleNames = new Set((cfg.accounts ?? []).map((a) => a.role));
  if (roleNames.size < 2) problems.push('accounts should cover at least two different roles for cross-role testing');
  for (const [name, r] of Object.entries(cfg.roles ?? {})) {
    if (typeof r?.level !== 'number') problems.push(`roles.${name}.level must be a number`);
  }
  if (cfg.auth?.login) {
    const l = cfg.auth.login;
    if (!l.path?.startsWith('/')) problems.push('auth.login.path must start with "/"');
    if (!l.tokenPath) problems.push('auth.login.tokenPath is required');
  }
  for (const [i, rule] of (cfg.accessRules ?? []).entries()) {
    if (!rule.path) problems.push(`accessRules[${i}].path is required`);
    if (rule.roles && !Array.isArray(rule.roles)) problems.push(`accessRules[${i}].roles must be a list`);
    if (rule.ownership && !['owner', 'none'].includes(rule.ownership)) problems.push(`accessRules[${i}].ownership must be "owner" or "none"`);
  }
  for (const k of ['requestTimeoutMs', 'delayMs', 'maxRequests']) {
    if (!(Number.isFinite(cfg.scan?.[k]) && cfg.scan[k] >= 0)) problems.push(`scan.${k} must be a non-negative number`);
  }
  return problems;
}

/** Refuses targets whose host is not explicitly allowed (default: loopback only). */
export function assertTargetAllowed(target, allowedHosts) {
  const host = new URL(target).hostname.replace(/^\[|\]$/g, '');
  if (!allowedHosts.includes(host)) {
    throw new Error(`Target host "${host}" is not in allowedHosts (${allowedHosts.join(', ')}). Only scan systems you are authorized to test.`);
  }
  return true;
}
