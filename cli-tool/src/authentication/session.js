import { getPath, readJwtClaims } from '../utils/object-path.js';

/**
 * Logs in every configured account through the configured login operation and keeps the
 * issued credentials. Each session exposes the account's identity (from the login response
 * or the token's `sub` claim) for ownership comparisons. Passwords and tokens are never logged.
 */
function fillTemplate(value, account) {
  if (typeof value === 'string') return value.replace(/\{\{(\w+)\}\}/g, (_, k) => account[k] ?? '');
  if (Array.isArray(value)) return value.map((v) => fillTemplate(v, account));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, fillTemplate(v, account)]));
  return value;
}

export async function loginAccount(http, cfg, account) {
  if (account.token) {
    const claims = readJwtClaims(account.token);
    return { name: account.name, role: account.role, token: account.token, identity: account.identity ?? claims?.sub ?? null, ok: true, via: 'static-token' };
  }
  const login = cfg.auth.login;
  const body = fillTemplate(login.body ?? { username: '{{username}}', password: '{{password}}' }, account);
  const res = await http.request(login.method ?? 'POST', login.path, { body });
  const token = res.isJson ? getPath(res.body, login.tokenPath) : undefined;
  if (res.status >= 400 || typeof token !== 'string' || !token) {
    return { name: account.name, role: account.role, ok: false, status: res.status, error: 'login failed or token not found at tokenPath' };
  }
  const claims = readJwtClaims(token);
  const identity = account.identity ?? (login.identityPath ? getPath(res.body, login.identityPath) : undefined) ?? claims?.sub ?? null;
  return { name: account.name, role: account.role, token, identity: identity === null ? null : String(identity), expiresAt: claims?.exp ? claims.exp * 1000 : null, ok: true, via: 'login' };
}

export async function loginAll(http, cfg) {
  const sessions = [];
  for (const account of cfg.accounts) sessions.push(await loginAccount(http, cfg, account));
  return sessions;
}

/** Authorization header for a session, using the configured header name and scheme. */
export function authHeaders(cfg, session) {
  if (!session?.token) return {};
  return { [cfg.auth.header]: cfg.auth.scheme ? `${cfg.auth.scheme} ${session.token}` : session.token };
}
