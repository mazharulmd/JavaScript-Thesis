import { createHmac } from 'node:crypto';
import { readJwtClaims } from '../utils/object-path.js';

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function signHs256(header, payload, secret) {
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const sig = createHmac('sha256', secret).update(signingInput).digest('base64url');
  return `${signingInput}.${sig}`;
}

function tamperSignature(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return 'invalid.jwt.signature';
  const sig = parts[2];
  const flipped = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  return `${parts[0]}.${parts[1]}.${flipped}`;
}

function makeNoneAlgToken(token) {
  const parts = String(token).split('.');
  const payload = parts.length === 3 ? parts[1] : b64url({ sub: '1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 });
  return `${b64url({ alg: 'none', typ: 'JWT' })}.${payload}.`;
}

/**
 * Builds the 5 authentication/JWT probe descriptors for an operation requiring auth.
 * Never hardcodes secrets: expired tokens are only forged when cfg.auth.jwtSecret
 * (resolved from jwtSecretEnv) or cfg.auth.expiredToken is supplied.
 */
export function buildAuthProbes(cfg, session) {
  const headerName = cfg.auth.header ?? 'Authorization';
  const scheme = cfg.auth.scheme ?? '';
  const formatAuth = (tok) => (scheme ? `${scheme} ${tok}` : tok);
  const validToken = session?.token ?? '';

  const probes = [
    {
      category: 'AUTH_MISSING',
      headers: {},
      expected: 'Request without credentials must be rejected (401).',
    },
    {
      category: 'AUTH_INVALID_TOKEN',
      headers: { [headerName]: formatAuth('not-a-valid-jwt-token') },
      expected: 'Malformed token must be rejected (401).',
    },
    {
      category: 'JWT_SIGNATURE',
      headers: { [headerName]: formatAuth(tamperSignature(validToken)) },
      expected: 'Token with invalid signature must be rejected (401).',
    },
    {
      category: 'JWT_NONE_ALG',
      headers: { [headerName]: formatAuth(makeNoneAlgToken(validToken)) },
      expected: 'Unsigned alg=none token must be rejected (401).',
    },
  ];

  let expiredToken = cfg.auth?.expiredToken;
  if (!expiredToken && cfg.auth?.jwtSecret && validToken) {
    const claims = readJwtClaims(validToken) ?? {};
    const now = Math.floor(Date.now() / 1000);
    const payload = { ...claims, iat: now - 7200, exp: now - 3600 };
    expiredToken = signHs256({ alg: 'HS256', typ: 'JWT' }, payload, cfg.auth.jwtSecret);
  }

  if (expiredToken) {
    probes.push({
      category: 'JWT_EXPIRED',
      headers: { [headerName]: formatAuth(expiredToken) },
      expected: 'Expired JWT must be rejected (401).',
    });
  } else {
    probes.push({
      category: 'JWT_EXPIRED',
      skipReason: 'no auth.jwtSecretEnv or auth.expiredToken configured',
      expected: 'Expired JWT must be rejected (401).',
    });
  }

  return probes;
}
