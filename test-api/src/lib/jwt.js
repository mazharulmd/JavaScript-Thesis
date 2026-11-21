import jwt from 'jsonwebtoken';

/**
 * Token handling for the benchmark API.
 *
 * `issueToken` and `verifyStrict` are the CORRECT implementation (library-based, HS256
 * whitelist, expiry enforced). The remaining verifiers are hand-written, deliberately
 * flawed variants that are only reachable through an enabled flaw (see flaws.js).
 */
export function issueToken(user, { jwtSecret, tokenTtlSeconds }) {
  return jwt.sign({ role: user.role, username: user.username }, jwtSecret, {
    algorithm: 'HS256',
    subject: String(user.id),
    expiresIn: tokenTtlSeconds,
  });
}

export function verifyStrict(token, secret) {
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
}

function b64urlJson(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

function assertNotExpired(payload) {
  if (typeof payload.exp === 'number' && payload.exp * 1000 <= Date.now()) {
    const err = new Error('jwt expired');
    err.name = 'TokenExpiredError';
    throw err;
  }
}

/** FLAW (JWT_SIGNATURE_*): decodes the token and trusts the claims without checking the signature. */
export function decodeWithoutVerification(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const header = b64urlJson(parts[0]);
  const payload = b64urlJson(parts[1]);
  if (!header || typeof payload !== 'object' || payload === null) throw new Error('malformed token');
  assertNotExpired(payload);
  return payload;
}

/** FLAW (JWT_NONE_*): accepts unsigned tokens whose header says alg "none". */
export function verifyAllowingNone(token, secret) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const header = b64urlJson(parts[0]);
  if (String(header.alg).toLowerCase() === 'none') {
    const payload = b64urlJson(parts[1]);
    assertNotExpired(payload);
    return payload;
  }
  return verifyStrict(token, secret);
}

/** FLAW (JWT_EXPIRED_*): verifies the signature but ignores `exp`. */
export function verifyIgnoringExpiry(token, secret) {
  return jwt.verify(token, secret, { algorithms: ['HS256'], ignoreExpiration: true });
}
