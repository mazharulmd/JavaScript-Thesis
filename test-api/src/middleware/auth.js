import { verifyStrict, decodeWithoutVerification, verifyAllowingNone, verifyIgnoringExpiry } from '../lib/jwt.js';
import { sendError } from './errors.js';

/**
 * Authentication middleware factory.
 *
 * Variants:
 *  - 'strict'          correct: Bearer JWT, HS256 only, signature + expiry verified (default)
 *  - 'none'            FLAW: no authentication at all
 *  - 'header-only'     FLAW: only checks that an Authorization: Bearer header is present
 *  - 'decode-only'     FLAW: trusts JWT claims without signature verification
 *  - 'allow-none-alg'  FLAW: accepts alg "none" tokens
 *  - 'ignore-expiry'   FLAW: accepts expired tokens
 *
 * For identity-bearing variants the user (and role) is always loaded from the store by `sub`.
 */
export function createAuth({ store, config, flaws }) {
  const verifiers = {
    strict: (t) => verifyStrict(t, config.jwtSecret),
    'decode-only': (t) => decodeWithoutVerification(t),
    'allow-none-alg': (t) => verifyAllowingNone(t, config.jwtSecret),
    'ignore-expiry': (t) => verifyIgnoringExpiry(t, config.jwtSecret),
  };

  function bearer(req) {
    const header = req.headers.authorization;
    if (typeof header !== 'string') return null;
    const match = /^Bearer\s+(.+)$/i.exec(header.trim());
    return match ? match[1].trim() : null;
  }

  function authenticate(variant = 'strict') {
    if (variant === 'none') {
      return (req, _res, next) => {
        req.user = null;
        req.authVariant = 'none';
        next();
      };
    }
    if (variant === 'header-only') {
      return (req, res, next) => {
        if (!bearer(req)) return sendError(res, 401, 'unauthorized', 'Missing bearer token');
        req.user = null;
        req.authVariant = 'header-only';
        next();
      };
    }
    const verify = verifiers[variant];
    if (!verify) throw new Error(`Unknown auth variant: ${variant}`);
    return (req, res, next) => {
      const token = bearer(req);
      if (!token) return sendError(res, 401, 'unauthorized', 'Missing bearer token');
      let claims;
      try {
        claims = verify(token);
      } catch (err) {
        const msg = err?.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
        return sendError(res, 401, 'unauthorized', msg);
      }
      const user = store.findUser(claims?.sub);
      if (!user) return sendError(res, 401, 'unauthorized', 'Unknown subject');
      req.user = user;
      req.authVariant = variant;
      next();
    };
  }

  /** Uses `vulnerableVariant` when `flawId` is enabled, otherwise the strict middleware. */
  function authFor(flawId, vulnerableVariant) {
    return flaws.has(flawId) ? authenticate(vulnerableVariant) : authenticate('strict');
  }

  /** Function-level authorization: the authenticated user's role must be in `roles`. */
  function requireRole(...roles) {
    return (req, res, next) => {
      if (!req.user) return sendError(res, 401, 'unauthorized', 'Authentication required');
      if (!roles.includes(req.user.role)) return sendError(res, 403, 'forbidden', 'Insufficient role');
      next();
    };
  }

  /** Like requireRole, but only enforced when `flawId` is disabled. */
  function requireRoleUnless(flawId, ...roles) {
    if (flaws.has(flawId)) return (_req, _res, next) => next();
    return requireRole(...roles);
  }

  return { authenticate, authFor, requireRole, requireRoleUnless, strict: authenticate('strict') };
}

/** Object-level helper: owner of the record or an administrator. */
export function isOwnerOrAdmin(user, ownerId) {
  return !!user && (user.role === 'admin' || String(user.id) === String(ownerId));
}
