/**
 * Registry of the intentionally injected flaws.
 *
 * Every vulnerable code path in the benchmark API is guarded by exactly one flaw ID.
 * With FLAWS=all (default) the API is the vulnerable benchmark; with FLAWS=none every
 * flaw is replaced by its correctly protected implementation, which yields a fully
 * patched build of the same API (used as an extra true-negative dataset and for the
 * CI gate demonstration). FLAWS may also be a comma-separated list of IDs.
 *
 * The IDs are referenced from ground-truth.json (field `flawId`).
 */
export const FLAWS = Object.freeze({
  // --- Broken Object Level Authorization (OWASP API1:2023) ---
  BOLA_USERS_READ: 'Any authenticated user can read any user profile (GET /api/users/{userId}).',
  BOLA_USERS_WRITE: 'Any authenticated user can modify any user profile (PATCH /api/users/{userId}).',
  BOLA_ORDERS_READ: 'Any authenticated user can read any order (GET /api/orders/{orderId}).',
  BOLA_ORDERS_DELETE: 'Any authenticated user can delete any order (DELETE /api/orders/{orderId}).',
  BOLA_INVOICES_READ: 'Any authenticated user can read any invoice (GET /api/invoices/{invoiceId}).',
  BOLA_DOCUMENTS_WRITE: 'Any authenticated user can modify any document (PATCH /api/documents/{documentId}).',
  BOLA_READINGS_READ: 'Any authenticated user can read sensor readings of any device (GET /api/devices/{deviceId}/readings).',
  BOLA_READINGS_WRITE: 'Any authenticated user can inject sensor readings into any device (POST /api/devices/{deviceId}/readings).',
  // --- Broken Function Level Authorization (OWASP API5:2023) ---
  BFLA_ADMIN_USERS_LIST: 'Non-admins can list all user accounts (GET /api/admin/users).',
  BFLA_ADMIN_USERS_DELETE: 'Non-admins can delete user accounts (DELETE /api/admin/users/{userId}).',
  BFLA_ANNOUNCEMENTS_CREATE: 'Non-admins can publish announcements (POST /api/admin/announcements).',
  BFLA_BACKUPS_CREATE: 'Non-admins can trigger backups (POST /api/admin/backups).',
  BFLA_PRODUCTS_CREATE: 'Non-admins can create catalogue products (POST /api/products).',
  BFLA_DOCUMENTS_CREATE_GUEST: 'Read-only guests can create documents (POST /api/documents).',
  // --- Authentication / JWT (OWASP API2:2023) ---
  AUTH_MISSING_DIAGNOSTICS: 'No authentication middleware on GET /api/system/diagnostics.',
  AUTH_MISSING_TICKETS: 'No authentication middleware on POST /api/support/tickets.',
  AUTH_INVALID_ANALYTICS: 'GET /api/analytics/summary only checks that a Bearer header is present.',
  JWT_SIGNATURE_MESSAGES: 'GET /api/messages decodes the JWT without verifying its signature.',
  JWT_NONE_NOTIFICATIONS: 'GET /api/notifications accepts unsigned tokens (alg: none).',
  JWT_EXPIRED_SESSIONS: 'GET /api/sessions does not check the token expiry (exp).',
});

export function createFlawSet(spec = 'all') {
  const value = String(spec).trim();
  let enabled;
  if (value === '' || value.toLowerCase() === 'none') enabled = new Set();
  else if (value.toLowerCase() === 'all') enabled = new Set(Object.keys(FLAWS));
  else {
    enabled = new Set();
    for (const id of value.split(',').map((s) => s.trim()).filter(Boolean)) {
      if (!(id in FLAWS)) throw new Error(`Unknown flaw ID in FLAWS: ${id}`);
      enabled.add(id);
    }
  }
  return {
    has: (id) => {
      if (!(id in FLAWS)) throw new Error(`Unknown flaw ID: ${id}`);
      return enabled.has(id);
    },
    list: () => [...enabled].sort(),
    mode: enabled.size === 0 ? 'secure' : enabled.size === Object.keys(FLAWS).length ? 'vulnerable' : 'custom',
  };
}
