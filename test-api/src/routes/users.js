import { Router } from 'express';
import { isOwnerOrAdmin } from '../middleware/auth.js';
import { sendError } from '../middleware/errors.js';
import { validateBody, pick } from '../middleware/validate.js';
import { publicUser } from '../models/store.js';

export function userRoutes({ store, flaws, auth }) {
  const r = Router();

  // GET /api/users/{userId}
  r.get('/api/users/:userId', auth.strict, (req, res) => {
    const target = store.findUser(req.params.userId);
    // FLAW BOLA_USERS_READ: the ownership check is skipped.
    if (!flaws.has('BOLA_USERS_READ') && !isOwnerOrAdmin(req.user, req.params.userId)) {
      return sendError(res, 403, 'forbidden', 'You may only view your own account');
    }
    if (!target) return sendError(res, 404, 'not_found', 'User not found');
    res.json(publicUser(target));
  });

  // PATCH /api/users/{userId}
  r.patch('/api/users/:userId', auth.strict, (req, res) => {
    const rules = { displayName: { type: 'string', maxLength: 80 }, phone: { type: 'string', maxLength: 32 } };
    const problem = validateBody(req.body, rules, { partial: true });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    // FLAW BOLA_USERS_WRITE: the ownership check is skipped.
    if (!flaws.has('BOLA_USERS_WRITE') && !isOwnerOrAdmin(req.user, req.params.userId)) {
      return sendError(res, 403, 'forbidden', 'You may only modify your own account');
    }
    const target = store.findUser(req.params.userId);
    if (!target) return sendError(res, 404, 'not_found', 'User not found');
    Object.assign(target, pick(req.body, Object.keys(rules)));
    res.json(publicUser(target));
  });

  // GET /api/profiles/{userId}  (always secure)
  r.get('/api/profiles/:userId', auth.strict, (req, res) => {
    if (!isOwnerOrAdmin(req.user, req.params.userId)) return sendError(res, 403, 'forbidden', 'Access denied');
    const u = store.findUser(req.params.userId);
    if (!u) return sendError(res, 404, 'not_found', 'Profile not found');
    res.json({ userId: u.id, displayName: u.displayName, email: u.email, phone: u.phone, bio: `Profile of ${u.displayName}` });
  });

  // GET /api/accounts/{accountId}/summary  (always secure, TRUE NEGATIVE with HTTP 200)
  // The path parameter is kept for backwards compatibility only: the summary is ALWAYS
  // computed for the authenticated caller, so requesting someone else's accountId returns
  // the caller's own data with 200 OK. A status-code-only oracle misclassifies this.
  r.get('/api/accounts/:accountId/summary', auth.strict, (req, res) => {
    const me = req.user;
    const myOrders = store.orders.filter((o) => o.ownerId === me.id);
    res.json({
      accountId: me.id,
      username: me.username,
      orderCount: myOrders.length,
      totalSpent: Number(myOrders.reduce((s, o) => s + o.total, 0).toFixed(2)),
      currency: 'EUR',
    });
  });

  return r;
}
