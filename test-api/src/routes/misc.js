import { Router } from 'express';
import { sendError } from '../middleware/errors.js';
import { validateBody } from '../middleware/validate.js';

/** Endpoints that carry the secondary authentication / JWT flaws, plus announcements. */
export function miscRoutes({ store, auth }) {
  const r = Router();
  const startedAt = Date.now();

  r.get('/api/announcements', auth.strict, (_req, res) => res.json({ announcements: store.announcements }));

  // FLAW AUTH_MISSING_DIAGNOSTICS: no authentication middleware.
  r.get('/api/system/diagnostics', auth.authFor('AUTH_MISSING_DIAGNOSTICS', 'none'), (_req, res) => {
    res.json({
      service: 'bac-test-api',
      version: '1.0.0',
      node: process.version,
      environment: 'benchmark',
      database: { engine: 'in-memory', users: store.users.length, orders: store.orders.length },
      internalHosts: ['db.internal.bench.local', 'cache.internal.bench.local'],
      uptimeSec: Math.round((Date.now() - startedAt) / 1000),
    });
  });

  // FLAW AUTH_MISSING_TICKETS: no authentication middleware.
  r.post('/api/support/tickets', auth.authFor('AUTH_MISSING_TICKETS', 'none'), (req, res) => {
    const problem = validateBody(req.body, {
      subject: { type: 'string', required: true, maxLength: 120 },
      message: { type: 'string', required: true, maxLength: 2000 },
    });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const ticket = { id: store.nextId('ticket'), subject: req.body.subject, message: req.body.message, createdBy: req.user?.id ?? null, status: 'open' };
    store.tickets.push(ticket);
    res.status(201).json(ticket);
  });

  // FLAW AUTH_INVALID_ANALYTICS: only the presence of a Bearer header is checked.
  r.get('/api/analytics/summary', auth.authFor('AUTH_INVALID_ANALYTICS', 'header-only'), (_req, res) => {
    const revenue = store.orders.reduce((s, o) => s + o.total, 0);
    res.json({ period: '2026-11', orders: store.orders.length, revenue: Number(revenue.toFixed(2)), activeDevices: store.devices.length });
  });

  // FLAW JWT_SIGNATURE_MESSAGES: JWT claims are trusted without signature verification.
  r.get('/api/messages', auth.authFor('JWT_SIGNATURE_MESSAGES', 'decode-only'), (req, res) => {
    res.json({ messages: store.messages.filter((m) => m.recipientId === req.user.id) });
  });

  // FLAW JWT_NONE_NOTIFICATIONS: unsigned (alg none) tokens are accepted.
  r.get('/api/notifications', auth.authFor('JWT_NONE_NOTIFICATIONS', 'allow-none-alg'), (req, res) => {
    res.json({ notifications: store.notifications.filter((n) => n.userId === req.user.id) });
  });

  // FLAW JWT_EXPIRED_SESSIONS: token expiry is not enforced.
  r.get('/api/sessions', auth.authFor('JWT_EXPIRED_SESSIONS', 'ignore-expiry'), (req, res) => {
    res.json({ sessions: store.sessions.filter((s) => s.userId === req.user.id) });
  });

  return r;
}
