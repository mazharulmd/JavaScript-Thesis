import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { sendError } from '../middleware/errors.js';
import { validateBody } from '../middleware/validate.js';
import { publicUser } from '../models/store.js';

/** Administrative functions (intended for role "admin" only). */
export function adminRoutes({ store, auth }) {
  const r = Router();
  const ROLES = ['admin', 'user', 'guest'];

  // FLAW BFLA_ADMIN_USERS_LIST: the admin role check is missing.
  r.get('/api/admin/users', auth.strict, auth.requireRoleUnless('BFLA_ADMIN_USERS_LIST', 'admin'), (_req, res) => {
    res.json({ users: store.users.map(publicUser) });
  });

  r.post('/api/admin/users', auth.strict, auth.requireRole('admin'), (req, res) => {
    const problem = validateBody(req.body, {
      username: { type: 'string', required: true, maxLength: 64 },
      email: { type: 'string', required: true, maxLength: 120 },
      password: { type: 'string', required: true, maxLength: 128 },
      role: { type: 'string', enum: ROLES },
    });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    if (store.findUserByUsername(req.body.username)) return sendError(res, 409, 'conflict', 'Username already exists');
    const user = {
      id: store.nextId('user'),
      username: req.body.username,
      displayName: req.body.username,
      email: req.body.email,
      phone: '',
      role: req.body.role ?? 'user',
      passwordHash: store.hashPassword(req.body.password),
      createdAt: new Date().toISOString(),
    };
    store.users.push(user);
    res.status(201).json(publicUser(user));
  });

  // FLAW BFLA_ADMIN_USERS_DELETE: the admin role check is missing.
  r.delete('/api/admin/users/:userId', auth.strict, auth.requireRoleUnless('BFLA_ADMIN_USERS_DELETE', 'admin'), (req, res) => {
    const target = store.findUser(req.params.userId);
    if (!target) return sendError(res, 404, 'not_found', 'User not found');
    if (String(target.id) === String(req.user.id)) return sendError(res, 400, 'bad_request', 'You cannot delete yourself');
    store.users = store.users.filter((u) => u !== target);
    res.json({ deleted: true, id: target.id });
  });

  r.put('/api/admin/users/:userId/role', auth.strict, auth.requireRole('admin'), (req, res) => {
    const problem = validateBody(req.body, { role: { type: 'string', required: true, enum: ROLES } });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const target = store.findUser(req.params.userId);
    if (!target) return sendError(res, 404, 'not_found', 'User not found');
    target.role = req.body.role;
    res.json(publicUser(target));
  });

  r.get('/api/admin/stats', auth.strict, auth.requireRole('admin'), (_req, res) => {
    res.json({ users: store.users.length, orders: store.orders.length, documents: store.documents.length, devices: store.devices.length });
  });

  // GET /api/admin/reports  (always secure, TRUE NEGATIVE with HTTP 200: role-filtered view;
  // non-admins receive an empty, self-scoped result instead of the global sales reports)
  r.get('/api/admin/reports', auth.strict, (req, res) => {
    if (req.user.role !== 'admin') return res.json({ scope: 'self', reports: [] });
    const byOwner = new Map();
    for (const o of store.orders) byOwner.set(o.ownerId, (byOwner.get(o.ownerId) ?? 0) + o.total);
    const reports = [...byOwner.entries()].map(([ownerId, revenue]) => ({ ownerId, revenue: Number(revenue.toFixed(2)) }));
    res.json({ scope: 'global', reports });
  });

  // GET /api/admin/audit-logs  (always secure, TRUE NEGATIVE with HTTP 200: soft denial)
  r.get('/api/admin/audit-logs', auth.strict, (req, res) => {
    if (req.user.role !== 'admin') return res.status(200).json({ success: false, error: 'Administrator privileges required' });
    res.json({ success: true, logs: store.auditLogs });
  });

  // FLAW BFLA_ANNOUNCEMENTS_CREATE: the admin role check is missing.
  r.post('/api/admin/announcements', auth.strict, auth.requireRoleUnless('BFLA_ANNOUNCEMENTS_CREATE', 'admin'), (req, res) => {
    const problem = validateBody(req.body, {
      title: { type: 'string', required: true, maxLength: 120 },
      message: { type: 'string', required: true, maxLength: 2000 },
    });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const a = { id: store.nextId('announcement'), title: req.body.title, message: req.body.message, createdBy: req.user.id, createdAt: new Date().toISOString() };
    store.announcements.push(a);
    res.status(201).json(a);
  });

  // FLAW BFLA_BACKUPS_CREATE: the admin role check is missing.
  r.post('/api/admin/backups', auth.strict, auth.requireRoleUnless('BFLA_BACKUPS_CREATE', 'admin'), (req, res) => {
    const backup = { backupId: `bkp-${store.nextId('backup')}`, status: 'started', requestedBy: req.user.id, jobId: randomUUID() };
    store.backups.push(backup);
    res.status(202).json(backup);
  });

  return r;
}
