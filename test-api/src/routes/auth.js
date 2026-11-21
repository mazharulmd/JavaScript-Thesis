import { Router } from 'express';
import { issueToken } from '../lib/jwt.js';
import { publicUser } from '../models/store.js';
import { sendError } from '../middleware/errors.js';
import { validateBody } from '../middleware/validate.js';

export function authRoutes({ store, config, auth }) {
  const r = Router();

  // POST /api/auth/login  (public)
  r.post('/api/auth/login', (req, res) => {
    const problem = validateBody(req.body, {
      username: { type: 'string', required: true, maxLength: 64 },
      password: { type: 'string', required: true, maxLength: 128 },
    });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const user = store.findUserByUsername(req.body.username);
    if (!user || !store.verifyPassword(req.body.password, user.passwordHash)) {
      return sendError(res, 401, 'invalid_credentials', 'Invalid username or password');
    }
    const token = issueToken(user, config);
    res.json({ token, tokenType: 'Bearer', expiresIn: config.tokenTtlSeconds, user: { id: user.id, username: user.username, role: user.role } });
  });

  // GET /api/auth/me  (secure)
  r.get('/api/auth/me', auth.strict, (req, res) => {
    res.json(publicUser(req.user));
  });

  return r;
}
