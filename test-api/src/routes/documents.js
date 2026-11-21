import { Router } from 'express';
import { isOwnerOrAdmin } from '../middleware/auth.js';
import { sendError } from '../middleware/errors.js';
import { validateBody, pick } from '../middleware/validate.js';

export function documentRoutes({ store, flaws, auth }) {
  const r = Router();
  const findDoc = (id) => store.documents.find((d) => d.id === String(id));
  const rules = {
    title: { type: 'string', maxLength: 120 },
    content: { type: 'string', maxLength: 5000 },
    visibility: { type: 'string', enum: ['private', 'public'] },
  };

  // GET /api/documents: own documents + public documents of everybody
  r.get('/api/documents', auth.strict, (req, res) => {
    const data = store.documents.filter((d) => d.visibility === 'public' || isOwnerOrAdmin(req.user, d.ownerId));
    res.json({ data });
  });

  // POST /api/documents: guests are read-only.
  // FLAW BFLA_DOCUMENTS_CREATE_GUEST: the role check is missing.
  r.post('/api/documents', auth.strict, auth.requireRoleUnless('BFLA_DOCUMENTS_CREATE_GUEST', 'user', 'admin'), (req, res) => {
    const problem = validateBody(req.body, { ...rules, title: { ...rules.title, required: true }, content: { ...rules.content, required: true } });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const doc = {
      id: `doc-new-${store.nextId('document')}`,
      ownerId: req.user.id,
      title: req.body.title,
      content: req.body.content,
      visibility: req.body.visibility ?? 'private',
      createdAt: new Date().toISOString(),
    };
    store.documents.push(doc);
    res.status(201).json(doc);
  });

  // GET /api/documents/{documentId}  (always secure; PUBLIC documents are readable by any
  // authenticated user by design -> TRUE NEGATIVE with HTTP 200 for other users' public docs)
  r.get('/api/documents/:documentId', auth.strict, (req, res) => {
    const doc = findDoc(req.params.documentId);
    if (!doc) return sendError(res, 404, 'not_found', 'Document not found');
    if (doc.visibility !== 'public' && !isOwnerOrAdmin(req.user, doc.ownerId)) {
      return sendError(res, 403, 'forbidden', 'This document is private');
    }
    res.json(doc);
  });

  // PATCH /api/documents/{documentId}
  r.patch('/api/documents/:documentId', auth.strict, (req, res) => {
    const problem = validateBody(req.body, rules, { partial: true });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const doc = findDoc(req.params.documentId);
    if (!doc) return sendError(res, 404, 'not_found', 'Document not found');
    // FLAW BOLA_DOCUMENTS_WRITE: no ownership check.
    if (!flaws.has('BOLA_DOCUMENTS_WRITE') && !isOwnerOrAdmin(req.user, doc.ownerId)) {
      return sendError(res, 403, 'forbidden', 'Only the owner may edit this document');
    }
    Object.assign(doc, pick(req.body, Object.keys(rules)), { updatedAt: new Date().toISOString() });
    res.json(doc);
  });

  // DELETE /api/documents/{documentId}  (always secure, TRUE NEGATIVE with HTTP 200:
  // non-owners receive 200 {success:false,...} and nothing is deleted - a "soft denial")
  r.delete('/api/documents/:documentId', auth.strict, (req, res) => {
    const doc = findDoc(req.params.documentId);
    if (!doc) return res.status(200).json({ success: false, error: 'Document not found' });
    if (!isOwnerOrAdmin(req.user, doc.ownerId)) {
      return res.status(200).json({ success: false, error: 'You are not allowed to delete this document' });
    }
    store.documents = store.documents.filter((d) => d !== doc);
    res.status(200).json({ success: true, deleted: doc.id });
  });

  return r;
}
