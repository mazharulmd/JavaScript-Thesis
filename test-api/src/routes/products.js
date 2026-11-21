import { Router } from 'express';
import { sendError } from '../middleware/errors.js';
import { validateBody, pick } from '../middleware/validate.js';

/** Product catalogue: public reads, admin-only writes. */
export function productRoutes({ store, auth }) {
  const r = Router();
  const rules = {
    sku: { type: 'string', required: true, maxLength: 32 },
    name: { type: 'string', required: true, maxLength: 80 },
    price: { type: 'number', required: true, min: 0, max: 100000 },
    stock: { type: 'integer', min: 0, max: 1000000 },
  };
  const find = (id) => store.products.find((p) => String(p.id) === String(id));

  r.get('/api/products', (_req, res) => res.json({ products: store.products }));

  r.get('/api/products/:productId', (req, res) => {
    const p = find(req.params.productId);
    if (!p) return sendError(res, 404, 'not_found', 'Product not found');
    res.json(p);
  });

  // FLAW BFLA_PRODUCTS_CREATE: the admin role check is missing.
  r.post('/api/products', auth.strict, auth.requireRoleUnless('BFLA_PRODUCTS_CREATE', 'admin'), (req, res) => {
    const problem = validateBody(req.body, rules);
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const product = { id: store.nextId('product'), ...pick(req.body, Object.keys(rules)), stock: req.body.stock ?? 0 };
    store.products.push(product);
    res.status(201).json(product);
  });

  r.put('/api/products/:productId', auth.strict, auth.requireRole('admin'), (req, res) => {
    const problem = validateBody(req.body, rules);
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const p = find(req.params.productId);
    if (!p) return sendError(res, 404, 'not_found', 'Product not found');
    Object.assign(p, pick(req.body, Object.keys(rules)));
    res.json(p);
  });

  r.delete('/api/products/:productId', auth.strict, auth.requireRole('admin'), (req, res) => {
    const p = find(req.params.productId);
    if (!p) return sendError(res, 404, 'not_found', 'Product not found');
    store.products = store.products.filter((x) => x !== p);
    res.status(204).end();
  });

  return r;
}
