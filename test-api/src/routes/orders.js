import { Router } from 'express';
import { isOwnerOrAdmin } from '../middleware/auth.js';
import { sendError } from '../middleware/errors.js';
import { validateBody, pick } from '../middleware/validate.js';

export function orderRoutes({ store, flaws, auth }) {
  const r = Router();
  const findOrder = (id) => store.orders.find((o) => String(o.id) === String(id));
  const visible = (user, list) => (user.role === 'admin' ? list : list.filter((o) => o.ownerId === user.id));

  r.get('/api/orders', auth.strict, (req, res) => {
    const data = visible(req.user, store.orders);
    res.json({ data, count: data.length });
  });

  // POST /api/orders: guests are read-only (function-level rule, always enforced)
  r.post('/api/orders', auth.strict, auth.requireRole('user', 'admin'), (req, res) => {
    const problem = validateBody(req.body, {
      sku: { type: 'string', required: true, maxLength: 32 },
      quantity: { type: 'integer', required: true, min: 1, max: 100 },
      shippingAddress: { type: 'string', required: true, maxLength: 200 },
      note: { type: 'string', maxLength: 500 },
    });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const product = store.products.find((p) => p.sku === req.body.sku);
    const unitPrice = product ? product.price : 10;
    const order = {
      id: store.nextId('order'),
      ownerId: req.user.id,
      status: 'processing',
      items: [{ sku: req.body.sku, quantity: req.body.quantity, unitPrice }],
      total: Number((unitPrice * req.body.quantity).toFixed(2)),
      shippingAddress: req.body.shippingAddress,
      note: req.body.note ?? '',
      createdAt: new Date().toISOString(),
    };
    store.orders.push(order);
    store.invoices.push({
      id: store.nextId('invoice'), orderId: order.id, amount: order.total, currency: 'EUR', status: 'open',
      billing: { accountId: req.user.id, iban: 'FI00 0000 0000 0000', address: order.shippingAddress }, issuedAt: order.createdAt,
    });
    res.status(201).json(order);
  });

  // GET /api/orders/{orderId}
  r.get('/api/orders/:orderId', auth.strict, (req, res) => {
    const order = findOrder(req.params.orderId);
    // FLAW BOLA_ORDERS_READ: no ownership check.
    if (!order || (!flaws.has('BOLA_ORDERS_READ') && !isOwnerOrAdmin(req.user, order.ownerId))) {
      return sendError(res, 404, 'not_found', 'Order not found');
    }
    res.json(order);
  });

  // PUT /api/orders/{orderId}  (always secure: 404 for orders of other users)
  r.put('/api/orders/:orderId', auth.strict, (req, res) => {
    const rules = { shippingAddress: { type: 'string', required: true, maxLength: 200 }, note: { type: 'string', maxLength: 500 } };
    const problem = validateBody(req.body, rules);
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const order = findOrder(req.params.orderId);
    if (!order || !isOwnerOrAdmin(req.user, order.ownerId)) return sendError(res, 404, 'not_found', 'Order not found');
    Object.assign(order, pick(req.body, Object.keys(rules)));
    res.json(order);
  });

  // DELETE /api/orders/{orderId}
  r.delete('/api/orders/:orderId', auth.strict, (req, res) => {
    const order = findOrder(req.params.orderId);
    // FLAW BOLA_ORDERS_DELETE: no ownership check.
    if (!order || (!flaws.has('BOLA_ORDERS_DELETE') && !isOwnerOrAdmin(req.user, order.ownerId))) {
      return sendError(res, 404, 'not_found', 'Order not found');
    }
    store.orders = store.orders.filter((o) => o !== order);
    res.status(204).end();
  });

  // GET /api/invoices  (own invoices; nested ownership: billing.accountId)
  r.get('/api/invoices', auth.strict, (req, res) => {
    const data = req.user.role === 'admin' ? store.invoices : store.invoices.filter((i) => i.billing.accountId === req.user.id);
    res.json({ data });
  });

  // GET /api/invoices/{invoiceId}  -> { data: { invoice: {..., billing: { accountId } } } }
  r.get('/api/invoices/:invoiceId', auth.strict, (req, res) => {
    const invoice = store.invoices.find((i) => String(i.id) === String(req.params.invoiceId));
    if (!invoice) return sendError(res, 404, 'not_found', 'Invoice not found');
    // FLAW BOLA_INVOICES_READ: no ownership check.
    if (!flaws.has('BOLA_INVOICES_READ') && !isOwnerOrAdmin(req.user, invoice.billing.accountId)) {
      return sendError(res, 403, 'forbidden', 'Access denied');
    }
    res.json({ data: { invoice } });
  });

  return r;
}
