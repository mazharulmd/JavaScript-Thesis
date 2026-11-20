/**
 * Deterministic, synthetic seed data for the benchmark API.
 *
 * All names, e-mail addresses, phone numbers and passwords are fictitious and exist only
 * for the isolated benchmark. The same seed is loaded on every start and on every
 * POST /__benchmark/reset, so experiments are reproducible.
 *
 * Test accounts used by the scanner: admin, alice, bob, guest.
 * carol and dave are additional data owners that are NOT configured in the scanner.
 */
export const SEED_ACCOUNTS = Object.freeze([
  { id: 1, username: 'admin', password: 'Admin#2026', role: 'admin', displayName: 'Ada Admin', email: 'admin@bench.local', phone: '+358-40-000-0001' },
  { id: 2, username: 'alice', password: 'Alice#2026', role: 'user', displayName: 'Alice Example', email: 'alice@bench.local', phone: '+358-40-000-0002' },
  { id: 3, username: 'bob', password: 'Bob#2026', role: 'user', displayName: 'Bob Example', email: 'bob@bench.local', phone: '+358-40-000-0003' },
  { id: 4, username: 'guest', password: 'Guest#2026', role: 'guest', displayName: 'Gus Guest', email: 'guest@bench.local', phone: '+358-40-000-0004' },
  { id: 5, username: 'carol', password: 'Carol#2026', role: 'user', displayName: 'Carol Example', email: 'carol@bench.local', phone: '+358-40-000-0005' },
  { id: 6, username: 'dave', password: 'Dave#2026', role: 'user', displayName: 'Dave Example', email: 'dave@bench.local', phone: '+358-40-000-0006' },
]);

const FIXED_TIME = Date.parse('2026-11-01T08:00:00.000Z');
const ts = (minutes) => new Date(FIXED_TIME + minutes * 60_000).toISOString();

export function buildSeed() {
  const owners = [1, 2, 3, 5, 6]; // the guest (4) owns nothing: read-only role
  const orders = [];
  const invoices = [];
  let orderId = 1001;
  let invoiceId = 7001;
  for (const ownerId of owners) {
    for (let k = 0; k < 2; k += 1) {
      const id = orderId++;
      const total = Number((19.9 + ownerId * 10 + k * 5.5).toFixed(2));
      orders.push({
        id,
        ownerId,
        status: k === 0 ? 'shipped' : 'processing',
        items: [{ sku: `SKU-${100 + ownerId}${k}`, quantity: k + 1, unitPrice: total / (k + 1) }],
        total,
        shippingAddress: `${ownerId}${k} Example Street, 70100 Kuopio`,
        note: '',
        createdAt: ts(ownerId * 10 + k),
      });
      invoices.push({
        id: invoiceId++,
        orderId: id,
        amount: total,
        currency: 'EUR',
        status: k === 0 ? 'paid' : 'open',
        billing: { accountId: ownerId, iban: `FI00 0000 0000 00${ownerId}${k}`, address: `${ownerId}${k} Example Street` },
        issuedAt: ts(ownerId * 10 + k + 1),
      });
    }
  }

  const documents = [];
  for (const ownerId of owners) {
    documents.push({
      id: `doc-${ownerId}-private`,
      ownerId,
      title: `Private notes of user ${ownerId}`,
      content: `Confidential content owned by user ${ownerId}.`,
      visibility: 'private',
      createdAt: ts(ownerId * 20),
    });
    documents.push({
      id: `doc-${ownerId}-public`,
      ownerId,
      title: `Public handbook by user ${ownerId}`,
      content: `Public content shared by user ${ownerId}.`,
      visibility: 'public',
      createdAt: ts(ownerId * 20 + 1),
    });
  }

  const devices = [];
  const readings = [];
  for (const ownerId of owners) {
    const deviceId = `dev-${String(ownerId).padStart(3, '0')}-a`;
    devices.push({
      deviceId,
      ownerId,
      name: `Thermostat of user ${ownerId}`,
      type: 'temperature-sensor',
      firmware: '2.4.1',
      location: `Room ${ownerId}01`,
      config: { samplingIntervalSec: 60, label: 'default' },
      registeredAt: ts(ownerId * 30),
    });
    for (let r = 0; r < 3; r += 1) {
      readings.push({ deviceId, ts: ts(ownerId * 30 + r * 5), value: 20 + ownerId + r / 10, unit: 'C', note: '' });
    }
  }

  const products = [
    { id: 501, sku: 'SKU-501', name: 'Smart Plug', price: 24.9, stock: 120 },
    { id: 502, sku: 'SKU-502', name: 'Temperature Sensor', price: 39.5, stock: 64 },
    { id: 503, sku: 'SKU-503', name: 'Door Contact', price: 19.0, stock: 210 },
  ];

  const announcements = [
    { id: 1, title: 'Welcome', message: 'Welcome to the benchmark platform.', createdBy: 1, createdAt: ts(1) },
  ];

  const messages = [];
  const notifications = [];
  const sessions = [];
  for (const { id } of SEED_ACCOUNTS) {
    messages.push({ id: 9000 + id, recipientId: id, from: 'support', subject: `Hello user ${id}`, body: `Private message for user ${id}.`, sentAt: ts(id) });
    notifications.push({ id: 9500 + id, userId: id, text: `You have ${id} new alerts.`, read: false, createdAt: ts(id + 1) });
    sessions.push({ id: `sess-${id}-1`, userId: id, device: 'Firefox on Linux', ip: `10.0.0.${id}`, lastSeen: ts(id + 2) });
  }

  const auditLogs = [
    { id: 1, actor: 1, action: 'user.create', target: 5, at: ts(2) },
    { id: 2, actor: 1, action: 'role.change', target: 6, at: ts(3) },
  ];

  return { orders, invoices, documents, devices, readings, products, announcements, messages, notifications, sessions, auditLogs, tickets: [], backups: [] };
}
