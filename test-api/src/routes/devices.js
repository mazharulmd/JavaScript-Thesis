import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { isOwnerOrAdmin } from '../middleware/auth.js';
import { sendError } from '../middleware/errors.js';
import { validateBody } from '../middleware/validate.js';

/** IoT devices and their sensor readings. */
export function deviceRoutes({ store, flaws, auth }) {
  const r = Router();
  const findDevice = (id) => store.devices.find((d) => d.deviceId === String(id));

  r.get('/api/devices', auth.strict, (req, res) => {
    const devices = req.user.role === 'admin' ? store.devices : store.devices.filter((d) => d.ownerId === req.user.id);
    res.json({ devices });
  });

  // POST /api/devices: guests are read-only (always enforced)
  r.post('/api/devices', auth.strict, auth.requireRole('user', 'admin'), (req, res) => {
    const problem = validateBody(req.body, {
      name: { type: 'string', required: true, maxLength: 80 },
      type: { type: 'string', required: true, enum: ['temperature-sensor', 'humidity-sensor', 'smart-plug'] },
      location: { type: 'string', maxLength: 80 },
    });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const device = {
      deviceId: `dev-new-${store.nextId('device')}`,
      ownerId: req.user.id,
      name: req.body.name,
      type: req.body.type,
      firmware: '2.4.1',
      location: req.body.location ?? '',
      config: { samplingIntervalSec: 60, label: 'default' },
      registeredAt: new Date().toISOString(),
    };
    store.devices.push(device);
    res.status(201).json(device);
  });

  // GET /api/devices/{deviceId}  (always secure: 404 hides other users' devices)
  r.get('/api/devices/:deviceId', auth.strict, (req, res) => {
    const device = findDevice(req.params.deviceId);
    if (!device || !isOwnerOrAdmin(req.user, device.ownerId)) return sendError(res, 404, 'not_found', 'Device not found');
    res.json(device);
  });

  // GET /api/devices/{deviceId}/readings -> { deviceId, unit, readings[] }  (NO owner field in the response)
  r.get('/api/devices/:deviceId/readings', auth.strict, (req, res) => {
    const device = findDevice(req.params.deviceId);
    // FLAW BOLA_READINGS_READ: no ownership check.
    if (!device || (!flaws.has('BOLA_READINGS_READ') && !isOwnerOrAdmin(req.user, device.ownerId))) {
      return sendError(res, 404, 'not_found', 'Device not found');
    }
    const readings = store.readings.filter((x) => x.deviceId === device.deviceId).map(({ deviceId, ...rest }) => rest);
    res.json({ deviceId: device.deviceId, unit: 'C', readings });
  });

  // POST /api/devices/{deviceId}/readings  (sensor data ingestion)
  r.post('/api/devices/:deviceId/readings', auth.strict, (req, res) => {
    const problem = validateBody(req.body, {
      value: { type: 'number', required: true, min: -100, max: 200 },
      unit: { type: 'string', enum: ['C', 'F', '%'] },
      note: { type: 'string', maxLength: 200 },
    });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const device = findDevice(req.params.deviceId);
    // FLAW BOLA_READINGS_WRITE: no ownership check.
    if (!device || (!flaws.has('BOLA_READINGS_WRITE') && !isOwnerOrAdmin(req.user, device.ownerId))) {
      return sendError(res, 404, 'not_found', 'Device not found');
    }
    const reading = { deviceId: device.deviceId, ts: new Date().toISOString(), value: req.body.value, unit: req.body.unit ?? 'C', note: req.body.note ?? '' };
    store.readings.push(reading);
    res.status(201).json(reading);
  });

  // PUT /api/devices/{deviceId}/config  (always secure, TRUE NEGATIVE with HTTP 202:
  // every request is accepted for asynchronous processing, but only the owner's change is applied)
  r.put('/api/devices/:deviceId/config', auth.strict, (req, res) => {
    const problem = validateBody(req.body, {
      samplingIntervalSec: { type: 'integer', required: true, min: 1, max: 86400 },
      label: { type: 'string', required: true, maxLength: 80 },
    });
    if (problem) return sendError(res, 400, 'bad_request', problem);
    const device = findDevice(req.params.deviceId);
    if (device && isOwnerOrAdmin(req.user, device.ownerId)) {
      device.config = { samplingIntervalSec: req.body.samplingIntervalSec, label: req.body.label };
    }
    res.status(202).json({ status: 'queued', requestId: randomUUID() });
  });

  // DELETE /api/devices/{deviceId}  (always secure)
  r.delete('/api/devices/:deviceId', auth.strict, (req, res) => {
    const device = findDevice(req.params.deviceId);
    if (!device) return sendError(res, 404, 'not_found', 'Device not found');
    if (!isOwnerOrAdmin(req.user, device.ownerId)) return sendError(res, 403, 'forbidden', 'Not your device');
    store.devices = store.devices.filter((d) => d !== device);
    store.readings = store.readings.filter((x) => x.deviceId !== device.deviceId);
    res.status(204).end();
  });

  return r;
}
