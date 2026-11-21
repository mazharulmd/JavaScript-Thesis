import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractOwnership,
  matchesPublicIndicator,
  isSoftDenial,
  isRoleFilteredEmptyView,
} from '../../cli-tool/src/analyzers/ownership.js';
import { evaluateStatusOnly } from '../../cli-tool/src/analyzers/status-oracle.js';
import { evaluateOwnershipDifferential } from '../../cli-tool/src/analyzers/ownership-oracle.js';
import { buildAuthProbes } from '../../cli-tool/src/detectors/auth-tests.js';

const cfg = {
  auth: { header: 'Authorization', scheme: 'Bearer' },
  ownership: {
    fields: ['ownerId', 'userId', 'accountId', 'createdBy', 'owner'],
    publicIndicators: [{ field: 'visibility', equals: 'public' }],
  },
};

test('ownership extraction finds nested and dotted owner identifiers', () => {
  const payload = { data: { invoice: { id: 7005, billing: { accountId: 3 } } } };
  const res = extractOwnership(payload, cfg.ownership.fields);
  assert.deepEqual(res.ids, ['3']);
  assert.equal(res.matches[0].path, 'data.invoice.billing.accountId');

  const dotted = extractOwnership(payload, [], ['data.invoice.billing.accountId']);
  assert.deepEqual(dotted.ids, ['3']);
});

test('public indicators and soft denials are detected', () => {
  assert.equal(matchesPublicIndicator({ id: 'doc-3-public', ownerId: 3, visibility: 'public' }, cfg.ownership.publicIndicators), true);
  assert.equal(matchesPublicIndicator({ id: 'doc-3-private', ownerId: 3, visibility: 'private' }, cfg.ownership.publicIndicators), false);
  assert.equal(isSoftDenial({ isJson: true, body: { success: false, error: 'denied' } }), true);
  assert.equal(isSoftDenial({ isJson: true, body: { success: true } }), false);
});

test('TN pattern: public document is flagged by status-only but denied by ownership-differential', () => {
  const tc = {
    category: 'BOLA',
    operation: { method: 'GET', path: '/api/documents/{documentId}' },
    attacker: { account: 'alice', role: 'user', identity: '2' },
    victim: { account: 'bob', role: 'user', identity: '3' },
    expected: 'Owner only',
  };
  const exec = {
    attackerRes: { status: 200, isJson: true, body: { id: 'doc-3-public', ownerId: 3, visibility: 'public' } },
  };
  assert.equal(evaluateStatusOnly(tc, exec).verdict, 'vulnerable');
  assert.equal(evaluateOwnershipDifferential(tc, exec, cfg).verdict, 'denied');
});

test('TN pattern: endpoint ignoring path id and returning caller data is denied by ownership-differential', () => {
  const tc = {
    category: 'BOLA',
    operation: { method: 'GET', path: '/api/accounts/{accountId}/summary' },
    attacker: { account: 'alice', role: 'user', identity: '2' },
    victim: { account: 'bob', role: 'user', identity: '3' },
    expected: 'Owner only',
  };
  const exec = {
    attackerRes: { status: 200, isJson: true, body: { accountId: 2, username: 'alice', orderCount: 2 } },
  };
  assert.equal(evaluateStatusOnly(tc, exec).verdict, 'vulnerable');
  assert.equal(evaluateOwnershipDifferential(tc, exec, cfg).verdict, 'denied');
});

test('TN pattern: soft denial (200 {success:false}) is flagged by status-only but denied by ownership-differential', () => {
  const tc = {
    category: 'BOLA',
    operation: { method: 'DELETE', path: '/api/documents/{documentId}' },
    attacker: { account: 'alice', role: 'user', identity: '2' },
    victim: { account: 'bob', role: 'user', identity: '3' },
    expected: 'Owner only',
  };
  const exec = {
    attackerRes: { status: 200, isJson: true, body: { success: false, error: 'Not allowed' } },
  };
  assert.equal(evaluateStatusOnly(tc, exec).verdict, 'vulnerable');
  assert.equal(evaluateOwnershipDifferential(tc, exec, cfg).verdict, 'denied');
});

test('TN pattern: 202 Accepted without state change is flagged by status-only but denied by ownership-differential', () => {
  const tc = {
    category: 'BOLA',
    operation: { method: 'PUT', path: '/api/devices/{deviceId}/config' },
    attacker: { account: 'alice', role: 'user', identity: '2' },
    victim: { account: 'bob', role: 'user', identity: '3' },
    expected: 'Owner only',
  };
  const exec = {
    attackerRes: { status: 202, isJson: true, body: { status: 'queued' } },
    ownerBeforeRes: { status: 200, isJson: true, body: { deviceId: 'dev-003-a', config: { label: 'default' } } },
    ownerAfterRes: { status: 200, isJson: true, body: { deviceId: 'dev-003-a', config: { label: 'default' } } },
  };
  assert.equal(evaluateStatusOnly(tc, exec).verdict, 'vulnerable');
  assert.equal(evaluateOwnershipDifferential(tc, exec, cfg).verdict, 'denied');
});

test('TN pattern: role-filtered admin view is flagged by status-only but denied by ownership-differential', () => {
  const tc = {
    category: 'BFLA',
    operation: { method: 'GET', path: '/api/admin/reports' },
    attacker: { account: 'alice', role: 'user', identity: '2' },
    expected: 'Admin only',
  };
  const exec = {
    attackerRes: { status: 200, isJson: true, body: { scope: 'self', reports: [] } },
    ownerBaselineRes: { status: 200, isJson: true, body: { scope: 'global', reports: [{ ownerId: 2, revenue: 50 }] } },
  };
  assert.equal(isRoleFilteredEmptyView(exec.attackerRes, exec.ownerBaselineRes), true);
  assert.equal(evaluateStatusOnly(tc, exec).verdict, 'vulnerable');
  assert.equal(evaluateOwnershipDifferential(tc, exec, cfg).verdict, 'denied');
});

test('TP pattern: BOLA read without owner ID is confirmed via owner baseline comparison', () => {
  const tc = {
    category: 'BOLA',
    operation: { method: 'GET', path: '/api/devices/{deviceId}/readings' },
    attacker: { account: 'alice', role: 'user', identity: '2' },
    victim: { account: 'bob', role: 'user', identity: '3' },
    expected: 'Owner only',
  };
  const exec = {
    attackerRes: { status: 200, isJson: true, body: { deviceId: 'dev-003-a', readings: [{ value: 23 }] } },
    ownerBaselineRes: { status: 200, isJson: true, body: { deviceId: 'dev-003-a', readings: [{ value: 23 }] } },
  };
  const res = evaluateOwnershipDifferential(tc, exec, cfg);
  assert.equal(res.verdict, 'vulnerable');
  assert.equal(res.status, 'confirmed');
});

test('auth probes build all 5 categories when jwtSecret is provided and skip JWT_EXPIRED without it', () => {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify({ sub: '2', role: 'user' })).toString('base64url');
  const token = `${h}.${p}.sig`;

  const withoutSecret = buildAuthProbes({ auth: { header: 'Authorization', scheme: 'Bearer' } }, { token });
  assert.equal(withoutSecret.length, 5);
  assert.ok(withoutSecret.find((x) => x.category === 'JWT_EXPIRED').skipReason);

  const withSecret = buildAuthProbes({ auth: { header: 'Authorization', scheme: 'Bearer', jwtSecret: 'test-only' } }, { token });
  assert.equal(withSecret.find((x) => x.category === 'JWT_EXPIRED').skipReason, undefined);
  assert.ok(withSecret.find((x) => x.category === 'JWT_EXPIRED').headers.Authorization.startsWith('Bearer '));
});
