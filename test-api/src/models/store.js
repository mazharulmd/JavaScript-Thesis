import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { SEED_ACCOUNTS, buildSeed } from '../data/seed-data.js';

/**
 * In-memory data store. Deliberately simple: the benchmark must be fast, deterministic and
 * resettable between experiment runs, so no external database is used.
 */
function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const hash = scryptSync(password, salt, 32).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const candidate = scryptSync(password, salt, 32);
  const expected = Buffer.from(hash, 'hex');
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

// Password hashes are computed once per process; the deterministic salt keeps resets cheap.
const SEED_HASHES = new Map(SEED_ACCOUNTS.map((u) => [u.id, hashPassword(u.password, `seed-salt-${u.id}`)]));

export function createStore() {
  const store = {};

  store.reset = () => {
    const seed = buildSeed();
    store.users = SEED_ACCOUNTS.map(({ password, ...u }) => ({
      ...u,
      passwordHash: SEED_HASHES.get(u.id),
      createdAt: '2026-11-01T08:00:00.000Z',
    }));
    Object.assign(store, seed);
    store.counters = {
      user: 100,
      order: 2001,
      invoice: 8001,
      document: 1,
      device: 1,
      product: 601,
      announcement: 2,
      ticket: 1,
      backup: 1,
    };
  };

  store.nextId = (kind) => store.counters[kind]++;
  store.hashPassword = hashPassword;
  store.verifyPassword = verifyPassword;

  store.findUser = (id) => store.users.find((u) => String(u.id) === String(id));
  store.findUserByUsername = (username) => store.users.find((u) => u.username === username);

  store.reset();
  return store;
}

/** Public representation of a user (never exposes the password hash). */
export function publicUser(u) {
  if (!u) return null;
  const { passwordHash, ...rest } = u;
  return rest;
}
