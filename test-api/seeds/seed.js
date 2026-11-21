#!/usr/bin/env node
/**
 * Prints the reproducible benchmark test accounts and a summary of the seed data.
 * The data itself lives in src/data/seed-data.js and is loaded into memory on every
 * start and on POST /__benchmark/reset (BENCHMARK_MODE=1).
 *
 * Usage: node seeds/seed.js [--json]
 */
import { SEED_ACCOUNTS, buildSeed } from '../src/data/seed-data.js';

const seed = buildSeed();
const summary = Object.fromEntries(Object.entries(seed).map(([k, v]) => [k, v.length]));

if (process.argv.includes('--json')) {
  console.log(JSON.stringify({ accounts: SEED_ACCOUNTS, summary }, null, 2));
} else {
  console.log('Benchmark test accounts (synthetic, benchmark-only credentials):\n');
  console.table(SEED_ACCOUNTS.map(({ id, username, password, role }) => ({ id, username, password, role })));
  console.log('Seed record counts:');
  console.table(summary);
}
