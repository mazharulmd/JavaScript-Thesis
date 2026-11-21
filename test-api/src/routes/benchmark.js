import { Router } from 'express';

/** Operational endpoints: health check and (benchmark mode only) state reset. Not part of the OpenAPI spec under test except /health. */
export function benchmarkRoutes({ store, config, flaws }) {
  const r = Router();
  r.get('/health', (_req, res) => res.json({ status: 'ok', flawsMode: flaws.mode }));
  if (config.benchmarkMode) {
    // Restores the deterministic seed so that every experiment run starts from identical state.
    r.post('/__benchmark/reset', (_req, res) => {
      store.reset();
      res.json({ reset: true, flaws: flaws.list() });
    });
  }
  return r;
}
