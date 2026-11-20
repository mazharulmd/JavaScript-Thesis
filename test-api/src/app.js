import express from 'express';
import { randomUUID } from 'node:crypto';
import { loadConfig } from './config.js';
import { createFlawSet } from './flaws.js';
import { createStore } from './models/store.js';
import { createAuth } from './middleware/auth.js';
import { notFoundHandler, errorHandler } from './middleware/errors.js';
import { authRoutes } from './routes/auth.js';
import { userRoutes } from './routes/users.js';
import { orderRoutes } from './routes/orders.js';
import { documentRoutes } from './routes/documents.js';
import { deviceRoutes } from './routes/devices.js';
import { productRoutes } from './routes/products.js';
import { adminRoutes } from './routes/admin.js';
import { miscRoutes } from './routes/misc.js';
import { benchmarkRoutes } from './routes/benchmark.js';

/**
 * Builds the Express application. Exported as a factory so integration tests can start
 * isolated instances (vulnerable or patched) on ephemeral ports without Docker.
 */
export function createApp(overrides = {}) {
  const config = { ...loadConfig(), ...overrides };
  const flaws = createFlawSet(config.flaws);
  const store = createStore();
  const auth = createAuth({ store, config, flaws });
  const ctx = { config, flaws, store, auth };

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '100kb' }));
  app.use((req, res, next) => {
    res.setHeader('X-Request-Id', randomUUID());
    if (config.logRequests) console.log(`[test-api] ${req.method} ${req.originalUrl}`);
    next();
  });

  for (const routes of [benchmarkRoutes, authRoutes, userRoutes, orderRoutes, documentRoutes, deviceRoutes, productRoutes, adminRoutes, miscRoutes]) {
    app.use(routes(ctx));
  }
  app.use(notFoundHandler);
  app.use(errorHandler);

  app.locals.ctx = ctx;
  return app;
}
