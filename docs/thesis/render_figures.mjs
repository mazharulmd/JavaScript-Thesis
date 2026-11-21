#!/usr/bin/env node
/**
 * Rasterises the thesis figures to PNG (docs/thesis/figures/*.png) with Playwright/Chromium.
 * Sources: docs/thesis/figures/architecture.svg and the archived comparison charts in
 * evaluation/results/. The PNGs are committed, so build_thesis_draft.py does not need a browser.
 *
 * Usage: node docs/thesis/render_figures.mjs
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

// Playwright is used from the global/preinstalled package (it is not a project dependency).
const { chromium } = createRequire(import.meta.url)('playwright');

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIG = join(ROOT, 'docs', 'thesis', 'figures');
const SOURCES = {
  'fig-architecture.png': 'docs/thesis/figures/architecture.svg',
  'fig-benchmark-primary.png': 'evaluation/results/2026-11-21-scanner-test-api/comparison/chart-primary.svg',
  'fig-benchmark-overall.png': 'evaluation/results/2026-11-21-scanner-test-api/comparison/chart-overall.svg',
  'fig-vampi-primary.png': 'evaluation/results/2026-11-21-scanner-vampi/comparison/chart-primary.svg',
};

const browser = await chromium.launch();
const page = await browser.newPage({ deviceScaleFactor: 3 });
for (const [out, src] of Object.entries(SOURCES)) {
  const svg = readFileSync(join(ROOT, src), 'utf8');
  const [, w, h] = svg.match(/viewBox="0 0 (\d+(?:\.\d+)?) (\d+(?:\.\d+)?)"/);
  await page.setViewportSize({ width: Math.ceil(Number(w)), height: Math.ceil(Number(h)) });
  await page.setContent(`<!doctype html><html><body style="margin:0">${svg}</body></html>`);
  await page.locator('svg').first().screenshot({ path: join(FIG, out) });
  console.log(`Wrote docs/thesis/figures/${out}`);
}
await browser.close();
