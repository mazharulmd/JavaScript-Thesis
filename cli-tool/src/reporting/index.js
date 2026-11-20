import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { validateFindingsDocument, FORMAT_VERSION, summarize } from './findings-format.js';
import { redactDocument } from './redact.js';
import { renderHtmlReport } from './html-report.js';

/**
 * Writes the JSON and HTML reports for a findings document.
 * The document is validated and redacted first; the written JSON includes the summary.
 * @returns {{ json: string, html: string, summary: object }}
 */
export function writeReports(doc, { outDir = 'reports', baseName } = {}) {
  const problems = validateFindingsDocument(doc);
  if (problems.length) throw new Error(`Invalid findings document:\n - ${problems.join('\n - ')}`);
  const safe = redactDocument(doc);
  safe.meta = { formatVersion: FORMAT_VERSION, ...safe.meta };
  safe.summary = summarize(safe);
  const name = baseName ?? `scan-${(safe.meta.scanId ?? new Date().toISOString()).replace(/[^A-Za-z0-9_-]/g, '-')}`;
  mkdirSync(join(outDir, 'json'), { recursive: true });
  mkdirSync(join(outDir, 'html'), { recursive: true });
  const json = join(outDir, 'json', `${name}.json`);
  const html = join(outDir, 'html', `${name}.html`);
  writeFileSync(json, `${JSON.stringify(safe, null, 2)}\n`);
  writeFileSync(html, renderHtmlReport(safe));
  return { json, html, summary: safe.summary };
}

export { validateFindingsDocument, summarize, redactDocument, renderHtmlReport };
export { exceedsThreshold } from './findings-format.js';
