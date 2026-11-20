import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateFindingsDocument, summarize, exceedsThreshold } from '../../cli-tool/src/reporting/findings-format.js';
import { redactDocument, redactHeaders, truncate } from '../../cli-tool/src/reporting/redact.js';
import { renderHtmlReport } from '../../cli-tool/src/reporting/html-report.js';
import { writeReports } from '../../cli-tool/src/reporting/index.js';
import { main } from '../../cli-tool/src/cli.js';

const fixturePath = new URL('../fixtures/sample-findings.json', import.meta.url);
const fixture = () => JSON.parse(readFileSync(fixturePath, 'utf8'));

test('the sample document is valid', () => {
  assert.deepEqual(validateFindingsDocument(fixture()), []);
});

test('validation reports missing and invalid fields', () => {
  const doc = fixture();
  doc.findings.push({ ...doc.findings[0] });
  doc.findings[1].category = 'XSS';
  doc.findings[1].confidence = 3;
  const problems = validateFindingsDocument(doc);
  assert.ok(problems.some((p) => p.includes('duplicated')));
  assert.ok(problems.some((p) => p.includes('category')));
  assert.ok(problems.some((p) => p.includes('confidence')));
  assert.deepEqual(validateFindingsDocument(null), ['document must be a JSON object']);
});

test('summary counts by status, severity and category', () => {
  const s = summarize(fixture());
  assert.equal(s.totalFindings, 2);
  assert.equal(s.byStatus.confirmed, 1);
  assert.equal(s.byStatus.potential, 1);
  assert.equal(s.byCategory.BOLA, 1);
  assert.equal(s.confirmedBySeverity.high, 1);
  assert.equal(s.totalRequests, 42);
});

test('severity gate only counts confirmed findings', () => {
  const doc = fixture();
  assert.equal(exceedsThreshold(doc, 'high'), true);
  assert.equal(exceedsThreshold(doc, 'critical'), false);
  assert.equal(exceedsThreshold(doc, 'none'), false);
  doc.findings[0].status = 'potential';
  assert.equal(exceedsThreshold(doc, 'info'), false);
  assert.throws(() => exceedsThreshold(doc, 'severe'));
});

test('redaction removes tokens, passwords and authorization headers', () => {
  const out = JSON.stringify(redactDocument(fixture()));
  assert.ok(!out.includes('eyJhbGciOiJIUzI1NiJ9'), 'JWT must be redacted');
  assert.ok(!out.includes('Alice#2026'), 'password must be redacted');
  assert.ok(!out.includes('"abc"'), 'token field must be redacted');
  assert.deepEqual(redactHeaders({ Authorization: 'Bearer xyz', Accept: 'json' }), { Authorization: 'Bearer [REDACTED]', Accept: 'json' });
});

test('truncate shortens long bodies', () => {
  assert.equal(truncate('abc', 10), 'abc');
  assert.match(truncate('x'.repeat(50), 10), /truncated 40 characters/);
});

test('HTML report is standalone and escapes response content', () => {
  const html = renderHtmlReport(redactDocument(fixture()));
  assert.ok(html.startsWith('<!doctype html>'));
  assert.ok(!html.includes('<script>alert(1)</script>'), 'response content must be escaped');
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!/<script\b/i.test(html), 'report must contain no scripts');
  assert.ok(!/(src|href)=["']https?:/i.test(html), 'report must load no external resources');
  assert.ok(html.includes('F-0001') && html.includes('/api/orders/{orderId}'));
});

test('writeReports writes redacted JSON (with summary) and HTML', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bac-report-'));
  const { json, html } = writeReports(fixture(), { outDir: dir, baseName: 'fixture' });
  assert.ok(existsSync(json) && existsSync(html));
  const written = JSON.parse(readFileSync(json, 'utf8'));
  assert.equal(written.summary.totalFindings, 2);
  assert.equal(written.meta.formatVersion, '1.0');
  assert.ok(!readFileSync(json, 'utf8').includes('Alice#2026'));
});

test('CLI exit codes: 1 when the gate trips, 0 when it does not, 2 on bad input', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bac-cli-'));
  const quiet = (fn) => { const l = console.log; const e = console.error; console.log = () => {}; console.error = () => {}; try { return fn(); } finally { console.log = l; console.error = e; } };
  const input = fixturePath.pathname;
  assert.equal(quiet(() => main(['report', '--input', input, '--out-dir', dir, '--fail-on', 'high'])), 1);
  assert.equal(quiet(() => main(['report', '--input', input, '--out-dir', dir, '--fail-on', 'critical'])), 0);
  assert.equal(quiet(() => main(['validate', '--input', input])), 0);
  assert.equal(quiet(() => main(['report', '--input', '/nonexistent.json'])), 2);
  assert.equal(quiet(() => main(['report'])), 2);
  assert.equal(quiet(() => main(['bogus'])), 2);
});
