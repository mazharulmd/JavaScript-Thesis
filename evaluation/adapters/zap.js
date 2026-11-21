#!/usr/bin/env node
/**
 * Converts an OWASP ZAP JSON report (zap-*-scan.py -J, "traditional-json") into the
 * findings format so ZAP can be scored against the same ground truth.
 *
 * Mapping rules (documented in evaluation/README.md, decided before running ZAP):
 *  - An alert instance is mapped to an OpenAPI operation by matching its URI path against
 *    the spec's path templates and its HTTP method.
 *  - Only alerts whose CWE denotes an access-control or authentication weakness are mapped
 *    to a category; all other alerts (missing headers, info leaks, injection, ...) are kept
 *    in `outOfScope` and are NOT scored, because the ground truth only covers access control.
 *      CWE-639                         -> BOLA  (authorization bypass through user-controlled key)
 *      CWE-284/285/862/863             -> BOLA if the path has a parameter, else BFLA
 *      CWE-287/306                     -> AUTH_MISSING
 *      CWE-347                         -> JWT_SIGNATURE
 *      CWE-613                         -> JWT_EXPIRED
 *  - Status: ZAP confidence High (3) / Confirmed (4) -> confirmed, otherwise potential.
 *  - Severity: ZAP riskcode 3/2/1/0 -> high/medium/low/info.
 *
 * Usage: node evaluation/adapters/zap.js --zap zap.json --spec test-api/openapi.yaml --out zap-findings.json
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { parse } from 'yaml';

const CWE_MAP = { 639: 'BOLA', 284: 'AC', 285: 'AC', 862: 'AC', 863: 'AC', 287: 'AUTH_MISSING', 306: 'AUTH_MISSING', 347: 'JWT_SIGNATURE', 613: 'JWT_EXPIRED' };
const RISK = { 3: 'high', 2: 'medium', 1: 'low', 0: 'info' };

/** Builds matchers that turn a concrete URL path into its OpenAPI path template. */
export function templateMatchers(spec) {
  return Object.keys(spec.paths)
    .map((tpl) => ({ tpl, re: new RegExp(`^${tpl.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\\?\{[^}]+\\?\}/g, '[^/]+')}/?$`), params: (tpl.match(/\{/g) ?? []).length }))
    // prefer the most specific template (fewest parameters) when several match
    .sort((a, b) => a.params - b.params);
}

export function matchTemplate(matchers, urlPath) {
  return matchers.find((m) => m.re.test(urlPath))?.tpl ?? null;
}

export function convertZapReport(zap, spec, { source = 'zap' } = {}) {
  const matchers = templateMatchers(spec);
  const findings = [];
  const outOfScope = [];
  const seen = new Set();
  for (const site of zap.site ?? []) {
    for (const alert of site.alerts ?? []) {
      const cwe = Number(alert.cweid);
      const mapped = CWE_MAP[cwe];
      for (const inst of alert.instances ?? [{ uri: site['@name'], method: 'GET' }]) {
        let urlPath;
        try { urlPath = new URL(inst.uri).pathname; } catch { urlPath = inst.uri; }
        const path = matchTemplate(matchers, urlPath);
        const method = String(inst.method ?? 'GET').toUpperCase();
        if (!mapped || !path) {
          outOfScope.push({ alert: alert.alert ?? alert.name, pluginId: alert.pluginid, cwe: cwe || null, risk: RISK[alert.riskcode] ?? 'info', method, uri: inst.uri, reason: !mapped ? 'CWE not access-control related' : 'URI not in specification' });
          continue;
        }
        const category = mapped === 'AC' ? (path.includes('{') ? 'BOLA' : 'BFLA') : mapped;
        const key = `${method} ${path} ${category} ${alert.pluginid}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: `ZAP-${String(findings.length + 1).padStart(4, '0')}`,
          category,
          severity: RISK[alert.riskcode] ?? 'info',
          status: Number(alert.confidence) >= 3 ? 'confirmed' : 'potential',
          method,
          path,
          expected: 'See ground truth.',
          observed: `${alert.alert ?? alert.name} (ZAP plugin ${alert.pluginid}, CWE-${cwe})`,
          evidence: { notes: [String(alert.desc ?? '').replace(/<[^>]+>/g, '').slice(0, 500)], request: { method, url: inst.uri } },
        });
      }
    }
  }
  return {
    meta: { tool: 'OWASP ZAP', version: zap['@version'] ?? null, mode: 'zap-api-scan', source, generated: zap['@generated'] ?? null },
    findings,
    outOfScope,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { values } = parseArgs({ options: { zap: { type: 'string' }, spec: { type: 'string' }, out: { type: 'string' }, 'duration-ms': { type: 'string' } } });
  if (!values.zap || !values.spec || !values.out) {
    console.error('Usage: zap.js --zap <zap.json> --spec <openapi.yaml> --out <findings.json> [--duration-ms N]');
    process.exit(2);
  }
  const doc = convertZapReport(JSON.parse(readFileSync(values.zap, 'utf8')), parse(readFileSync(values.spec, 'utf8')), { source: values.zap });
  if (values['duration-ms']) doc.meta.durationMs = Number(values['duration-ms']);
  writeFileSync(values.out, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`ZAP alerts converted: ${doc.findings.length} access-control findings, ${doc.outOfScope.length} out-of-scope alert instances.`);
}
