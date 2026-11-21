#!/usr/bin/env node
/**
 * bac-scanner command-line interface.
 *
 *   report   Validate a findings document and render redacted JSON + HTML reports.
 *            Exit codes (CI gate): 0 = OK, 1 = confirmed finding at/above --fail-on,
 *            2 = usage or input error.
 *   validate Validate a findings document only.
 *   preflight Check spec + configuration, log in every account and print the
 *            operation inventory and the role/policy matrix. Sends only the login
 *            requests. Exit codes: 0 = ready, 2 = invalid input, 3 = target/login failure.
 */
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { writeFileSync } from 'node:fs';
import { writeReports, validateFindingsDocument, exceedsThreshold } from './reporting/index.js';
import { runPreflight, printPreflight } from './preflight.js';

const USAGE = `Usage:
  bac-scanner report    --input <findings.json> [--out-dir reports] [--name <base>] [--fail-on critical|high|medium|low|info|none]
  bac-scanner validate  --input <findings.json>
  bac-scanner preflight --spec <openapi.yaml> --config <config.yaml> [--target <url>] [--json <out.json>]`;

function load(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`Cannot read findings file ${path}: ${err.message}`);
  }
}

export async function main(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;
  let values;
  try {
    ({ values } = parseArgs({
      args: rest,
      options: {
        input: { type: 'string', short: 'i' },
        'out-dir': { type: 'string', short: 'o', default: 'reports' },
        name: { type: 'string' },
        'fail-on': { type: 'string', default: 'high' },
        spec: { type: 'string', short: 's' },
        config: { type: 'string', short: 'c' },
        target: { type: 'string', short: 't' },
        json: { type: 'string' },
        help: { type: 'boolean', short: 'h' },
      },
    }));
  } catch (err) {
    console.error(`${err.message}\n\n${USAGE}`);
    return 2;
  }
  if (!command || values.help || !['report', 'validate', 'preflight'].includes(command)) {
    console.error(USAGE);
    return values.help ? 0 : 2;
  }
  if (command === 'preflight') {
    if (!values.spec || !values.config) {
      console.error(`--spec and --config are required\n\n${USAGE}`);
      return 2;
    }
    const result = await runPreflight({ spec: values.spec, config: values.config, target: values.target });
    printPreflight(result);
    if (values.json) writeFileSync(values.json, `${JSON.stringify(result, null, 2)}\n`);
    return result.exitCode;
  }
  if (!values.input) {
    console.error(`--input is required\n\n${USAGE}`);
    return 2;
  }
  try {
    const doc = load(values.input);
    if (command === 'validate') {
      const problems = validateFindingsDocument(doc);
      if (problems.length) {
        console.error(`Invalid findings document:\n - ${problems.join('\n - ')}`);
        return 2;
      }
      console.log(`Valid findings document (${doc.findings.length} findings).`);
      return 0;
    }
    const { json, html, summary } = writeReports(doc, { outDir: values['out-dir'], baseName: values.name });
    console.log(`JSON report: ${json}\nHTML report: ${html}`);
    console.log(`Findings: ${summary.byStatus.confirmed} confirmed, ${summary.byStatus.potential} potential, ${summary.byStatus.inconclusive} inconclusive`);
    if (exceedsThreshold(doc, values['fail-on'])) {
      console.error(`FAIL: confirmed finding(s) at or above severity "${values['fail-on']}".`);
      return 1;
    }
    return 0;
  } catch (err) {
    console.error(err.message);
    return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main().then((code) => { process.exitCode = code; });
