import { summarize, SEVERITIES, CATEGORIES } from './findings-format.js';
import { truncate } from './redact.js';

/**
 * Renders a findings document as ONE self-contained HTML file (inline CSS, no scripts,
 * no external resources) so it can be archived as a CI artifact or thesis appendix.
 * The document must already be redacted (see redact.js).
 */
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const CATEGORY_LABELS = {
  BOLA: 'Broken Object Level Authorization',
  BFLA: 'Broken Function Level Authorization',
  AUTH_MISSING: 'Missing authentication',
  AUTH_INVALID_TOKEN: 'Malformed token accepted',
  JWT_SIGNATURE: 'JWT signature not verified',
  JWT_NONE_ALG: 'Unsigned JWT (alg none) accepted',
  JWT_EXPIRED: 'Expired JWT accepted',
};

function pretty(body) {
  if (body === undefined || body === null || body === '') return '';
  if (typeof body === 'string') {
    try { return truncate(JSON.stringify(JSON.parse(body), null, 2)); } catch { return truncate(body); }
  }
  return truncate(JSON.stringify(body, null, 2));
}

function exchangeBlock(label, ex) {
  if (!ex) return '';
  const req = ex.request ?? {};
  const res = ex.response ?? {};
  const reqHeaders = Object.entries(req.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  const resHeaders = Object.entries(res.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  return `
    <div class="exchange">
      <h4>${esc(label)}${ex.account ? ` <span class="muted">as ${esc(ex.account)}${ex.role ? ` (${esc(ex.role)})` : ''}</span>` : ''}</h4>
      <div class="cols">
        <div><div class="label">Request</div><pre>${esc(`${req.method ?? ''} ${req.url ?? ''}`)}${reqHeaders ? `\n${esc(reqHeaders)}` : ''}${req.body !== undefined ? `\n\n${esc(pretty(req.body))}` : ''}</pre></div>
        <div><div class="label">Response</div><pre>${esc(res.status !== undefined ? `HTTP ${res.status}` : '')}${resHeaders ? `\n${esc(resHeaders)}` : ''}${res.body !== undefined ? `\n\n${esc(pretty(res.body))}` : ''}</pre></div>
      </div>
    </div>`;
}

function findingCard(f) {
  const ev = f.evidence ?? {};
  const exchanges = ev.exchanges ?? (ev.request || ev.response ? [{ label: 'Evidence', request: ev.request, response: ev.response }] : []);
  return `
  <details class="finding sev-${esc(f.severity)}" id="${esc(f.id)}">
    <summary>
      <span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span>
      <span class="badge status-${esc(f.status)}">${esc(f.status)}</span>
      <code>${esc(f.method)} ${esc(f.path)}</code>
      <span class="cat">${esc(f.category)}</span>
      <span class="fid muted">${esc(f.id)}</span>
    </summary>
    <dl>
      <dt>Category</dt><dd>${esc(CATEGORY_LABELS[f.category] ?? f.category)}</dd>
      ${f.resource ? `<dt>Affected resource</dt><dd><code>${esc(typeof f.resource === 'string' ? f.resource : JSON.stringify(f.resource))}</code></dd>` : ''}
      ${f.attacker ? `<dt>Acting identity</dt><dd>${esc(f.attacker.account ?? '')} ${f.attacker.role ? `(${esc(f.attacker.role)})` : ''}</dd>` : ''}
      ${f.victim ? `<dt>Resource owner</dt><dd>${esc(f.victim.account ?? '')} ${f.victim.role ? `(${esc(f.victim.role)})` : ''}</dd>` : ''}
      <dt>Expected behaviour</dt><dd>${esc(f.expected ?? '')}</dd>
      <dt>Observed behaviour</dt><dd>${esc(f.observed ?? '')}</dd>
      ${f.confidence !== undefined ? `<dt>Confidence</dt><dd>${esc((f.confidence * 100).toFixed(0))}%</dd>` : ''}
      ${f.timestamp ? `<dt>Timestamp</dt><dd>${esc(f.timestamp)}</dd>` : ''}
      ${(ev.notes ?? []).length ? `<dt>Analysis</dt><dd><ul>${ev.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul></dd>` : ''}
    </dl>
    ${exchanges.map((x, i) => exchangeBlock(x.label ?? `Exchange ${i + 1}`, x)).join('')}
  </details>`;
}

export function renderHtmlReport(doc) {
  const s = summarize(doc);
  const meta = doc.meta ?? {};
  const findings = [...(doc.findings ?? [])].sort((a, b) =>
    ['confirmed', 'potential', 'inconclusive'].indexOf(a.status) - ['confirmed', 'potential', 'inconclusive'].indexOf(b.status)
    || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
    || a.path.localeCompare(b.path));
  const metaRows = [
    ['Tool', `${meta.tool ?? ''} ${meta.version ?? ''}`],
    ['Detection mode', meta.mode],
    ['Target', meta.target],
    ['Specification', meta.spec],
    ['Started', meta.startedAt],
    ['Finished', meta.finishedAt],
    ['Duration', s.durationMs !== null ? `${(s.durationMs / 1000).toFixed(2)} s` : undefined],
    ['Scan ID', meta.scanId],
  ].filter(([, v]) => v !== undefined && v !== null && v !== '');

  const catRows = CATEGORIES.filter((c) => s.byCategory[c] > 0).map((c) => {
    const inCat = (doc.findings ?? []).filter((f) => f.category === c);
    return `<tr><td>${esc(c)}</td><td>${esc(CATEGORY_LABELS[c])}</td><td class="num">${inCat.filter((f) => f.status === 'confirmed').length}</td><td class="num">${inCat.filter((f) => f.status === 'potential').length}</td><td class="num">${inCat.filter((f) => f.status === 'inconclusive').length}</td></tr>`;
  }).join('');

  const card = (label, value, cls = '') => `<div class="card ${cls}"><div class="value">${esc(value ?? '–')}</div><div class="label">${esc(label)}</div></div>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Control Scan Report</title>
<style>
  :root { --bg:#fbfbfa; --panel:#ffffff; --text:#1d1f23; --muted:#646a73; --border:#e2e4e8; --code:#f3f4f6;
          --critical:#9b1c1c; --high:#c2410c; --medium:#a16207; --low:#1d4ed8; --info:#4b5563; --ok:#15803d; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#16181c; --panel:#1e2126; --text:#e6e7ea; --muted:#9aa0a9; --border:#30343b; --code:#262a30;
            --critical:#f87171; --high:#fb923c; --medium:#facc15; --low:#60a5fa; --info:#9ca3af; --ok:#4ade80; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 1100px; margin: 0 auto; padding: 32px 16px 64px; }
  h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 19px; margin: 36px 0 12px; } h4 { margin: 14px 0 6px; font-size: 14px; }
  .muted { color: var(--muted); font-weight: normal; }
  table { width:100%; border-collapse: collapse; background: var(--panel); border:1px solid var(--border); border-radius: 8px; overflow:hidden; }
  th, td { text-align:left; padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { font-size: 13px; color: var(--muted); font-weight: 600; } td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  .cards { display:grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
  .card { background: var(--panel); border:1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
  .card .value { font-size: 26px; font-weight: 650; font-variant-numeric: tabular-nums; } .card .label { color: var(--muted); font-size: 13px; }
  .card.alert .value { color: var(--critical); } .card.good .value { color: var(--ok); }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
  pre { background: var(--code); padding: 10px 12px; border-radius: 6px; overflow-x:auto; white-space: pre-wrap; word-break: break-word; margin:0; }
  .finding { background: var(--panel); border:1px solid var(--border); border-left: 4px solid var(--info); border-radius: 8px; margin: 10px 0; padding: 0 16px; }
  .finding.sev-critical { border-left-color: var(--critical); } .finding.sev-high { border-left-color: var(--high); }
  .finding.sev-medium { border-left-color: var(--medium); } .finding.sev-low { border-left-color: var(--low); }
  summary { cursor: pointer; padding: 12px 0; display:flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .badge { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; padding: 2px 8px; border-radius: 999px; border: 1px solid currentColor; }
  .badge.sev-critical { color: var(--critical); } .badge.sev-high { color: var(--high); } .badge.sev-medium { color: var(--medium); }
  .badge.sev-low { color: var(--low); } .badge.sev-info { color: var(--info); }
  .badge.status-confirmed { color: var(--text); } .badge.status-potential, .badge.status-inconclusive { color: var(--muted); border-style: dashed; }
  .cat { font-weight: 600; } .fid { margin-left: auto; font-size: 12px; }
  dl { display:grid; grid-template-columns: 180px 1fr; gap: 6px 16px; margin: 4px 0 12px; } dt { color: var(--muted); } dd { margin: 0; }
  dd ul { margin: 0; padding-left: 18px; }
  .cols { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; } .label { color: var(--muted); font-size: 12px; margin-bottom: 4px; }
  .exchange { margin-bottom: 14px; }
  .notice { background: var(--panel); border:1px solid var(--border); border-radius: 8px; padding: 12px 16px; color: var(--muted); font-size: 13px; }
  @media (max-width: 700px) { .cols { grid-template-columns: 1fr; } dl { grid-template-columns: 1fr; } .fid { margin-left: 0; } }
</style>
</head>
<body>
<main>
  <h1>Access Control Scan Report</h1>
  <div class="muted">${esc(meta.target ?? '')}${meta.mode ? ` · ${esc(meta.mode)} mode` : ''}</div>

  <h2>Summary</h2>
  <div class="cards">
    ${card('Confirmed findings', s.byStatus.confirmed, s.byStatus.confirmed > 0 ? 'alert' : 'good')}
    ${card('Potential findings', s.byStatus.potential)}
    ${card('Inconclusive', s.byStatus.inconclusive)}
    ${card('Endpoints tested', s.endpointsTested)}
    ${card('HTTP requests', s.totalRequests)}
    ${card('Duration (s)', s.durationMs !== null ? (s.durationMs / 1000).toFixed(2) : null)}
  </div>

  <h2>Findings by category</h2>
  ${catRows ? `<table><thead><tr><th>Category</th><th>Description</th><th class="num">Confirmed</th><th class="num">Potential</th><th class="num">Inconclusive</th></tr></thead><tbody>${catRows}</tbody></table>` : '<div class="notice">No findings were reported.</div>'}

  <h2>Confirmed findings by severity</h2>
  <table><thead><tr>${SEVERITIES.map((v) => `<th class="num">${esc(v)}</th>`).join('')}</tr></thead>
  <tbody><tr>${SEVERITIES.map((v) => `<td class="num">${s.confirmedBySeverity[v]}</td>`).join('')}</tr></tbody></table>

  <h2>Findings (${findings.length})</h2>
  ${findings.map(findingCard).join('') || '<div class="notice">No findings.</div>'}

  <h2>Scan metadata</h2>
  <table><tbody>${metaRows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('')}</tbody></table>
  <p class="notice">Credentials and tokens are redacted from this report. Generated ${esc(new Date().toISOString())}.</p>
</main>
</body>
</html>
`;
}
