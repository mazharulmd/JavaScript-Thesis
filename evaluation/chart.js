/**
 * Static SVG grouped bar chart for thesis figures (light theme, print-friendly).
 * Colors: reference categorical slots 1-3 (validated all-pairs; slot 3 needs a table
 * view for contrast relief - compare.js always writes the same numbers to comparison.md).
 */
const SERIES_COLORS = ['#2a78d6', '#eb6834', '#1baf7a'];
const TEXT = '#0b0b0b';
const MUTED = '#52514e';
const GRID = '#e4e3df';
const SURFACE = '#fcfcfb';

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

/**
 * @param {{title:string, subtitle?:string, groups:string[], series:Array<{name:string, values:(number|null)[]}>}} data
 *   values are in [0,1]; null renders an "n/a" marker (metric undefined).
 */
export function groupedBarChart({ title, subtitle = '', groups, series }) {
  if (series.length > SERIES_COLORS.length) throw new Error('At most 3 series (validated palette slots); facet instead.');
  const W = 760, H = 420, m = { top: 84, right: 24, bottom: 56, left: 56 };
  const pw = W - m.left - m.right, ph = H - m.top - m.bottom;
  const groupW = pw / groups.length;
  const gap = 2; // surface gap between adjacent bars
  const barW = Math.min(36, (groupW * 0.7 - gap * (series.length - 1)) / series.length);
  const clusterW = barW * series.length + gap * (series.length - 1);
  const y = (v) => m.top + ph - v * ph;
  const r = Math.min(4, barW / 2);

  const grid = [0, 0.25, 0.5, 0.75, 1].map((t) => `
    <line x1="${m.left}" x2="${W - m.right}" y1="${y(t)}" y2="${y(t)}" stroke="${t === 0 ? MUTED : GRID}" stroke-width="1"/>
    <text x="${m.left - 8}" y="${y(t) + 4}" text-anchor="end" font-size="12" fill="${MUTED}">${t.toFixed(2)}</text>`).join('');

  const bars = groups.map((g, gi) => {
    const x0 = m.left + gi * groupW + (groupW - clusterW) / 2;
    const cells = series.map((s, si) => {
      const v = s.values[gi];
      const x = x0 + si * (barW + gap);
      if (v === null || v === undefined) {
        return `<text x="${x + barW / 2}" y="${y(0) - 6}" text-anchor="middle" font-size="10" fill="${MUTED}">n/a<title>${esc(s.name)} - ${esc(g)}: undefined</title></text>`;
      }
      const h = Math.max(0, v * ph);
      const top = y(v);
      // rounded data-end (top), square at the baseline
      const path = h < r
        ? `M${x},${y(0)} h${barW} v${-h} h${-barW} Z`
        : `M${x},${y(0)} v${-(h - r)} q0,${-r} ${r},${-r} h${barW - 2 * r} q${r},0 ${r},${r} v${h - r} Z`;
      return `<path d="${path}" fill="${SERIES_COLORS[si]}"><title>${esc(s.name)} - ${esc(g)}: ${v.toFixed(3)}</title></path>` +
        (h === 0 ? `<rect x="${x}" y="${top - 1}" width="${barW}" height="2" fill="${SERIES_COLORS[si]}"/>` : '');
    }).join('');
    return `${cells}<text x="${m.left + gi * groupW + groupW / 2}" y="${H - m.bottom + 22}" text-anchor="middle" font-size="13" fill="${TEXT}">${esc(g)}</text>`;
  }).join('');

  let lx = m.left;
  const legend = series.map((s, si) => {
    const item = `<rect x="${lx}" y="52" width="12" height="12" rx="2" fill="${SERIES_COLORS[si]}"/><text x="${lx + 18}" y="62" font-size="13" fill="${TEXT}">${esc(s.name)}</text>`;
    lx += 30 + s.name.length * 7.2;
    return item;
  }).join('');

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" font-family="system-ui, -apple-system, 'Segoe UI', sans-serif" role="img" aria-label="${esc(title)}">
  <rect width="${W}" height="${H}" fill="${SURFACE}"/>
  <text x="${m.left}" y="26" font-size="16" font-weight="600" fill="${TEXT}">${esc(title)}</text>
  <text x="${m.left}" y="44" font-size="12" fill="${MUTED}">${esc(subtitle)}</text>
  ${legend}
  ${grid}
  ${bars}
</svg>
`;
}
