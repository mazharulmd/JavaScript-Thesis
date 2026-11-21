/**
 * Evaluation metrics for comparing detection results against a ground-truth manifest.
 *
 * A "case" is one (method, path, category) combination with a known label
 * (vulnerable: true/false). A tool "detects" a case when it reports at least one
 * finding that maps to that case.
 *
 * Zero denominators are handled explicitly: the metric is reported as `null`
 * (undefined) together with a note, never silently as 0 or 1.
 */

export function caseKey({ method, path, category }) {
  return `${String(method).toUpperCase()} ${path} ${category}`;
}

/** Safe division: returns null when the denominator is 0. */
export function ratio(numerator, denominator) {
  return denominator === 0 ? null : numerator / denominator;
}

/**
 * Builds a confusion matrix.
 * @param {Array<{method,path,category,vulnerable,applicable?}>} cases ground-truth cases
 * @param {Iterable<string>} detectedKeys case keys the tool flagged
 * @returns {{tp,fp,tn,fn,unlisted:string[],perCase:Array}}
 */
export function confusionMatrix(cases, detectedKeys) {
  const detected = new Set(detectedKeys);
  const known = new Set();
  let tp = 0, fp = 0, tn = 0, fn = 0;
  const perCase = [];
  for (const c of cases) {
    if (c.applicable === false) continue; // excluded from scoring (documented in the manifest)
    const key = caseKey(c);
    known.add(key);
    const hit = detected.has(key);
    let outcome;
    if (c.vulnerable && hit) { tp += 1; outcome = 'TP'; }
    else if (c.vulnerable && !hit) { fn += 1; outcome = 'FN'; }
    else if (!c.vulnerable && hit) { fp += 1; outcome = 'FP'; }
    else { tn += 1; outcome = 'TN'; }
    perCase.push({ id: c.id, key, vulnerable: !!c.vulnerable, detected: hit, outcome });
  }
  // Findings that match no ground-truth case are counted as false positives,
  // because the manifest is meant to be exhaustive for the benchmark.
  const unlisted = [...detected].filter((k) => !known.has(k));
  fp += unlisted.length;
  return { tp, fp, tn, fn, unlisted, perCase };
}

/** Derives precision, recall, F1, false-positive rate and accuracy from a matrix. */
export function computeMetrics({ tp, fp, tn, fn }) {
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const f1 = precision === null || recall === null || precision + recall === 0
    ? (precision === 0 && recall === 0 ? 0 : null)
    : (2 * precision * recall) / (precision + recall);
  const falsePositiveRate = ratio(fp, fp + tn);
  const accuracy = ratio(tp + tn, tp + tn + fp + fn);
  const notes = [];
  if (precision === null) notes.push('precision undefined: no positive detections (TP + FP = 0)');
  if (recall === null) notes.push('recall undefined: no vulnerable cases (TP + FN = 0)');
  if (falsePositiveRate === null) notes.push('false-positive rate undefined: no secure cases (FP + TN = 0)');
  return { tp, fp, tn, fn, precision, recall, f1, falsePositiveRate, detectionRate: recall, accuracy, notes };
}

/** Metrics per vulnerability category plus an overall row. */
export function metricsByCategory(cases, detectedKeys) {
  const detected = [...detectedKeys];
  const categories = [...new Set(cases.map((c) => c.category))].sort();
  const rows = {};
  for (const cat of categories) {
    const subset = cases.filter((c) => c.category === cat);
    const keys = detected.filter((k) => k.endsWith(` ${cat}`));
    rows[cat] = computeMetrics(confusionMatrix(subset, keys));
  }
  rows.OVERALL = computeMetrics(confusionMatrix(cases, detected));
  return rows;
}

/** Formats a metric value for tables: 3 decimals, or "n/a" when undefined. */
export function fmt(value) {
  return value === null || value === undefined ? 'n/a' : value.toFixed(3);
}

/** Category groups used in the thesis tables. */
export const GROUPS = {
  PRIMARY: ['BOLA', 'BFLA'],
  SECONDARY: ['AUTH_MISSING', 'AUTH_INVALID_TOKEN', 'JWT_SIGNATURE', 'JWT_NONE_ALG', 'JWT_EXPIRED'],
};

/** Metrics per category, per group (PRIMARY = BOLA+BFLA, SECONDARY = auth/JWT) and overall. */
export function metricsReport(cases, detectedKeys) {
  const detected = [...detectedKeys];
  const rows = metricsByCategory(cases, detected);
  for (const [group, cats] of Object.entries(GROUPS)) {
    const subset = cases.filter((c) => cats.includes(c.category));
    if (!subset.length) continue;
    const keys = detected.filter((k) => cats.some((cat) => k.endsWith(` ${cat}`)));
    rows[group] = computeMetrics(confusionMatrix(subset, keys));
  }
  return rows;
}
