# Evaluation framework

This folder turns detector output into the evidence needed for **RQ2** (precision, recall, F1 and
false-positive rate vs. OWASP ZAP and a status-code-only approach) and **RQ3** (time, number of requests,
CI suitability).

## Pipeline

```
detector run ──► findings.json ──┐
ZAP run ──► zap-report.json ──► adapters/zap.js ──► findings.json ──┼──► compare.js ──► metrics.json / metrics.csv
                                                                     │                   per-case.csv / comparison.md
ground-truth.json ───────────────────────────────────────────────────┘                   chart-*.svg
```

| File | Purpose |
|---|---|
| `metrics.js` | Confusion matrix, precision, recall (detection rate), F1, FPR, accuracy; per category, per group, overall |
| `compare.js` | Scores any number of runs against one ground truth at two thresholds and writes all artefacts |
| `chart.js` | Static SVG grouped bar chart (max. 3 series, validated colour slots) for thesis figures |
| `check-regression.js` | CI check: fails when recall falls below or false positives rise above set floors |
| `build-ground-truth.js` | Generates `test-api/ground-truth*.json` from hand labels and documented rules |
| `adapters/zap.js` | Converts a ZAP JSON report into the findings format |
| `results/<date>-<name>/` | Archived, executed experiments with raw tool output and provenance |

## Unit of analysis and metrics

A **case** is one `(HTTP method, OpenAPI path template, category)` with a known label. A run detects a case
if at least one of its findings has the same triple.

* Precision = TP / (TP + FP)
* Recall = detection rate = TP / (TP + FN)
* F1 = 2PR / (P + R)
* FPR = FP / (FP + TN)

When a denominator is zero, the metric is **undefined** (`null`, shown as `n/a`) and a note is added. It is
never replaced by 0 or 1. Findings that match no case count as false positives.

Two **thresholds** are always reported: *confirmed* (only `status: confirmed`) and
*confirmed+potential*. Results are given per category and in two groups:
- **PRIMARY**: BOLA + BFLA, the focus of RQ1 and RQ2.
- **SECONDARY**: authentication and JWT checks.

Grouping prevents the roughly 200 easy authentication true negatives from making every tool's
overall FPR look excellent.

**Root-cause rule:** when an operation has a broad authentication flaw, the narrower categories on that
operation are excluded from scoring (12 cases on the vulnerable benchmark). See `docs/DECISIONS.md`.

## Datasets

| Dataset | Scored cases | Vulnerable | Source |
|---|---:|---:|---|
| test-api, vulnerable build | 234 | 20 | `test-api/ground-truth.json` |
| test-api, patched build | 246 | 0 | `test-api/ground-truth.secure.json` |
| VAmPI, vulnerable mode | 35 | 3 | `benchmarks/vampi/ground-truth.json` |
| VAmPI, patched mode | 35 | 1 | `benchmarks/vampi/ground-truth.secure.json` |
| crAPI | — | — | not yet labelled (`benchmarks/crapi/README.md`) |

## Experiments

| ID | Description | Status |
|---|---|---|
| E1 | OWASP ZAP 2.17.0 API scan on test-api (vulnerable + patched) | **Executed**: `results/2026-11-20-zap-test-api/` |
| E2 | OWASP ZAP API scan on VAmPI (vulnerable + patched) | **Executed**: `results/2026-11-20-zap-vampi/` (ReDoS operation excluded in vulnerable mode, see its README) |
| E3 | Role-aware scanner (ownership-differential oracle) on test-api | **Executed**: `results/2026-11-21-scanner-test-api/` |
| E4 | Status-code-only baseline on test-api, same request set as E3 | **Executed**: `results/2026-11-21-scanner-test-api/` |
| E5 | E3/E4 on VAmPI | **Executed**: `results/2026-11-21-scanner-vampi/` |
| E6 | Ablation: scanner without `x-access-control` annotations | Planned (recommended) |
| E7 | RQ3: repeated runs (n ≥ 5) for time and request counts; CI run time on GitHub Actions | **Partly executed**: 5-run timing in `results/2026-11-21-scanner-test-api/rq3-timing.csv`; GitHub Actions run still pending |
| E8 | crAPI | Planned; requires manual account and vehicle preparation |

Only experiments marked **Executed** have results. Nothing in this repository reports numbers for planned experiments.

## Reproducing E1

```bash
docker compose up -d --build --wait
```

```bash
benchmarks/zap/run-zap.sh http://localhost:3000 evaluation/results/tmp/zap
```

```bash
benchmarks/zap/run-zap.sh http://localhost:3001 evaluation/results/tmp/zap-secure
```

```bash
node evaluation/compare.js --ground-truth test-api/ground-truth.json --run "OWASP ZAP=evaluation/results/tmp/zap/zap-findings.json" --out evaluation/results/tmp/zap/metrics
```

## Scoring a detector run (E3–E5)

```bash
node evaluation/compare.js --ground-truth test-api/ground-truth.json \
  --run "Role-aware=reports/findings-vulnerable.json" \
  --run "Status-only=reports/findings-status-only.json" \
  --run "OWASP ZAP=evaluation/results/2026-11-20-zap-test-api/vulnerable/zap-findings.json" \
  --out evaluation/results/<date>-comparison
```

For RQ3, detectors should fill `meta.durationMs` and `meta.requests`. Repeat each run at least five times,
resetting the benchmark between runs, and report the mean and standard deviation.

## Threats to validity (to discuss in the thesis)

* **Author bias:** the benchmark and the tool are designed by the same person. Mitigations are the
  external benchmarks (VAmPI, crAPI), the patched build, and the ground truth being fixed before any tool run.
* **Annotation advantage:** the benchmark spec contains `x-access-control`. Report the ablation (E6).
* **ZAP configuration:** ZAP was run in its standard API-scan mode with one user. Its separate Access
  Control Testing add-on needs per-user contexts configured manually and was not used.
* **Small number of cases:** 20 vulnerable cases (14 BOLA/BFLA). Report the raw TP/FP/TN/FN numbers next to the ratios.
