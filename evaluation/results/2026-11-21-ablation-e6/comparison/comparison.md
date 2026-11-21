# Detection comparison: BAC Benchmark API (test-api)

Ground truth: vulnerable (FLAWS=all); 234 scored cases (20 vulnerable).

| Run | Tool | Findings | Requests | Duration (s) | Case coverage |
|---|---|---:|---:|---:|---:|
| Annotations (baseline) | bac-scanner | 33 | 362 | 1.08 | 97.9% |
| Config rules, no annotations | bac-scanner | 33 | 362 | 1.12 | 97.9% |
| No policy source | bac-scanner | 6 | 256 | 0.83 | 84.6% |

## Threshold: confirmed

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | Annotations (baseline) | 14 | 0 | 17 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| PRIMARY | Config rules, no annotations | 14 | 0 | 17 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| PRIMARY | No policy source | 0 | 0 | 17 | 14 | n/a | 0.000 | n/a | 0.000 |
| BOLA | Annotations (baseline) | 8 | 0 | 8 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | Config rules, no annotations | 8 | 0 | 8 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | No policy source | 0 | 0 | 8 | 8 | n/a | 0.000 | n/a | 0.000 |
| BFLA | Annotations (baseline) | 6 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | Config rules, no annotations | 6 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | No policy source | 0 | 0 | 9 | 6 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | Annotations (baseline) | 6 | 0 | 197 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| SECONDARY | Config rules, no annotations | 6 | 0 | 197 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| SECONDARY | No policy source | 6 | 0 | 197 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | Annotations (baseline) | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | Config rules, no annotations | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | No policy source | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_INVALID_TOKEN | Annotations (baseline) | 1 | 0 | 40 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_INVALID_TOKEN | Config rules, no annotations | 1 | 0 | 40 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_INVALID_TOKEN | No policy source | 1 | 0 | 40 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_SIGNATURE | Annotations (baseline) | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_SIGNATURE | Config rules, no annotations | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_SIGNATURE | No policy source | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_NONE_ALG | Annotations (baseline) | 1 | 0 | 38 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_NONE_ALG | Config rules, no annotations | 1 | 0 | 38 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_NONE_ALG | No policy source | 1 | 0 | 38 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_EXPIRED | Annotations (baseline) | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_EXPIRED | Config rules, no annotations | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_EXPIRED | No policy source | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | Annotations (baseline) | 20 | 0 | 214 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | Config rules, no annotations | 20 | 0 | 214 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | No policy source | 6 | 0 | 214 | 14 | 1.000 | 0.300 | 0.462 | 0.000 |

## Threshold: confirmed+potential

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | Annotations (baseline) | 14 | 0 | 17 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| PRIMARY | Config rules, no annotations | 14 | 0 | 17 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| PRIMARY | No policy source | 0 | 0 | 17 | 14 | n/a | 0.000 | n/a | 0.000 |
| BOLA | Annotations (baseline) | 8 | 0 | 8 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | Config rules, no annotations | 8 | 0 | 8 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | No policy source | 0 | 0 | 8 | 8 | n/a | 0.000 | n/a | 0.000 |
| BFLA | Annotations (baseline) | 6 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | Config rules, no annotations | 6 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | No policy source | 0 | 0 | 9 | 6 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | Annotations (baseline) | 6 | 0 | 197 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| SECONDARY | Config rules, no annotations | 6 | 0 | 197 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| SECONDARY | No policy source | 6 | 0 | 197 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | Annotations (baseline) | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | Config rules, no annotations | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | No policy source | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_INVALID_TOKEN | Annotations (baseline) | 1 | 0 | 40 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_INVALID_TOKEN | Config rules, no annotations | 1 | 0 | 40 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_INVALID_TOKEN | No policy source | 1 | 0 | 40 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_SIGNATURE | Annotations (baseline) | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_SIGNATURE | Config rules, no annotations | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_SIGNATURE | No policy source | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_NONE_ALG | Annotations (baseline) | 1 | 0 | 38 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_NONE_ALG | Config rules, no annotations | 1 | 0 | 38 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_NONE_ALG | No policy source | 1 | 0 | 38 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_EXPIRED | Annotations (baseline) | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_EXPIRED | Config rules, no annotations | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_EXPIRED | No policy source | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | Annotations (baseline) | 20 | 0 | 214 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | Config rules, no annotations | 20 | 0 | 214 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | No policy source | 6 | 0 | 214 | 14 | 1.000 | 0.300 | 0.462 | 0.000 |

`n/a` = undefined because the denominator is zero (see evaluation/metrics.js).
