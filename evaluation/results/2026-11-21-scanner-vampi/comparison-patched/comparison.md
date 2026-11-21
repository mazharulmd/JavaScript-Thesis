# Detection comparison: VAmPI (erev0s/vampi)

Ground truth: patched mode (vulnerable=0); 35 scored cases (1 vulnerable).

| Run | Tool | Findings | Requests | Duration (s) | Case coverage |
|---|---|---:|---:|---:|---:|
| Role-aware | bac-scanner | 1 | 43 | 0.28 | 82.9% |

## Threshold: confirmed

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | Role-aware | 1 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | Role-aware | 0 | 0 | 3 | 0 | n/a | n/a | n/a | 0.000 |
| BFLA | Role-aware | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| SECONDARY | Role-aware | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| OVERALL | Role-aware | 1 | 0 | 34 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |

## Threshold: confirmed+potential

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | Role-aware | 1 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | Role-aware | 0 | 0 | 3 | 0 | n/a | n/a | n/a | 0.000 |
| BFLA | Role-aware | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| SECONDARY | Role-aware | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| OVERALL | Role-aware | 1 | 0 | 34 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |

`n/a` = undefined because the denominator is zero (see evaluation/metrics.js).
