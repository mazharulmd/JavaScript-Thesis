# Detection comparison: VAmPI (erev0s/vampi)

Ground truth: patched mode (vulnerable=0); 35 scored cases (1 vulnerable).

| Run | Tool | Findings | Requests | Duration (s) | Case coverage |
|---|---|---:|---:|---:|---:|
| OWASP ZAP | OWASP ZAP | 0 | n/a | 24.71 | n/a |

## Threshold: confirmed

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | OWASP ZAP | 0 | 0 | 4 | 1 | n/a | 0.000 | n/a | 0.000 |
| BOLA | OWASP ZAP | 0 | 0 | 3 | 0 | n/a | n/a | n/a | 0.000 |
| BFLA | OWASP ZAP | 0 | 0 | 1 | 1 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | OWASP ZAP | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| OVERALL | OWASP ZAP | 0 | 0 | 34 | 1 | n/a | 0.000 | n/a | 0.000 |

## Threshold: confirmed+potential

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | OWASP ZAP | 0 | 0 | 4 | 1 | n/a | 0.000 | n/a | 0.000 |
| BOLA | OWASP ZAP | 0 | 0 | 3 | 0 | n/a | n/a | n/a | 0.000 |
| BFLA | OWASP ZAP | 0 | 0 | 1 | 1 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | OWASP ZAP | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| OVERALL | OWASP ZAP | 0 | 0 | 34 | 1 | n/a | 0.000 | n/a | 0.000 |

`n/a` = undefined because the denominator is zero (see evaluation/metrics.js).
