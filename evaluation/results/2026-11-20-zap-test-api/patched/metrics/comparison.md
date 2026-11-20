# Detection comparison: BAC Benchmark API (test-api)

Ground truth: patched (FLAWS=none); 246 scored cases (0 vulnerable).

| Run | Tool | Findings | Requests | Duration (s) | Case coverage |
|---|---|---:|---:|---:|---:|
| OWASP ZAP | OWASP ZAP | 0 | n/a | 30.92 | n/a |

## Threshold: confirmed

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | OWASP ZAP | 0 | 0 | 31 | 0 | n/a | n/a | n/a | 0.000 |
| BOLA | OWASP ZAP | 0 | 0 | 16 | 0 | n/a | n/a | n/a | 0.000 |
| BFLA | OWASP ZAP | 0 | 0 | 15 | 0 | n/a | n/a | n/a | 0.000 |
| SECONDARY | OWASP ZAP | 0 | 0 | 215 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| OVERALL | OWASP ZAP | 0 | 0 | 246 | 0 | n/a | n/a | n/a | 0.000 |

## Threshold: confirmed+potential

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | OWASP ZAP | 0 | 0 | 31 | 0 | n/a | n/a | n/a | 0.000 |
| BOLA | OWASP ZAP | 0 | 0 | 16 | 0 | n/a | n/a | n/a | 0.000 |
| BFLA | OWASP ZAP | 0 | 0 | 15 | 0 | n/a | n/a | n/a | 0.000 |
| SECONDARY | OWASP ZAP | 0 | 0 | 215 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 43 | 0 | n/a | n/a | n/a | 0.000 |
| OVERALL | OWASP ZAP | 0 | 0 | 246 | 0 | n/a | n/a | n/a | 0.000 |

`n/a` = undefined because the denominator is zero (see evaluation/metrics.js).
