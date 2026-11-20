# Detection comparison: BAC Benchmark API (test-api)

Ground truth: vulnerable (FLAWS=all); 234 scored cases (20 vulnerable).

| Run | Tool | Findings | Requests | Duration (s) | Case coverage |
|---|---|---:|---:|---:|---:|
| OWASP ZAP | OWASP ZAP | 0 | n/a | 31.23 | n/a |

## Threshold: confirmed

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | OWASP ZAP | 0 | 0 | 17 | 14 | n/a | 0.000 | n/a | 0.000 |
| BOLA | OWASP ZAP | 0 | 0 | 8 | 8 | n/a | 0.000 | n/a | 0.000 |
| BFLA | OWASP ZAP | 0 | 0 | 9 | 6 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | OWASP ZAP | 0 | 0 | 197 | 6 | n/a | 0.000 | n/a | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 41 | 2 | n/a | 0.000 | n/a | 0.000 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 40 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 39 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 38 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 39 | 1 | n/a | 0.000 | n/a | 0.000 |
| OVERALL | OWASP ZAP | 0 | 0 | 214 | 20 | n/a | 0.000 | n/a | 0.000 |

## Threshold: confirmed+potential

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | OWASP ZAP | 0 | 0 | 17 | 14 | n/a | 0.000 | n/a | 0.000 |
| BOLA | OWASP ZAP | 0 | 0 | 8 | 8 | n/a | 0.000 | n/a | 0.000 |
| BFLA | OWASP ZAP | 0 | 0 | 9 | 6 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | OWASP ZAP | 0 | 0 | 197 | 6 | n/a | 0.000 | n/a | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 41 | 2 | n/a | 0.000 | n/a | 0.000 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 40 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 39 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 38 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 39 | 1 | n/a | 0.000 | n/a | 0.000 |
| OVERALL | OWASP ZAP | 0 | 0 | 214 | 20 | n/a | 0.000 | n/a | 0.000 |

`n/a` = undefined because the denominator is zero (see evaluation/metrics.js).
