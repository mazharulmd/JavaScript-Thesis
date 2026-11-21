# Detection comparison: BAC Benchmark API (test-api)

Ground truth: vulnerable (FLAWS=all); 234 scored cases (20 vulnerable).

| Run | Tool | Findings | Requests | Duration (s) | Case coverage |
|---|---|---:|---:|---:|---:|
| Role-aware | bac-scanner | 33 | 362 | 1.20 | 97.9% |
| Status-only | bac-scanner | 57 | 362 | 1.04 | 97.9% |
| OWASP ZAP | OWASP ZAP | 0 | n/a | 31.23 | n/a |

## Threshold: confirmed

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | Role-aware | 14 | 0 | 17 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| PRIMARY | Status-only | 14 | 6 | 11 | 0 | 0.700 | 1.000 | 0.824 | 0.353 |
| PRIMARY | OWASP ZAP | 0 | 0 | 17 | 14 | n/a | 0.000 | n/a | 0.000 |
| BOLA | Role-aware | 8 | 0 | 8 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | Status-only | 8 | 4 | 4 | 0 | 0.667 | 1.000 | 0.800 | 0.500 |
| BOLA | OWASP ZAP | 0 | 0 | 8 | 8 | n/a | 0.000 | n/a | 0.000 |
| BFLA | Role-aware | 6 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | Status-only | 6 | 2 | 7 | 0 | 0.750 | 1.000 | 0.857 | 0.222 |
| BFLA | OWASP ZAP | 0 | 0 | 9 | 6 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | Role-aware | 6 | 0 | 197 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| SECONDARY | Status-only | 6 | 12 | 197 | 0 | 0.333 | 1.000 | 0.500 | 0.057 |
| SECONDARY | OWASP ZAP | 0 | 0 | 197 | 6 | n/a | 0.000 | n/a | 0.000 |
| AUTH_MISSING | Role-aware | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | Status-only | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 41 | 2 | n/a | 0.000 | n/a | 0.000 |
| AUTH_INVALID_TOKEN | Role-aware | 1 | 0 | 40 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_INVALID_TOKEN | Status-only | 1 | 2 | 40 | 0 | 0.333 | 1.000 | 0.500 | 0.048 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 40 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_SIGNATURE | Role-aware | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_SIGNATURE | Status-only | 1 | 3 | 39 | 0 | 0.250 | 1.000 | 0.400 | 0.071 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 39 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_NONE_ALG | Role-aware | 1 | 0 | 38 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_NONE_ALG | Status-only | 1 | 4 | 38 | 0 | 0.200 | 1.000 | 0.333 | 0.095 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 38 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_EXPIRED | Role-aware | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_EXPIRED | Status-only | 1 | 3 | 39 | 0 | 0.250 | 1.000 | 0.400 | 0.071 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 39 | 1 | n/a | 0.000 | n/a | 0.000 |
| OVERALL | Role-aware | 20 | 0 | 214 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | Status-only | 20 | 18 | 208 | 0 | 0.526 | 1.000 | 0.690 | 0.080 |
| OVERALL | OWASP ZAP | 0 | 0 | 214 | 20 | n/a | 0.000 | n/a | 0.000 |

## Threshold: confirmed+potential

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | Role-aware | 14 | 0 | 17 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| PRIMARY | Status-only | 14 | 6 | 11 | 0 | 0.700 | 1.000 | 0.824 | 0.353 |
| PRIMARY | OWASP ZAP | 0 | 0 | 17 | 14 | n/a | 0.000 | n/a | 0.000 |
| BOLA | Role-aware | 8 | 0 | 8 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | Status-only | 8 | 4 | 4 | 0 | 0.667 | 1.000 | 0.800 | 0.500 |
| BOLA | OWASP ZAP | 0 | 0 | 8 | 8 | n/a | 0.000 | n/a | 0.000 |
| BFLA | Role-aware | 6 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | Status-only | 6 | 2 | 7 | 0 | 0.750 | 1.000 | 0.857 | 0.222 |
| BFLA | OWASP ZAP | 0 | 0 | 9 | 6 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | Role-aware | 6 | 0 | 197 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| SECONDARY | Status-only | 6 | 12 | 197 | 0 | 0.333 | 1.000 | 0.500 | 0.057 |
| SECONDARY | OWASP ZAP | 0 | 0 | 197 | 6 | n/a | 0.000 | n/a | 0.000 |
| AUTH_MISSING | Role-aware | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | Status-only | 2 | 0 | 41 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 41 | 2 | n/a | 0.000 | n/a | 0.000 |
| AUTH_INVALID_TOKEN | Role-aware | 1 | 0 | 40 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| AUTH_INVALID_TOKEN | Status-only | 1 | 2 | 40 | 0 | 0.333 | 1.000 | 0.500 | 0.048 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 40 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_SIGNATURE | Role-aware | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_SIGNATURE | Status-only | 1 | 3 | 39 | 0 | 0.250 | 1.000 | 0.400 | 0.071 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 39 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_NONE_ALG | Role-aware | 1 | 0 | 38 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_NONE_ALG | Status-only | 1 | 4 | 38 | 0 | 0.200 | 1.000 | 0.333 | 0.095 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 38 | 1 | n/a | 0.000 | n/a | 0.000 |
| JWT_EXPIRED | Role-aware | 1 | 0 | 39 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| JWT_EXPIRED | Status-only | 1 | 3 | 39 | 0 | 0.250 | 1.000 | 0.400 | 0.071 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 39 | 1 | n/a | 0.000 | n/a | 0.000 |
| OVERALL | Role-aware | 20 | 0 | 214 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | Status-only | 20 | 18 | 208 | 0 | 0.526 | 1.000 | 0.690 | 0.080 |
| OVERALL | OWASP ZAP | 0 | 0 | 214 | 20 | n/a | 0.000 | n/a | 0.000 |

`n/a` = undefined because the denominator is zero (see evaluation/metrics.js).
