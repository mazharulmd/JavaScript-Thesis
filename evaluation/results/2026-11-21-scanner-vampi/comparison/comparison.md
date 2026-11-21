# Detection comparison: VAmPI (erev0s/vampi)

Ground truth: vulnerable mode (vulnerable=1); 35 scored cases (3 vulnerable).

| Run | Tool | Findings | Requests | Duration (s) | Case coverage |
|---|---|---:|---:|---:|---:|
| Role-aware | bac-scanner | 2 | 43 | 0.26 | 82.9% |
| Status-only | bac-scanner | 3 | 43 | 0.26 | 82.9% |
| OWASP ZAP | OWASP ZAP | 0 | n/a | 23.39 | n/a |

## Threshold: confirmed

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | Role-aware | 2 | 0 | 2 | 1 | 1.000 | 0.667 | 0.800 | 0.000 |
| PRIMARY | Status-only | 3 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| PRIMARY | OWASP ZAP | 0 | 0 | 2 | 3 | n/a | 0.000 | n/a | 0.000 |
| BOLA | Role-aware | 1 | 0 | 1 | 1 | 1.000 | 0.500 | 0.667 | 0.000 |
| BOLA | Status-only | 2 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | OWASP ZAP | 0 | 0 | 1 | 2 | n/a | 0.000 | n/a | 0.000 |
| BFLA | Role-aware | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | Status-only | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | OWASP ZAP | 0 | 0 | 1 | 1 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | Role-aware | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| SECONDARY | Status-only | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| SECONDARY | OWASP ZAP | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| OVERALL | Role-aware | 2 | 0 | 32 | 1 | 1.000 | 0.667 | 0.800 | 0.000 |
| OVERALL | Status-only | 3 | 0 | 32 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | OWASP ZAP | 0 | 0 | 32 | 3 | n/a | 0.000 | n/a | 0.000 |

## Threshold: confirmed+potential

| Scope | Run | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PRIMARY | Role-aware | 2 | 0 | 2 | 1 | 1.000 | 0.667 | 0.800 | 0.000 |
| PRIMARY | Status-only | 3 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| PRIMARY | OWASP ZAP | 0 | 0 | 2 | 3 | n/a | 0.000 | n/a | 0.000 |
| BOLA | Role-aware | 1 | 0 | 1 | 1 | 1.000 | 0.500 | 0.667 | 0.000 |
| BOLA | Status-only | 2 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA | OWASP ZAP | 0 | 0 | 1 | 2 | n/a | 0.000 | n/a | 0.000 |
| BFLA | Role-aware | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | Status-only | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BFLA | OWASP ZAP | 0 | 0 | 1 | 1 | n/a | 0.000 | n/a | 0.000 |
| SECONDARY | Role-aware | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| SECONDARY | Status-only | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| SECONDARY | OWASP ZAP | 0 | 0 | 30 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_MISSING | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| AUTH_INVALID_TOKEN | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_SIGNATURE | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_NONE_ALG | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | Role-aware | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | Status-only | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| JWT_EXPIRED | OWASP ZAP | 0 | 0 | 6 | 0 | n/a | n/a | n/a | 0.000 |
| OVERALL | Role-aware | 2 | 0 | 32 | 1 | 1.000 | 0.667 | 0.800 | 0.000 |
| OVERALL | Status-only | 3 | 0 | 32 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| OVERALL | OWASP ZAP | 0 | 0 | 32 | 3 | n/a | 0.000 | n/a | 0.000 |

`n/a` = undefined because the denominator is zero (see evaluation/metrics.js).
