# Experiment E5: role-aware scanner and status-only baseline on VAmPI

**Status: EXECUTED and validated.**

| Item | Value |
|---|---|
| Date | 2026-11-21 |
| Tool | bac-scanner 1.0.0, both oracles |
| Targets | erev0s/vampi:latest, vulnerable mode (:5002) and patched mode (:5003); GET /createdb reset before each run |
| Config | benchmarks/vampi/vampi.config.yaml (accounts name1, name2, admin; ownership fields owner/user/username; access rules for VAmPI's unannotated spec) |
| Ground truth | benchmarks/vampi/ground-truth.json (35 cases, 3 vulnerable), ground-truth.secure.json (35 cases, 1 vulnerable) |

## Results, vulnerable mode (threshold: confirmed)

| Scope | Oracle | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| BOLA+BFLA | Role-aware | 2 | 0 | 2 | 1 | 1.000 | 0.667 | 0.800 | 0.000 |
| BOLA+BFLA | Status-only | 3 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA+BFLA | OWASP ZAP | 0 | 0 | 2 | 3 | n/a | 0.000 | n/a | 0.000 |

Patched mode (role-aware): 1 finding, `GET /users/v1/_debug` (BFLA). This is a true positive: VAmPI exposes the
unauthenticated debug endpoint in both modes, and the secure ground truth marks it vulnerable.

## Interpretation (for the discussion)

- The role-aware oracle keeps precision 1.000 and raises no false positive on VAmPI.
- It detects the BOLA on `GET /books/v1/{book_title}` (ownership exposed as the `user`/`owner` field) and the
  BFLA on `/users/v1/_debug`.
- It MISSES the cross-user password change on `PUT /users/v1/{username}/password` (recall 0.667). This is a
  genuine limitation, not a defect: VAmPI answers 204 with no body and has no endpoint that reads a password
  back, so state verification cannot observe the effect through the API. The ground-truth note records this.
- On VAmPI the status-only baseline reaches precision 1.000 as well, because VAmPI has almost no legitimate
  "2xx to a forbidden request" responses. This contrasts with the benchmark (E4), where status-only's precision
  falls to 0.526. The comparison therefore shows that the status-only baseline's precision depends entirely on
  whether the target API contains true-negative 2xx patterns, whereas the ownership-differential oracle keeps
  precision 1.000 on both targets.
- Per-API ownership configuration is required: `user` had to be added to ownership.fields so discovery could
  identify victim-owned books. This matches the documented expectation that external APIs need manual
  ownership configuration (benchmarks/vampi/README.md, benchmarks/crapi/README.md).
