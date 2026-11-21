# Experiment E2: OWASP ZAP on VAmPI

**Status: EXECUTED.** The valid runs are in `vulnerable/` and `patched/`. One earlier attempt was invalid and
is kept in `failed-attempt-vulnerable/` for transparency only. It is not scored.

| Item | Value |
|---|---|
| Date | 2026-11-20 |
| Tool | OWASP ZAP 2.17.0, `zap-api-scan.py`; same image digest as E1 (`sha256:9624669d…f328af`) |
| Targets | `erev0s/vampi:latest`, `vulnerable=1` (:5002) and `vulnerable=0` (:5003), `tokentimetolive=3600` |
| Authentication | `name1` / `pass1`; bearer token injected by a ZAP replacer rule |
| Reset | `GET /createdb` before and after each run |
| Ground truth | `benchmarks/vampi/ground-truth.json` (35 cases, 3 vulnerable) and `ground-truth.secure.json` (35 cases, 1 vulnerable) |

## Run log

1. **Invalid attempt (vulnerable mode, full spec).** VAmPI stopped responding 11 s into the active scan. Its
   last access-log entry is at 18:59:19, after which ZAP worked against a hung server for about 23 minutes.
   This matches VAmPI's documented ReDoS in the vulnerable e-mail update (`PUT /users/v1/{username}/email`)
   on its single-threaded development server. The run was discarded.
2. **Valid vulnerable-mode run.** The container was restarted. ZAP imported
   `benchmarks/vampi/openapi3.zap-no-redos.yml`, which is VAmPI's spec minus that one operation. The server stayed
   responsive (verified after the scan). Duration 23.4 s. VAmPI's access log recorded about 1,400 HTTP
   requests since the restart. That figure includes a handful of requests from the run script; most went to
   `POST /users/v1/register`, `/users/v1/login` and `/books/v1`.
3. **Valid patched-mode run** with the full spec. Duration 24.7 s.

The excluded operation is still in the ground truth (1 BOLA case and 5 auth cases, all secure). ZAP did not test
it, so it cannot have produced findings there. Those cases count as true negatives for ZAP, and the thesis
should report this exclusion.

## Observations

* ZAP imported 15 URLs and reached 53 (vulnerable) / 55 (patched) URLs.
* Alerts in both modes: Server version disclosure (CWE-497), X-Content-Type-Options missing (CWE-693),
  client-error responses (CWE-388), and Authentication Request Identified. None of them is access-control related.
* ZAP raised no alert for VAmPI's BOLA on `GET /books/v1/{book_title}`, its cross-user password change, or the
  unauthenticated `/users/v1/_debug` endpoint.

## Results (threshold: confirmed; identical for confirmed+potential)

| Mode | Scope | TP | FP | TN | FN | Precision | Recall | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| vulnerable | BOLA + BFLA | 0 | 0 | 2 | 3 | n/a | 0.000 | 0.000 |
| vulnerable | Overall | 0 | 0 | 32 | 3 | n/a | 0.000 | 0.000 |
| patched | BOLA + BFLA | 0 | 0 | 4 | 1 | n/a | 0.000 | 0.000 |
| patched | Overall | 0 | 0 | 34 | 1 | n/a | 0.000 | 0.000 |

In patched mode the one vulnerable case is `/users/v1/_debug`, which VAmPI leaves exposed in both modes.
Full tables are in `*/metrics/comparison.md`.
