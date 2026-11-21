# Experiment E1: OWASP ZAP on the benchmark API

**Status: EXECUTED and validated** (raw tool output archived in this folder).

| Item | Value |
|---|---|
| Date | 2026-11-20 |
| Tool | OWASP ZAP 2.17.0, `zap-api-scan.py` (OpenAPI import + active scan) |
| Image | `ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af` |
| Targets | `test-api` vulnerable build (`FLAWS=all`, :3000), patched build (`FLAWS=none`, :3001), both via `docker compose` |
| Authentication | One regular account (`alice`); bearer token injected into every request with a ZAP replacer rule |
| Command | `benchmarks/zap/run-zap.sh http://localhost:3000 <out>` and `... http://localhost:3001 <out>` |
| Scoring | `evaluation/adapters/zap.js` (CWE mapping fixed before the run), then `evaluation/compare.js` |
| Ground truth | `test-api/ground-truth.json` (234 scored cases, 20 vulnerable); `ground-truth.secure.json` for the patched build |

## Observations (from `zap-console.log`)

- ZAP imported **44 URLs** from the OpenAPI specification, reached **105 URLs** in total, and reported **112 passed rules**.
- Vulnerable build: 98 alert instances, all out of scope for access control:
  - Client Error response code (CWE-388, informational)
  - X-Content-Type-Options Header Missing (CWE-693, low)
  - Private IP Disclosure (CWE-497, low). It was raised on the unauthenticated diagnostics endpoint. ZAP reports the information leak, not the missing authentication.
  - Authentication Request Identified (informational)
- Patched build: 106 alert instances, also all out of scope.
- Duration: 31.2 s (vulnerable build), 30.9 s (patched build), wall-clock including container start-up.
- The number of HTTP requests sent by ZAP was not recorded in this run.

## Results (threshold: confirmed; identical for confirmed+potential)

| Scope | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| BOLA + BFLA | 0 | 0 | 17 | 14 | n/a | 0.000 | n/a | 0.000 |
| Auth / JWT | 0 | 0 | 197 | 6 | n/a | 0.000 | n/a | 0.000 |
| Overall (vulnerable build) | 0 | 0 | 214 | 20 | n/a | 0.000 | n/a | 0.000 |
| Overall (patched build) | 0 | 0 | 246 | 0 | n/a | n/a | n/a | 0.000 |

`n/a`: precision is undefined because ZAP reported no access-control finding (TP + FP = 0).
Full tables are in `vulnerable/metrics/comparison.md` and `patched/metrics/comparison.md`.

## Validity notes

- This is ZAP in a realistic default API-scan configuration with one authenticated user. ZAP has no
  built-in multi-user differential test, so it cannot observe cross-user or cross-role access. Its
  separate "Access Control Testing" add-on needs manual per-user context configuration in the GUI.
  That add-on was not used, and this limits the comparison.
- The CWE mapping is deliberately generous: any access-control or authentication CWE on a benchmark
  operation would have counted as a detection. No alert qualified.
