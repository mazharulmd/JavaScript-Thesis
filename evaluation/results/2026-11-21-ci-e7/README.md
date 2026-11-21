# Experiment E7: the scanner in a CI pipeline (GitHub Actions)

**Status: EXECUTED.** The `security-scan` workflow runs the scanner unattended on GitHub-hosted runners
and gates the pipeline by exit code, answering the CI-suitability part of RQ3.

| Item | Value |
|---|---|
| Workflow | `.github/workflows/security-scan.yml` |
| Reference run | #29, commit `40075f8` on `main` ([run 44921938007](https://github.com/mazharulmd/JavaScript-Thesis/actions/runs/44921938007)) |
| Trigger | push to `main` |
| Result | success; total wall time ~40 s (2026-11-21 15:57:49–15:58:30 UTC) |
| Runs to date | 29 (pull_request and push), all completed |

## Jobs in the reference run

1. **Unit and integration tests** — success. `npm ci` + `npm test` (all 80 tests).
2. **Access-control scan of the benchmark** — success, every step:
   - Start benchmark (vulnerable :3000, patched :3001) via `docker compose` and wait for health checks.
   - Run the access-control scan (`npm run scan:ci`): scans both builds, writes the findings documents.
   - Security gate on the patched build (`report --fail-on high`) — passed (no confirmed high/critical finding).
   - Detection regression check on the vulnerable build (`check-regression.js`) — passed.
   - Upload the reports as a build artifact (`access-control-reports`, 10 files).
   - Clean up Docker resources.
3. **OWASP ZAP comparison (manual)** — skipped by design (only on `workflow_dispatch` with `run_zap`).

## Interpretation (RQ3)

The tool builds and starts the benchmark, runs the scan, enforces a security gate and a detection
regression check, and uploads evidence, all unattended in under a minute on a standard GitHub-hosted
runner. The gate uses the process exit code, so a confirmed high/critical access-control finding fails
the pipeline. This demonstrates CI suitability.

Evidence is the GitHub Actions run history (the API is read-only; the run URLs above are the primary
record). The uploaded report artifact for run #29 is `access-control-reports` (49,602 bytes).
