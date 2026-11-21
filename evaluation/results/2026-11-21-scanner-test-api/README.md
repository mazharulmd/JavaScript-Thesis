# Experiments E3 and E4: role-aware scanner and status-only baseline on the benchmark API

**Status: EXECUTED and validated.** Raw findings, the three-way comparison and RQ3 timing are archived here.

| Item | Value |
|---|---|
| Date | 2026-11-21 |
| Tool | bac-scanner 1.0.0 (this repository), ownership-differential oracle (E3) and status-only oracle (E4) |
| Targets | test-api vulnerable build (FLAWS=all, :3000) and patched build (FLAWS=none, :3001), via docker compose |
| Config | cli-tool/config/example.config.yaml (accounts admin, alice, bob, guest) |
| Ground truth | test-api/ground-truth.json (234 scored cases, 20 vulnerable) |
| Command | `node cli-tool/src/cli.js scan --spec test-api/openapi.yaml --config cli-tool/config/example.config.yaml --target <url> [--status-only]` |

Both oracles run from one shared test plan (test-generator.js), so the only difference between E3 and E4
is the decision rule. Each run sends 362 HTTP requests. The patched build (role-aware) produces 0 findings.

## Results (threshold: confirmed findings)

| Scope | Oracle | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| BOLA+BFLA | Role-aware (E3) | 14 | 0 | 17 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| BOLA+BFLA | Status-only (E4) | 14 | 6 | 11 | 0 | 0.700 | 1.000 | 0.824 | 0.353 |
| BOLA+BFLA | OWASP ZAP (E1) | 0 | 0 | 17 | 14 | n/a | 0.000 | n/a | 0.000 |
| Overall | Role-aware (E3) | 20 | 0 | 214 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| Overall | Status-only (E4) | 20 | 18 | 208 | 0 | 0.526 | 1.000 | 0.690 | 0.080 |
| Overall | OWASP ZAP (E1) | 0 | 0 | 214 | 20 | n/a | 0.000 | n/a | 0.000 |

Full tables and charts are in comparison/. The status-only baseline matches the role-aware recall but raises
18 false positives, all on the benchmark's deliberate true-negative patterns (public documents, path-id-ignored
summaries, soft denials, the 202-accepted-not-applied config change, role-filtered admin views). The
ownership-differential oracle distinguishes every one of them.

## RQ3 (rq3-timing.csv, 5 runs, benchmark reset between each)

- Requests per run: 362 (deterministic).
- Duration: mean 1026 ms, standard deviation 30 ms (n=5), against a localhost target.
- The scanner runs unattended in GitHub Actions and gates the pipeline by exit code (see .github/workflows/security-scan.yml).
