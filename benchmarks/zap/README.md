# OWASP ZAP comparison

`run-zap.sh` runs ZAP's packaged API scan (`zap-api-scan.py`) in Docker against a **local** target.
The steps are:
1. Import the OpenAPI specification.
2. Authenticate as one account through a replacer rule that adds `Authorization: Bearer <token>`.
3. Run the passive and active scan rules.
4. Convert the JSON report with `evaluation/adapters/zap.js`.

The script resets the benchmark before and after the run and refuses non-local targets.

```bash
benchmarks/zap/run-zap.sh http://localhost:3000 evaluation/results/tmp/zap
```

Outputs: `zap-report.json`, `zap-report.html`, `zap-console.log`, `zap-findings.json` (findings format,
plus `outOfScope` alerts that are not scored).

**Why ZAP is the comparison baseline:** it is the most widely used open-source DAST tool, and its API scan is what
a team would typically add to a CI pipeline. ZAP tests requests one user at a time and has no notion of resource
ownership, so it is expected to miss BOLA and BFLA. The thesis measures that expectation instead of assuming it.
Results: `evaluation/results/`.
