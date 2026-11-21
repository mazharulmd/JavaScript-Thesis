# Thesis guide: from repository to report

This guide maps the thesis report (Savonia reporting template, `Thesis Template/`) to the evidence
in this repository. It also lists the work that remains for the author. It is a planning aid, not thesis text.

## Chapter map

| Thesis chapter | Evidence in the repository | Author's remaining work |
|---|---|---|
| 1 Introduction | Proposal (`Thesis-Topic-Proposal - V2.docx`), README | Write from the proposal; add references (OWASP API Security Top 10 2023) |
| 2–4 Theory: REST and OpenAPI, authentication and authorization, BOLA/BFLA, JWT, DAST tools and existing approaches | — | Literature review: OWASP API Top 10, ZAP, Burp Autorize/AuthMatrix, RESTler, research on access-control testing. Every reference must be checked against the original source |
| 5 Purpose, objective, RQs | Proposal, README | Keep the RQs exactly as approved |
| 6 Method: DSR | `docs/ARCHITECTURE.md`, `docs/DECISIONS.md` | Describe the DSR cycle (problem → design → build → evaluate) with methodology references |
| 6.x Benchmark design | `test-api/`, `test-api/src/flaws.js`, `openapi.yaml`, `ground-truth.json`, D2–D7 | Explain flaw selection, the true-negative patterns, the patched build and the root-cause rule |
| 6.x Tool design | `docs/ARCHITECTURE.md` ("Intended design"), `docs/FINDINGS-FORMAT.md` | Implement the detection engine and describe it (see below) |
| 6.x Evaluation design | `evaluation/README.md`, `evaluation/metrics.js` | Metrics, thresholds, datasets, experiment list, threats to validity |
| 7 Results | `evaluation/results/*` (E1 executed) | Run E3–E7; report raw counts and ratios; use `comparison.md` tables and `chart-*.svg` figures |
| 8 Discussion | Experiment READMEs (observations, validity notes) | Answer RQ1–RQ3; discuss limitations and threats to validity |
| 9 Conclusion | — | Contributions, future work (e.g. crAPI, BOPLA/mass assignment, GraphQL) |
| Appendices | HTML/JSON reports, ground-truth tables, CI workflow | Select representative reports |

## Remaining implementation: the detection engine

The pipeline around the engine is complete and tested. So is the groundwork the engine builds on:
`parser/openapi.js` (operation inventory), `config/` (accounts, roles, access rules, host allowlist,
policy resolution), `authentication/session.js` (login and identities), `utils/http.js` (timeouts,
throttling, request budget and counter for RQ3) and `utils/sample.js` (valid request bodies).
`preflight` exercises all of these. The engine must:

1. Reuse the parser, config, policy and session modules (inputs and login are already handled).
2. Discover which objects belong to which account (e.g. from list endpoints and the ownership fields).
3. Generate cross-user tests (for each object owned by user B, request it as user A) and cross-role
   tests (for each restricted function, invoke it as a role that is not allowed). Use the same request set for
   both oracles.
4. Classify each test with **two separate oracles**: status-only, and ownership-differential (ownership fields,
   a comparison with the owner's response, state verification after writes and deletes).
5. Write one findings document per oracle (`docs/FINDINGS-FORMAT.md`), including `meta.requests` and
   `meta.durationMs`.
6. Add a root `package.json` script `scan:ci` that writes `reports/findings-patched.json` and
   `reports/findings-vulnerable.json`. The CI workflow then gates and regression-checks automatically.

**Acceptance check** (already automated):

```bash
node evaluation/check-regression.js --ground-truth test-api/ground-truth.json --findings reports/findings-vulnerable.json --scope PRIMARY --min-recall 1 --max-fp 0
```

```bash
node cli-tool/src/cli.js report --input reports/findings-patched.json --fail-on high
```

The second command must exit 0 on the patched build.

## Academic integrity

* Report only experiments that were executed. `evaluation/README.md` keeps the planned/executed status.
* Say which parts of the code and text were produced with AI assistance, following Savonia's guidelines on AI use.
* The thesis text, the analysis and the conclusions must be the author's own work.
