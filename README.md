# Automated Detection of Broken Access Control Vulnerabilities in REST APIs

**A Role-Aware Testing Tool in JavaScript** — Bachelor's thesis artifact (Design Science Research)

> ⚠️ This repository contains an **intentionally vulnerable** benchmark API. Run it only
> locally or in an isolated Docker environment. All credentials in this repository are
> synthetic and exist only for the benchmark.

## Project status

| Component | Status |
|---|---|
| Thesis proposal (`Thesis-Topic-Proposal - V2.docx`) and `Thesis Template/` | Preserved, unchanged |
| Benchmark test API (`test-api/`) | Implemented, manually smoke-tested |
| OpenAPI 3.0 specification (`test-api/openapi.yaml`) | Implemented |
| Evaluation metrics (`evaluation/metrics.js`) | Implemented, unit-tested (8 tests pass) |
| Ground-truth manifest | Not yet implemented |
| Role-aware scanner CLI (`cli-tool/`) | Not yet implemented |
| JSON/HTML reporting | Not yet implemented |
| Benchmarks vs. OWASP ZAP, crAPI, VAmPI | Not yet executed — **no experimental results exist yet** |
| GitHub Actions workflow | Not yet implemented |

No experimental results are reported in this repository until they have actually been executed.

## Thesis objectives

The aim is to design, implement and evaluate a JavaScript tool that automatically detects
Broken Access Control vulnerabilities in REST APIs. These are Broken Object Level Authorization
(BOLA, OWASP API1:2023) and Broken Function Level Authorization (BFLA, OWASP API5:2023), with
missing authentication and basic JWT validation as secondary checks. The tool reads an OpenAPI
specification and several test accounts. It replays requests under different users and roles,
and it decides from **response data and resource ownership**, not only from HTTP status codes.

### Research questions

1. **RQ1:** How can a role-aware testing tool use an OpenAPI specification and several user accounts to detect BOLA and BFLA vulnerabilities automatically?
2. **RQ2:** How do its precision, recall and false-positive rate compare with OWASP ZAP and with a simpler approach that checks only HTTP status codes?
3. **RQ3:** How much time and how many requests does the tool need, and can it run as part of a CI pipeline?

### Methodology: Design Science Research

The tool is the designed artifact. It is evaluated in controlled experiments against a benchmark
with a known ground truth. The benchmark contains known vulnerable endpoints placed next to
correctly protected equivalents, so that both missed vulnerabilities and false alarms can be measured.

## Repository structure

```
JavaScript-Thesis/
├── Thesis-Topic-Proposal - V2.docx   # approved proposal (unchanged)
├── Thesis Template/                  # Savonia reporting template + guidelines (unchanged)
├── package.json                      # npm workspaces root
├── .env.example                      # benchmark-only configuration values
├── test-api/                         # intentionally vulnerable benchmark REST API
│   ├── openapi.yaml                  # spec documenting the INTENDED access policy (x-access-control)
│   ├── seeds/seed.js                 # prints the reproducible test accounts
│   └── src/
│       ├── app.js, server.js, config.js
│       ├── flaws.js                  # registry of injected flaws; FLAWS=all|none|<ids>
│       ├── lib/jwt.js
│       ├── middleware/               # authentication, errors, validation
│       ├── models/store.js           # resettable in-memory store
│       ├── data/seed-data.js         # deterministic synthetic data
│       └── routes/                   # users, orders, documents, devices, products, admin, ...
├── evaluation/
│   └── metrics.js                    # precision, recall, F1, FPR with explicit zero handling
├── tests/unit/                       # node:test unit tests
├── cli-tool/, reports/, benchmarks/, docs/, .github/workflows/   # planned components
```

## Benchmark test API

* **Stack:** Node.js (ESM), Express 5, jsonwebtoken. Data is held in memory and re-seeded on every start.
* **Roles:** `admin` (full access), `user` (regular customer), `guest` (authenticated, read-only).
* **Resources:** user profiles, orders, invoices (nested ownership), documents (private/public), IoT devices and sensor readings, products, and admin functions.
* **Flaw toggle:** every injected flaw is guarded by one ID in `test-api/src/flaws.js`.
  * `FLAWS=all` (default) gives the vulnerable benchmark.
  * `FLAWS=none` gives a fully patched build of the same API, which serves as an extra true-negative dataset.
* **True-negative patterns:** some protected endpoints still return a success status. Examples:
  * public documents that any user may read,
  * an endpoint that ignores the path ID and returns the caller's own data,
  * soft denials (`200 {success:false}`),
  * asynchronous `202 Accepted` requests that are not applied for non-owners,
  * role-filtered admin views.

  These cases are designed to expose the weakness of status-code-only detection.

### Test accounts (synthetic)

| id | username | password | role |
|---|---|---|---|
| 1 | admin | Admin#2026 | admin |
| 2 | alice | Alice#2026 | user |
| 3 | bob | Bob#2026 | user |
| 4 | guest | Guest#2026 | guest |
| 5 | carol | Carol#2026 | user (data owner, not a scanner account) |
| 6 | dave | Dave#2026 | user (data owner, not a scanner account) |

### Run locally

```bash
npm install
```

```bash
npm run start:api
```

```bash
FLAWS=none PORT=3001 npm run start:api
```

```bash
npm run seed:print
```

```bash
npm test
```

## Evaluation metrics

A *case* is one (HTTP method, path template, vulnerability category) combination with a known
label in the ground truth. A tool detects a case when at least one of its findings maps to it.

* Precision = TP / (TP + FP)
* Recall (detection rate) = TP / (TP + FN)
* F1 = 2 · Precision · Recall / (Precision + Recall)
* False-positive rate = FP / (FP + TN)

When a denominator is zero, the metric is reported as *undefined* (`null` / `n/a`) together with an
explanatory note. It is never silently reported as 0 or 1. Findings that match no ground-truth case
are counted as false positives. Metrics are reported per category and overall.

## Ethics and scope

All testing takes place only against the local benchmark and against intentionally vulnerable
training applications running locally in Docker. No third-party systems are tested, and no personal data is used.

## Limitations (current)

* The benchmark is designed by the same author as the tool, which carries a risk of design bias.
  The planned mitigations are the external benchmarks (VAmPI, crAPI) and the patched build.
* The scanner, reporting, ground-truth manifest, CI workflow and all experiments are not yet implemented (see *Project status*).
