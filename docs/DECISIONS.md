# Design decisions

Short architecture decision records (ADR style). Each records the context, the decision and its
consequence for the validity of the thesis evaluation.

## D1: Monorepo with npm workspaces, ES modules, built-in test runner
**Context:** the thesis needs a benchmark, a tool and an evaluation that share data formats.
**Decision:** one repository with the workspaces `test-api` and `cli-tool`. It uses ESM throughout and
`node:test` instead of a test framework.
**Consequence:** the runtime dependencies are express, jsonwebtoken and yaml, and nothing else. The setup is easy to reproduce.

## D2: The specification states the intended policy; the implementation deviates
**Context:** a ground truth needs a statement of what *should* happen.
**Decision:** every operation in `test-api/openapi.yaml` carries `x-access-control`
(`roles`, `ownership`, `ownerField`). The implementation deviates on a known set of operations.
**Consequence:** a detector may use the annotations. For VAmPI and crAPI, which have none, the
same information must come from configuration. The thesis has to report this as an assumption.
An ablation without annotations is recommended.

## D3: Flaw toggle gives a vulnerable and a patched build of the same code
**Decision:** each injected flaw is guarded by one ID (`test-api/src/flaws.js`). `FLAWS=none` yields
a fully patched API.
**Consequence:** the patched build is a second, independent true-negative dataset, and it gives the CI
gate a build that should pass.

## D4: Deliberate true-negative patterns with 2xx responses
**Decision:** six protected operations return 2xx by design:
- public documents,
- an endpoint that ignores the path ID and returns the caller's own data,
- two soft denials (`200 {success:false}`),
- an asynchronous `202` that is not applied for non-owners,
- a role-filtered admin view.

**Consequence:** these cases show the difference between a status-code oracle and a
content- and ownership-aware oracle (RQ2). They are documented, and tested as correct behaviour.

## D5: Ground truth from labels plus explicit rules, not from tool output
**Decision:** `evaluation/build-ground-truth.js` combines a hand-labelled list of 20 vulnerable
cases (one per flaw) with documented applicability rules. A unit test fails if the committed manifest drifts
from the spec or the flaw registry.
**Consequence:** the ground truth is independent of every detector and can be regenerated deterministically.

## D6: Root-cause rule for authentication categories
**Context:** an endpoint without any authentication also "accepts" invalid, unsigned and expired tokens.
**Decision:** a broader authentication flaw on an operation makes the narrower categories on the same
operation non-applicable (12 cases are excluded and listed in the manifest).
**Consequence:** a single root cause is not counted several times. All tools are scored under the same rule.

## D7: Case-level scoring with two thresholds
**Decision:** a case = (method, path template, category). Detection means at least one matching finding.
Metrics are reported at a strict threshold (confirmed findings only) and a loose one (confirmed + potential).
Findings outside the ground truth count as false positives. Zero denominators are reported as undefined.
**Consequence:** the scoring is transparent and tool-agnostic. Per-category and grouped rows (BOLA+BFLA vs.
auth/JWT) keep the many easy authentication true negatives from dominating the overall false-positive rate.

## D8: A common findings format and adapters for external tools
**Decision:** all detectors produce `docs/FINDINGS-FORMAT.md` documents. ZAP output is converted by
`evaluation/adapters/zap.js`, whose CWE mapping was fixed before ZAP was run.
**Consequence:** the reporting, the CI gate and the scoring are identical for every tool.

## D9: Reports are redacted and self-contained
**Decision:** credentials are redacted before writing. The HTML report has no scripts or external resources.
**Consequence:** reports can be published as CI artifacts and thesis appendices.

## D10: Local-only execution
**Decision:** the Docker ports bind to `127.0.0.1`, and `run-zap.sh` refuses non-local targets.
**Consequence:** this is consistent with the ethics statement of the proposal: no third-party systems are tested.

## D11: Docker build works behind TLS-intercepting proxies without changing CI
**Decision:** the Dockerfile accepts an *optional* BuildKit secret `ca`. Without it, the build is a plain `npm ci`.
