# Findings format (v1.0)

The findings format is the contract between **detectors** and the **reporting and evaluation
pipeline**. Detectors are the role-aware scanner, the status-code-only baseline, and external tools
converted by an adapter. Every detector writes one JSON document per run. Reports (`cli-tool report`), scoring
(`evaluation/compare.js`) and the CI gate (`--fail-on`, `evaluation/check-regression.js`) read
only this format. That keeps the detection strategies separate and comparable.

Validation: `node cli-tool/src/cli.js validate --input <file>` (implemented in
`cli-tool/src/reporting/findings-format.js`).

## Document

```jsonc
{
  "meta": {
    "tool": "bac-scanner",            // required
    "version": "1.0.0",
    "formatVersion": "1.0",
    "mode": "ownership-differential",  // or "status-only", "zap-api-scan", ...
    "target": "http://localhost:3000",
    "spec": "test-api/openapi.yaml",
    "scanId": "2026-11-20T10-00-00Z",
    "startedAt": "...", "finishedAt": "...",
    "durationMs": 2500,                // wall-clock time (RQ3)
    "requests": 412,                   // HTTP requests sent (RQ3)
    "endpointsTested": 44
  },
  "findings": [ /* Finding */ ],
  "tests": [ /* optional TestResult, enables case-coverage reporting */ ]
}
```

## Finding

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique within the document, e.g. `F-0001` |
| `category` | yes | `BOLA`, `BFLA`, `AUTH_MISSING`, `AUTH_INVALID_TOKEN`, `JWT_SIGNATURE`, `JWT_NONE_ALG`, `JWT_EXPIRED` |
| `method` | yes | HTTP method (upper case) |
| `path` | yes | **OpenAPI path template** (`/api/orders/{orderId}`), not the concrete URL. This is the key that is matched to the ground truth. |
| `severity` | yes | `critical`, `high`, `medium`, `low`, `info` |
| `status` | yes | `confirmed`, `potential` or `inconclusive` |
| `confidence` | no | Number in [0, 1] |
| `resource` | no | Affected object, e.g. `{ "orderId": 1005 }` |
| `attacker` | no | `{ account, role }`: the identity that performed the request |
| `victim` | no | `{ account, role }`: the owner of the affected object (BOLA) |
| `expected` / `observed` | no | Expected authorization behaviour vs. what was observed |
| `timestamp` | no | ISO 8601 |
| `evidence` | no | `{ notes: string[], request, response }` or `{ notes, exchanges: [{ label, account, role, request, response }] }` |

`request` = `{ method, url, headers, body }`; `response` = `{ status, headers, body }`.

**Scoring rule:** a ground-truth case `(method, path, category)` counts as detected when at
least one finding with the same triple exists. The confirmed threshold counts `status: confirmed`
only; the loose threshold also counts `potential`. `inconclusive` findings are never counted.

## TestResult (optional)

```json
{ "method": "GET", "path": "/api/orders/{orderId}", "category": "BOLA", "verdict": "denied" }
```

`verdict` is one of `vulnerable`, `potential`, `denied`, `inconclusive` or `skipped`. With `tests` present,
`compare.js` reports *case coverage*: the share of scored ground-truth cases that the detector actually exercised.

## Credentials

The reporting module redacts `Authorization`/`Cookie` headers, JWT-shaped strings and keys such as
`password`, `token` or `secret` before anything is written. Detectors should still avoid putting
credentials into evidence.
