# Interactive web app (`docs/webapp/`)

A small, self-contained web app that explains **how the role-aware broken-access-control
scanner works**, end to end, for a non-expert reader. It is the companion to the
results dashboard in [`docs/dashboard/`](../dashboard/): the dashboard is a reference
read-out of the numbers; this app is the guided story behind them.

> **It is a static viewer, not a scanner.** The page does **not** run a live scan,
> start Docker, or make any network request. Every number, request, response and
> verdict it shows is read from results that were **already computed and committed**
> under `evaluation/results/2026-11-21-scanner-test-api/` and `…-scanner-vampi/`.

## Open it

Just open `docs/webapp/index.html` — double-click it, or drag it into a browser.
No server, no build step, no internet connection required. It works offline and
loads no external libraries (plain HTML/CSS/JavaScript, no CDN).

## The four views

1. **Overview** — what broken access control is (BOLA and BFLA in plain language),
   the three approaches compared at a glance, and the benchmark (20 injected flaws,
   234 scored cases).
2. **How it works** — an interactive, step-by-step walkthrough of the pipeline for one
   concrete request at a time (e.g. *Alice tries to read Bob's order*): load the OpenAPI
   policy → log in as several accounts → craft the cross-user request → send it and see the
   real request/response → **watch the two oracles decide the same response differently**
   (the RQ2 point) → the verdict. Pick a different scenario, or step with Previous/Next.
3. **Results** — the RQ2 comparison (precision / recall / F1 / false-positive-rate bar
   charts, per category) and a per-case detection grid for all 234 cases, plus the RQ3
   cost panel (362 requests, ~1.0 s per run).
4. **Explore findings** — a filterable, searchable table of the role-aware scanner's
   findings, each expandable to the exact (redacted) request and response that justified it.

## Rebuild

Browsers cannot read local JSON/CSV over `file://`, so the data is **inlined** into
`index.html` at build time (exactly like `docs/dashboard/build.js`). To regenerate the
page after the archived results or the benchmark definitions change:

```bash
node docs/webapp/build.js
```

- Edit **`template.html`** (the markup, styles and app logic) — never `index.html`,
  which is generated.
- `build.js` reads the sources, inlines them as one JSON blob into the
  `/*__DATA__*/null` placeholder in `template.html`, and writes `index.html`.

### Where the data comes from

`build.js` reads only files already in the repository:

| Source | Used for |
|---|---|
| `evaluation/results/2026-11-21-scanner-test-api/role-aware-findings.json` | Findings table; "How it works" evidence (ownership-differential run) |
| `…/status-only-findings.json` | "How it works" evidence for the status-only oracle's decisions |
| `…/comparison/metrics.json` | RQ2 precision/recall/F1/FPR per approach and category |
| `…/comparison/per-case.csv` | Per-case detection grid |
| `…/rq3-timing.csv` | RQ3 cost panel |
| `evaluation/results/2026-11-21-scanner-vampi/comparison/metrics.json` | External-benchmark (VAmPI) note |
| `test-api/ground-truth.json` | Case labels, categories, true-negative notes |
| `test-api/openapi.yaml` | The `x-access-control` policy shown in the walkthrough |
| `test-api/src/flaws.js` | The list of injected flaws |
| `cli-tool/config/example.config.yaml` | The benchmark accounts/roles |

Nothing on the page is typed in by hand. Credentials are already redacted in the
archived findings; the build does not add or reveal any.
