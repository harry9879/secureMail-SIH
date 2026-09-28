# 09 · Scoring and reports (stages 11–12)

Code: [`scoring.py`](../securemailscope/scoring.py), [`report.py`](../securemailscope/report.py),
[`cli.py`](../securemailscope/cli.py), [`server.py`](../securemailscope/server.py)

## Severity is not priority

Severity says how bad a weakness is in the abstract. Priority says which one to fix first **here**.
Each finding gets a priority risk:

```
risk = 100 × severity_weight × exposure × (0.5 + 0.5 × exploitability) × asset_criticality
```

| Factor | Values | Rationale |
|---|---|---|
| severity weight | critical 1.0 · high 0.7 · medium 0.4 · low 0.15 · info 0 | |
| exposure | submission/access 1.0 · non-standard 0.9 · relay 0.85; ×0.8 if both ends are private addresses | client ports carry user passwords and mailboxes; internal-only traffic is less exposed |
| exploitability | set per rule: 1.0 for cleartext (a passive observer can read it) … 0.2 for hygiene | needs active attacker? key compromise? offline work? |
| asset criticality | from `--assets assets.json`, default 1.0 | the analyst knows the payroll relay matters more |

```json
{ "203.0.113.11:587": 1.5, "mx.example.com": 1.2, "default": 1.0 }
```

Findings are sorted by risk (then severity, rule, session) and numbered `priority` 1…n. That's why
"credentials in cleartext on submission" (risk 80) ranks above "stripping on the relay" (65), even
though both are critical.

**Session risk** blends the two views: `0.6 × rule risk + 0.4 × model risk`, plus 10 if the
isolation forest flagged it.

## Posture score

```
score = 100 − Σ penalty over unique (rule, endpoint) pairs
        penalty: critical 30 · high 12 · medium 5 · low 1 · info 0
any critical finding caps the score at 59 (grade F)
grades: A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60
```

Counting unique `(rule, endpoint)` pairs means one noisy endpoint with 500 identical sessions
can't sink the score 500 times. It's one issue to fix. Every endpoint also gets its own score and
grade.

## Outputs

| Output | For | Notes |
|---|---|---|
| **Terminal** | the analyst | posture, the top-N findings grouped by (rule, endpoint), output paths; `--fail-on high` gives exit code 2 for CI or cron |
| **HTML** | people | one self-contained file: inline CSS/SVG and 20 lines of JS, no network requests. Light/dark theme. Posture gauge, severity bar, "act on these first", endpoints table, sessions table (click a row for the transcript summary, TLS, chain and the explanation chart), filterable/searchable findings, method and limits, rule catalogue |
| **JSON** | SIEM / automation | `meta`, `posture`, `findings[]` (full), `sessions[]` (session, TLS, chain, features, risks, explanation), `endpoint_baselines`, `ml`, `timings_seconds` |
| **PDF** | email / archive | via reportlab (`pip install reportlab`): summary, findings table, details |
| **audit.log** | evidence integrity | one JSON line per analysis, appended |

**Numpy scalars aren't JSON-serialisable.** `np.bool_` isn't `bool`, and the encoder rejects it.
`report._json_default` coerces with `.item()`. `test_json_handles_numpy_scalars` guards it.

**Attacker-controlled strings.** Banners, capability tokens, hostnames, usernames and certificate
subjects all come off the wire. Every one is HTML-escaped before it reaches the page.
`test_html_escapes_attacker_controlled_banner` sends `220 <script>alert("x")</script>` and checks
that it renders as text.

## Evidence integrity

- The input file is **SHA-256 hashed before anything else touches it**. The hash appears in the
  report header, the footer, the JSON `meta` and the audit log.
- `audit.log` records, per run: UTC time, tool version, absolute input path, hash, size, output files,
  posture, severity counts and the options used.
- Capture start and end times come from the packets, analysis time from the clock, and both are
  shown. Certificate validity is judged at capture time.
- The report is metadata-only, so it can be shared or archived without re-exposing passwords or mail.

## Web UI and API

```bash
python -m securemailscope serve --port 8000 --trust-store samples/demo-ca.pem
```

- `GET /` is the upload form plus recent analyses (in memory, the last 20).
- `POST /analyze` takes an upload and redirects to `/report/<id>` (HTML) and `/report/<id>.json`.
- `POST /api/analyze` takes a multipart `file` and returns JSON (`?ml=0` to skip ML).

Uploads go to a temp file, are analysed, and are **deleted immediately**. Only the metadata-only
report is kept, in memory. The server binds to `127.0.0.1` by default; the Dockerfile binds
`0.0.0.0` inside the container. Upload size is capped at 256 MB.
