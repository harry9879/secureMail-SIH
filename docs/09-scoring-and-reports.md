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

The frontend is a single page in `securemailscope/web/` (vanilla JS, no build step) that reads the JSON API:

| View | What it shows |
|---|---|
| `#/` | drag-and-drop upload, "run the built-in demo", recent analyses; the 12 pipeline stages animate during analysis and then show real per-stage timings |
| `#/r/<id>/<section>` | an app shell with a **sidebar**: the report's grade, the sections **Overview** (animated posture ring, counters, severity bar, top four findings), **Wire replay** (every session plays back in order as packets between clients and servers; sealed, cleartext and attacked links are coloured differently, with a live findings feed, play/pause/speed/scrub), **Findings** (filterable, searchable), **Endpoints** (table plus channel and version charts) and **Sessions**, then a quick-jump list of every session with a status dot. Each section fits one screen at 1440×900: long lists scroll inside their card. Below 900 px wide the sidebar becomes a horizontal tab bar |
| `#/r/<id>/s/<sid>` | inside the same shell: **handshake replay** as a client / network path / server sequence diagram, built from the session's redacted `transcript` and the TLS `client_flow` / `server_flow`. Tampering is drawn at the path lane: a stripped offer morphs `STARTTLS` into `XXXXXXXX`, and a swapped certificate morphs "CA cert" into "self-signed". A channel badge moves from cleartext to negotiating to encrypted (or stripped). Each step has a plain-language explanation in the right column; below it, tabs for Findings (each lights up at the step that triggers it), Why this score and Connection |

The replay data is metadata-only too. `MailSession.transcript` keeps commands and replies, but
replaces every password, SASL response and token with `•••••• (secret redacted)` and every message
body with a byte count. `test_transcript_is_redacted_and_ordered` enforces this.

API:

- `GET /api/reports` lists recent analyses; `GET /api/report/<id>` returns one as JSON.
- `POST /api/analyze` takes a multipart `file` and returns the JSON report with its `id` (`?ml=0` to skip ML).
- `POST /api/demo` generates the demo captures once, learns the clean baseline week, then analyses the demo capture.
- `GET /report/<id>` exports the self-contained HTML report; `/report/<id>.json` downloads the JSON.
- `POST /analyze` is the no-JavaScript fallback: an upload form that redirects to the HTML report.

Uploads go to a temp file, are analysed, and are **deleted immediately**. Only the metadata-only
report is kept, in memory. The server binds to `127.0.0.1` by default; the Dockerfile binds
`0.0.0.0` inside the container. Upload size is capped at 256 MB.
