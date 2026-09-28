"""Minimal web UI and JSON API (Flask).

    GET  /                 upload form + recent analyses (this process only)
    POST /analyze          upload a capture -> redirect to its HTML report
    GET  /report/<id>      HTML report        GET /report/<id>.json   JSON
    POST /api/analyze      multipart 'file' -> JSON (for SIEM / automation)

Uploaded captures are written to a temp file, analysed, and deleted immediately:
only the metadata-only report is kept, and only in memory.
"""
from __future__ import annotations

import os
import tempfile
import uuid
from collections import OrderedDict
from html import escape

from flask import Flask, Response, abort, jsonify, redirect, request, url_for

from . import __version__, report
from .pipeline import Options, analyze

MAX_UPLOAD = 256 * 1024 * 1024
KEEP = 20

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SecureMailScope</title>
<style>
:root{{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--muted:#6b6a64;--line:#e4e2da;--accent:#2f5bd3}}
@media (prefers-color-scheme:dark){{:root{{--bg:#161615;--card:#1f1f1d;--ink:#ecebe6;--muted:#a3a19a;--line:#34332f;--accent:#8fb0ff}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
main{{max-width:760px;margin:0 auto;padding:40px 16px}}h1{{margin:0 0 6px}}p{{color:var(--muted)}}
form,.list{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:20px 0}}
input[type=file]{{display:block;margin:10px 0 16px;max-width:100%}}
button{{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:9px 18px;font:inherit;cursor:pointer}}
label{{display:block;margin:6px 0;color:var(--muted);font-size:14px}}a{{color:var(--accent)}}
li{{margin:6px 0;overflow-wrap:anywhere}}code{{font-size:13px}}.err{{color:#b3261e}}
</style></head><body><main>
<h1>SecureMailScope</h1>
<p>Passive analysis of SMTP, IMAP and POP3 transport security from a packet capture: STARTTLS stripping,
plaintext credentials, TLS and certificate weaknesses, and per-endpoint anomalies.</p>
{error}
<form method="post" action="/analyze" enctype="multipart/form-data">
 <b>Upload a .pcap or .pcapng</b>
 <input type="file" name="file" accept=".pcap,.pcapng,.cap" required>
 <label><input type="checkbox" name="no_ml"> Rules and baseline only (skip ML)</label>
 <button type="submit">Analyse</button>
 <p style="font-size:13px">The capture is deleted as soon as it has been analysed; the report keeps metadata only.</p>
</form>
<div class="list"><b>Recent analyses</b>{recent}</div>
<p style="font-size:13px">API: <code>curl -F file=@capture.pcap http://HOST/api/analyze</code> · v{version}</p>
</main></body></html>"""


def create_app(trust_store: str | None = None, baseline_db: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
    reports: "OrderedDict[str, tuple[str, str, str, str]]" = OrderedDict()  # id -> (name, grade, html, json)

    def run(upload, use_ml: bool):
        fd, tmp = tempfile.mkstemp(suffix=".pcap")
        try:
            with os.fdopen(fd, "wb") as f:
                upload.save(f)
            a = analyze(tmp, Options(trust_store=trust_store, baseline_db=baseline_db, use_ml=use_ml))
            a.meta["input"] = os.path.basename(upload.filename or "upload.pcap")
            return a
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    def page(error: str = "") -> str:
        items = "".join(f'<li><a href="{url_for("show", rid=k)}">{escape(v[0])}</a> - grade {escape(v[1])} '
                        f'(<a href="{url_for("show_json", rid=k)}">json</a>)</li>'
                        for k, v in reversed(reports.items()))
        return PAGE.format(error=f'<p class="err">{escape(error)}</p>' if error else "",
                           recent=f"<ul>{items}</ul>" if items else "<p>None yet.</p>", version=__version__)

    @app.get("/")
    def index():
        return page()

    @app.post("/analyze")
    def upload():
        f = request.files.get("file")
        if not f or not f.filename:
            return page("Choose a capture file first."), 400
        try:
            a = run(f, use_ml=not request.form.get("no_ml"))
        except Exception as ex:   # malformed captures must not take the service down
            return page(f"Could not analyse {f.filename}: {ex}"), 400
        rid = uuid.uuid4().hex[:12]
        reports[rid] = (a.meta["input"], f"{a.posture['grade']} ({a.posture['score']})",
                        report.to_html(a), report.to_json(a))
        while len(reports) > KEEP:
            reports.popitem(last=False)
        return redirect(url_for("show", rid=rid))

    @app.get("/report/<rid>")
    def show(rid: str):
        if rid not in reports:
            abort(404)
        return Response(reports[rid][2], mimetype="text/html")

    @app.get("/report/<rid>.json")
    def show_json(rid: str):
        if rid not in reports:
            abort(404)
        return Response(reports[rid][3], mimetype="application/json")

    @app.post("/api/analyze")
    def api():
        f = request.files.get("file")
        if not f:
            return jsonify(error="multipart field 'file' is required"), 400
        try:
            a = run(f, use_ml=request.args.get("ml", "1") != "0")
        except Exception as ex:
            return jsonify(error=str(ex)), 400
        return Response(report.to_json(a), mimetype="application/json")

    return app
