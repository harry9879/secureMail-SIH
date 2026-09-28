"""Web frontend and JSON API (Flask).

    GET  /                       single-page app (securemailscope/web/)
    GET  /api/reports            recent analyses (this process only)
    GET  /api/report/<id>        one analysis as JSON
    POST /api/analyze            multipart 'file' -> JSON report (+ "id")
    POST /api/demo               analyse the bundled demo captures (baseline week, then the demo)
    GET  /report/<id>            the self-contained HTML report, for export
    GET  /report/<id>.json       the JSON report, for download
    POST /analyze                no-JavaScript fallback: upload form -> redirect to /report/<id>

Uploaded captures are written to a temp file, analysed, and deleted immediately:
only the metadata-only report is kept, and only in memory.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from collections import OrderedDict

from flask import Flask, Response, abort, jsonify, redirect, request, send_from_directory, url_for

from . import __version__, report
from .pipeline import Options, analyze

MAX_UPLOAD = 256 * 1024 * 1024
KEEP = 20
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


def _demo_dir() -> str:
    root = os.environ.get("SECUREMAILSCOPE_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "securemailscope")
    return os.path.join(root, "demo-samples")


def create_app(trust_store: str | None = None, baseline_db: str | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
    reports: "OrderedDict[str, dict]" = OrderedDict()   # id -> {"name", "json", "html", "summary"}
    lock = threading.Lock()

    def store(a, name: str) -> str:
        a.meta["input"] = name
        rid = uuid.uuid4().hex[:12]
        data = report.to_dict(a)
        data["id"] = rid
        entry = {"name": name, "json": json.dumps(data, default=report._json_default), "html": report.to_html(a),
                 "summary": {"id": rid, "name": name, "grade": a.posture["grade"], "score": a.posture["score"],
                             "sessions": a.meta["mail_sessions"], "counts": a.posture["counts"],
                             "sha256": a.meta["input_sha256"], "analysed_at": a.meta["analysed_at"]}}
        with lock:
            reports[rid] = entry
            while len(reports) > KEEP:
                reports.popitem(last=False)
        return rid

    def run_upload(upload, use_ml: bool):
        fd, tmp = tempfile.mkstemp(suffix=".pcap")
        try:
            with os.fdopen(fd, "wb") as f:
                upload.save(f)
            return analyze(tmp, Options(trust_store=trust_store, baseline_db=baseline_db, use_ml=use_ml))
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    # ------------------------------------------------------------------ the app
    @app.get("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name: str):
        return send_from_directory(WEB_DIR, name)

    # ------------------------------------------------------------------ API
    @app.get("/api/reports")
    def api_reports():
        with lock:
            return jsonify([e["summary"] for e in reversed(reports.values())])

    @app.get("/api/report/<rid>")
    def api_report(rid: str):
        if rid not in reports:
            abort(404)
        return Response(reports[rid]["json"], mimetype="application/json")

    @app.post("/api/analyze")
    def api_analyze():
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify(error="multipart field 'file' is required"), 400
        try:
            a = run_upload(f, use_ml=request.args.get("ml", "1") != "0" and not request.form.get("no_ml"))
        except Exception as ex:   # malformed captures must not take the service down
            return jsonify(error=f"could not analyse {f.filename}: {ex}"), 400
        rid = store(a, os.path.basename(f.filename))
        return Response(reports[rid]["json"], mimetype="application/json")

    @app.post("/api/demo")
    def api_demo():
        """Generate the demo captures once, learn the clean week, then analyse the demo capture."""
        from .samples import generate
        d = _demo_dir()
        paths = {"trust_store": os.path.join(d, "demo-ca.pem"), "baseline": os.path.join(d, "healthy_baseline.pcap"),
                 "demo": os.path.join(d, "demo_enterprise.pcap")}
        if not all(os.path.exists(p) for p in paths.values()):
            paths = generate(d)
        db = os.path.join(tempfile.mkdtemp(prefix="sms-demo-"), "baseline.sqlite")
        opts = Options(trust_store=paths["trust_store"], baseline_db=db,
                       use_ml=request.args.get("ml", "1") != "0")
        analyze(paths["baseline"], opts)
        a = analyze(paths["demo"], Options(trust_store=paths["trust_store"], baseline_db=db, learn=False,
                                           use_ml=opts.use_ml))
        rid = store(a, "demo_enterprise.pcap")
        return Response(reports[rid]["json"], mimetype="application/json")

    # ------------------------------------------------------------------ exports and no-JS fallback
    @app.get("/report/<rid>")
    def show(rid: str):
        if rid not in reports:
            abort(404)
        return Response(reports[rid]["html"], mimetype="text/html")

    @app.get("/report/<rid>.json")
    def show_json(rid: str):
        if rid not in reports:
            abort(404)
        return Response(reports[rid]["json"], mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{reports[rid]["name"]}.json"'})

    @app.post("/analyze")
    def upload_form():
        f = request.files.get("file")
        if not f or not f.filename:
            return redirect(url_for("index"))
        try:
            a = run_upload(f, use_ml=not request.form.get("no_ml"))
        except Exception as ex:
            return Response(f"Could not analyse the capture: {ex}", status=400, mimetype="text/plain")
        return redirect(url_for("show", rid=store(a, os.path.basename(f.filename))))

    @app.get("/api/version")
    def version():
        return jsonify(version=__version__)

    return app
