"""The whole pipeline, stage 00 to 12, as one function.

    00-01 pcapio     read container, walk link/IP/TCP
    02    flows      TCP reassembly, client/server roles
    03-04 mailproto  banner protocol ID, STARTTLS state machine, TLS slicing
    05    tls        handshake parsing, JA3/JA3S
    06    certs      X.509 analysis
    07    rules      findings with evidence, fix, compliance
    08    features   feature vectors
    09    baseline   per-endpoint profile, deviations, escalation
    10    ml         risk model + isolation forest
    11    scoring    prioritisation, posture
    12    report     JSON / HTML / PDF (see report.py)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from . import __version__, baseline, certs, mailproto, ml, rules, scoring, tls
from .features import to_row, vector
from .flows import build_flows
from .models import Finding, SessionResult
from .pcapio import read_packets


@dataclass
class Options:
    trust_store: Optional[str] = None
    use_default_trust: bool = True
    baseline_db: Optional[str] = None
    learn: bool = True
    use_ml: bool = True
    contamination: Optional[float] = None
    criticality: dict = field(default_factory=dict)
    model_path: Optional[str] = None


@dataclass
class Analysis:
    meta: dict
    results: list[SessionResult]
    findings: list[Finding]
    posture: dict
    endpoints: list[dict]
    ml_info: dict
    timings: dict


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def analyze(path: str, opts: Optional[Options] = None) -> Analysis:
    opts = opts or Options()
    t0 = time.perf_counter()
    timings: dict[str, float] = {}

    def lap(name: str, since: float) -> float:
        now = time.perf_counter()
        timings[name] = round(now - since, 4)
        return now

    digest = sha256_file(path)   # evidence integrity: hash the input before touching it
    t = time.perf_counter()

    # ---------------- Part 1
    packets, rstats = read_packets(path)
    t = lap("read", t)
    flows = build_flows(packets)
    t = lap("reassembly", t)
    sessions = []
    for flow in flows:
        s = mailproto.parse_session(flow, f"S{len(sessions) + 1:03d}")
        if s is not None:
            sessions.append(s)
    t = lap("protocol", t)

    # ---------------- Part 2
    results: list[SessionResult] = []
    for s in sessions:
        hs = tls.analyze(s.tls_client_bytes, s.tls_server_bytes) if s.tls_used else None
        hostname = (hs.sni if hs and hs.sni else None) or s.server_name
        chain = certs.analyze(hs, hostname, s.start_ts, opts.trust_store, opts.use_default_trust) \
            if hs is not None else None
        results.append(SessionResult(session=s, tls=hs, chain=chain, findings=rules.evaluate(s, hs, chain)))
    t = lap("crypto_rules", t)

    # ---------------- Part 3: baseline (leave-one-out within capture + stored history)
    store = baseline.BaselineStore(opts.baseline_db)
    observations = []
    for r in results:
        feats = to_row(vector(r.session, r.tls, r.chain))
        observations.append(baseline.observe(r.session, r.tls, r.chain, r.findings, digest[:16], feats))
    history_cache: dict[str, list] = {}
    for i, (r, o) in enumerate(zip(results, observations)):
        if o.endpoint not in history_cache:
            history_cache[o.endpoint] = store.history(o.endpoint)
        peers = history_cache[o.endpoint] + [p for j, p in enumerate(observations) if j != i and p.endpoint == o.endpoint]
        codes, new = baseline.compare(o, r.session, peers, r.findings)
        r.baseline_deviations = codes
        r.findings.extend(new)
        r.features = vector(r.session, r.tls, r.chain, set(codes))
    t = lap("baseline", t)

    # ---------------- Part 3: ML
    ml_info: dict = {"enabled": opts.use_ml}
    if opts.use_ml and results:
        model = ml.load_model(opts.model_path)
        rows = [to_row(r.features) for r in results]
        for r, risk, expl in zip(results, model.predict(rows), model.explain(rows)):
            r.model_risk = risk
            r.explanation = expl
        anomalies = ml.detect_anomalies(rows, store.feature_history(), opts.contamination)
        for r, flag, reasons, i in zip(results, anomalies.flags, anomalies.reasons, range(len(results))):
            r.anomaly_score = anomalies.scores[i] if anomalies.scores else None
            if flag:
                r.findings.append(Finding(
                    rule_id="SMS-ML-001", title="Statistical outlier session (isolation forest)", severity="medium",
                    category="anomaly", session_id=r.session.session_id, endpoint=r.session.endpoint,
                    evidence=[f"anomaly score {r.anomaly_score}"] + reasons,
                    remediation="Review this session against the endpoint's normal behaviour; outliers are leads, not verdicts.",
                    references=["Isolation Forest (Liu et al., 2008)"], exploitability=0.3, confidence=0.5))
        ml_info.update({"model": type(model.model).__name__, "trained_on": model.trained_on,
                        "holdout_r2": model.holdout_r2, "holdout_mae": model.holdout_mae,
                        "explainer": model.explainer, "anomaly": anomalies.note})
    for r in results:
        r.risk = scoring.blend(scoring.rule_risk(r.findings), r.model_risk,
                               any(f.rule_id == "SMS-ML-001" for f in r.findings))
    t = lap("ml", t)

    # ---------------- Part 3: scoring
    findings = scoring.prioritise(results, opts.criticality)
    post = scoring.posture(findings, len(results))
    for r in results:
        ep = r.session.endpoint
        post["endpoints"].setdefault(ep, {"score": 100, "grade": "A", "findings": {}})
    # Re-judge cleanliness after escalation and ML, so an attack session never enters the baseline.
    for r, o in zip(results, observations):
        o.clean = not (any(f.severity in ("critical", "high") for f in r.findings) or r.baseline_deviations)
    learned = store.learn(observations) if (opts.learn and opts.baseline_db) else 0
    endpoints = [baseline.profile_summary(ep, store.history(ep)) for ep in sorted({o.endpoint for o in observations})] \
        if opts.baseline_db else []
    store.close()
    t = lap("scoring", t)
    timings["total"] = round(time.perf_counter() - t0, 4)

    ts = [r.session.start_ts for r in results] or [0.0]
    meta = {
        "tool": f"SecureMailScope {__version__}",
        "input": os.path.basename(path),
        "input_sha256": digest,
        "input_bytes": os.path.getsize(path),
        "analysed_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "capture_start": dt.datetime.fromtimestamp(min(ts), dt.timezone.utc).isoformat(timespec="seconds"),
        "capture_end": dt.datetime.fromtimestamp(max(r.session.end_ts for r in results) if results else 0,
                                                 dt.timezone.utc).isoformat(timespec="seconds"),
        "read": rstats.to_dict(),
        "flows": len(flows),
        "mail_sessions": len(results),
        "non_mail_flows": len(flows) - len(results),
        "baseline_db": opts.baseline_db,
        "baseline_learned": learned,
        "trust_store": opts.trust_store or ("certifi (Mozilla)" if opts.use_default_trust else None),
        "mode": "passive, metadata-only (no passwords, tokens or message bodies retained)",
    }
    return Analysis(meta=meta, results=results, findings=findings, posture=post, endpoints=endpoints,
                    ml_info=ml_info, timings=timings)
