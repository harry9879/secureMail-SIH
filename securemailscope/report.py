"""Stage 12: outputs.

  JSON  - machine-readable, for SIEM ingest (numpy scalars coerced: np.bool_ is not JSON)
  HTML  - one self-contained file, inline SVG, no external requests, works offline
  PDF   - optional, via reportlab when installed

Every string that came off the wire (banners, capabilities, hostnames, usernames)
is attacker-controlled and is HTML-escaped before it reaches the page.
"""
from __future__ import annotations

import datetime as dt
import json
import math
from collections import OrderedDict, defaultdict
from dataclasses import asdict
from html import escape
from typing import Any

from .ciphers import GROUP_NAMES, profile, version_name
from .models import Finding, SessionResult
from .pipeline import Analysis
from .rules import CATALOG
from .scoring import rule_risk
from .tls import alert_name

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


# =========================================================================== JSON

def _json_default(o: Any):
    try:
        import numpy as np
        if isinstance(o, np.generic):
            return o.item()
        if isinstance(o, np.ndarray):
            return o.tolist()
    except ImportError:
        pass
    if isinstance(o, (bytes, bytearray)):
        return {"bytes": len(o)}
    if isinstance(o, set):
        return sorted(o)
    return str(o)


def session_dict(r: SessionResult) -> dict:
    s = asdict(r.session)
    s["tls_client_bytes"] = len(r.session.tls_client_bytes)
    s["tls_server_bytes"] = len(r.session.tls_server_bytes)
    s["endpoint"] = r.session.endpoint
    return {
        "session": s,
        "tls": r.tls.to_dict() if r.tls else None,
        "certificate_chain": asdict(r.chain) if r.chain else None,
        "findings": [f.rule_id for f in r.findings],
        "features": r.features,
        "rule_risk": rule_risk(r.findings),
        "model_risk": r.model_risk,
        "anomaly_score": r.anomaly_score,
        "risk": r.risk,
        "explanation": [{"feature": f, "contribution": v} for f, v in r.explanation],
        "baseline_deviations": r.baseline_deviations,
    }


def to_dict(a: Analysis) -> dict:
    return {
        "meta": a.meta,
        "posture": a.posture,
        "findings": [f.to_dict() for f in a.findings],
        "sessions": [session_dict(r) for r in a.results],
        "endpoint_baselines": a.endpoints,
        "ml": a.ml_info,
        "timings_seconds": a.timings,
    }


def to_json(a: Analysis, indent: int = 2) -> str:
    return json.dumps(to_dict(a), indent=indent, default=_json_default)


# =========================================================================== HTML helpers

def e(x: Any) -> str:
    return escape("" if x is None else str(x), quote=True)


def _pill(sev: str) -> str:
    return f'<span class="pill sev-{e(sev)}">{e(sev)}</span>'


def _gauge(score: int, grade: str) -> str:
    r, c = 52, 2 * math.pi * 52
    frac = max(0.0, min(1.0, score / 100))
    tone = "good" if score >= 80 else "warn" if score >= 60 else "bad"
    return (f'<svg class="gauge" viewBox="0 0 132 132" role="img" aria-label="Posture score {score} of 100, grade {e(grade)}">'
            f'<circle cx="66" cy="66" r="{r}" class="g-track"/>'
            + (f'<circle cx="66" cy="66" r="{r}" class="g-val g-{tone}" stroke-dasharray="{c * frac:.1f} {c:.1f}" '
               f'transform="rotate(-90 66 66)"/>' if score > 0 else "") +
            f'<text x="66" y="64" class="g-grade">{e(grade)}</text>'
            f'<text x="66" y="88" class="g-score">{score}/100</text></svg>')


def _sev_bar(counts: dict) -> str:
    total = sum(counts.get(s, 0) for s in SEV_ORDER) or 1
    segs, x = [], 0.0
    for s in SEV_ORDER:
        n = counts.get(s, 0)
        if not n:
            continue
        w = 100 * n / total
        segs.append(f'<rect x="{x:.2f}%" y="0" width="{w:.2f}%" height="14" class="fill-{s}"><title>{s}: {n}</title></rect>')
        x += w
    legend = "".join(f'<span class="lg"><i class="dot fill-{s}"></i>{s} <b>{counts.get(s, 0)}</b></span>'
                     for s in SEV_ORDER)
    return f'<svg class="sevbar" width="100%" height="14" role="img" aria-label="Findings by severity">{"".join(segs)}</svg><div class="legend">{legend}</div>'


def _risk_bar(v: float | None) -> str:
    if v is None:
        return '<span class="muted">n/a</span>'
    tone = "bad" if v >= 70 else "warn" if v >= 35 else "good"
    return (f'<span class="riskbar" title="{v:.1f}"><span class="rb-{tone}" style="width:{max(2, v):.0f}%"></span></span>'
            f'<span class="num">{v:.0f}</span>')


def _explain_svg(pairs: list[tuple[str, float]]) -> str:
    if not pairs:
        return '<p class="muted">No feature moves this session\'s model risk by more than half a point.</p>'
    m = max(abs(v) for _, v in pairs) or 1
    rows = []
    for i, (f, v) in enumerate(pairs):
        w = 150 * abs(v) / m
        y = i * 22
        x = 170 if v >= 0 else 170 - w
        cls = "exp-pos" if v >= 0 else "exp-neg"
        rows.append(f'<text x="0" y="{y + 14}" class="exp-l">{e(f)}</text>'
                    f'<rect x="{x:.1f}" y="{y + 3}" width="{w:.1f}" height="14" rx="2" class="{cls}"/>'
                    f'<text x="{(x + w + 6) if v >= 0 else (x - 6):.1f}" y="{y + 14}" class="exp-v" '
                    f'text-anchor="{"start" if v >= 0 else "end"}">{v:+.1f}</text>')
    h = len(pairs) * 22 + 4
    return (f'<svg class="explain" viewBox="0 0 400 {h}" width="100%" style="max-width:520px" role="img" '
            f'aria-label="Model risk contributions"><line x1="170" y1="0" x2="170" y2="{h}" class="axis"/>{"".join(rows)}</svg>')


def _mode_label(r: SessionResult) -> str:
    s = r.session
    if s.mode == "implicit":
        return '<span class="tag t-good">implicit TLS</span>'
    if s.mode == "starttls":
        return '<span class="tag t-good">STARTTLS</span>'
    if s.strip_indicators:
        return '<span class="tag t-bad">stripped</span>'
    return '<span class="tag t-bad">cleartext</span>'


def _cert_label(r: SessionResult) -> str:
    c = r.chain
    if c is None:
        return '<span class="muted">none</span>'
    if not c.present:
        return '<span class="muted">not visible</span>' if r.tls and r.tls.version == 0x0304 else '<span class="muted">none</span>'
    bad = [x for x, cond in (("expired", c.expired), ("self-signed", c.self_signed),
                             ("name mismatch", c.hostname_match is False), ("untrusted", c.trusted is False and not c.self_signed))
           if cond]
    if bad:
        return f'<span class="tag t-bad">{e(", ".join(bad))}</span>'
    return '<span class="tag t-good">valid</span>' if c.trusted else '<span class="tag">unverified</span>'


def _finding_block(f: Finding, sessions: list[str] | None = None, open_: bool = False) -> str:
    esc = (f'<p class="esc">Escalated from <b>{e(f.escalated_from)}</b> by the endpoint baseline.</p>'
           if f.escalated_from else "")
    affected = ""
    if sessions and len(sessions) > 1:
        affected = f' <span class="muted">· {len(sessions)} sessions ({e(", ".join(sessions[:8]))}{" ..." if len(sessions) > 8 else ""})</span>'
    comp = "".join(f"<li>{e(c)}</li>" for c in f.compliance)
    refs = f'<p class="refs"><b>Why it matters:</b> {e(", ".join(f.references))}</p>' if f.references else ""
    return (f'<details class="finding sev-border-{e(f.severity)}" data-sev="{e(f.severity)}"{" open" if open_ else ""}>'
            f'<summary>{_pill(f.severity)} <span class="ftitle">{e(f.title)}</span>'
            f'<span class="fmeta"><code>{e(f.rule_id)}</code> · {e(f.endpoint)}{affected}</span>'
            f'<span class="frisk">priority risk <b>{(f.risk or 0):.0f}</b></span></summary>'
            f'<div class="fbody">{esc}<h4>Evidence</h4><ul class="evidence">{"".join(f"<li>{e(x)}</li>" for x in f.evidence)}</ul>'
            f'<h4>Fix</h4><p class="fix">{_code(f.remediation)}</p>{refs}'
            f'{f"<h4>Compliance (indicative)</h4><ul class=comp>{comp}</ul>" if comp else ""}'
            f'<p class="muted small">exploitability {f.exploitability:.1f} · confidence {f.confidence:.1f}'
            f'{f" · session {e(f.session_id)}" if f.session_id else ""}</p></div></details>')


def _code(text: str) -> str:
    """Escape, then render `backticked` spans as <code>."""
    out, parts = [], e(text).split("`")
    for i, p in enumerate(parts):
        out.append(f"<code>{p}</code>" if i % 2 else p)
    return "".join(out)


def _session_detail(r: SessionResult) -> str:
    s, hs, ch = r.session, r.tls, r.chain
    rows = [("Client", f"{s.client[0]}:{s.client[1]}"), ("Server", f"{s.server[0]}:{s.server[1]}"),
            ("Banner", s.banner[:160]), ("Capabilities", " ".join(s.capabilities) or "-"),
            ("STARTTLS offered", {True: "yes", False: "no", None: "unknown"}[s.starttls_offered]),
            ("STARTTLS requested / reply", f"{'yes' if s.starttls_requested else 'no'}"
                                           f"{' / ' + s.starttls_response if s.starttls_response else ''}"),
            ("TLS starts at byte", f"client {s.tls_client_offset}, server {s.tls_server_offset}"
             if s.tls_client_offset is not None or s.tls_server_offset is not None else "-"),
            ("Cleartext commands", " ".join(s.cleartext_commands[:20]) or "-")]
    if s.auth_events:
        rows.append(("Auth in cleartext", "; ".join(f"{a.mechanism} user={a.username} "
                                                   f"({'secret exposed' if a.secret_exposed else 'hash only'})"
                                                   for a in s.auth_events)))
    q = s.stream_quality
    rows.append(("TCP stream", f"retransmissions {q.get('retransmissions', 0)}, out-of-order {q.get('out_of_order', 0)}, "
                               f"overlaps trimmed {q.get('overlaps_trimmed', 0)}, conflicts {q.get('overlap_conflicts', 0)}, "
                               f"gaps {q.get('gaps', 0)} · client role: {q.get('client_role', '')}"))
    if hs is not None:
        p = profile(hs.cipher_suite) if hs.cipher_suite is not None else None
        rows += [("TLS version", f"{hs.version_name} (legacy_version "
                                 f"{version_name(hs.server_legacy_version) if hs.server_legacy_version else '-'})"),
                 ("Cipher", f"{hs.cipher_name or '-'}" + (f" · grade {p.grade} · FS {'yes' if p.forward_secrecy else 'no'}"
                                                         f" · AEAD {'yes' if p.aead else 'no'}" if p else "")),
                 ("Key exchange group", GROUP_NAMES.get(hs.selected_group or -1, str(hs.selected_group or "-")) +
                  (f" · DH {hs.dh_bits} bits" if hs.dh_bits else "")),
                 ("SNI / ALPN", f"{hs.sni or '-'} / {', '.join(hs.alpn) or '-'}"),
                 ("Client offered", f"{len(hs.client_ciphers)} suites; versions "
                                    f"{', '.join(version_name(v) for v in hs.client_supported_versions) or version_name(hs.client_legacy_version)}"),
                 ("JA3", f"{hs.ja3 or '-'}"), ("JA3S", f"{hs.ja3s or '-'}")]
        if hs.alerts:
            rows.append(("Alerts", ", ".join(f"{'fatal' if l == 2 else 'warning'} {alert_name(d)}" for l, d in hs.alerts)))
    if ch is not None:
        if ch.present:
            for i, c in enumerate(ch.certs):
                rows.append((f"Cert #{i}", f"{c.subject} ← {c.issuer} · {c.key_type} {c.key_bits} · "
                                           f"{(c.signature_hash or '?').upper()} · {c.not_before[:10]} → {c.not_after[:10]} · "
                                           f"SAN {', '.join(c.sans[:4]) or '-'} · sha256 {c.sha256[:16]}…"))
            rows.append(("Chain verdict", f"hostname {ch.hostname or '?'}: "
                                          f"{ {True: 'match', False: 'MISMATCH', None: 'not checked'}[ch.hostname_match]} · "
                                          f"trust: {ch.trust_detail or '-'} · revocation: {ch.revocation}"))
        else:
            rows.append(("Certificate", ch.reason_absent or "-"))
    if s.notes:
        rows.append(("Notes", " · ".join(s.notes)))
    table = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows)
    anomaly = (f"anomaly score {r.anomaly_score:.3f}" if r.anomaly_score is not None else "anomaly detector not run")
    return (f'<div class="sdetail"><table class="kv">{table}</table>'
            f'<div class="xp"><h4>Why the model scored it {r.model_risk if r.model_risk is not None else "-"}</h4>'
            f'{_explain_svg(r.explanation)}<p class="muted small">{e(anomaly)}'
            f'{" · baseline deviations: " + e(", ".join(r.baseline_deviations)) if r.baseline_deviations else ""}</p></div></div>')


# =========================================================================== HTML

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--muted:#6b6a64;--line:#e4e2da;--accent:#2f5bd3;
--crit:#b3261e;--high:#d9480f;--med:#b7791f;--low:#3b7ea1;--info:#8a8980;--good:#2f7d4f;--warn:#b7791f;--bad:#b3261e;
--crit-bg:#fbe9e7;--high-bg:#fdeee4;--med-bg:#fbf3e0;--low-bg:#e7f1f7;--info-bg:#efeee9;--good-bg:#e6f3ea;--code:#f0efe9}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#161615;--card:#1f1f1d;--ink:#ecebe6;--muted:#a3a19a;
--line:#34332f;--accent:#8fb0ff;--crit:#ff8a80;--high:#ffab70;--med:#f2c46b;--low:#8cc3e3;--info:#a3a19a;--good:#7fd19b;
--warn:#f2c46b;--bad:#ff8a80;--crit-bg:#3a1d1b;--high-bg:#3a2518;--med-bg:#352c17;--low-bg:#1a2b35;--info-bg:#2a2a27;
--good-bg:#1a3123;--code:#2a2a27}}
:root[data-theme=dark]{--bg:#161615;--card:#1f1f1d;--ink:#ecebe6;--muted:#a3a19a;--line:#34332f;--accent:#8fb0ff;
--crit:#ff8a80;--high:#ffab70;--med:#f2c46b;--low:#8cc3e3;--info:#a3a19a;--good:#7fd19b;--warn:#f2c46b;--bad:#ff8a80;
--crit-bg:#3a1d1b;--high-bg:#3a2518;--med-bg:#352c17;--low-bg:#1a2b35;--info-bg:#2a2a27;--good-bg:#1a3123;--code:#2a2a27}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px}
h4{margin:14px 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}
.muted{color:var(--muted)}.small{font-size:12.5px}.sub{color:var(--muted);margin:0 0 20px;overflow-wrap:anywhere}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr));gap:14px}
.hero{display:grid;grid-template-columns:170px minmax(0,1fr);gap:22px;align-items:center}
@media (max-width:640px){.hero{grid-template-columns:1fr}}
.gauge{width:150px;height:150px}.g-track{fill:none;stroke:var(--line);stroke-width:12}.g-val{fill:none;stroke-width:12;stroke-linecap:round}
.g-good{stroke:var(--good)}.g-warn{stroke:var(--warn)}.g-bad{stroke:var(--bad)}
.g-grade{font-size:40px;font-weight:700;text-anchor:middle;fill:var(--ink)}.g-score{font-size:13px;text-anchor:middle;fill:var(--muted)}
.stat b{display:block;font-size:24px}.stat span{color:var(--muted);font-size:13px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(120px,100%),1fr));gap:12px;margin-bottom:14px}
.hero>div{min-width:0}.sevbar{border-radius:7px;overflow:hidden;background:var(--line)}.legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:8px;font-size:13px}
.dot{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}
.fill-critical{fill:var(--crit);background:var(--crit)}.fill-high{fill:var(--high);background:var(--high)}
.fill-medium{fill:var(--med);background:var(--med)}.fill-low{fill:var(--low);background:var(--low)}.fill-info{fill:var(--info);background:var(--info)}
.pill{display:inline-block;font-size:11.5px;font-weight:600;padding:1px 8px;border-radius:999px;text-transform:uppercase;letter-spacing:.03em}
.sev-critical{background:var(--crit-bg);color:var(--crit)}.sev-high{background:var(--high-bg);color:var(--high)}
.sev-medium{background:var(--med-bg);color:var(--med)}.sev-low{background:var(--low-bg);color:var(--low)}.sev-info{background:var(--info-bg);color:var(--info)}
.tag{display:inline-block;font-size:12px;padding:1px 7px;border-radius:6px;background:var(--info-bg);color:var(--muted)}
.t-good{background:var(--good-bg);color:var(--good)}.t-bad{background:var(--crit-bg);color:var(--crit)}
details.finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:0;margin:8px 0}
.sev-border-critical{border-left-color:var(--crit)!important}.sev-border-high{border-left-color:var(--high)!important}
.sev-border-medium{border-left-color:var(--med)!important}.sev-border-low{border-left-color:var(--low)!important}
details.finding>summary{cursor:pointer;padding:12px 14px;display:flex;flex-wrap:wrap;gap:6px 10px;align-items:baseline;list-style:none}
details.finding>summary::-webkit-details-marker{display:none}
.ftitle{font-weight:600;overflow-wrap:anywhere;min-width:0}.fmeta{overflow-wrap:anywhere}.fmeta{color:var(--muted);font-size:13px}.frisk{margin-left:auto;font-size:13px;color:var(--muted)}
.fbody{padding:0 16px 14px}.evidence li,.comp li{margin:2px 0;overflow-wrap:anywhere}.fix{margin:0}.esc{color:var(--crit);margin:4px 0}
.refs{font-size:13.5px}
.tablewrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:12px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13.5px}
thead th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}
table.wide{min-width:980px}td code{white-space:nowrap}tr.srow{cursor:pointer}tr.srow:hover td{background:var(--bg)}tr.sdet>td{background:var(--bg);padding:0}
.sdetail{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:18px;padding:14px}
@media (max-width:860px){.sdetail{grid-template-columns:1fr}}
table.kv th{width:190px;color:var(--muted);font-weight:500;font-size:12.5px}table.kv td{overflow-wrap:anywhere;font-size:12.5px}
.riskbar{display:inline-block;width:64px;height:8px;background:var(--line);border-radius:4px;overflow:hidden;vertical-align:middle;margin-right:6px}
.riskbar span{display:block;height:100%}.rb-good{background:var(--good)}.rb-warn{background:var(--warn)}.rb-bad{background:var(--bad)}
.num{font-variant-numeric:tabular-nums}
.explain .exp-l{font-size:11.5px;fill:var(--muted)}.explain .exp-v{font-size:11.5px;fill:var(--ink)}
.exp-pos{fill:var(--bad)}.exp-neg{fill:var(--good)}.axis{stroke:var(--line)}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 10px}
.filters label{font-size:13px;display:inline-flex;gap:5px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:999px;padding:3px 10px;cursor:pointer}
.filters input[type=search]{flex:1;min-width:200px;padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);font:inherit}
.kvs{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(260px,100%),1fr));gap:4px 24px;font-size:13.5px}
.kvs div{overflow-wrap:anywhere}.kvs b{color:var(--muted);font-weight:500}
footer{margin-top:40px;color:var(--muted);font-size:12.5px;overflow-wrap:anywhere}
"""

JS = """
(function(){
 var boxes=[].slice.call(document.querySelectorAll('[data-filter]')),q=document.getElementById('q');
 function apply(){var on={};boxes.forEach(function(b){on[b.value]=b.checked});var t=(q&&q.value||'').toLowerCase();
  document.querySelectorAll('#allf details.finding').forEach(function(d){
   var ok=on[d.dataset.sev]!==false&&(!t||d.textContent.toLowerCase().indexOf(t)>=0);d.style.display=ok?'':'none'})}
 boxes.forEach(function(b){b.addEventListener('change',apply)});if(q)q.addEventListener('input',apply);
 document.querySelectorAll('tr.srow').forEach(function(r){r.addEventListener('click',function(){
  var d=document.getElementById(r.dataset.det);d.hidden=!d.hidden;r.setAttribute('aria-expanded',!d.hidden)})});
})();
"""


def to_html(a: Analysis) -> str:
    m, p = a.meta, a.posture
    groups: "OrderedDict[tuple, list[Finding]]" = OrderedDict()
    for f in a.findings:   # already sorted by priority
        groups.setdefault((f.rule_id, f.endpoint, f.severity), []).append(f)
    top = [(fs[0], [x.session_id for x in fs]) for fs in groups.values() if fs[0].severity in ("critical", "high")][:6]

    by_ep: dict[str, list[SessionResult]] = defaultdict(list)
    for r in a.results:
        by_ep[r.session.endpoint].append(r)

    ep_rows = []
    for ep, rs in sorted(by_ep.items(), key=lambda kv: p["endpoints"].get(kv[0], {}).get("score", 100)):
        info = p["endpoints"].get(ep, {"score": 100, "grade": "A", "findings": {}})
        protos = sorted({r.session.protocol for r in rs})
        modes = sorted({r.session.mode for r in rs})
        vers = sorted({r.tls.version_name for r in rs if r.tls and r.tls.server_hello_seen})
        fc = info["findings"]
        ep_rows.append(f"<tr><td><b>{e(ep)}</b></td><td>{e(', '.join(protos))}</td><td>{e(', '.join(modes))}</td>"
                       f"<td>{e(', '.join(vers) or '-')}</td><td class=num>{len(rs)}</td>"
                       f"<td><b>{e(info['grade'])}</b> <span class=muted>{info['score']}</span></td>"
                       f"<td>{' '.join(f'{_pill(s)} {n}' for s, n in sorted(fc.items(), key=lambda x: SEV_ORDER.index(x[0])))}</td></tr>")

    s_rows = []
    for r in sorted(a.results, key=lambda r: -(r.risk or 0)):
        s, hs = r.session, r.tls
        sev = min((SEV_ORDER.index(f.severity) for f in r.findings), default=4)
        did = f"det-{s.session_id}"
        s_rows.append(
            f'<tr class="srow" data-det="{did}" aria-expanded="false" tabindex="0"><td><code>{e(s.session_id)}</code></td>'
            f"<td>{e(s.client[0])} → <b>{e(s.endpoint)}</b></td><td>{e(s.protocol)}</td><td>{_mode_label(r)}</td>"
            f"<td>{e(hs.version_name if hs and hs.server_hello_seen else '-')}</td>"
            f"<td class=small>{e((hs.cipher_name or '-') if hs else '-')}</td><td>{_cert_label(r)}</td>"
            f"<td>{_pill(SEV_ORDER[sev]) if r.findings else '<span class=muted>none</span>'} "
            f"<span class=muted>{len(r.findings)}</span></td><td>{_risk_bar(r.risk)}</td></tr>"
            f'<tr class="sdet" id="{did}" hidden><td colspan="9">{_session_detail(r)}</td></tr>')

    all_blocks = "".join(_finding_block(fs[0], [x.session_id for x in fs]) for fs in groups.values())
    top_blocks = "".join(_finding_block(f, sids, open_=i == 0) for i, (f, sids) in enumerate(top)) or \
        '<p class="muted">No critical or high findings.</p>'

    rd, ml = m["read"], a.ml_info
    ml_line = (f"{e(ml.get('model'))} trained on {e(ml.get('trained_on'))}; hold-out R² {e(ml.get('holdout_r2'))}, "
               f"MAE {e(ml.get('holdout_mae'))}; explanations: {e(ml.get('explainer'))}. {e(ml.get('anomaly'))}."
               if ml.get("enabled") and ml.get("model") else "ML disabled (--no-ml): rule risk only.")
    base_line = (f"Baseline database <code>{e(m.get('baseline_db'))}</code>: {len(a.endpoints)} endpoint profile(s); "
                 f"{m.get('baseline_learned', 0)} clean session(s) learned from this capture."
                 if m.get("baseline_db") else
                 "No baseline database: endpoints were profiled from the other sessions in this capture only "
                 "(pass <code>--baseline-db</code> to remember endpoints across captures).")
    legend_rows = "".join(f"<tr><td><code>{e(k)}</code></td><td>{e(v[0])}</td><td>{e(v[1])}</td></tr>"
                          for k, v in CATALOG.items())

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureMailScope report</title><style>{CSS}</style></head>
<body><main>
<h1>SecureMailScope report</h1>
<p class="sub">{e(m['input'])} · capture {e(m['capture_start'])} → {e(m['capture_end'])} · analysed {e(m['analysed_at'])} · {e(m['mode'])}</p>

<section class="card hero">
 <div>{_gauge(p['score'], p['grade'])}</div>
 <div>
  <div class="stats">
   <div class="stat"><b>{p['sessions']}</b><span>mail sessions</span></div>
   <div class="stat"><b>{len(by_ep)}</b><span>endpoints</span></div>
   <div class="stat"><b>{sum(1 for r in a.results if r.session.tls_used)}</b><span>used TLS</span></div>
   <div class="stat"><b>{sum(1 for r in a.results if any(ev.secret_exposed for ev in r.session.auth_events))}</b><span>exposed credentials</span></div>
   <div class="stat"><b>{p['unique_issues']}</b><span>distinct issues</span></div>
  </div>
  {_sev_bar(p['counts'])}
 </div>
</section>

<h2>Act on these first</h2>
{top_blocks}

<h2>Endpoints</h2>
<div class="tablewrap"><table class="wide"><thead><tr><th>Endpoint</th><th>Protocol</th><th>Mode</th><th>TLS</th><th>Sessions</th><th>Grade</th><th>Issues</th></tr></thead>
<tbody>{''.join(ep_rows)}</tbody></table></div>

<h2>Sessions</h2>
<p class="muted small">Click a row for the protocol transcript summary, TLS and certificate details, and the model's explanation.</p>
<div class="tablewrap"><table class="wide"><thead><tr><th>ID</th><th>Client → endpoint</th><th>Proto</th><th>Channel</th><th>TLS</th><th>Cipher</th><th>Certificate</th><th>Worst</th><th>Risk</th></tr></thead>
<tbody>{''.join(s_rows)}</tbody></table></div>

<h2>All findings</h2>
<div class="filters" role="group" aria-label="Filter findings">
 {''.join(f'<label><input type="checkbox" data-filter value="{s}" checked> {s}</label>' for s in SEV_ORDER)}
 <input id="q" type="search" placeholder="Search findings, endpoints, rule IDs…" aria-label="Search findings">
</div>
<div id="allf">{all_blocks or '<p class="muted">No findings.</p>'}</div>

<h2>Method and limits</h2>
<div class="card kvs">
 <div><b>Input SHA-256</b><br><code>{e(m['input_sha256'])}</code></div>
 <div><b>Container</b><br>{e(rd['format'])}, link types {e(rd['link_types'])}, {rd['frames']} frames, {rd['tcp_segments']} TCP segments</div>
 <div><b>Skipped</b><br>{rd['fragments_skipped']} IP fragments, {rd['non_tcp']} non-TCP, {rd['non_ip']} non-IP, {rd['truncated']} truncated</div>
 <div><b>Flows</b><br>{m['flows']} TCP conversations; {m['mail_sessions']} mail, {m['non_mail_flows']} ignored (not mail)</div>
 <div><b>Trust store</b><br>{e(m['trust_store'] or 'none')}</div>
 <div><b>Timing</b><br>{e(', '.join(f'{k} {v:.3f}s' for k, v in a.timings.items()))}</div>
</div>
<p class="small">{ml_line}</p>
<p class="small">{base_line}</p>
<p class="small muted">Passive analysis cannot see certificates inside TLS 1.3 (encrypted by design), cannot check revocation
(reported as unknown, never as valid), and cannot reassemble IP fragments (counted above). Severities are intrinsic; priority
risk also weighs exposure, exploitability and asset criticality. Compliance mappings are indicative, not an audit opinion.
Passwords, tokens and message bodies are never stored: only usernames, verbs and byte counts.</p>

<details class="card"><summary><b>Rule catalogue</b></summary>
<div style="overflow-x:auto"><table><thead><tr><th>Rule</th><th>Meaning</th><th>Severity</th></tr></thead><tbody>{legend_rows}</tbody></table></div></details>

<footer>{e(m['tool'])} · report generated {e(dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'))} ·
evidence hash sha256:{e(m['input_sha256'])}</footer>
</main><script>{JS}</script></body></html>"""


# =========================================================================== PDF (optional)

def to_pdf(a: Analysis, path: str) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as ex:
        raise RuntimeError("PDF output needs reportlab: pip install reportlab") from ex

    st = getSampleStyleSheet()
    sev_col = {"critical": "#b3261e", "high": "#d9480f", "medium": "#b7791f", "low": "#3b7ea1", "info": "#8a8980"}
    m, p = a.meta, a.posture
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title="SecureMailScope report")
    story = [Paragraph("SecureMailScope report", st["Title"]),
             Paragraph(e(f"{m['input']} · capture {m['capture_start']} to {m['capture_end']} · analysed {m['analysed_at']}"), st["Normal"]),
             Paragraph(e(f"Input SHA-256 {m['input_sha256']}"), st["Normal"]), Spacer(1, 6 * mm),
             Paragraph(f"Posture <b>{e(p['grade'])}</b> ({p['score']}/100) · {p['sessions']} sessions · " +
                       " · ".join(f"{s} {p['counts'][s]}" for s in SEV_ORDER), st["Heading2"])]
    groups: "OrderedDict[tuple, list[Finding]]" = OrderedDict()
    for f in a.findings:
        groups.setdefault((f.rule_id, f.endpoint, f.severity), []).append(f)
    rows = [["#", "Severity", "Finding", "Endpoint", "Risk"]]
    for i, fs in enumerate(groups.values(), 1):
        f = fs[0]
        rows.append([str(i), f.severity.upper(), Paragraph(e(f"{f.title} ({f.rule_id}) ×{len(fs)}"), st["BodyText"]),
                     Paragraph(e(f.endpoint), st["BodyText"]), f"{f.risk or 0:.0f}"])
    t = Table(rows, colWidths=[8 * mm, 20 * mm, 90 * mm, 45 * mm, 12 * mm], repeatRows=1)
    style = [("FONT", (0, 0), (-1, 0), "Helvetica-Bold"), ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
             ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 8)]
    for i, fs in enumerate(groups.values(), 1):
        style.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor(sev_col[fs[0].severity])))
    t.setStyle(TableStyle(style))
    story += [Spacer(1, 4 * mm), t, Spacer(1, 6 * mm), Paragraph("Details", st["Heading2"])]
    for fs in groups.values():
        f = fs[0]
        if f.severity == "info":
            continue
        story.append(Paragraph(f'<font color="{sev_col[f.severity]}"><b>{e(f.severity.upper())}</b></font> '
                               f"<b>{e(f.title)}</b> — {e(f.endpoint)} ({e(', '.join(x.session_id or '' for x in fs))})",
                               st["BodyText"]))
        for ev in f.evidence:
            story.append(Paragraph("• " + e(ev), st["BodyText"]))
        story.append(Paragraph("<b>Fix:</b> " + e(f.remediation).replace("`", ""), st["BodyText"]))
        if f.compliance:
            story.append(Paragraph("<i>" + e("; ".join(f.compliance)) + "</i>", st["BodyText"]))
        story.append(Spacer(1, 3 * mm))
    doc.build(story)
