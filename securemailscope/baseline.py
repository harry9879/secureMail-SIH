"""Stage 09: per-endpoint baselining - the differentiator.

A self-signed certificate on its own is a Medium. A self-signed certificate on an
endpoint that presented the same CA-issued certificate in forty earlier sessions
is a possible active MITM, and is Critical. Only a per-endpoint profile can tell
the two apart.

Endpoints are keyed by server IP:port, never by the banner hostname: an attacker
in the path controls the banner.

Peers for a session are (a) clean observations from earlier captures, stored in
SQLite, and (b) the *other* clean sessions to the same endpoint in this capture
(leave-one-out, so a bad session cannot dilute its own baseline). Only sessions
without critical findings are learned, so an attack does not poison the profile.
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Optional

from .ciphers import VERSION_ORDINAL, profile, version_name
from .models import ChainInfo, Finding, MailSession, TlsHandshake, hostport

MIN_SUPPORT = 3


@dataclass
class Observation:
    endpoint: str
    ts: float
    session_id: str
    capture: str
    starttls_offered: Optional[bool]
    tls_used: bool
    version: Optional[int]
    cipher: Optional[int]
    grade: Optional[str]
    ja3s: Optional[str]
    cert_fp: Optional[str]
    cert_issuer: Optional[str]
    self_signed: Optional[bool]
    trusted: Optional[bool]
    clean: bool
    features: list[float] = field(default_factory=list)


def endpoint_key(sess: MailSession) -> str:
    return hostport(sess.server[0], sess.server[1])


def observe(sess: MailSession, hs: Optional[TlsHandshake], chain: Optional[ChainInfo], findings: list[Finding],
            capture: str, features: list[float]) -> Observation:
    leaf = chain.leaf if chain is not None and chain.present else None
    return Observation(
        endpoint=endpoint_key(sess), ts=sess.start_ts, session_id=sess.session_id, capture=capture,
        starttls_offered=True if sess.mode == "implicit" else sess.starttls_offered,
        tls_used=bool(hs and hs.server_hello_seen),
        version=hs.version if hs else None,
        cipher=hs.cipher_suite if hs else None,
        grade=profile(hs.cipher_suite).grade if hs and hs.cipher_suite is not None else None,
        ja3s=hs.ja3s if hs else None,
        cert_fp=leaf.sha256 if leaf else None,
        cert_issuer=leaf.issuer if leaf else None,
        self_signed=chain.self_signed if leaf else None,
        trusted=chain.trusted if leaf else None,
        clean=not any(f.severity == "critical" for f in findings),
        features=features,
    )


class BaselineStore:
    """SQLite-backed history of clean observations. path=None keeps it in memory."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.db = sqlite3.connect(path or ":memory:")
        self.db.execute("""CREATE TABLE IF NOT EXISTS observations (
            endpoint TEXT, ts REAL, session_id TEXT, capture TEXT, data TEXT)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS ix_ep ON observations(endpoint)")
        self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_obs ON observations(capture, session_id)")
        self.db.commit()

    def history(self, endpoint: str) -> list[Observation]:
        rows = self.db.execute("SELECT data FROM observations WHERE endpoint = ? ORDER BY ts", (endpoint,))
        return [Observation(**json.loads(r[0])) for r in rows]

    def feature_history(self, limit: int = 5000) -> list[list[float]]:
        rows = self.db.execute("SELECT data FROM observations ORDER BY ts DESC LIMIT ?", (limit,))
        return [json.loads(r[0])["features"] for r in rows if json.loads(r[0])["features"]]

    def learn(self, observations: list[Observation]) -> int:
        n = 0
        for o in observations:
            if not o.clean:
                continue
            self.db.execute("INSERT OR IGNORE INTO observations VALUES (?,?,?,?,?)",
                            (o.endpoint, o.ts, o.session_id, o.capture, json.dumps(asdict(o))))
            n += 1
        self.db.commit()
        return n

    def summary(self) -> list[dict]:
        out = []
        for (ep,) in self.db.execute("SELECT DISTINCT endpoint FROM observations ORDER BY endpoint"):
            out.append(profile_summary(ep, self.history(ep)))
        return out

    def close(self) -> None:
        self.db.close()


def profile_summary(endpoint: str, obs: list[Observation]) -> dict:
    offered = [o.starttls_offered for o in obs if o.starttls_offered is not None]
    versions = Counter(version_name(o.version) for o in obs if o.version)
    return {
        "endpoint": endpoint,
        "sessions": len(obs),
        "starttls_rate": round(sum(offered) / len(offered), 2) if offered else None,
        "tls_rate": round(sum(o.tls_used for o in obs) / len(obs), 2) if obs else None,
        "versions": dict(versions),
        "certificates": len({o.cert_fp for o in obs if o.cert_fp}),
        "ja3s": len({o.ja3s for o in obs if o.ja3s}),
    }


def _finding(o: Observation, sess: MailSession, rule: str, title: str, sev: str, evidence: list[str],
             fix: str, exploit: float) -> Finding:
    return Finding(rule_id=rule, title=title, severity=sev, category="anomaly", session_id=sess.session_id,
                   endpoint=sess.endpoint, evidence=evidence, remediation=fix,
                   compliance=["CERT-In Directions 28 Apr 2022 (attack on mail server: report within 6 h)",
                               "ISO/IEC 27001:2022 A.5.25 (assessment of security events)"],
                   references=["per-endpoint baseline"], exploitability=exploit, confidence=0.8)


MITM_FIX = ("Treat as a potential active interception: preserve this capture (hash recorded in the report), "
            "trace the network path between the client and the server (ARP/DHCP/DNS spoofing, rogue gateway, "
            "compromised middlebox), and verify the server's real certificate out-of-band. Long term: MTA-STS "
            "enforce / DANE for relays, implicit TLS with certificate validation for clients.")


def compare(o: Observation, sess: MailSession, peers: list[Observation],
            findings: list[Finding]) -> tuple[list[str], list[Finding]]:
    """Return (deviation codes, new findings) and escalate related rule findings in place."""
    peers = [p for p in peers if p.clean]
    codes: list[str] = []
    new: list[Finding] = []
    if len(peers) < MIN_SUPPORT:
        return codes, new

    # 1. STARTTLS vanished
    offered = [p.starttls_offered or p.tls_used for p in peers if p.starttls_offered is not None or p.tls_used]
    if len(offered) >= MIN_SUPPORT and sum(offered) / len(offered) >= 0.8 and not o.tls_used \
            and (o.starttls_offered is False or sess.strip_indicators):
        # (a client that ignores an offered STARTTLS is misconfigured, not attacked: SMS-PLAIN-002)
        codes.append("starttls_drop")
        new.append(_finding(o, sess, "SMS-BASE-001", "STARTTLS vanished versus endpoint baseline - possible active MITM",
                            "critical",
                            [f"endpoint offered TLS in {sum(offered)} of {len(offered)} baseline sessions; "
                             f"this session: {'capability absent' if o.starttls_offered is False else 'no TLS'}"] +
                            sess.strip_indicators[:2], MITM_FIX, 0.9))
        _escalate(findings, {"SMS-STRIP-001", "SMS-PLAIN-001", "SMS-PLAIN-003"}, "critical",
                  "deviates from endpoint baseline: possible active MITM")

    # 2. certificate changed
    fps = Counter(p.cert_fp for p in peers if p.cert_fp)
    issuers = {p.cert_issuer for p in peers if p.cert_issuer}
    if o.cert_fp and sum(fps.values()) >= MIN_SUPPORT and o.cert_fp not in fps:
        suspicious = bool(o.self_signed) or o.trusted is False or (issuers and o.cert_issuer not in issuers)
        if suspicious:
            codes.append("cert_change")
            known = ", ".join(f"{fp[:16]}... x{n}" for fp, n in fps.most_common(2))
            new.append(_finding(o, sess, "SMS-BASE-002",
                                "Certificate changed versus endpoint baseline - possible MITM", "critical",
                                [f"presented {o.cert_fp[:16]}... (issuer {o.cert_issuer})",
                                 f"baseline certificates: {known}",
                                 "new certificate is " + ("self-signed" if o.self_signed else
                                                          "untrusted" if o.trusted is False else "from a new issuer")],
                                MITM_FIX, 0.8))
            _escalate(findings, {"SMS-CERT-002", "SMS-CERT-003", "SMS-CERT-007"}, "critical",
                      "deviates from endpoint baseline: possible MITM with substitute certificate")

    # 3. downgrade of protocol version or cipher grade
    versions = Counter(p.version for p in peers if p.version)
    if o.version and versions:
        usual, n = versions.most_common(1)[0]
        if n / sum(versions.values()) >= 0.8 and VERSION_ORDINAL.get(o.version, 0) < VERSION_ORDINAL.get(usual, 0):
            codes.append("downgrade")
            new.append(_finding(o, sess, "SMS-BASE-003", "Protocol downgrade versus endpoint baseline", "high",
                                [f"negotiated {version_name(o.version)}; endpoint normally negotiates "
                                 f"{version_name(usual)} ({n}/{sum(versions.values())} sessions)"], MITM_FIX, 0.6))
    grades = Counter(p.grade for p in peers if p.grade)
    if "downgrade" not in codes and o.grade and grades:
        usual_g, n = grades.most_common(1)[0]
        order = "ABCF"
        if n / sum(grades.values()) >= 0.8 and o.grade in order and usual_g in order and \
                order.index(o.grade) > order.index(usual_g):
            codes.append("downgrade")
            new.append(_finding(o, sess, "SMS-BASE-003", "Cipher downgrade versus endpoint baseline", "high",
                                [f"cipher grade {o.grade}; endpoint normally grade {usual_g}"], MITM_FIX, 0.6))

    # 4. new server fingerprint
    ja3s = {p.ja3s for p in peers if p.ja3s}
    if o.ja3s and len([p for p in peers if p.ja3s]) >= MIN_SUPPORT and o.ja3s not in ja3s and not codes:
        codes.append("new_ja3s")
        new.append(_finding(o, sess, "SMS-BASE-004", "New server TLS fingerprint for endpoint", "low",
                            [f"JA3S {o.ja3s} not seen in {len(ja3s)} known fingerprint(s)",
                             "benign after a server upgrade; suspicious if unannounced"],
                            "Confirm a planned server/TLS library change; otherwise investigate.", 0.3))
    return codes, new


def _escalate(findings: list[Finding], rule_ids: set[str], to: str, why: str) -> None:
    for f in findings:
        if f.rule_id in rule_ids and f.severity != to:
            f.escalated_from = f.severity
            f.severity = to
            f.title = f"{f.title} ({why})"
