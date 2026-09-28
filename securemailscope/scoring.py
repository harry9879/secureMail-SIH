"""Stage 11: prioritisation and posture scoring.

Severity is not priority. A finding's priority risk is

    risk = 100 x severity x exposure x exploitability x asset criticality

  severity        intrinsic weight of the finding (critical 1.0 ... info 0)
  exposure        what the channel carries: submission/access carry user credentials
                  and mailbox content (1.0); relays carry mail but no user passwords (0.85);
                  purely internal traffic is discounted (x0.8)
  exploitability  can a passive observer exploit it (1.0) or does it need an active
                  attacker, key compromise or offline work (lower)
  criticality     analyst-supplied per asset (assets.json), default 1.0
"""
from __future__ import annotations

import ipaddress
import json
from collections import Counter, defaultdict
from typing import Optional

from .models import SEVERITY_WEIGHT, Finding, SessionResult, hostport
from .rules import port_class

EXPOSURE = {"submission": 1.0, "access": 1.0, "relay": 0.85, "nonstandard": 0.9}
PENALTY = {"critical": 30, "high": 12, "medium": 5, "low": 1, "info": 0}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def load_criticality(path: Optional[str]) -> dict[str, float]:
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        return {str(k): float(v) for k, v in json.load(f).items()}


def criticality_for(res: SessionResult, table: dict[str, float]) -> float:
    s = res.session
    for key in (hostport(s.server[0], s.server[1]), s.server[0], s.endpoint, s.server_name or "", "default"):
        if key and key in table:
            return table[key]
    return 1.0


def exposure_for(res: SessionResult) -> float:
    s = res.session
    e = EXPOSURE.get(port_class(s), 0.9)
    if _private(s.client[0]) and _private(s.server[0]):
        e *= 0.8
    return e


def finding_risk(f: Finding, exposure: float, criticality: float) -> float:
    exploit = 0.5 + 0.5 * f.exploitability
    return round(min(100.0, 100.0 * SEVERITY_WEIGHT[f.severity] * exposure * exploit * criticality), 1)


def rule_risk(findings: list[Finding]) -> float:
    """Noisy-OR of finding weights: several mediums add up, but never exceed one critical."""
    p = 1.0
    for f in findings:
        p *= 1.0 - SEVERITY_WEIGHT[f.severity] * (0.6 + 0.4 * f.exploitability)
    return round(100.0 * (1.0 - p), 1)


def blend(rule: float, model: Optional[float], anomaly_flag: bool) -> float:
    r = rule if model is None else 0.6 * rule + 0.4 * model
    if anomaly_flag:
        r = min(100.0, r + 10.0)
    return round(r, 1)


def prioritise(results: list[SessionResult], criticality: dict[str, float]) -> list[Finding]:
    all_f: list[Finding] = []
    for res in results:
        exp, crit = exposure_for(res), criticality_for(res, criticality)
        for f in res.findings:
            f.risk = finding_risk(f, exp, crit)
            all_f.append(f)
    order = {s: i for i, s in enumerate(("critical", "high", "medium", "low", "info"))}
    all_f.sort(key=lambda f: (-(f.risk or 0), order[f.severity], f.rule_id, f.session_id or ""))
    for i, f in enumerate(all_f, 1):
        f.priority = i
    return all_f


def posture(findings: list[Finding], n_sessions: int) -> dict:
    """0-100 score from unique (rule, endpoint) pairs, so one noisy endpoint cannot sink the score twice."""
    unique: dict[tuple[str, str], str] = {}
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in findings:
        k = (f.rule_id, f.endpoint)
        if k not in unique or rank[f.severity] < rank[unique[k]]:
            unique[k] = f.severity
    penalty = sum(PENALTY[s] for s in unique.values())
    score = max(0, 100 - penalty)
    counts = Counter(f.severity for f in findings)
    if counts.get("critical"):
        score = min(score, 59)   # any critical finding caps the posture at F
    grade = next(g for t, g in GRADES if score >= t)
    per_ep: dict[str, list[str]] = defaultdict(list)
    for (rule, ep), sev in unique.items():
        per_ep[ep].append(sev)
    endpoints = {}
    for ep, sevs in per_ep.items():
        s = max(0, 100 - sum(PENALTY[x] for x in sevs))
        if "critical" in sevs:
            s = min(s, 59)
        endpoints[ep] = {"score": s, "grade": next(g for t, g in GRADES if s >= t),
                         "findings": dict(Counter(sevs))}
    return {"score": score, "grade": grade, "sessions": n_sessions,
            "counts": {s: counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
            "unique_issues": len(unique), "endpoints": endpoints}
