"""Stage 10: risk model and anomaly detection.

Cold start, stated openly: no public labelled corpus of email-crypto risk exists.
So the *rules engine generates the labels*. We synthesise thousands of plausible
sessions (MailSession / TlsHandshake / ChainInfo objects), run the real rules
engine and baseline escalation on them, and label each with its rule risk. A
gradient-boosted tree ensemble then learns that mapping from the feature vector.

Why trees and not deep learning: tabular features, small data, and every score
must be explainable to an analyst. Why bother with a model at all: it generalises
smoothly to combinations the rules never enumerated, gives per-feature
explanations, and can be retrained on real analyst-labelled captures later.

The anomaly side (Isolation Forest) is unsupervised and needs no labels at all.
"""
from __future__ import annotations

import math
import os
import pickle
import random
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from . import __version__
from .baseline import _escalate
from .ciphers import version_name
from .features import FEATURES, GROUPS, REFERENCE, to_row, vector
from .models import AuthEvent, CertInfo, ChainInfo, Finding, MailSession, TlsHandshake
from .rules import evaluate
from .scoring import rule_risk

MODEL_SEED = 7
MODEL_REV = 3          # bump when the corpus or model changes, to invalidate caches
CORPUS_SIZE = 4000

_T13 = [0x1301, 0x1302, 0x1303]
_LEGACY = [(0xC02F, 30), (0xC030, 25), (0xCCA8, 10), (0xC013, 8), (0xC014, 8), (0x009C, 5), (0x002F, 5),
           (0x0035, 4), (0x009E, 4), (0x0033, 3), (0x000A, 3), (0x0005, 2), (0x0004, 1), (0x0003, 1),
           (0x0018, 1), (0x0002, 1)]


def _choice(rng: random.Random, weighted: list[tuple]):
    items, weights = zip(*weighted)
    return rng.choices(items, weights=weights, k=1)[0]


def synthesize(rng: random.Random) -> tuple[MailSession, Optional[TlsHandshake], Optional[ChainInfo], set[str], list[Finding]]:
    # ~30% well-configured sessions, so the model learns the "nothing wrong" corner precisely
    healthy = rng.random() < 0.3
    proto = rng.choice(["SMTP", "SMTP", "IMAP", "POP3"])
    port = rng.choice({"SMTP": [25, 25, 587, 465, 2525], "IMAP": [143, 993], "POP3": [110, 995]}[proto])
    implicit = port in (465, 993, 995)
    mode = "implicit" if implicit else "starttls" if healthy else _choice(rng, [("starttls", 60), ("plaintext", 40)])
    s = MailSession("SYN", ("198.51.100.7", 50000), ("203.0.113.5", port), proto, mode, 0.0, 0.0)
    def bad(p: float) -> bool:   # a weakness occurs with probability p, never in a healthy session
        return not healthy and rng.random() < p

    s.stream_quality = {"overlap_conflicts": 1 if bad(0.02) else 0}
    hs = chain = None
    if mode == "plaintext":
        s.starttls_offered = rng.random() < 0.55
        if rng.random() < 0.2:
            s.starttls_offered = False
            s.strip_indicators = ["synthetic stripping indicator"]
        s.cleartext_commands = ["EHLO", "MAIL"]
        if rng.random() < 0.35:
            s.auth_events.append(AuthEvent("LOGIN", "u", secret_exposed=rng.random() < 0.8, accepted=True))
        if rng.random() < 0.4:
            s.cleartext_message_bytes = rng.randint(200, 200000)
    else:
        if mode == "starttls":
            s.starttls_offered = s.starttls_requested = s.starttls_accepted = True
            if bad(0.04):
                s.injection_indicators = ["synthetic injection"]
        s.tls_client_bytes = s.tls_server_bytes = b"\x16"
        hs = TlsHandshake(client_hello_seen=True, server_hello_seen=not bad(0.04))
        if hs.server_hello_seen:
            hs.version = _choice(rng, [(0x0304, 55), (0x0303, 45)] if healthy else
                                 [(0x0304, 45), (0x0303, 40), (0x0302, 5), (0x0301, 7), (0x0300, 3)])
            hs.version_name = version_name(hs.version)
            hs.server_legacy_version = min(hs.version, 0x0303)
            hs.server_extensions = [43, 51] if hs.version == 0x0304 else [0xFF01, 23]
            good = [(0xC02F, 1), (0xC030, 1), (0xCCA8, 1), (0xC02B, 1)]
            hs.cipher_suite = rng.choice(_T13) if hs.version == 0x0304 else _choice(rng, good if healthy else _LEGACY)
            if hs.cipher_suite in (0x009E, 0x0033):
                hs.dh_bits = rng.choice([1024, 2048, 2048])
            hs.compression = 1 if bad(0.02) else 0
            hs.secure_renegotiation = not bad(0.08) or hs.version == 0x0304
            hs.extended_master_secret = None if hs.version == 0x0304 else not bad(0.2)
            if hs.version != 0x0304 and bad(0.04):
                hs.downgrade_sentinel = "TLS1.2"
                hs.client_supported_versions = [0x0304, 0x0303]
        else:
            hs.alerts = [(2, 40)]
        if hs.server_hello_seen and hs.version != 0x0304:
            key_type, bits = _choice(rng, [(("RSA", 2048), 60), (("RSA", 4096), 10), (("EC-secp256r1", 256), 22)] +
                                     ([] if healthy else [(("RSA", 1024), 8)]))
            self_signed = bad(0.15)
            leaf = CertInfo("CN=mail", "CN=ca" if not self_signed else "CN=mail", "1", "", "", key_type, bits,
                            "sha256" if healthy else _choice(rng, [("sha256", 88), ("sha1", 10), ("md5", 2)]),
                            ["DNS:mail"], False, self_signed, format(rng.getrandbits(64), "x"), False, True)
            expired = bad(0.1)
            chain = ChainInfo(present=True, certs=[leaf], hostname="mail", hostname_match=not bad(0.1),
                              expired=expired, not_yet_valid=False, days_to_expiry=-5 if expired else 200,
                              self_signed=self_signed, chain_links_ok=True,
                              trusted=False if self_signed or bad(0.1) else True)
        elif hs.server_hello_seen:
            chain = ChainInfo(present=False, reason_absent="TLS 1.3")

    findings = evaluate(s, hs, chain)
    devs: set[str] = set()
    extra: list[Finding] = []

    def base(code: str, sev: str, ids: set[str]) -> None:
        devs.add(code)
        extra.append(Finding(f"SMS-BASE-{code}", code, sev, "anomaly", "SYN", s.endpoint, [], "", exploitability=0.8))
        if sev == "critical":
            _escalate(findings, ids, "critical", "baseline")

    if s.strip_indicators or (mode == "plaintext" and s.starttls_offered is False and rng.random() < 0.3):
        if rng.random() < 0.6:
            base("starttls_drop", "critical", {"SMS-STRIP-001", "SMS-PLAIN-001", "SMS-PLAIN-003"})
    if chain is not None and chain.present and (chain.self_signed or chain.trusted is False) and rng.random() < 0.4:
        base("cert_change", "critical", {"SMS-CERT-002", "SMS-CERT-003", "SMS-CERT-007"})
    if hs is not None and hs.server_hello_seen and rng.random() < 0.05:
        base("downgrade", "high", set())
    if hs is not None and hs.server_hello_seen and not devs and rng.random() < 0.05:
        base("new_ja3s", "low", set())
    return s, hs, chain, devs, findings + extra


def build_corpus(n: int = CORPUS_SIZE, seed: int = MODEL_SEED) -> tuple[np.ndarray, np.ndarray]:
    rng = random.Random(seed)
    X, y = [], []
    for _ in range(n):
        s, hs, chain, devs, findings = synthesize(rng)
        X.append(to_row(vector(s, hs, chain, devs)))
        y.append(rule_risk(findings))
    return np.asarray(X, dtype=float), np.asarray(y, dtype=float)


@dataclass
class RiskModel:
    model: object
    features: list[str]
    version: str
    holdout_r2: float
    holdout_mae: float
    trained_on: str
    explainer: str = "group-shapley"
    _shap: object = field(default=None, repr=False)

    def _raw(self, rows: list[list[float]]) -> list[float]:
        p = self.model.predict(np.asarray(rows, dtype=float))
        return [float(min(100.0, max(0.0, v))) for v in p]

    def predict(self, rows: list[list[float]]) -> list[float]:
        return [round(v, 1) for v in self._raw(rows)] if rows else []

    def explain(self, rows: list[list[float]], top: int = 5) -> list[list[tuple[str, float]]]:
        """Contribution of each feature *group* to each session's model risk.

        With shap installed: TreeSHAP per feature, summed per group.
        Otherwise: exact Shapley values over the groups, measured against the ideal
        reference session. Only groups that differ from the reference take part
        (usually 2-6), so all 2^G coalitions are enumerated - for every session at
        once, in a single predict call. The values sum to f(x) - f(ideal).
        """
        if not rows:
            return []
        idx = {f: i for i, f in enumerate(self.features)}
        groups = [(g, [idx[f] for f in fs]) for g, fs in GROUPS.items()]
        if self._shap is not None:
            vals = self._shap.shap_values(np.asarray(rows, dtype=float))
            all_pairs = [[(g, float(sum(vs[i] for i in cols))) for g, cols in groups] for vs in vals]
        else:
            ref = [REFERENCE[f] for f in self.features]
            batch, plan = [], []
            for row in rows:
                active = [(g, cols) for g, cols in groups if any(row[i] != ref[i] for i in cols)]
                start = len(batch)
                for mask in range(1 << len(active)):
                    r = list(ref)
                    for k, (_, cols) in enumerate(active):
                        if mask >> k & 1:
                            for i in cols:
                                r[i] = row[i]
                    batch.append(r)
                plan.append((start, active))
            p = self._raw(batch)
            all_pairs = []
            for start, active in plan:
                n = len(active)
                w = [math.factorial(s) * math.factorial(n - s - 1) / math.factorial(n) for s in range(n)]
                phis = []
                for k, (g, _) in enumerate(active):
                    bit, phi = 1 << k, 0.0
                    for mask in range(1 << n):
                        if not mask & bit:
                            phi += w[bin(mask).count("1")] * (p[start + (mask | bit)] - p[start + mask])
                    phis.append((g, phi))
                all_pairs.append(phis)
        out = []
        for pairs in all_pairs:
            pairs = [(f, round(v, 1)) for f, v in pairs if abs(v) >= 0.5]
            pairs.sort(key=lambda x: -abs(x[1]))
            out.append(pairs[:top])
        return out


def _cache_path() -> str:
    root = os.environ.get("SECUREMAILSCOPE_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "securemailscope")
    return os.path.join(root, f"risk-model-{__version__}-r{MODEL_REV}.pkl")


def train(n: int = CORPUS_SIZE, seed: int = MODEL_SEED) -> RiskModel:
    from sklearn.ensemble import HistGradientBoostingRegressor
    from sklearn.metrics import mean_absolute_error, r2_score
    from sklearn.model_selection import train_test_split

    X, y = build_corpus(n, seed)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=seed)
    # scikit-learn's histogram gradient boosting: same family as XGBoost/LightGBM, trains in seconds
    gbr = HistGradientBoostingRegressor(max_iter=500, learning_rate=0.06, max_leaf_nodes=31,
                                        min_samples_leaf=10, l2_regularization=0.1, random_state=seed)
    gbr.fit(Xtr, ytr)
    pred = gbr.predict(Xte)
    return RiskModel(model=gbr, features=list(FEATURES), version=__version__,
                     holdout_r2=round(float(r2_score(yte, pred)), 3),
                     holdout_mae=round(float(mean_absolute_error(yte, pred)), 2),
                     trained_on=f"{n} synthetic sessions labelled by the rules engine (seed {seed})")


def load_model(path: Optional[str] = None, retrain: bool = False) -> RiskModel:
    path = path or _cache_path()
    m: Optional[RiskModel] = None
    if not retrain and os.path.exists(path):
        try:
            with open(path, "rb") as f:
                m = pickle.load(f)   # only ever a file this tool wrote itself
            if m.features != FEATURES or m.version != __version__:
                m = None
        except Exception:
            m = None
    if m is None:
        m = train()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                pickle.dump(m, f)
        except OSError:
            pass
    try:
        import shap  # optional
        m._shap = shap.TreeExplainer(m.model)
        m.explainer = "shap"
    except Exception:
        m.explainer = "exact Shapley over feature groups"
    return m


# ------------------------------------------------------------------ anomaly detection

@dataclass
class AnomalyResult:
    scores: Optional[list[float]]
    flags: list[bool]
    reasons: list[list[str]]
    note: str


def detect_anomalies(current: list[list[float]], history: list[list[float]],
                     contamination: Optional[float] = None, min_samples: int = 8) -> AnomalyResult:
    from sklearn.ensemble import IsolationForest

    n_cur = len(current)
    X = np.asarray(current + history, dtype=float)
    if len(X) < min_samples:
        return AnomalyResult(None, [False] * n_cur, [[] for _ in current],
                             f"isolation forest skipped: {len(X)} sessions < {min_samples} (baseline rules still apply)")
    # On small captures a fixed 10% contamination would flag healthy sessions just to fill the quota.
    c = contamination if contamination is not None else float(min(0.1, max(1.0 / len(X), 0.01)))
    iso = IsolationForest(n_estimators=200, contamination=c, random_state=MODEL_SEED)
    iso.fit(X)
    cur = X[:n_cur]
    scores = [round(float(s), 3) for s in -iso.score_samples(cur)]
    flags = [bool(p == -1) for p in iso.predict(cur)]
    mu, sd = X.mean(axis=0), X.std(axis=0)
    sd[sd == 0] = 1.0
    reasons = []
    for row, flag in zip(cur, flags):
        if not flag:
            reasons.append([])
            continue
        z = (row - mu) / sd
        idx = np.argsort(-np.abs(z))[:3]
        reasons.append([f"{FEATURES[i]}={row[i]:g} (population mean {mu[i]:.2f}, z={z[i]:+.1f})" for i in idx])
    return AnomalyResult(scores, flags, reasons,
                         f"isolation forest over {len(X)} sessions ({len(history)} from baseline history), "
                         f"contamination={c:.3f}")
