"""End to end: every scenario in the demo capture produces the findings it should."""
import json
import os

import pytest

from securemailscope import report, samples
from securemailscope.cli import main
from securemailscope.pipeline import Options, analyze
from securemailscope.scoring import posture, rule_risk


@pytest.fixture(scope="module")
def demo(sample_paths):
    return analyze(sample_paths["demo"], Options(trust_store=sample_paths["trust_store"], use_ml=False))


def rules_for(a, **match):
    out = []
    for r in a.results:
        s = r.session
        if all(getattr(s, k) == v if k != "client_ip" else s.client[0] == v for k, v in match.items()):
            out.append({f.rule_id for f in r.findings})
    return out


def test_capture_level_counts(demo):
    m = demo.meta
    assert m["mail_sessions"] == 19 and m["non_mail_flows"] == 1       # the HTTPS flow is ignored
    assert m["read"]["fragments_skipped"] == 1 and m["read"]["non_tcp"] == 1
    assert len(m["input_sha256"]) == 64


def test_healthy_sessions_are_clean(demo):
    for r in demo.results:
        if r.session.client[0] in ("198.51.100.40", "198.51.100.41", "198.51.100.42", "198.51.100.43"):
            assert r.findings == [], r.session.session_id
            assert r.tls.version_name == "TLS 1.2" and r.chain.trusted


def test_reassembly_chaos_session(demo):
    (r,) = [r for r in demo.results if r.session.client[0] == "198.51.100.40"]
    q = r.session.stream_quality
    assert q["retransmissions"] >= 1 and q["out_of_order"] >= 1 and q["overlaps_trimmed"] >= 1
    assert r.session.starttls_offered and r.tls.complete


def test_seq_wrap_and_vlan_sessions_parse(demo):
    for ip in ("198.51.100.41", "198.51.100.42"):
        (r,) = [r for r in demo.results if r.session.client[0] == ip]
        assert r.tls is not None and r.tls.version == 0x0303 and r.chain.present


@pytest.mark.parametrize("client,expected", [
    ("10.20.0.23", {"SMS-STRIP-001", "SMS-CRED-001", "SMS-DATA-001", "SMS-BASE-001"}),
    ("198.51.100.52", {"SMS-STRIP-001", "SMS-DATA-001", "SMS-BASE-001"}),
    ("198.51.100.51", {"SMS-CERT-002", "SMS-BASE-002"}),
    ("10.20.0.26", {"SMS-INJ-001"}),
    ("10.20.0.25", {"SMS-TLS-010", "SMS-BASE-003"}),
    ("10.20.0.27", {"SMS-TLS-005", "SMS-TLS-004"}),
    ("10.20.0.28", {"SMS-TLS-005", "SMS-CERT-003"}),
    ("10.20.0.31", {"SMS-PLAIN-001", "SMS-CRED-001", "SMS-DATA-001"}),
    ("10.20.0.40", {"SMS-TLS-001", "SMS-TLS-002", "SMS-TLS-003", "SMS-CERT-001", "SMS-CERT-004", "SMS-CERT-005",
                    "SMS-CERT-007", "SMS-TLS-009", "SMS-TLS-006"}),
    ("10.20.0.60", {"SMS-PLAIN-002", "SMS-DATA-001", "SMS-PORT-001"}),
])
def test_scenario_findings(demo, client, expected):
    (ids,) = rules_for(demo, client_ip=client)
    assert expected <= ids, f"{client}: missing {expected - ids}"


def test_baseline_escalates_self_signed_to_critical(demo):
    """The PDF's differentiator: 'self-signed, Medium' becomes 'possible active MITM, Critical'."""
    (r,) = [r for r in demo.results if r.session.client[0] == "198.51.100.51"]
    (f,) = [f for f in r.findings if f.rule_id == "SMS-CERT-002"]
    assert f.escalated_from == "medium" and f.severity == "critical"


def test_tls13_sessions_report_certificate_unknown_not_valid(demo):
    r = next(r for r in demo.results if r.session.server[1] == 993)
    assert not r.chain.present and {f.rule_id for f in r.findings} == {"SMS-CERT-010"}


def test_priorities_and_posture(demo):
    prios = [f.priority for f in demo.findings]
    assert prios == sorted(prios) and prios[0] == 1
    risks = [f.risk for f in demo.findings]
    assert risks == sorted(risks, reverse=True)
    assert demo.posture["grade"] == "F" and demo.posture["counts"]["critical"] >= 8


def test_posture_math():
    assert posture([], 3)["score"] == 100 and posture([], 3)["grade"] == "A"
    assert rule_risk([]) == 0.0


def test_json_is_serialisable_and_privacy_preserving(demo):
    text = report.to_json(demo)
    data = json.loads(text)
    assert data["meta"]["input_sha256"] == demo.meta["input_sha256"]
    for secret in ("Monsoon#2026", "Winter2025!", "TW9uc29vbiMyMDI2"):   # passwords, raw or base64
        assert secret not in text


def test_json_handles_numpy_scalars():
    import numpy as np
    assert json.loads(json.dumps({"a": np.bool_(True), "b": np.float64(1.5)}, default=report._json_default)) == \
        {"a": True, "b": 1.5}                                                  # gotcha 8


def test_html_escapes_attacker_controlled_banner(tmp_path):
    cap = samples.Capture()
    import random
    rng = random.Random(1)
    conv = samples.Conv(cap, samples.DEMO_T0, ("10.0.0.5", 50000), ("203.0.113.9", 25), rng).open()
    conv.s(samples._lines('220 <script>alert("x")</script> ESMTP'))
    conv.c(samples._lines("EHLO x")).s(samples._lines("250-<img src=x onerror=alert(1)>", "250 8BITMIME"))
    conv.c(samples._lines("QUIT")).s(samples._lines("221 bye"))
    conv.close()
    p = tmp_path / "xss.pcap"
    cap.write_pcap(str(p))
    html = report.to_html(analyze(str(p), Options(use_ml=False)))
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_ml_scores_and_explanations(sample_paths):
    a = analyze(sample_paths["demo"], Options(trust_store=sample_paths["trust_store"]))
    healthy = [r for r in a.results if not r.findings]
    risky = [r for r in a.results if any(f.severity == "critical" for f in r.findings)]
    assert all(r.model_risk < 10 for r in healthy)
    assert all(r.model_risk > 60 for r in risky)
    inj = next(r for r in a.results if r.session.injection_indicators)
    assert inj.explanation[0][0] == "command injection"
    assert a.ml_info["holdout_r2"] > 0.9


def test_cross_capture_baseline(tmp_path, sample_paths):
    db = str(tmp_path / "base.sqlite")
    opts = Options(trust_store=sample_paths["trust_store"], baseline_db=db, use_ml=False)
    first = analyze(sample_paths["baseline"], opts)
    assert first.meta["baseline_learned"] == 10
    ng = analyze(sample_paths["pcapng"], opts)            # pcapng + Linux SLL
    stripped = next(r for r in ng.results if r.session.strip_indicators)
    assert "starttls_drop" in stripped.baseline_deviations
    assert ng.meta["baseline_learned"] == 3               # the stripped session is not learned


def test_cli_analyze_writes_reports_and_audit(tmp_path, sample_paths):
    out = tmp_path / "out"
    code = main(["analyze", sample_paths["pcapng"], "-o", str(out), "--no-ml", "-q",
                 "--trust-store", sample_paths["trust_store"], "--fail-on", "critical"])
    assert code == 2
    stem = "starttls_stripping"
    assert (out / f"{stem}.html").exists() and (out / f"{stem}.json").exists()
    audit = [json.loads(l) for l in (out / "audit.log").read_text().splitlines()]
    assert audit[0]["sha256"] and audit[0]["outputs"]


def test_server_upload_roundtrip(sample_paths):
    from securemailscope.server import create_app
    app = create_app(trust_store=sample_paths["trust_store"])
    c = app.test_client()
    assert c.get("/").status_code == 200
    with open(sample_paths["pcapng"], "rb") as f:
        r = c.post("/analyze", data={"file": (f, "cap.pcapng"), "no_ml": "on"}, content_type="multipart/form-data")
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert c.get(loc).status_code == 200
    j = c.get(loc + ".json")
    assert j.status_code == 200 and j.get_json()["meta"]["input"] == "cap.pcapng"
    with open(sample_paths["pcapng"], "rb") as f:
        api = c.post("/api/analyze?ml=0", data={"file": (f, "x.pcapng")}, content_type="multipart/form-data")
    assert api.status_code == 200 and api.get_json()["posture"]["grade"] == "F"
    bad = c.post("/api/analyze", data={"file": (open(os.devnull, "rb"), "x.pcap")}, content_type="multipart/form-data")
    assert bad.status_code == 400
