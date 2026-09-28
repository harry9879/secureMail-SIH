"""Stage 06: X.509 analysis."""
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from securemailscope import certs, samples
from securemailscope.models import TlsHandshake


@pytest.mark.parametrize("host,pattern,ok", [
    ("x.a.com", "*.a.com", True),
    ("x.y.a.com", "*.a.com", False),     # gotcha 9: one label only
    ("a.com", "*.a.com", False),
    ("x.a.com", "x.a.com", True),
    ("x.com", "*.com", False),           # no wildcard directly under a TLD-like label
])
def test_rfc6125_wildcards(host, pattern, ok):
    assert certs._dns_match(host, pattern) is ok


def _hs(ders, version=0x0303):
    return TlsHandshake(client_hello_seen=True, server_hello_seen=True, version=version, certificates=ders,
                        certificate_visible=bool(ders))


def _ca_file(tmp_path, pki):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.root.public_bytes(serialization.Encoding.PEM))
    return str(p)


def test_valid_chain_trusted_with_private_ca(tmp_path, pki):
    info = certs.analyze(_hs(pki.chain_der("mx")), "mx.example.com", samples.DEMO_T0, _ca_file(tmp_path, pki))
    assert info.present and info.trusted is True and info.hostname_match is True
    assert info.chain_links_ok is True and info.expired is False and not info.self_signed
    assert info.leaf.key_type == "RSA" and info.leaf.key_bits == 2048
    assert "unknown" in info.revocation


def test_same_chain_untrusted_without_its_root(pki):
    info = certs.analyze(_hs(pki.chain_der("mx")), "mx.example.com", samples.DEMO_T0, None, use_default_trust=True)
    assert info.trusted is False     # demo CA is not in the Mozilla bundle


def test_self_signed_and_wildcard_mismatch(tmp_path, pki):
    mitm = certs.analyze(_hs(pki.chain_der("mitm")), "mx.example.com", samples.DEMO_T0, _ca_file(tmp_path, pki))
    assert mitm.self_signed and mitm.trusted is False
    wild = certs.analyze(_hs(pki.chain_der("wild")), "mail.corp.example.com", samples.DEMO_T0, _ca_file(tmp_path, pki))
    assert wild.hostname_match is False
    # the trust verdict must not be polluted by the name mismatch
    assert wild.trusted is True


def test_legacy_cert_judged_at_capture_time(pki):
    info = certs.analyze(_hs(pki.chain_der("legacy")), "pop.oldmail.example.net", samples.DEMO_T0)
    assert info.expired is True and info.leaf.key_bits == 1024 and info.leaf.signature_hash == "sha1"
    in_2023 = dt.datetime(2023, 6, 1, tzinfo=dt.timezone.utc).timestamp()
    assert certs.analyze(_hs(pki.chain_der("legacy")), None, in_2023).expired is False


def test_tls13_certificate_not_observable(pki):
    info = certs.analyze(_hs([], version=0x0304), "x", samples.DEMO_T0)
    assert not info.present and "TLS 1.3" in info.reason_absent


def test_misordered_chain_detected(pki):
    leaf, inter = pki.chain_der("mx")
    info = certs.analyze(_hs([inter, leaf]), None, samples.DEMO_T0, use_default_trust=False)
    assert info.chain_links_ok is False


def test_cert_info_fields(pki):
    c = x509.load_der_x509_certificate(pki.chain_der("wild")[0])
    ci = certs.cert_info(c)
    assert "DNS:*.example.com" in ci.sans and ci.eku_server_auth is True and not ci.is_ca
    assert len(ci.sha256) == 64
