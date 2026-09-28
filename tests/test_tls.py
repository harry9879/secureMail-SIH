"""Stage 05: TLS record/handshake parsing, versions, JA3."""
import hashlib
import random
import struct

from securemailscope import samples, tls
from securemailscope.ciphers import is_grease, profile, version_issue


def test_grease_values():
    assert all(is_grease(g) for g in samples.GREASE)
    assert not is_grease(0x1301) and not is_grease(0x0A0B)


def test_tls13_version_comes_from_supported_versions():
    rng = random.Random(3)
    hs = tls.analyze(samples.client_hello(rng, "a.example"),
                     samples.record(22, samples.server_hello(rng, 0x0303, 0x1302, tls13=True)) + samples.record(20, b"\x01"))
    assert hs.server_legacy_version == 0x0303       # gotcha 1: the legacy field says 1.2 ...
    assert hs.version == 0x0304 and hs.version_name == "TLS 1.3"   # ... extension 43 says 1.3
    assert hs.cipher_name == "TLS_AES_256_GCM_SHA384"
    assert hs.selected_group == 29 and hs.sni == "a.example"
    assert not hs.certificates and not hs.certificate_visible     # gotcha 2


def test_ja3_filters_grease_and_matches_manual_md5():
    rng = random.Random(4)
    hs = tls.analyze(samples.client_hello(rng, "a.example"), b"")
    assert not any(is_grease(c) for c in hs.client_ciphers)
    assert not any(is_grease(e) for e in hs.client_extensions)
    fields = hs.ja3_string.split(",")
    assert fields[0] == "771" and fields[4] == "0"
    assert fields[1].split("-")[0] == str(0x1301)
    assert fields[3] == "29-23-24"
    assert hs.ja3 == hashlib.md5(hs.ja3_string.encode()).hexdigest()
    # GREASE is random per connection; the fingerprint must not be
    hs2 = tls.analyze(samples.client_hello(random.Random(99), "a.example"), b"")
    assert hs2.ja3 == hs.ja3


def test_handshake_message_spanning_two_records():
    rng = random.Random(5)
    hs = tls.analyze(samples.client_hello(rng, "split.example", split_at=40), b"")   # gotcha 3
    assert hs.client_hello_seen and hs.sni == "split.example"
    assert not [e for e in hs.errors if "malformed" in e]


def test_tls12_certificate_and_ske_in_one_record(pki):
    rng = random.Random(6)
    chain = pki.chain_der("mx")
    flight = samples.server_hello(rng, 0x0303, 0xC02F) + samples.certificate_msg(chain) + \
        samples.ske_ecdhe(rng) + samples._hs(14, b"")
    hs = tls.analyze(samples.client_hello(rng, "mx.example.com", tls13=False),
                     samples.records(22, flight) + samples.record(20, b"\x01"))
    assert hs.version_name == "TLS 1.2" and hs.certificates == chain and hs.certificate_visible
    assert hs.ecdhe_curve == 23 and hs.secure_renegotiation and hs.extended_master_secret
    assert hs.complete is False    # client never sent CCS in this fragment


def test_dhe_prime_size_and_downgrade_sentinel(pki):
    rng = random.Random(7)
    flight = samples.server_hello(rng, 0x0303, 0x0033, downgrade=b"DOWNGRD\x01") + \
        samples.certificate_msg(pki.chain_der("wild")) + samples.ske_dhe(rng, 1024) + samples._hs(14, b"")
    hs = tls.analyze(samples.client_hello(rng, "x.example.com"), samples.records(22, flight))
    assert hs.dh_bits == 1024 and hs.downgrade_sentinel == "TLS1.2"
    assert 0x0304 in hs.client_supported_versions


def test_alert_and_garbage_are_reported_not_raised():
    hs = tls.analyze(samples.client_hello(random.Random(8), None), samples.record(21, bytes([2, 40])))
    assert hs.alerts == [(2, 40)] and not hs.complete
    hs2 = tls.analyze(b"\x16\x03\x01\x00\x05\x01\x00\x00\xff\xff", b"garbage")
    assert hs2.errors


def test_cipher_profiles_from_names():
    assert profile(0x1301).grade == "A" and profile(0x1301).tls13
    p = profile(0xC030)
    assert (p.kx, p.auth, p.enc, p.mac, p.forward_secrecy, p.aead, p.grade) == \
        ("ECDHE", "RSA", "AES_256_GCM", "SHA384", True, True, "A")
    assert profile(0xC013).grade == "B"                       # ECDHE + CBC
    assert profile(0x009C).grade == "C" and not profile(0x009C).forward_secrecy
    for weak in (0x000A, 0x0005, 0x0003, 0x0018, 0x0002):     # 3DES, RC4, EXPORT, anon, NULL
        assert profile(weak).grade == "F"
    assert version_issue(0x0301)[0] == "high" and version_issue(0x0300)[0] == "critical"
    assert version_issue(0x0303) is None


def test_u16_list_ignores_odd_trailing_byte():
    assert tls._u16_list(struct.pack("!HH", 1, 2) + b"\x01") == [1, 2]


def test_record_flow_names_messages_until_encryption(pki):
    rng = random.Random(9)
    flight = samples.server_hello(rng, 0x0303, 0xC02F) + samples.certificate_msg(pki.chain_der("mx")) + \
        samples.ske_ecdhe(rng) + samples._hs(14, b"")
    server = samples.records(22, flight) + samples.record(20, b"\x01") + samples.record(22, b"x" * 40) + samples.record(23, b"y" * 30)
    assert tls.record_flow(server) == ["ServerHello", "Certificate", "ServerKeyExchange", "ServerHelloDone",
                                       "ChangeCipherSpec", "encrypted records ×2"]
    hs = tls.analyze(samples.client_hello(rng, "a"), server)
    assert hs.client_flow == ["ClientHello"] and hs.server_flow[0] == "ServerHello"
