"""Stages 03-04: banner identification and the STARTTLS state machine."""
import base64
import json
import random
from dataclasses import asdict

import pytest

from securemailscope import samples
from securemailscope.mailproto import _looks_mangled, parse_session
from tests.conftest import make_flow

L = samples._lines
RNG = random.Random(1)
CH = samples.client_hello(RNG, "mx.example.com")
SH = samples.record(22, samples.server_hello(RNG, 0x0303, 0x1301, tls13=True))


def smtp_server(caps=("PIPELINING", "STARTTLS", "8BITMIME"), host="mx.example.com"):
    lines = [f"250-{host}"] + [f"250-{c}" for c in caps[:-1]] + [f"250 {caps[-1]}"]
    return L(f"220 {host} ESMTP Postfix") + L(*lines)


def test_smtp_starttls_each_direction_has_its_own_offset():
    client_pre = L("EHLO c.example.org", "STARTTLS")
    server_pre = smtp_server() + L("220 2.0.0 Ready to start TLS")
    s = parse_session(make_flow(client_pre + CH, server_pre + SH), "S1")
    assert s.protocol == "SMTP" and s.mode == "starttls" and s.starttls_offered
    assert s.tls_client_offset == len(client_pre)
    assert s.tls_server_offset == len(server_pre)          # gotcha 4: the offsets differ
    assert s.tls_client_bytes == CH and s.tls_server_bytes == SH
    assert s.server_name == "mx.example.com" and not s.strip_indicators and not s.injection_indicators


def test_stripped_capability_and_cleartext_login():
    client = L("EHLO laptop", "AUTH LOGIN", base64.b64encode(b"ananya@example.com").decode(),
               base64.b64encode(b"Monsoon#2026").decode(), "MAIL FROM:<a@example.com>", "QUIT")
    server = smtp_server(("PIPELINING", "XXXXXXXX", "AUTH LOGIN", "8BITMIME")) + \
        L("334 VXNlcm5hbWU6", "334 UGFzc3dvcmQ6", "235 2.7.0 ok", "250 ok", "221 bye")
    s = parse_session(make_flow(client, server, port=587), "S1")
    assert s.mode == "plaintext" and s.starttls_offered is False
    assert any("XXXXXXXX" in x for x in s.strip_indicators)
    (a,) = s.auth_events
    assert a.mechanism == "LOGIN" and a.username == "ananya@example.com" and a.secret_exposed and a.accepted
    # privacy: the password must not survive anywhere in the session object
    assert "Monsoon" not in json.dumps(asdict(s), default=str)


def test_auth_plain_initial_response():
    blob = base64.b64encode(b"\x00bob@example.com\x00hunter2").decode()
    s = parse_session(make_flow(L("EHLO x", f"AUTH PLAIN {blob}"), smtp_server() + L("235 ok"), port=587), "S")
    assert s.auth_events[0].username == "bob@example.com" and s.auth_events[0].secret_exposed


def test_starttls_refused_is_a_strip_indicator():
    s = parse_session(make_flow(L("EHLO x", "STARTTLS", "MAIL FROM:<a@b>"),
                                smtp_server() + L("454 4.7.0 TLS not available", "250 ok")), "S")
    assert s.starttls_requested and not s.starttls_accepted
    assert any("454" in x for x in s.strip_indicators)


def test_client_command_injection_after_starttls():
    client = L("EHLO x") + L("STARTTLS", "RSET", "MAIL FROM:<evil@example>") + CH
    server = smtp_server() + L("220 Ready") + SH
    s = parse_session(make_flow(client, server), "S")
    assert s.mode == "starttls" and s.tls_client_bytes == CH
    assert any("RSET" in x and "client" in x for x in s.injection_indicators)


def test_server_response_injection_after_starttls():
    client = L("EHLO x", "STARTTLS") + CH
    server = smtp_server() + L("220 Ready", "250 injected") + SH
    s = parse_session(make_flow(client, server), "S")
    assert any("server" in x and "250" in x for x in s.injection_indicators)


def test_protocol_by_banner_not_port():
    s = parse_session(make_flow(L("EHLO x", "QUIT"), smtp_server() + L("221 bye"), port=110), "S")
    assert s.protocol == "SMTP"                  # gotcha 7: port 110 does not make it POP3
    assert any("non-standard port 110" in n for n in s.notes)


def test_implicit_tls_uses_port_only_as_hint():
    s = parse_session(make_flow(CH, SH, port=993), "S")
    assert s.mode == "implicit" and s.protocol == "IMAP" and s.tls_client_offset == 0
    assert parse_session(make_flow(CH, SH, port=443), "S") is None   # TLS but not mail


def test_non_mail_flow_ignored():
    assert parse_session(make_flow(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n", port=80), "S") is None


def test_imap_login_with_literal_password():
    client = L("a1 CAPABILITY") + b"a2 LOGIN rahul {11}\r\n" + b"Winter2025!" + L("", "a3 LOGOUT")
    server = L("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready", "* CAPABILITY IMAP4rev1 AUTH=PLAIN", "a1 OK",
               "+ go ahead", "a2 OK Logged in", "* BYE", "a3 OK")
    s = parse_session(make_flow(client, server, port=143), "S")
    assert s.protocol == "IMAP" and s.starttls_offered is False
    (a,) = s.auth_events
    assert a.mechanism == "IMAP-LOGIN" and a.username == "rahul" and a.secret_exposed and a.accepted


def test_imap_starttls_and_authenticate_sasl_ir():
    s = parse_session(make_flow(L("a1 STARTTLS") + CH,
                                L("* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] ok", "a1 OK Begin TLS") + SH,
                                port=143), "S")
    assert s.mode == "starttls" and s.starttls_offered and s.tls_client_bytes == CH
    blob = base64.b64encode(b"\x00eve\x00pw").decode()
    s2 = parse_session(make_flow(L(f"a1 AUTHENTICATE PLAIN {blob}"), L("* OK ready", "a1 OK"), port=143), "S")
    assert s2.auth_events[0].username == "eve" and s2.auth_events[0].secret_exposed


def test_imap_fetch_literal_counts_message_bytes():
    body = b"Subject: x\r\n\r\nsecret board pack\r\n"
    server = L("* OK ready") + f"* 1 FETCH (BODY[] {{{len(body)}}}\r\n".encode() + body + L(")", "a1 OK")
    s = parse_session(make_flow(L("a1 FETCH 1 BODY[]"), server, port=143), "S")
    assert s.cleartext_message_bytes == len(body)


def test_pop3_user_pass_and_stls():
    s = parse_session(make_flow(L("CAPA", "USER priya", "PASS pw", "QUIT"),
                                L("+OK pop.example.com ready", "+OK", "USER", "UIDL", ".", "+OK", "+OK", "+OK bye"),
                                port=110), "S")
    assert s.protocol == "POP3" and s.starttls_offered is False and s.server_name == "pop.example.com"
    assert s.auth_events[0].mechanism == "USER/PASS" and s.auth_events[0].username == "priya"
    s2 = parse_session(make_flow(L("CAPA", "STLS") + CH, L("+OK ready", "+OK", "STLS", ".", "+OK go") + SH, port=110), "S")
    assert s2.mode == "starttls" and s2.tls_server_bytes == SH


def test_smtp_data_body_not_parsed_as_commands():
    body = L("Subject: STARTTLS", "", "EHLO this is body text", ".")
    s = parse_session(make_flow(L("EHLO x", "MAIL FROM:<a@b>", "DATA") + body + L("QUIT"),
                                smtp_server() + L("250 ok", "354 go", "250 queued", "221 bye")), "S")
    assert s.cleartext_commands == ["EHLO", "MAIL", "DATA", "QUIT"]
    assert s.cleartext_message_bytes == len(body)


@pytest.mark.parametrize("token,target,expected", [
    ("XXXXXXXX", "STARTTLS", True), ("STARTTLX", "STARTTLS", True), ("XTARTTLS", "STARTTLS", True),
    ("8BITMIME", "STARTTLS", False), ("CHUNKING", "STARTTLS", False), ("SMTPUTF8", "STARTTLS", False),
    ("STARTTLS", "STARTTLS", False), ("XXXX", "STLS", True), ("USER", "STLS", False), ("UIDL", "STLS", False),
])
def test_mangled_capability_detection(token, target, expected):
    assert _looks_mangled(token, target) is expected


def test_transcript_is_redacted_and_ordered():
    client = L("EHLO laptop", "AUTH LOGIN", base64.b64encode(b"ananya@example.com").decode(),
               base64.b64encode(b"Monsoon#2026").decode(), "DATA") + L("Subject: secret board pack", "", "body", ".") + L("QUIT")
    server = smtp_server(("PIPELINING", "XXXXXXXX", "AUTH LOGIN")) + \
        L("334 VXNlcm5hbWU6", "334 UGFzc3dvcmQ6", "235 ok", "354 go", "250 queued", "221 bye")
    s = parse_session(make_flow(client, server, port=587), "S1")
    kinds = [(e["dir"], e["kind"]) for e in s.transcript]
    assert kinds[0] == ("S", "banner") and ("S", "caps") in kinds and ("C", "data") in kinds
    caps = next(e for e in s.transcript if e["kind"] == "caps")
    assert "XXXXXXXX" in caps["caps"]
    text = json.dumps(s.transcript)
    for secret in ("Monsoon", base64.b64encode(b"Monsoon#2026").decode(), base64.b64encode(b"ananya@example.com").decode(),
                   "secret board pack"):
        assert secret not in text


def test_transcript_marks_injection_and_tls_switch():
    client = L("EHLO x") + L("STARTTLS", "RSET") + CH
    s = parse_session(make_flow(client, smtp_server() + L("220 Ready") + SH), "S")
    inj = next(e for e in s.transcript if e["kind"] == "inject")
    assert inj["text"].startswith("RSET ") and "\r" not in inj["text"]
    assert s.transcript[-1]["kind"] == "tls-switch"
