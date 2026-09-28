"""The lab stripping proxy produces exactly what the detector looks for."""
import importlib.util
import os

from securemailscope.mailproto import parse_session
from tests.conftest import make_flow

_spec = importlib.util.spec_from_file_location(
    "strip_proxy", os.path.join(os.path.dirname(__file__), "..", "lab", "strip_proxy.py"))
strip_proxy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(strip_proxy)


def test_smtp_rewrite_keeps_length_and_is_detected():
    real = b"220 mail.lab.test ESMTP\r\n250-mail.lab.test\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 8BITMIME\r\n"
    stripped = strip_proxy.strip(real)
    assert len(stripped) == len(real) and b"STARTTLS" not in stripped and b"250-XXXXXXXX" in stripped
    s = parse_session(make_flow(b"EHLO c\r\nQUIT\r\n", stripped + b"221 bye\r\n", port=587), "S")
    assert s.strip_indicators and s.starttls_offered is False


def test_imap_and_pop3_rewrites():
    imap = strip_proxy.strip(b"* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] ready\r\n")
    assert b"STARTTLS" not in imap and b"XXXXXXXX" in imap
    pop = strip_proxy.strip(b"+OK\r\nUSER\r\nSTLS\r\n.\r\n")
    assert pop == b"+OK\r\nUSER\r\nXXXX\r\n.\r\n"
    s = parse_session(make_flow(b"CAPA\r\nQUIT\r\n", b"+OK ready\r\n" + pop + b"+OK bye\r\n", port=110), "S")
    assert s.strip_indicators
