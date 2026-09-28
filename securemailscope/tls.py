"""Stage 05: parse the cleartext part of a TLS handshake from each direction.

Two framing layers must not be conflated:
  record layer    : type(1) version(2) length(2) fragment
  handshake layer : msg_type(1) length(3) body   -- may span records, or share one

So: concatenate every handshake-record fragment first, *then* split messages.
Stop at ChangeCipherSpec / ApplicationData; everything after is encrypted.

TLS 1.3 pins legacy_version to 0x0303; the real version is in supported_versions
(extension 43). TLS 1.3 also encrypts the Certificate message, so a missing
certificate is expected, not an error.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Optional

from .ciphers import is_grease, suite_name, version_name
from .models import TlsHandshake

CT_CCS, CT_ALERT, CT_HANDSHAKE, CT_APPDATA = 20, 21, 22, 23
HS_CLIENT_HELLO, HS_SERVER_HELLO, HS_CERTIFICATE, HS_SERVER_KEY_EXCHANGE, HS_SERVER_HELLO_DONE = 1, 2, 11, 12, 14

EXT_SNI, EXT_GROUPS, EXT_POINT_FORMATS, EXT_SIG_ALGS, EXT_ALPN = 0, 10, 11, 13, 16
EXT_EMS, EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_RENEGOTIATION_INFO = 23, 43, 51, 0xFF01

HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
DOWNGRD_12 = b"DOWNGRD\x01"
DOWNGRD_11 = b"DOWNGRD\x00"

ALERT_NAMES = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
               42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
               45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
               48: "unknown_ca", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
               71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
               90: "user_canceled", 109: "missing_extension", 112: "unrecognized_name",
               116: "certificate_required", 120: "no_application_protocol"}


class _Buf:
    def __init__(self, data: bytes):
        self.d, self.p = data, 0

    def u8(self) -> int:
        v = self.d[self.p]; self.p += 1; return v

    def u16(self) -> int:
        v = struct.unpack_from("!H", self.d, self.p)[0]; self.p += 2; return v

    def u24(self) -> int:
        b = self.d[self.p:self.p + 3]; self.p += 3; return int.from_bytes(b, "big")

    def take(self, n: int) -> bytes:
        if self.p + n > len(self.d):
            raise ValueError("truncated")
        v = self.d[self.p:self.p + n]; self.p += n; return v

    def vec8(self) -> bytes: return self.take(self.u8())
    def vec16(self) -> bytes: return self.take(self.u16())
    def left(self) -> int: return len(self.d) - self.p


def _u16_list(b: bytes) -> list[int]:
    return [struct.unpack_from("!H", b, i)[0] for i in range(0, len(b) - 1, 2)]


def read_records(data: bytes) -> tuple[bytes, list[tuple[int, int]], bool, list[str]]:
    """Walk records until encryption starts.

    Returns (concatenated handshake payload, alerts, encrypted_seen, errors).
    """
    hs = bytearray()
    alerts: list[tuple[int, int]] = []
    errors: list[str] = []
    p = 0
    while p + 5 <= len(data):
        ctype, _ver, length = data[p], struct.unpack_from("!H", data, p + 1)[0], struct.unpack_from("!H", data, p + 3)[0]
        if ctype not in (CT_CCS, CT_ALERT, CT_HANDSHAKE, CT_APPDATA) or data[p + 1] != 3:
            errors.append(f"not a TLS record at offset {p}")
            break
        frag = data[p + 5:p + 5 + length]
        if len(frag) < length:
            errors.append("record truncated (capture ends mid-record)")
        p += 5 + length
        if ctype == CT_HANDSHAKE:
            hs += frag
        elif ctype == CT_ALERT:
            if len(frag) == 2:
                alerts.append((frag[0], frag[1]))
            else:
                return bytes(hs), alerts, True, errors  # encrypted alert
        else:  # CCS or application data: the rest of this direction is encrypted
            return bytes(hs), alerts, True, errors
    return bytes(hs), alerts, False, errors


def split_messages(hs: bytes) -> list[tuple[int, bytes]]:
    msgs = []
    p = 0
    while p + 4 <= len(hs):
        mtype = hs[p]
        mlen = int.from_bytes(hs[p + 1:p + 4], "big")
        if p + 4 + mlen > len(hs):
            break
        msgs.append((mtype, hs[p + 4:p + 4 + mlen]))
        p += 4 + mlen
    return msgs


def _parse_extensions(b: _Buf) -> list[tuple[int, bytes]]:
    exts = []
    if b.left() < 2:
        return exts
    eb = _Buf(b.vec16())
    while eb.left() >= 4:
        etype = eb.u16()
        exts.append((etype, eb.vec16()))
    return exts


def parse_client_hello(body: bytes, hs: TlsHandshake) -> None:
    b = _Buf(body)
    hs.client_hello_seen = True
    hs.client_legacy_version = b.u16()
    b.take(32)                     # random
    b.vec8()                       # session id
    raw_ciphers = _u16_list(b.vec16())
    b.vec8()                       # compression methods
    exts = _parse_extensions(b)
    hs.fallback_scsv = 0x5600 in raw_ciphers
    hs.client_ciphers = [c for c in raw_ciphers if not is_grease(c)]
    hs.client_extensions = [e for e, _ in exts if not is_grease(e)]
    reneg = 0x00FF in raw_ciphers
    for etype, data in exts:
        try:
            if etype == EXT_SNI and len(data) > 5:
                eb = _Buf(data); eb.u16()
                while eb.left() >= 3:
                    ntype, name = eb.u8(), eb.vec16()
                    if ntype == 0:
                        hs.sni = name.decode("ascii", "replace").lower()
            elif etype == EXT_GROUPS:
                hs.supported_groups = [g for g in _u16_list(data[2:]) if not is_grease(g)]
            elif etype == EXT_POINT_FORMATS:
                hs.ec_point_formats = list(data[1:1 + data[0]]) if data else []
            elif etype == EXT_SIG_ALGS:
                hs.signature_algorithms = _u16_list(data[2:])
            elif etype == EXT_ALPN:
                eb = _Buf(data); eb.u16()
                while eb.left() >= 1:
                    hs.alpn.append(eb.vec8().decode("ascii", "replace"))
            elif etype == EXT_SUPPORTED_VERSIONS:
                hs.client_supported_versions = [v for v in _u16_list(data[1:1 + data[0]]) if not is_grease(v)]
            elif etype == EXT_RENEGOTIATION_INFO:
                reneg = True
        except (ValueError, IndexError, struct.error):
            hs.errors.append(f"malformed ClientHello extension {etype}")
    hs.secure_renegotiation = reneg

    # JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats), GREASE removed
    hs.ja3_string = ",".join([
        str(hs.client_legacy_version),
        "-".join(str(c) for c in hs.client_ciphers),
        "-".join(str(e) for e in hs.client_extensions),
        "-".join(str(g) for g in hs.supported_groups),
        "-".join(str(f) for f in hs.ec_point_formats),
    ])
    hs.ja3 = hashlib.md5(hs.ja3_string.encode(), usedforsecurity=False).hexdigest()


def parse_server_hello(body: bytes, hs: TlsHandshake) -> None:
    b = _Buf(body)
    hs.server_hello_seen = True
    hs.server_legacy_version = b.u16()
    random = b.take(32)
    b.vec8()
    hs.cipher_suite = b.u16()
    hs.cipher_name = suite_name(hs.cipher_suite)
    hs.compression = b.u8()
    exts = _parse_extensions(b)
    hs.server_extensions = [e for e, _ in exts]
    hs.hello_retry = random == HRR_RANDOM
    version = hs.server_legacy_version
    for etype, data in exts:
        try:
            if etype == EXT_SUPPORTED_VERSIONS and len(data) == 2:
                version = struct.unpack("!H", data)[0]
            elif etype == EXT_KEY_SHARE and len(data) >= 2:
                hs.selected_group = struct.unpack_from("!H", data)[0]
            elif etype == EXT_ALPN and len(data) > 3:
                hs.alpn = [data[3:3 + data[2]].decode("ascii", "replace")]
            elif etype == EXT_RENEGOTIATION_INFO:
                hs.secure_renegotiation = True
        except (ValueError, IndexError, struct.error):
            hs.errors.append(f"malformed ServerHello extension {etype}")
    if EXT_RENEGOTIATION_INFO not in hs.server_extensions and version != 0x0304:
        hs.secure_renegotiation = False
    hs.extended_master_secret = EXT_EMS in hs.server_extensions if version != 0x0304 else None
    hs.version = version
    hs.version_name = version_name(version)
    # RFC 8446 4.1.3: a TLS 1.3-capable server that negotiates lower marks the random
    if version != 0x0304:
        tail = random[-8:]
        if tail == DOWNGRD_12:
            hs.downgrade_sentinel = "TLS1.2"
        elif tail == DOWNGRD_11:
            hs.downgrade_sentinel = "TLS1.1-or-below"
    hs.ja3s_string = ",".join([str(hs.server_legacy_version), str(hs.cipher_suite),
                               "-".join(str(e) for e in hs.server_extensions)])
    hs.ja3s = hashlib.md5(hs.ja3s_string.encode(), usedforsecurity=False).hexdigest()


def parse_certificate(body: bytes, hs: TlsHandshake) -> None:
    b = _Buf(body)
    total = b.u24()
    end = b.p + total
    while b.p + 3 <= end and b.p < len(body):
        n = b.u24()
        hs.certificates.append(b.take(n))
    hs.certificate_visible = bool(hs.certificates)


def parse_server_key_exchange(body: bytes, hs: TlsHandshake) -> None:
    name = hs.cipher_name or ""
    try:
        if "ECDHE" in name and body[:1] == b"\x03":         # named_curve
            hs.ecdhe_curve = struct.unpack_from("!H", body, 1)[0]
            hs.selected_group = hs.selected_group or hs.ecdhe_curve
        elif "DHE" in name or "DH_anon" in name:
            plen = struct.unpack_from("!H", body, 0)[0]
            p = body[2:2 + plen].lstrip(b"\x00")
            hs.dh_bits = len(p) * 8 - (8 - p[0].bit_length()) if p else 0
    except (IndexError, struct.error):
        hs.errors.append("malformed ServerKeyExchange")


HS_NAMES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
            11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone",
            15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished"}


def record_flow(data: bytes) -> list[str]:
    """The messages one direction sent, in order, for the replay view.

    Cleartext handshake messages by name; after ChangeCipherSpec or the first
    application-data record, only a count of encrypted records.
    """
    out: list[str] = []
    hs = bytearray()
    encrypted, enc_n, p = False, 0, 0

    def flush() -> None:
        for mtype, _ in split_messages(bytes(hs)):
            out.append(HS_NAMES.get(mtype, f"handshake type {mtype}"))
        hs.clear()

    while p + 5 <= len(data) and len(out) < 40:
        ctype, length = data[p], struct.unpack_from("!H", data, p + 3)[0]
        if ctype not in (CT_CCS, CT_ALERT, CT_HANDSHAKE, CT_APPDATA) or data[p + 1] != 3:
            break
        frag = data[p + 5:p + 5 + length]
        p += 5 + length
        if encrypted:
            enc_n += 1
        elif ctype == CT_HANDSHAKE:
            hs += frag
        elif ctype == CT_ALERT:
            flush()
            level = "fatal" if frag[:1] == bytes([2]) else "warning"
            out.append(f"Alert {level} {alert_name(frag[1]) if len(frag) > 1 else ''}".strip())
        elif ctype == CT_CCS:
            flush()
            out.append("ChangeCipherSpec")
            encrypted = True
        else:
            flush()
            encrypted, enc_n = True, 1
    flush()
    if enc_n:
        out.append(f"encrypted records ×{enc_n}")
    return out


def analyze(client_bytes: bytes, server_bytes: bytes) -> TlsHandshake:
    hs = TlsHandshake()
    hs.client_flow = record_flow(client_bytes)
    hs.server_flow = record_flow(server_bytes)
    c_hs, c_alerts, c_enc, c_err = read_records(client_bytes)
    s_hs, s_alerts, s_enc, s_err = read_records(server_bytes)
    hs.alerts = c_alerts + s_alerts
    hs.errors += c_err + s_err
    for mtype, body in split_messages(c_hs):
        if mtype == HS_CLIENT_HELLO and not hs.client_hello_seen:
            try:
                parse_client_hello(body, hs)
            except (ValueError, IndexError, struct.error):
                hs.errors.append("malformed ClientHello")
    for mtype, body in split_messages(s_hs):
        try:
            if mtype == HS_SERVER_HELLO and not hs.server_hello_seen:
                parse_server_hello(body, hs)
            elif mtype == HS_CERTIFICATE and hs.version != 0x0304:
                parse_certificate(body, hs)
            elif mtype == HS_SERVER_KEY_EXCHANGE:
                parse_server_key_exchange(body, hs)
        except (ValueError, IndexError, struct.error):
            hs.errors.append(f"malformed server handshake message type {mtype}")
    fatal = any(level == 2 for level, _ in hs.alerts)
    hs.complete = hs.client_hello_seen and hs.server_hello_seen and c_enc and s_enc and not fatal
    if hs.version is None and hs.server_hello_seen is False and hs.client_hello_seen:
        hs.errors.append("no ServerHello: handshake refused or capture truncated")
    return hs


def alert_name(desc: int) -> str:
    return ALERT_NAMES.get(desc, f"alert_{desc}")
