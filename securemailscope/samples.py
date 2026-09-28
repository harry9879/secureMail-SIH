"""Synthetic but byte-accurate demo captures.

Teams lose more time to "no realistic traffic" than to any algorithm. This module
writes PCAP / PCAPNG files containing real TCP handshakes, real SMTP/IMAP/POP3
dialogues and real TLS ClientHello/ServerHello/Certificate bytes (certificates
generated with pyca/cryptography under a demo CA), plus deliberate TCP chaos:
out-of-order segments, retransmissions, overlaps and sequence-number wrap.

Everything is fictitious (example.com / example.net / documentation IP ranges).
Open the output in Wireshark to check it against SecureMailScope's parser.
"""
from __future__ import annotations

import base64
import datetime as dt
import os
import random
import struct
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = dt.timezone.utc
DEMO_T0 = dt.datetime(2026, 9, 14, 9, 0, tzinfo=UTC).timestamp()
BASELINE_T0 = dt.datetime(2026, 9, 7, 9, 0, tzinfo=UTC).timestamp()


# =========================================================================== checksums & frames

def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _ip_bytes(ip: str) -> bytes:
    import ipaddress
    return ipaddress.ip_address(ip).packed


def tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 64240, 0, 0)
    seg = hdr + payload
    if ":" in src:
        pseudo = _ip_bytes(src) + _ip_bytes(dst) + struct.pack("!IxxxB", len(seg), 6)
    else:
        pseudo = _ip_bytes(src) + _ip_bytes(dst) + struct.pack("!BBH", 0, 6, len(seg))
    c = _csum(pseudo + seg)
    return seg[:16] + struct.pack("!H", c) + seg[18:]


_ip_id = [1000]


def ip_packet(src: str, dst: str, proto: int, body: bytes, frag_flags: int = 0) -> bytes:
    if ":" in src:
        return struct.pack("!IHBB", 6 << 28, len(body), proto, 64) + _ip_bytes(src) + _ip_bytes(dst) + body
    _ip_id[0] += 1
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), _ip_id[0] & 0xFFFF, frag_flags, 64, proto, 0,
                      _ip_bytes(src), _ip_bytes(dst))
    return hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:] + body


def ethernet(ip: bytes, v6: bool, vlan: Optional[int] = None) -> bytes:
    etype = 0x86DD if v6 else 0x0800
    macs = bytes.fromhex("02005e0000aa") + bytes.fromhex("02005e0000bb")
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return macs + tag + struct.pack("!H", etype) + ip


def linux_sll(ip: bytes, v6: bool) -> bytes:
    return struct.pack("!HHH8sH", 0, 1, 6, bytes.fromhex("02005e0000aa0000"), 0x86DD if v6 else 0x0800) + ip


# =========================================================================== writers

@dataclass
class Capture:
    frames: list[tuple[float, bytes, bool, Optional[int]]] = field(default_factory=list)  # ts, ip packet, v6, vlan

    def add(self, ts: float, ip: bytes, v6: bool = False, vlan: Optional[int] = None) -> None:
        self.frames.append((ts, ip, v6, vlan))

    def write_pcap(self, path: str) -> None:
        self.frames.sort(key=lambda x: x[0])
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, ip, v6, vlan in self.frames:
                fr = ethernet(ip, v6, vlan)
                sec = int(ts)
                f.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(fr), len(fr)))
                f.write(fr)

    def write_pcapng(self, path: str, linktype: int = 113) -> None:
        self.frames.sort(key=lambda x: x[0])

        def block(btype: int, body: bytes) -> bytes:
            body += b"\x00" * ((4 - len(body) % 4) % 4)
            n = len(body) + 12
            return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

        with open(path, "wb") as f:
            f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
            opts = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)   # if_tsresol = 10^-9
            f.write(block(1, struct.pack("<HHI", linktype, 0, 65535) + opts))
            for ts, ip, v6, vlan in self.frames:
                fr = linux_sll(ip, v6) if linktype == 113 else ethernet(ip, v6, vlan)
                t = int(round(ts * 1e9))
                f.write(block(6, struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(fr), len(fr)) + fr))


# =========================================================================== TCP conversation

class Conv:
    """Builds one TCP conversation as a list of timed segments."""

    def __init__(self, cap: Capture, t0: float, cli: tuple[str, int], srv: tuple[str, int],
                 rng: random.Random, isn_c: Optional[int] = None, isn_s: Optional[int] = None,
                 mss: int = 1400, vlan: Optional[int] = None, rtt: float = 0.02):
        self.cap, self.t, self.cli, self.srv, self.rng = cap, t0, cli, srv, rng
        self.v6 = ":" in cli[0]
        self.seq_c = isn_c if isn_c is not None else rng.getrandbits(32)
        self.seq_s = isn_s if isn_s is not None else rng.getrandbits(32)
        self.mss, self.vlan, self.rtt = mss, vlan, rtt
        self.segs: list[tuple[float, bool, int, int, int, bytes]] = []  # ts, from_client, seq, ack, flags, data

    def _emit(self, from_client: bool, flags: int, data: bytes = b"") -> None:
        seq, ack = (self.seq_c, self.seq_s) if from_client else (self.seq_s, self.seq_c)
        self.segs.append((self.t, from_client, seq, ack, flags, data))

    def open(self) -> "Conv":
        self._emit(True, 0x02); self.seq_c += 1; self.t += self.rtt / 2
        self._emit(False, 0x12); self.seq_s += 1; self.t += self.rtt / 2
        self._emit(True, 0x10); self.t += 0.001
        return self

    def send(self, from_client: bool, data: bytes, think: float = 0.004) -> "Conv":
        for i in range(0, len(data), self.mss):
            chunk = data[i:i + self.mss]
            self._emit(from_client, 0x18, chunk)
            if from_client:
                self.seq_c += len(chunk)
            else:
                self.seq_s += len(chunk)
            self.t += 0.0005
        self.t += self.rtt / 2
        self._emit(not from_client, 0x10)  # pure ACK
        self.t += think
        return self

    def c(self, data: bytes) -> "Conv": return self.send(True, data)
    def s(self, data: bytes) -> "Conv": return self.send(False, data)

    def close(self) -> None:
        self._emit(True, 0x11); self.seq_c += 1; self.t += self.rtt / 2
        self._emit(False, 0x11); self.seq_s += 1; self.t += self.rtt / 2
        self._emit(True, 0x10)
        self._flush()

    def chaos(self) -> "Conv":
        """Reorder, retransmit and overlap some server data segments (all byte-consistent)."""
        data_idx = [i for i, s in enumerate(self.segs) if not s[1] and s[5]]
        if len(data_idx) < 4:
            return self
        # 1. swap two server segments' timestamps: out-of-order arrival
        a, b = data_idx[2], data_idx[3]
        sa, sb = self.segs[a], self.segs[b]
        self.segs[a], self.segs[b] = (sb[0],) + sa[1:], (sa[0],) + sb[1:]
        # 2. retransmit one segment later
        s1, s2 = self.segs[data_idx[0]], self.segs[data_idx[1]]
        self.segs.append((s1[0] + 0.2,) + s1[1:])
        # 3. overlapping resend: last 4 bytes of one segment + first 6 of the next, identical bytes
        self.segs.append((s1[0] + 0.25, False, s1[2] + len(s1[5]) - 4, s1[3], 0x18, s1[5][-4:] + s2[5][:6]))
        return self

    def _flush(self) -> None:
        for ts, from_client, seq, ack, flags, data in self.segs:
            src, dst = (self.cli, self.srv) if from_client else (self.srv, self.cli)
            seg = tcp_segment(src[0], dst[0], src[1], dst[1], seq, ack, flags, data)
            self.cap.add(ts, ip_packet(src[0], dst[0], 6, seg), self.v6, self.vlan)


# =========================================================================== PKI

@dataclass
class DemoPKI:
    root_key: rsa.RSAPrivateKey
    root: x509.Certificate
    inter_key: rsa.RSAPrivateKey
    inter: x509.Certificate
    leaves: dict[str, tuple[x509.Certificate, list[x509.Certificate]]] = field(default_factory=dict)

    def chain_der(self, name: str) -> list[bytes]:
        leaf, extra = self.leaves[name]
        return [c.public_bytes(serialization.Encoding.DER) for c in [leaf] + extra]


def _name(cn: str, org: str = "Example Corp") -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(subject: x509.Name, issuer: x509.Name, key, signer, signer_cert, start, end, path_len):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
         .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                      crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if signer_cert is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_cert.public_key()), critical=False)
    return b.sign(signer, hashes.SHA256())


def _leaf(cn: str, sans: list[str], key, issuer_cert, issuer_key, start, end, sig=hashes.SHA256(),
          self_signed: bool = False, org: str = "Example Corp") -> x509.Certificate:
    subject = _name(cn, org)
    b = (x509.CertificateBuilder().subject_name(subject)
         .issuer_name(subject if self_signed else issuer_cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if not self_signed:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    signer = key if self_signed else issuer_key
    if not isinstance(sig, hashes.SHA1):
        return b.sign(signer, sig)
    # Modern pyca refuses to *create* SHA-1 signatures. Sign with SHA-256, swap the
    # (same-length) algorithm OID, and re-sign the patched TBS bytes with SHA-1.
    cert = b.sign(signer, hashes.SHA256())
    o256, o1 = bytes.fromhex("2a864886f70d01010b"), bytes.fromhex("2a864886f70d010105")
    tbs = cert.tbs_certificate_bytes.replace(o256, o1)
    new_sig = signer.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    der = cert.public_bytes(serialization.Encoding.DER).replace(o256, o1).replace(cert.signature, new_sig)
    return x509.load_der_x509_certificate(der)


def build_pki() -> DemoPKI:
    k = lambda bits=2048: rsa.generate_private_key(public_exponent=65537, key_size=bits)
    y = lambda year, m=1, d=1: dt.datetime(year, m, d, tzinfo=UTC)
    root_key, inter_key = k(), k()
    root_name = _name("SecureMailScope Demo Root CA", "SecureMailScope Demo")
    root = _ca(root_name, root_name, root_key, root_key, None, y(2025), y(2035), 1)
    inter = _ca(_name("SecureMailScope Demo Issuing CA", "SecureMailScope Demo"), root_name, inter_key, root_key,
                root, y(2025), y(2031), 0)
    pki = DemoPKI(root_key, root, inter_key, inter)

    mx_key = k()
    pki.leaves["mx"] = (_leaf("mx.example.com", ["mx.example.com", "mail.example.com"], mx_key, inter, inter_key,
                              y(2026), y(2027)), [inter])
    wild_key = k()
    pki.leaves["wild"] = (_leaf("*.example.com", ["*.example.com", "example.com"], wild_key, inter, inter_key,
                                y(2026), y(2027)), [inter])
    atk_key = k()
    pki.leaves["mitm"] = (_leaf("mx.example.com", ["mx.example.com"], atk_key, None, None, y(2026, 9, 1),
                                y(2027, 9, 1), self_signed=True, org="Example Corp"), [])
    old_ca_key = k()
    old_ca_name = _name("OldMail Internal CA", "OldMail Ltd")
    old_ca = _ca(old_ca_name, old_ca_name, old_ca_key, old_ca_key, None, y(2015), y(2030), 0)
    weak_key = k(1024)
    pki.leaves["legacy"] = (_leaf("pop.oldmail.example.net", ["pop.oldmail.example.net"], weak_key, old_ca,
                                  old_ca_key, y(2022), y(2024), sig=hashes.SHA1(), org="OldMail Ltd"), [])
    return pki


# =========================================================================== TLS message builders

def _v16(b: bytes) -> bytes: return struct.pack("!H", len(b)) + b
def _v8(b: bytes) -> bytes: return struct.pack("!B", len(b)) + b
def _v24(b: bytes) -> bytes: return len(b).to_bytes(3, "big") + b
def _ext(t: int, body: bytes) -> bytes: return struct.pack("!H", t) + _v16(body)
def _hs(t: int, body: bytes) -> bytes: return struct.pack("!B", t) + _v24(body)
def record(ct: int, body: bytes, ver: int = 0x0303) -> bytes: return struct.pack("!BHH", ct, ver, len(body)) + body


def records(ct: int, body: bytes, ver: int = 0x0303, max_frag: int = 16384) -> bytes:
    return b"".join(record(ct, body[i:i + max_frag], ver) for i in range(0, len(body), max_frag))


GREASE = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA]
MODERN_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
                  0x009C, 0x009D, 0x002F, 0x0035]
LEGACY_CIPHERS = [0x0035, 0x002F, 0x000A, 0x0005, 0x0004, 0x0003, 0x00FF]


def client_hello(rng: random.Random, sni: Optional[str], tls13: bool = True, legacy: bool = False,
                 split_at: Optional[int] = None) -> bytes:
    g = rng.sample(GREASE, 4)
    if legacy:
        ciphers, version, exts = LEGACY_CIPHERS, 0x0301, b""
        if sni:
            exts = _ext(0, _v16(b"\x00" + _v16(sni.encode())))
    else:
        ciphers = [g[0]] + (MODERN_CIPHERS if tls13 else MODERN_CIPHERS[3:])
        version = 0x0303
        e = [_ext(g[1], b"")]
        if sni:
            e.append(_ext(0, _v16(b"\x00" + _v16(sni.encode()))))
        e += [_ext(23, b""), _ext(0xFF01, b"\x00"),
              _ext(10, _v16(struct.pack("!4H", g[2], 29, 23, 24))),
              _ext(11, _v8(b"\x00")), _ext(35, b""),
              _ext(13, _v16(struct.pack("!8H", 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)))]
        if tls13:
            e += [_ext(43, _v8(struct.pack("!3H", g[3], 0x0304, 0x0303))),
                  _ext(51, _v16(struct.pack("!H", g[2]) + _v16(b"\x00") + struct.pack("!H", 29) + _v16(rng.randbytes(32)))),
                  _ext(45, _v8(b"\x01"))]
        e.append(_ext(g[3], b"\x00"))   # trailing GREASE extension, as Chrome/BoringSSL do
        exts = b"".join(e)
    body = (struct.pack("!H", version) + rng.randbytes(32) + _v8(rng.randbytes(32) if not legacy else b"") +
            _v16(b"".join(struct.pack("!H", c) for c in ciphers)) + _v8(b"\x00") + (_v16(exts) if exts else b""))
    msg = _hs(1, body)
    rec_ver = 0x0301
    if split_at:   # one handshake message spanning two records
        return record(22, msg[:split_at], rec_ver) + record(22, msg[split_at:], rec_ver)
    return record(22, msg, rec_ver)


def server_hello(rng: random.Random, version: int, cipher: int, tls13: bool = False, reneg: bool = True,
                 ems: bool = True, downgrade: Optional[bytes] = None) -> bytes:
    rand = rng.randbytes(24) + (downgrade if downgrade else rng.randbytes(8))
    e = []
    if tls13:
        e += [_ext(43, struct.pack("!H", 0x0304)), _ext(51, struct.pack("!H", 29) + _v16(rng.randbytes(32)))]
    else:
        if reneg:
            e.append(_ext(0xFF01, b"\x00"))
        if ems:
            e.append(_ext(23, b""))
        e.append(_ext(11, _v8(b"\x00")))
    body = (struct.pack("!H", 0x0303 if tls13 else version) + rand + _v8(rng.randbytes(32)) +
            struct.pack("!HB", cipher, 0) + (_v16(b"".join(e)) if e else b""))
    return _hs(2, body)


def certificate_msg(ders: list[bytes]) -> bytes:
    return _hs(11, _v24(b"".join(_v24(d) for d in ders)))


def ske_ecdhe(rng: random.Random) -> bytes:
    return _hs(12, b"\x03" + struct.pack("!H", 23) + _v8(b"\x04" + rng.randbytes(64)) +
               struct.pack("!H", 0x0401) + _v16(rng.randbytes(256)))


def ske_dhe(rng: random.Random, bits: int) -> bytes:
    p = bytearray(rng.randbytes(bits // 8)); p[0] |= 0x80; p[-1] |= 1
    return _hs(12, _v16(bytes(p)) + _v16(b"\x02") + _v16(rng.randbytes(bits // 8)) +
               struct.pack("!H", 0x0401) + _v16(rng.randbytes(256)))


def tls12_exchange(conv: Conv, rng: random.Random, sni: Optional[str], cipher: int, chain: list[bytes],
                   kx: str = "ecdhe", dh_bits: int = 2048, version: int = 0x0303, legacy_client: bool = False,
                   client_tls13: bool = False, downgrade: Optional[bytes] = None, reneg: bool = True,
                   ems: bool = True, split_client_hello: bool = False) -> None:
    ch = client_hello(rng, sni, tls13=client_tls13, legacy=legacy_client,
                      split_at=40 if split_client_hello else None)
    conv.c(ch)
    flight = server_hello(rng, version, cipher, reneg=reneg, ems=ems, downgrade=downgrade) + certificate_msg(chain)
    if kx == "ecdhe":
        flight += ske_ecdhe(rng)
    elif kx == "dhe":
        flight += ske_dhe(rng, dh_bits)
    flight += _hs(14, b"")
    conv.s(records(22, flight, version))   # several handshake messages in one record
    # ClientKeyExchange: ECDHE point is <1..255>; DHE Yc and the RSA-encrypted premaster are <1..2^16-1>
    cke = _v8(b"\x04" + rng.randbytes(64)) if kx == "ecdhe" else \
        _v16(rng.randbytes(dh_bits // 8 if kx == "dhe" else 256))
    conv.c(record(22, _hs(16, cke), version) + record(20, b"\x01", version) +
           record(22, rng.randbytes(40), version))
    conv.s(record(20, b"\x01", version) + record(22, rng.randbytes(40), version))
    _appdata(conv, rng, version)


def tls13_exchange(conv: Conv, rng: random.Random, sni: Optional[str], cipher: int = 0x1302) -> None:
    conv.c(client_hello(rng, sni, tls13=True))
    conv.s(record(22, server_hello(rng, 0x0303, cipher, tls13=True)) + record(20, b"\x01") +
           record(23, rng.randbytes(2800)) + record(23, rng.randbytes(300)))
    conv.c(record(20, b"\x01") + record(23, rng.randbytes(69)))
    _appdata(conv, rng, 0x0303)


def _appdata(conv: Conv, rng: random.Random, version: int) -> None:
    for _ in range(3):
        conv.c(record(23, rng.randbytes(rng.randint(40, 400)), version))
        conv.s(record(23, rng.randbytes(rng.randint(40, 200)), version))


# =========================================================================== protocol dialogues

CRLF = b"\r\n"


def _lines(*ls: str) -> bytes:
    return "".join(l + "\r\n" for l in ls).encode()


def _message(frm: str, to: str, subject: str, rng: random.Random) -> bytes:
    body = " ".join(rng.choice(["quarterly", "invoice", "attached", "review", "figures", "meeting", "budget",
                                "please", "confirm", "draft"]) for _ in range(120))
    return _lines(f"From: <{frm}>", f"To: <{to}>", f"Subject: {subject}",
                  "Date: Mon, 14 Sep 2026 09:12:00 +0530", "MIME-Version: 1.0",
                  "Content-Type: text/plain; charset=utf-8", "", body, ".")


def smtp_ehlo(conv: Conv, banner: str, client_name: str, server_name: str, caps: list[str]) -> None:
    conv.s(_lines(f"220 {banner}"))
    conv.c(_lines(f"EHLO {client_name}"))
    lines = [f"250-{server_name}"] + [f"250-{c}" for c in caps[:-1]] + [f"250 {caps[-1]}"]
    conv.s(_lines(*lines))


POSTFIX_CAPS = ["PIPELINING", "SIZE 10240000", "VRFY", "ETRN", "STARTTLS", "ENHANCEDSTATUSCODES", "8BITMIME",
                "DSN", "SMTPUTF8", "CHUNKING"]


def scenario_relay_ok(cap, pki, rng, t, cli, chaos=False, isn=None, vlan=None):
    conv = Conv(cap, t, (cli, rng.randint(40000, 60000)), ("203.0.113.10", 25), rng, isn_c=isn,
                mss=48 if chaos else 1400, vlan=vlan).open()
    smtp_ehlo(conv, "mx.example.com ESMTP Postfix (Debian/GNU)", "mta.partner.example.net", "mx.example.com",
              POSTFIX_CAPS)
    conv.c(_lines("STARTTLS")).s(_lines("220 2.0.0 Ready to start TLS"))
    if chaos:
        conv.chaos()
    conv.mss = 1400
    tls12_exchange(conv, rng, "mx.example.com", 0xC030, pki.chain_der("mx"), client_tls13=True,
                   split_client_hello=True)
    conv.close()


def scenario_relay_mitm_cert(cap, pki, rng, t):
    conv = Conv(cap, t, ("198.51.100.51", 51514), ("203.0.113.10", 25), rng).open()
    smtp_ehlo(conv, "mx.example.com ESMTP Postfix (Debian/GNU)", "mta.partner.example.net", "mx.example.com",
              POSTFIX_CAPS)
    conv.c(_lines("STARTTLS")).s(_lines("220 2.0.0 Ready to start TLS"))
    tls12_exchange(conv, rng, "mx.example.com", 0xC02F, pki.chain_der("mitm"), client_tls13=True, ems=False)
    conv.close()


def scenario_relay_454(cap, pki, rng, t):
    conv = Conv(cap, t, ("198.51.100.52", 52020), ("203.0.113.10", 25), rng).open()
    smtp_ehlo(conv, "mx.example.com ESMTP Postfix (Debian/GNU)", "mta2.partner.example.net", "mx.example.com",
              POSTFIX_CAPS)
    conv.c(_lines("STARTTLS")).s(_lines("454 4.7.0 TLS not available due to local problem"))
    conv.c(_lines("MAIL FROM:<payroll@partner.example.net>")).s(_lines("250 2.1.0 Ok"))
    conv.c(_lines("RCPT TO:<hr@example.com>")).s(_lines("250 2.1.5 Ok"))
    conv.c(_lines("DATA")).s(_lines("354 End data with <CR><LF>.<CR><LF>"))
    conv.c(_message("payroll@partner.example.net", "hr@example.com", "September salary register", rng))
    conv.s(_lines("250 2.0.0 Ok: queued as 7C1D22A0F1"))
    conv.c(_lines("QUIT")).s(_lines("221 2.0.0 Bye"))
    conv.close()


SUB_CAPS_TLS = ["PIPELINING", "SIZE 52428800", "STARTTLS", "ENHANCEDSTATUSCODES", "8BITMIME", "DSN"]


def scenario_submission_ok(cap, pki, rng, t, cli):
    conv = Conv(cap, t, (cli, rng.randint(40000, 60000)), ("203.0.113.11", 587), rng).open()
    smtp_ehlo(conv, "smtp.example.com ESMTP Postfix", "laptop", "smtp.example.com", SUB_CAPS_TLS)
    conv.c(_lines("STARTTLS")).s(_lines("220 2.0.0 Ready to start TLS"))
    tls13_exchange(conv, rng, "smtp.example.com")
    conv.close()


def scenario_submission_stripped(cap, pki, rng, t):
    conv = Conv(cap, t, ("10.20.0.23", 49822), ("203.0.113.11", 587), rng).open()
    caps = ["PIPELINING", "SIZE 52428800", "XXXXXXXX", "AUTH PLAIN LOGIN", "ENHANCEDSTATUSCODES", "8BITMIME", "DSN"]
    smtp_ehlo(conv, "smtp.example.com ESMTP Postfix", "laptop-23.corp.example.com", "smtp.example.com", caps)
    conv.c(_lines("AUTH LOGIN")).s(_lines("334 VXNlcm5hbWU6"))
    conv.c(_lines(base64.b64encode(b"ananya.sharma@example.com").decode())).s(_lines("334 UGFzc3dvcmQ6"))
    conv.c(_lines(base64.b64encode(b"Monsoon#2026").decode())).s(_lines("235 2.7.0 Authentication successful"))
    conv.c(_lines("MAIL FROM:<ananya.sharma@example.com>")).s(_lines("250 2.1.0 Ok"))
    conv.c(_lines("RCPT TO:<finance@partner.example.net>")).s(_lines("250 2.1.5 Ok"))
    conv.c(_lines("DATA")).s(_lines("354 End data with <CR><LF>.<CR><LF>"))
    conv.c(_message("ananya.sharma@example.com", "finance@partner.example.net", "Wire details for Q3", rng))
    conv.s(_lines("250 2.0.0 Ok: queued as 4F2A1C9B3E"))
    conv.c(_lines("QUIT")).s(_lines("221 2.0.0 Bye"))
    conv.close()


def scenario_submission_injection(cap, pki, rng, t):
    conv = Conv(cap, t, ("10.20.0.26", 50611), ("203.0.113.11", 587), rng).open()
    smtp_ehlo(conv, "smtp.example.com ESMTP Postfix", "laptop-26", "smtp.example.com", SUB_CAPS_TLS)
    conv.c(_lines("STARTTLS", "RSET", "MAIL FROM:<attacker@evil.example>"))
    conv.s(_lines("220 2.0.0 Ready to start TLS"))
    tls13_exchange(conv, rng, "smtp.example.com")
    conv.close()


def scenario_submission_downgrade(cap, pki, rng, t):
    conv = Conv(cap, t, ("10.20.0.25", 50400), ("203.0.113.11", 587), rng).open()
    smtp_ehlo(conv, "smtp.example.com ESMTP Postfix", "laptop-25", "smtp.example.com", SUB_CAPS_TLS)
    conv.c(_lines("STARTTLS")).s(_lines("220 2.0.0 Ready to start TLS"))
    tls12_exchange(conv, rng, "smtp.example.com", 0xC02F, pki.chain_der("wild"), client_tls13=True,
                   downgrade=b"DOWNGRD\x01")
    conv.close()


def scenario_smtps_dhe(cap, pki, rng, t, cli, sni):
    conv = Conv(cap, t, (cli, rng.randint(40000, 60000)), ("203.0.113.11", 465), rng).open()
    tls12_exchange(conv, rng, sni, 0x0033, pki.chain_der("wild"), kx="dhe", dh_bits=1024, ems=False)
    conv.close()


IMAP_CAPS_PLAIN = "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN AUTH=LOGIN"


def scenario_imap_plain(cap, pki, rng, t):
    conv = Conv(cap, t, ("10.20.0.31", 51200), ("203.0.113.12", 143), rng).open()
    conv.s(_lines(f"* OK [CAPABILITY {IMAP_CAPS_PLAIN}] Dovecot ready."))
    conv.c(_lines("a001 CAPABILITY"))
    conv.s(_lines(f"* CAPABILITY {IMAP_CAPS_PLAIN}", "a001 OK Pre-login capabilities listed."))
    conv.c(_lines('a002 LOGIN "rahul.verma" "Winter2025!"'))
    conv.s(_lines("a002 OK [CAPABILITY IMAP4rev1 IDLE] Logged in"))
    conv.c(_lines("a003 SELECT INBOX"))
    conv.s(_lines("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)", "* 3 EXISTS", "* 0 RECENT",
                  "a003 OK [READ-WRITE] Select completed."))
    msg = _message("cfo@example.com", "rahul.verma@example.com", "Board pack (confidential)", rng)
    conv.c(_lines("a004 FETCH 1 BODY[]"))
    conv.s(f"* 1 FETCH (BODY[] {{{len(msg)}}}\r\n".encode() + msg + _lines(")", "a004 OK Fetch completed."))
    conv.c(_lines("a005 LOGOUT")).s(_lines("* BYE Logging out", "a005 OK Logout completed."))
    conv.close()


def scenario_imap_starttls_v6(cap, pki, rng, t):
    conv = Conv(cap, t, ("2001:db8:20::31", 51300), ("2001:db8:113::12", 143), rng).open()
    conv.s(_lines("* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS "
                  "LOGINDISABLED] Dovecot ready."))
    conv.c(_lines("a001 STARTTLS")).s(_lines("a001 OK Begin TLS negotiation now."))
    tls12_exchange(conv, rng, "imap.example.com", 0xC02F, pki.chain_der("wild"), client_tls13=False)
    conv.close()


def scenario_imaps(cap, pki, rng, t, cli):
    conv = Conv(cap, t, (cli, rng.randint(40000, 60000)), ("203.0.113.12", 993), rng).open()
    tls13_exchange(conv, rng, "imap.example.com", 0x1301)
    conv.close()


def scenario_pop3_legacy(cap, pki, rng, t):
    conv = Conv(cap, t, ("10.20.0.40", 50999), ("198.51.100.20", 110), rng).open()
    conv.s(_lines("+OK pop.oldmail.example.net POP3 server ready <1896.697170952@pop.oldmail.example.net>"))
    conv.c(_lines("CAPA")).s(_lines("+OK Capability list follows", "TOP", "USER", "UIDL", "STLS", "."))
    conv.c(_lines("STLS")).s(_lines("+OK Begin TLS negotiation"))
    tls12_exchange(conv, rng, None, 0x000A, pki.chain_der("legacy"), kx="rsa", version=0x0301,
                   legacy_client=True, reneg=False, ems=False)
    conv.close()


def scenario_shadow_smtp(cap, pki, rng, t):
    conv = Conv(cap, t, ("10.20.0.60", 41022), ("10.20.5.9", 2525), rng).open()
    conv.s(_lines("220 printer-relay.corp.example.com ESMTP Sendmail 8.14.4; Mon, 14 Sep 2026 09:40:00 +0530"))
    conv.c(_lines("EHLO scanner-3f.corp.example.com"))
    conv.s(_lines("250-printer-relay.corp.example.com Hello scanner-3f", "250-ENHANCEDSTATUSCODES",
                  "250-8BITMIME", "250-SIZE", "250-STARTTLS", "250 HELP"))
    conv.c(_lines("MAIL FROM:<scanner@corp.example.com>")).s(_lines("250 2.1.0 Sender ok"))
    conv.c(_lines("RCPT TO:<legal@example.com>")).s(_lines("250 2.1.5 Recipient ok"))
    conv.c(_lines("DATA")).s(_lines("354 Enter mail, end with \".\" on a line by itself"))
    conv.c(_message("scanner@corp.example.com", "legal@example.com", "Scanned contract 2026-0914", rng))
    conv.s(_lines("250 2.0.0 Message accepted for delivery"))
    conv.c(_lines("QUIT")).s(_lines("221 2.0.0 closing connection"))
    conv.close()


def scenario_https_noise(cap, pki, rng, t):
    conv = Conv(cap, t, ("10.20.0.23", 49900), ("192.0.2.80", 443), rng).open()
    tls13_exchange(conv, rng, "intranet.example.com")
    conv.close()


def _udp_and_fragment_noise(cap: Capture, t: float, rng: random.Random) -> None:
    qname = b"".join(bytes([len(p)]) + p for p in b"mx.example.com".split(b".")) + b"\x00"
    dns = struct.pack("!HHHHHH", rng.getrandbits(16), 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 15, 1)  # MX?
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    cap.add(t, ip_packet("10.20.0.23", "10.20.0.1", 17, udp))
    cap.add(t + 0.001, ip_packet("10.20.0.23", "10.20.0.1", 6, rng.randbytes(64), frag_flags=0x2000))


# =========================================================================== public entry points

def generate(out_dir: str, seed: int = 2026) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    rng = random.Random(seed)
    pki = build_pki()
    paths: dict[str, str] = {}

    ca_path = os.path.join(out_dir, "demo-ca.pem")
    with open(ca_path, "wb") as f:
        f.write(pki.root.public_bytes(serialization.Encoding.PEM))
    paths["trust_store"] = ca_path

    # ---- a clean week earlier: seeds the per-endpoint baseline
    base = Capture()
    t = BASELINE_T0
    for i in range(5):
        scenario_relay_ok(base, pki, rng, t, f"198.51.100.{40 + i}"); t += 60
    for i in range(3):
        scenario_submission_ok(base, pki, rng, t, f"10.20.0.{10 + i}"); t += 60
    for i in range(2):
        scenario_imaps(base, pki, rng, t, f"10.20.0.{30 + i}"); t += 60
    paths["baseline"] = os.path.join(out_dir, "healthy_baseline.pcap")
    base.write_pcap(paths["baseline"])

    # ---- the demo capture: healthy traffic plus every weakness class
    cap = Capture()
    t = DEMO_T0
    scenario_relay_ok(cap, pki, rng, t, "198.51.100.40", chaos=True); t += 30
    scenario_relay_ok(cap, pki, rng, t, "198.51.100.41", isn=0xFFFFFF00); t += 30   # sequence wrap
    scenario_relay_ok(cap, pki, rng, t, "198.51.100.42", vlan=120); t += 30          # 802.1Q tagged
    scenario_relay_ok(cap, pki, rng, t, "198.51.100.43"); t += 30
    for i in range(3):
        scenario_submission_ok(cap, pki, rng, t, f"10.20.0.{10 + i}"); t += 30
    scenario_imaps(cap, pki, rng, t, "10.20.0.32"); t += 30
    scenario_imap_starttls_v6(cap, pki, rng, t); t += 30
    scenario_submission_stripped(cap, pki, rng, t); t += 30
    scenario_relay_454(cap, pki, rng, t); t += 30
    scenario_relay_mitm_cert(cap, pki, rng, t); t += 30
    scenario_submission_injection(cap, pki, rng, t); t += 30
    scenario_submission_downgrade(cap, pki, rng, t); t += 30
    scenario_smtps_dhe(cap, pki, rng, t, "10.20.0.27", "smtp.example.com"); t += 30
    scenario_smtps_dhe(cap, pki, rng, t, "10.20.0.28", "mail.corp.example.com"); t += 30   # wildcard is one label
    scenario_imap_plain(cap, pki, rng, t); t += 30
    scenario_pop3_legacy(cap, pki, rng, t); t += 30
    scenario_shadow_smtp(cap, pki, rng, t); t += 30
    scenario_https_noise(cap, pki, rng, t); t += 30
    _udp_and_fragment_noise(cap, t, rng)
    paths["demo"] = os.path.join(out_dir, "demo_enterprise.pcap")
    cap.write_pcap(paths["demo"])

    # ---- a small pcapng (Linux cooked capture) with just the stripping story
    ng = Capture()
    t = DEMO_T0
    for i in range(3):
        scenario_submission_ok(ng, pki, rng, t, f"10.20.0.{10 + i}"); t += 20
    scenario_submission_stripped(ng, pki, rng, t)
    paths["pcapng"] = os.path.join(out_dir, "starttls_stripping.pcapng")
    ng.write_pcapng(paths["pcapng"], linktype=113)
    return paths
