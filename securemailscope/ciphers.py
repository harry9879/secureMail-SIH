"""Stage 05b: cipher suite and protocol version grading.

Suite properties are *derived from the IANA name* (TLS_<kx>_<auth>_WITH_<enc>_<mac>)
instead of a thousand-row lookup table. The table below only maps code -> name.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SUITE_NAMES: dict[int, str] = {
    # TLS 1.3
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # ECDHE
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", 0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA", 0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    # static ECDH
    0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", 0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA", 0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    # DHE
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    # anonymous DH
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5", 0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA", 0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    # static RSA key transport
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM", 0xC09D: "TLS_RSA_WITH_AES_256_CCM",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0096: "TLS_RSA_WITH_SEED_CBC_SHA", 0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA", 0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0062: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
    0x0064: "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
    # PSK
    0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA", 0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    # signalling values
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0x5600: "TLS_FALLBACK_SCSV",
}

SCSV = {0x00FF, 0x5600}

VERSION_NAMES = {0x0200: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
VERSION_ORDINAL = {None: 0, 0x0200: 1, 0x0300: 1, 0x0301: 2, 0x0302: 3, 0x0303: 4, 0x0304: 5}

GROUP_NAMES = {19: "secp192r1", 21: "secp224r1", 22: "secp256k1", 23: "secp256r1", 24: "secp384r1",
               25: "secp521r1", 29: "x25519", 30: "x448", 256: "ffdhe2048", 257: "ffdhe3072",
               258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192", 0x11EC: "X25519MLKEM768"}
WEAK_GROUPS = {19, 21}
GROUP_BITS = {19: 192, 21: 224, 22: 256, 23: 256, 24: 384, 25: 521, 29: 255, 30: 448}


def is_grease(v: int) -> bool:
    """RFC 8701 GREASE values: 0x0A0A, 0x1A1A ... 0xFAFA."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def version_name(v: int | None) -> str:
    if v is None:
        return "none"
    return VERSION_NAMES.get(v, f"0x{v:04x}")


def suite_name(code: int) -> str:
    return SUITE_NAMES.get(code, f"UNKNOWN_0x{code:04X}")


@dataclass
class SuiteProfile:
    code: int
    name: str
    tls13: bool = False
    kx: str = "unknown"
    auth: str = "unknown"
    enc: str = "unknown"
    mac: str = ""
    forward_secrecy: bool = False
    aead: bool = False
    grade: str = "?"
    weaknesses: list[tuple[str, str]] = field(default_factory=list)  # (short, why)

    @property
    def broken(self) -> bool:
        return self.grade == "F"


_MACS = ("SHA384", "SHA256", "SHA", "MD5")


def profile(code: int) -> SuiteProfile:
    name = suite_name(code)
    p = SuiteProfile(code=code, name=name)
    if name.startswith("UNKNOWN"):
        return p
    body = name[4:]
    if "_WITH_" not in body:
        # TLS 1.3 suites name only the AEAD and hash; key exchange is always (EC)DHE
        p.tls13 = True
        p.kx, p.auth = "ECDHE/DHE (TLS 1.3)", "certificate"
        p.enc, p.mac = body.rsplit("_", 1) if body.endswith(_MACS) else (body, "")
        p.forward_secrecy = p.aead = True
        p.grade = "A"
        return p

    kxauth, rest = body.split("_WITH_", 1)
    toks = rest.split("_")
    if toks[-1] in _MACS:
        p.mac, p.enc = toks[-1], "_".join(toks[:-1])
    else:
        p.enc = rest
    k = kxauth.split("_")
    export = "EXPORT" in kxauth
    anon = "anon" in k
    p.kx = k[0]
    p.auth = "none" if anon else (k[1] if len(k) > 1 and k[1] not in ("EXPORT", "EXPORT1024") else k[0])
    p.forward_secrecy = p.kx in ("ECDHE", "DHE")
    p.aead = any(x in p.enc for x in ("GCM", "CCM", "POLY1305"))

    w = p.weaknesses
    if anon:
        w.append(("anonymous", "no server authentication: any active attacker can impersonate the server"))
    if export:
        w.append(("export-grade",
                  "export-grade key exchange (FREAK for RSA_EXPORT, Logjam for DHE_EXPORT)"))
    if p.enc == "NULL":
        w.append(("null-cipher", "no encryption at all"))
    if "RC4" in p.enc:
        w.append(("rc4", "RC4 keystream biases; prohibited by RFC 7465"))
    if any(x in p.enc for x in ("3DES", "DES", "IDEA", "RC2")):
        w.append(("64-bit-block", "64-bit block cipher: Sweet32 birthday attack (CVE-2016-2183)"))
    if p.mac == "MD5":
        w.append(("md5-mac", "HMAC-MD5 record MAC"))
    if not p.forward_secrecy:
        w.append(("no-fs", "static key exchange: recorded traffic is decryptable if the server key leaks "
                           "(harvest-now-decrypt-later); RSA key transport is also the ROBOT/DROWN attack surface"))
    if "CBC" in p.enc and not any(s in ("anonymous", "null-cipher") for s, _ in w):
        w.append(("cbc", "MAC-then-encrypt CBC: Lucky13 timing oracle; BEAST on TLS 1.0"))

    if any(s in ("anonymous", "export-grade", "null-cipher", "rc4", "64-bit-block") for s, _ in w):
        p.grade = "F"
    elif p.forward_secrecy and p.aead:
        p.grade = "A"
    elif p.forward_secrecy:
        p.grade = "B"
    else:
        p.grade = "C"
    return p


def version_issue(v: int | None) -> tuple[str, str] | None:
    """(severity, reason) for a negotiated protocol version, or None when acceptable."""
    if v in (0x0200, 0x0300):
        return "critical", "SSL is broken (POODLE, DROWN); prohibited by RFC 6176 / RFC 7568"
    if v == 0x0301:
        return "high", "TLS 1.0 is deprecated by RFC 8996 (BEAST, no AEAD suites, SHA-1/MD5 PRF)"
    if v == 0x0302:
        return "high", "TLS 1.1 is deprecated by RFC 8996 (no AEAD suites, SHA-1/MD5 PRF)"
    return None
