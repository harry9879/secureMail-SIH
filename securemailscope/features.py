"""Stage 08: turn one analysed session into a fixed-length numeric vector.

Encoding choices (docs/08-ml-and-baselining.md):
  * nominal categories (protocol, port class)  -> one-hot
  * ordered categories (TLS version, grade)    -> ordinal
  * unbounded counts (bytes)                   -> log1p then clip
  * key sizes                                  -> clip then scale to [0, 1]
The feature vector *is* the ML work; the model choice is almost incidental.
"""
from __future__ import annotations

import math
from typing import Optional

from .ciphers import VERSION_ORDINAL, WEAK_GROUPS, profile
from .models import ChainInfo, MailSession, TlsHandshake
from .rules import port_class

FEATURES = [
    "proto_smtp", "proto_imap", "proto_pop3",
    "port_relay", "port_submission", "port_access", "port_nonstandard",
    "mode_ordinal", "tls_version", "forward_secrecy", "aead", "cipher_grade",
    "weak_dh_or_curve", "compression", "downgrade_signal", "handshake_failed",
    "cert_visible", "cert_expired", "cert_self_signed", "cert_hostname_mismatch", "cert_untrusted",
    "cert_key_weakness", "cert_weak_sig",
    "starttls_offered", "strip_indicator", "injection", "cleartext_auth", "weak_auth", "cleartext_data",
    "overlap_conflicts",
    "base_starttls_drop", "base_cert_change", "base_downgrade", "base_new_ja3s",
]

GRADE_ORD = {"A": 0, "B": 1, "C": 2, "F": 3, "?": 2}
MODE_ORD = {"plaintext": 0, "unknown": 0, "starttls": 1, "implicit": 2}

# The ideal session, used as the occlusion reference for explanations.
REFERENCE = dict.fromkeys(FEATURES, 0.0)
REFERENCE.update({"proto_smtp": 1.0, "port_submission": 1.0, "mode_ordinal": 2.0, "tls_version": 5.0,
                  "forward_secrecy": 1.0, "aead": 1.0, "starttls_offered": 1.0})

# Explanations are given per *group*: analysts reason about "the channel was unencrypted",
# not about three correlated columns that all encode it.
GROUPS: dict[str, list[str]] = {
    "service and port": ["proto_smtp", "proto_imap", "proto_pop3", "port_relay", "port_submission",
                         "port_access", "port_nonstandard"],
    "channel encryption": ["mode_ordinal", "tls_version", "forward_secrecy", "aead", "cipher_grade"],
    "key exchange strength": ["weak_dh_or_curve"],
    "TLS negotiation anomalies": ["compression", "downgrade_signal", "handshake_failed"],
    "certificate": ["cert_visible", "cert_expired", "cert_self_signed", "cert_hostname_mismatch",
                    "cert_untrusted", "cert_key_weakness", "cert_weak_sig"],
    "STARTTLS offer / stripping": ["starttls_offered", "strip_indicator"],
    "command injection": ["injection"],
    "cleartext credentials": ["cleartext_auth", "weak_auth"],
    "cleartext message data": ["cleartext_data"],
    "TCP anomalies": ["overlap_conflicts"],
    "endpoint baseline deviation": ["base_starttls_drop", "base_cert_change", "base_downgrade", "base_new_ja3s"],
}


def vector(sess: MailSession, hs: Optional[TlsHandshake], chain: Optional[ChainInfo],
           deviations: Optional[set[str]] = None) -> dict[str, float]:
    deviations = deviations or set()
    v = dict.fromkeys(FEATURES, 0.0)
    v[f"proto_{sess.protocol.lower()}"] = 1.0 if sess.protocol in ("SMTP", "IMAP", "POP3") else 0.0
    v[f"port_{port_class(sess)}"] = 1.0
    v["mode_ordinal"] = float(MODE_ORD.get(sess.mode, 0))

    if hs is not None and hs.server_hello_seen:
        v["tls_version"] = float(VERSION_ORDINAL.get(hs.version, 0))
        if hs.cipher_suite is not None:
            p = profile(hs.cipher_suite)
            v["forward_secrecy"] = float(p.forward_secrecy)
            v["aead"] = float(p.aead)
            v["cipher_grade"] = float(GRADE_ORD.get(p.grade, 2))
        v["weak_dh_or_curve"] = float(bool((hs.dh_bits and hs.dh_bits < 2048) or
                                           (hs.ecdhe_curve or hs.selected_group) in WEAK_GROUPS))
        v["compression"] = float(hs.compression not in (None, 0))
        v["downgrade_signal"] = float(bool(hs.downgrade_sentinel or hs.fallback_scsv))
    else:
        v["cipher_grade"] = 4.0  # no encryption is worse than any cipher
    if hs is not None and hs.client_hello_seen:
        v["handshake_failed"] = float(any(l == 2 for l, _ in hs.alerts) or not hs.server_hello_seen)

    if chain is not None and chain.present and chain.leaf:
        leaf = chain.leaf
        v["cert_visible"] = 1.0
        v["cert_expired"] = float(bool(chain.expired or chain.not_yet_valid))
        v["cert_self_signed"] = float(bool(chain.self_signed))
        v["cert_hostname_mismatch"] = float(chain.hostname_match is False)
        v["cert_untrusted"] = float(chain.trusted is False)
        target = 256 if leaf.key_type.startswith(("EC", "Ed")) else 2048
        v["cert_key_weakness"] = round(max(0.0, 1.0 - leaf.key_bits / target), 3) if leaf.key_bits else 1.0
        v["cert_weak_sig"] = float((leaf.signature_hash or "").lower() in ("md5", "sha1"))

    v["starttls_offered"] = float(bool(sess.starttls_offered) or sess.mode == "implicit")
    v["strip_indicator"] = float(bool(sess.strip_indicators))
    v["injection"] = float(bool(sess.injection_indicators))
    v["cleartext_auth"] = float(any(e.secret_exposed for e in sess.auth_events))
    v["weak_auth"] = float(any(not e.secret_exposed for e in sess.auth_events))
    v["cleartext_data"] = round(min(math.log1p(sess.cleartext_message_bytes) / 12.0, 1.0), 3)
    v["overlap_conflicts"] = float(min(sess.stream_quality.get("overlap_conflicts", 0), 5)) / 5.0

    for d in deviations:
        key = f"base_{d}"
        if key in v:
            v[key] = 1.0
    return v


def to_row(v: dict[str, float]) -> list[float]:
    return [float(v[f]) for f in FEATURES]
