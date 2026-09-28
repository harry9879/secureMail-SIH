"""Stage 07: deterministic weakness rules -> Finding objects.

Every finding carries evidence (what was seen), a configuration-level fix
(Postfix / Dovecot) and an indicative compliance mapping. Severities here are
*intrinsic*; Part 3 later turns them into priorities using exposure,
exploitability, asset criticality and the per-endpoint baseline.
"""
from __future__ import annotations

from typing import Optional

from .ciphers import GROUP_BITS, GROUP_NAMES, WEAK_GROUPS, profile, version_issue, version_name
from .models import ChainInfo, Finding, MailSession, TlsHandshake
from .tls import alert_name

# ------------------------------------------------------------------ compliance references (indicative)
NIST = "NIST SP 800-52 Rev. 2"
C_VERSION = [f"{NIST} §3.1 (TLS 1.2 minimum, TLS 1.3 support)", "RFC 8996 (TLS 1.0/1.1 deprecated)",
             "PCI DSS 4.0 Req. 4.2.1"]
C_CIPHER = [f"{NIST} §3.3.1 (approved cipher suites)", "PCI DSS 4.0 Req. 4.2.1", "ISO/IEC 27001:2022 A.8.24"]
C_CERT = [f"{NIST} §3.2 (server certificates)", "PCI DSS 4.0 Req. 4.2.1 (certificates valid, not expired)",
          "ISO/IEC 27001:2022 A.8.24"]
C_CRED = ["PCI DSS 4.0 Req. 8.3.2 (auth factors unreadable in transit)", "RFC 8314 §3",
          "ISO/IEC 27001:2022 A.8.5"]
C_PLAIN = ["RFC 8314 (cleartext submission/access deprecated)", "ISO/IEC 27001:2022 A.5.14",
           "ISO/IEC 27001:2022 A.8.24"]
C_STRIP = ["RFC 3207 §6", "RFC 8461 (MTA-STS)", "RFC 7672 (DANE)", "RFC 8314",
           "CERT-In Directions 28 Apr 2022 (attack on mail server: report within 6 h)"]
C_INJ = ["CVE-2011-0411 class", "Poddebniak et al., USENIX Security 2021",
         "CERT-In Directions 28 Apr 2022 (attack on mail server: report within 6 h)"]

# ------------------------------------------------------------------ remediation text
FIX = {
    "strip_relay": ("Publish an MTA-STS policy in `mode: enforce` (RFC 8461) and/or DANE TLSA records (RFC 7672) "
                    "so sending MTAs refuse to deliver without TLS. On Postfix senders use "
                    "`smtp_tls_security_level = dane` (or `encrypt`/`verify` per destination via `smtp_tls_policy_maps`). "
                    "Inspect the network path: a same-length rewrite of the capability is the signature of an inline "
                    "stripping device or compromised middlebox."),
    "strip_client": ("Move clients to implicit TLS (465 / 993 / 995, RFC 8314): there is no cleartext upgrade to strip. "
                     "Postfix submission: `smtpd_tls_security_level = encrypt`, `smtpd_tls_auth_only = yes`. "
                     "Dovecot: `ssl = required` and `disable_plaintext_auth = yes` (2.4: `auth_allow_cleartext = no`). "
                     "Set mail clients to 'TLS required', never 'STARTTLS if available'."),
    "no_tls_relay": ("Enable opportunistic TLS inbound: `smtpd_tls_security_level = may` with a valid "
                     "`smtpd_tls_chain_files`; then publish MTA-STS/DANE to make it mandatory for senders."),
    "no_tls_client": ("Enable TLS and make it mandatory: Postfix `smtpd_tls_security_level = encrypt`; Dovecot "
                      "`ssl = required`. Prefer implicit TLS ports 465/993/995 (RFC 8314) and close 110/143 to clients."),
    "client_skipped": ("Server offered STARTTLS but the client did not use it. Configure the client (or sending MTA: "
                       "`smtp_tls_security_level = may` at minimum) to always upgrade; for submission/access require TLS "
                       "server-side so the client cannot proceed in cleartext."),
    "cred": ("Refuse authentication before TLS: Postfix `smtpd_tls_auth_only = yes`; Dovecot "
             "`disable_plaintext_auth = yes` / `auth_allow_cleartext = no`. Rotate the exposed credentials listed in "
             "the evidence - they must be assumed compromised."),
    "weak_cred": ("Challenge-response over cleartext exposes an offline-crackable hash and the full session. Require "
                  "TLS before AUTH and prefer SCRAM-SHA-256 or OAUTHBEARER over TLS."),
    "data": ("Message content crossed the network unencrypted. Require TLS for this path (see transport findings) "
             "and treat the listed messages as disclosed."),
    "inject": ("Upgrade the server/client: the implementation must discard any buffered plaintext when TLS starts "
               "(CVE-2011-0411 class; 40+ implementations affected per Poddebniak et al. 2021). Check Postfix, Dovecot, "
               "Exim, Courier versions; prefer implicit TLS ports which have no upgrade step."),
    "version": ("Postfix: `smtpd_tls_protocols = >=TLSv1.2` and `smtpd_tls_mandatory_protocols = >=TLSv1.2` "
                "(same for `smtp_` on the client side). Dovecot: `ssl_min_protocol = TLSv1.2`."),
    "cipher": ("Postfix: `smtpd_tls_mandatory_ciphers = high`, `smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, RC4, "
               "3DES, MD5, DES, IDEA`, `tls_preempt_cipherlist = yes`. Dovecot: `ssl_cipher_list = "
               "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!RC4:!3DES`, `ssl_prefer_server_ciphers = yes`."),
    "fs": ("Prefer ECDHE key exchange: put ECDHE suites first and remove static-RSA suites "
           "(`smtpd_tls_exclude_ciphers = kRSA` in Postfix; `!kRSA` in Dovecot `ssl_cipher_list`)."),
    "cbc": "Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305) ahead of CBC suites, or enable TLS 1.3.",
    "dh": ("Use a 2048-bit or larger DH group (`openssl dhparam -out dh2048.pem 2048`; Postfix "
           "`smtpd_tls_dh1024_param_file = /etc/postfix/dh2048.pem`, Dovecot `ssl_dh = </etc/dovecot/dh.pem`) "
           "or drop DHE in favour of ECDHE."),
    "curve": "Restrict groups to x25519, secp256r1, secp384r1 (Postfix `tls_eecdh_auto_curves`, Dovecot `ssl_curve_list`).",
    "compression": "Disable TLS compression (Postfix `tls_ssl_options = NO_COMPRESSION`; modern OpenSSL disables it by default).",
    "reneg": "Upgrade OpenSSL / the TLS library to one supporting RFC 5746 secure renegotiation.",
    "ems": "Upgrade to a TLS library supporting RFC 7627 Extended Master Secret (OpenSSL >= 1.1.0) or enable TLS 1.3.",
    "downgrade": ("A TLS 1.3-capable server negotiated a lower version and signalled it (RFC 8446 §4.1.3). Check the "
                  "client's TLS library and any middlebox on the path; enable TLS 1.3 end to end."),
    "alert": "Review both endpoints' TLS configuration for a shared protocol/cipher/certificate the peer accepts.",
    "fallback": ("The client retried the handshake at a lower version. Make sure the server honours TLS_FALLBACK_SCSV "
                 "(RFC 7507) and investigate why the first attempt failed."),
    "client_weak": "Remove legacy suites from the client/sending MTA (`smtp_tls_exclude_ciphers`, client TLS settings).",
    "expired": ("Renew the certificate and automate renewal (ACME: certbot / acme.sh with a deploy hook running "
                "`postfix reload` and `doveadm reload`)."),
    "expiring": "Renew now and automate renewal with ACME so it cannot lapse.",
    "selfsigned": ("Replace with a certificate from a publicly trusted CA, or - for MX hosts that intentionally use a "
                   "private certificate - publish a DANE-EE TLSA record (`3 1 1`) so senders can authenticate it."),
    "hostname": "Reissue the certificate with the mail host's name (the MX / submission hostname) in subjectAltName.",
    "weak_key": "Reissue with RSA >= 2048 bits or ECDSA P-256.",
    "weak_sig": "Reissue with a SHA-256 (or stronger) signature.",
    "chain": ("Serve the full chain in order: leaf, then intermediates (Postfix `smtpd_tls_chain_files`; Dovecot "
              "`ssl_cert` containing leaf + intermediates)."),
    "untrusted": "Use a certificate chaining to a trusted root, or distribute the private CA to all clients / use DANE.",
    "leaf_ca": "Issue a dedicated end-entity certificate (BasicConstraints CA:FALSE, EKU serverAuth).",
    "overlap": ("Overlapping TCP segments carried different bytes. This is an IDS-evasion / injection technique - "
                "investigate the path and preserve this capture as evidence."),
    "tls13_cert": ("No action required: this is TLS 1.3 working as designed. To audit the certificate, probe the "
                   "endpoint actively (`openssl s_client -starttls smtp -connect host:25`) or rely on the endpoint "
                   "baseline from earlier TLS 1.2 sessions."),
    "port": ("A mail service answered on a non-standard port. Confirm it is sanctioned; if not, it is shadow "
             "infrastructure outside your TLS policy - inventory it or shut it down."),
}

PORT_CLASS = {25: "relay", 587: "submission", 465: "submission", 143: "access", 110: "access",
              993: "access", 995: "access"}


def port_class(sess: MailSession) -> str:
    return PORT_CLASS.get(sess.server[1], "nonstandard")


def _f(sess: MailSession, rule_id: str, title: str, severity: str, category: str, evidence: list[str],
       fix: str, compliance: list[str], references: Optional[list[str]] = None,
       exploitability: float = 0.5, confidence: float = 0.9) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category=category,
                   session_id=sess.session_id, endpoint=sess.endpoint, evidence=evidence,
                   remediation=FIX[fix], compliance=compliance, references=references or [],
                   exploitability=exploitability, confidence=confidence)


# ------------------------------------------------------------------ transport / STARTTLS rules

def _transport_rules(sess: MailSession) -> list[Finding]:
    out: list[Finding] = []
    pc = port_class(sess)
    client_facing = pc in ("submission", "access", "nonstandard")
    proto_up = "STLS" if sess.protocol == "POP3" else "STARTTLS"

    if sess.strip_indicators:
        out.append(_f(sess, "SMS-STRIP-001", f"{proto_up} stripping indicators", "critical", "stripping",
                      sess.strip_indicators + [f"capabilities seen: {' '.join(sess.capabilities) or '(none)'}"],
                      "strip_client" if client_facing else "strip_relay", C_STRIP,
                      ["RFC 3207 §6", "Poddebniak et al. 2021"], exploitability=0.9))

    if sess.injection_indicators:
        out.append(_f(sess, "SMS-INJ-001", f"{proto_up} command/response injection", "critical", "injection",
                      list(sess.injection_indicators), "inject", C_INJ,
                      ["CVE-2011-0411", "USENIX Security 2021: Why TLS is better without STARTTLS"],
                      exploitability=0.8))

    if not sess.tls_used and sess.mode != "implicit":
        if sess.starttls_offered is False and not sess.strip_indicators:
            sev = "high" if client_facing else "medium"
            out.append(_f(sess, "SMS-PLAIN-001", f"Server does not offer {proto_up}", sev, "plaintext",
                          [f"capabilities: {' '.join(sess.capabilities) or '(none)'}", f"port class: {pc}"],
                          "no_tls_client" if client_facing else "no_tls_relay", C_PLAIN,
                          exploitability=1.0))
        elif sess.starttls_offered and not sess.starttls_requested:
            out.append(_f(sess, "SMS-PLAIN-002", f"Client ignored offered {proto_up}", "medium", "plaintext",
                          [f"server advertised {proto_up}; client continued with "
                           f"{', '.join(sess.cleartext_commands[:6])}"],
                          "client_skipped", C_PLAIN, exploitability=1.0))
        elif sess.starttls_offered is None and sess.cleartext_commands and not sess.strip_indicators:
            out.append(_f(sess, "SMS-PLAIN-003", "Session carried in cleartext", "medium", "plaintext",
                          [f"commands: {', '.join(sess.cleartext_commands[:8])}",
                           "server TLS capability not observed"],
                          "no_tls_client" if client_facing else "no_tls_relay", C_PLAIN, exploitability=1.0))

    for ev in sess.auth_events:
        user = ev.username or "(unknown user)"
        outcome = {True: "accepted", False: "rejected", None: "outcome not observed"}[ev.accepted]
        if ev.secret_exposed:
            out.append(_f(sess, "SMS-CRED-001", "Credentials sent in cleartext", "critical", "credentials",
                          [f"{ev.mechanism} for user '{user}' ({outcome}); password/token crossed the wire unencrypted "
                           f"(secret not stored)"], "cred", C_CRED, exploitability=1.0, confidence=0.98))
        else:
            out.append(_f(sess, "SMS-CRED-002", "Challenge-response authentication in cleartext", "medium",
                          "credentials", [f"{ev.mechanism} for user '{user}' ({outcome}): offline-crackable"],
                          "weak_cred", C_CRED, exploitability=0.6))

    if sess.cleartext_message_bytes:
        sev = "high" if client_facing else "medium"
        out.append(_f(sess, "SMS-DATA-001", "Message content transmitted in cleartext", sev, "plaintext",
                      [f"{sess.cleartext_message_bytes} bytes of message data outside TLS (content not stored)"],
                      "data", C_PLAIN, exploitability=1.0))

    q = sess.stream_quality
    if q.get("overlap_conflicts"):
        out.append(_f(sess, "SMS-TCP-001", "TCP overlaps with conflicting data", "medium", "anomaly",
                      [f"{q['overlap_conflicts']} overlapping segment(s) disagreed with earlier bytes"],
                      "overlap", ["ISO/IEC 27001:2022 A.8.16 (monitoring)"], exploitability=0.5, confidence=0.7))

    if pc == "nonstandard":
        out.append(_f(sess, "SMS-PORT-001", f"{sess.protocol} on non-standard port {sess.server[1]}", "low",
                      "anomaly", [f"identified from banner: '{sess.banner[:80]}'"], "port",
                      ["ISO/IEC 27001:2022 A.5.9 (asset inventory)"], exploitability=0.3))
    return out


# ------------------------------------------------------------------ TLS rules

def _tls_rules(sess: MailSession, hs: TlsHandshake) -> list[Finding]:
    out: list[Finding] = []
    if not hs.client_hello_seen:
        return out
    fatal = [(l, d) for l, d in hs.alerts if l == 2]
    if fatal or not hs.server_hello_seen:
        names = ", ".join(alert_name(d) for _, d in fatal) or "no ServerHello"
        sev = "medium"
        if any(d == 86 for _, d in fatal):  # inappropriate_fallback: the defence fired
            names += " (TLS_FALLBACK_SCSV defence triggered: a downgrade was attempted)"
            sev = "high"
        out.append(_f(sess, "SMS-TLS-007", "TLS handshake failed", sev, "protocol",
                      [f"alerts: {names}"] + hs.errors[:3], "alert", C_VERSION, exploitability=0.3))

    if hs.server_hello_seen and hs.version is not None:
        vi = version_issue(hs.version)
        if vi:
            out.append(_f(sess, "SMS-TLS-001", f"Obsolete protocol {hs.version_name}", vi[0], "protocol",
                          [f"negotiated {hs.version_name} (ServerHello legacy_version 0x{hs.server_legacy_version or 0:04x}"
                           f"{', supported_versions ext' if 43 in hs.server_extensions else ''})", vi[1]],
                          "version", C_VERSION, ["RFC 8996", "POODLE", "BEAST"], exploitability=0.5))

    if hs.cipher_suite is not None:
        p = profile(hs.cipher_suite)
        broken = [w for w in p.weaknesses if w[0] in ("anonymous", "export-grade", "null-cipher", "rc4", "64-bit-block", "md5-mac")]
        if broken:
            sev = "critical" if any(w[0] in ("anonymous", "export-grade", "null-cipher") for w in broken) else "high"
            out.append(_f(sess, "SMS-TLS-002", f"Weak cipher suite {p.name}", sev, "cipher",
                          [f"negotiated 0x{p.code:04X} {p.name} (grade {p.grade})"] + [w[1] for w in broken],
                          "cipher", C_CIPHER, ["RFC 7465", "Sweet32", "FREAK", "Logjam"], exploitability=0.5))
        if not p.forward_secrecy and not p.tls13 and not any(w[0] == "anonymous" for w in p.weaknesses):
            out.append(_f(sess, "SMS-TLS-003", "No forward secrecy", "medium", "cipher",
                          [f"{p.name} uses {p.kx} key transport",
                           "all recorded sessions become decryptable if the server private key is ever exposed"],
                          "fs", C_CIPHER, ["ROBOT", "DROWN"], exploitability=0.4))
        if "CBC" in p.enc and not broken:
            out.append(_f(sess, "SMS-TLS-004", "CBC-mode cipher negotiated", "low", "cipher",
                          [f"{p.name}: MAC-then-encrypt"], "cbc", C_CIPHER, ["Lucky13", "BEAST"],
                          exploitability=0.3))

    if hs.dh_bits:
        if hs.dh_bits < 2048:
            sev = "critical" if hs.dh_bits <= 768 else "high" if hs.dh_bits < 1024 + 1 else "medium"
            out.append(_f(sess, "SMS-TLS-005", f"Weak Diffie-Hellman group ({hs.dh_bits} bits)", sev, "cipher",
                          [f"ServerKeyExchange DH prime is {hs.dh_bits} bits"], "dh", C_CIPHER, ["Logjam"],
                          exploitability=0.5))
    grp = hs.ecdhe_curve or hs.selected_group
    if grp in WEAK_GROUPS:
        out.append(_f(sess, "SMS-TLS-013", f"Weak elliptic curve {GROUP_NAMES.get(grp, grp)}", "medium", "cipher",
                      [f"group {GROUP_NAMES.get(grp, grp)} ({GROUP_BITS.get(grp, '?')} bits)"], "curve", C_CIPHER,
                      exploitability=0.4))

    if hs.compression not in (None, 0):
        out.append(_f(sess, "SMS-TLS-008", "TLS compression enabled", "high", "protocol",
                      [f"compression method {hs.compression}"], "compression", C_VERSION, ["CRIME"],
                      exploitability=0.4))
    if hs.server_hello_seen and hs.secure_renegotiation is False:
        out.append(_f(sess, "SMS-TLS-009", "No secure renegotiation (RFC 5746)", "medium", "protocol",
                      ["ServerHello lacks renegotiation_info"], "reneg", C_VERSION, exploitability=0.3))
    if hs.extended_master_secret is False and hs.version == 0x0303:
        out.append(_f(sess, "SMS-TLS-012", "No Extended Master Secret", "low", "protocol",
                      ["TLS 1.2 without RFC 7627 EMS (triple-handshake class)"], "ems", C_VERSION,
                      exploitability=0.2))
    # The sentinel alone only says "this server could do TLS 1.3". It is a downgrade signal
    # when the client offered TLS 1.3 too - then something between them removed it.
    if hs.downgrade_sentinel and 0x0304 in hs.client_supported_versions:
        out.append(_f(sess, "SMS-TLS-010", "Downgrade sentinel present", "high", "protocol",
                      [f"ServerHello.random ends with DOWNGRD marker ({hs.downgrade_sentinel}) while negotiating "
                       f"{hs.version_name}", f"client offered: {', '.join(version_name(v) for v in hs.client_supported_versions) or version_name(hs.client_legacy_version)}"],
                      "downgrade", C_VERSION, ["RFC 8446 §4.1.3"], exploitability=0.6))
    if hs.fallback_scsv:
        out.append(_f(sess, "SMS-TLS-011", "Client fallback handshake (TLS_FALLBACK_SCSV)", "low", "protocol",
                      ["ClientHello carries TLS_FALLBACK_SCSV: this is a retry at a lower version"],
                      "fallback", C_VERSION, ["RFC 7507", "POODLE"], exploitability=0.3))
    weak_offered = sorted({profile(c).name for c in hs.client_ciphers
                           if any(w[0] in ("export-grade", "null-cipher", "anonymous", "rc4") for w in profile(c).weaknesses)})
    if weak_offered:
        out.append(_f(sess, "SMS-TLS-006", "Client offers broken cipher suites", "low", "cipher",
                      [f"offered: {', '.join(weak_offered[:6])}{' ...' if len(weak_offered) > 6 else ''}"],
                      "client_weak", C_CIPHER, exploitability=0.2))
    return out


# ------------------------------------------------------------------ certificate rules

def _cert_rules(sess: MailSession, chain: ChainInfo, hs: Optional[TlsHandshake]) -> list[Finding]:
    out: list[Finding] = []
    if not chain.present:
        if hs is not None and hs.version == 0x0304:
            out.append(_f(sess, "SMS-CERT-010", "Certificate not observable (TLS 1.3)", "info", "certificate",
                          [chain.reason_absent or ""], "tls13_cert", [], exploitability=0.0, confidence=1.0))
        return out
    leaf = chain.leaf
    assert leaf is not None
    if chain.expired:
        out.append(_f(sess, "SMS-CERT-001", "Certificate expired", "high", "certificate",
                      [f"notAfter {leaf.not_after} ({-chain.days_to_expiry} days before capture)", leaf.subject],
                      "expired", C_CERT, exploitability=0.6))
    elif chain.not_yet_valid:
        out.append(_f(sess, "SMS-CERT-001", "Certificate not yet valid", "high", "certificate",
                      [f"notBefore {leaf.not_before}"], "expired", C_CERT, exploitability=0.6))
    elif chain.days_to_expiry is not None and chain.days_to_expiry < 30:
        out.append(_f(sess, "SMS-CERT-009", "Certificate expires within 30 days", "low", "certificate",
                      [f"notAfter {leaf.not_after} ({chain.days_to_expiry} days left at capture time)"],
                      "expiring", C_CERT, exploitability=0.1))
    if chain.self_signed:
        sev = "medium" if port_class(sess) == "relay" else "high"
        out.append(_f(sess, "SMS-CERT-002", "Self-signed certificate", sev, "certificate",
                      [f"subject = issuer = {leaf.subject}", f"sha256 {leaf.sha256[:32]}..."],
                      "selfsigned", C_CERT, exploitability=0.7))
    if chain.hostname_match is False:
        out.append(_f(sess, "SMS-CERT-003", "Certificate hostname mismatch", "high", "certificate",
                      [f"expected '{chain.hostname}'", f"certificate names: {', '.join(leaf.sans) or leaf.subject}"],
                      "hostname", C_CERT, ["RFC 6125"], exploitability=0.7))
    weak_key = (leaf.key_type in ("RSA", "DSA") and leaf.key_bits < 2048) or \
               (leaf.key_type.startswith("EC-") and leaf.key_bits < 256)
    if weak_key:
        out.append(_f(sess, "SMS-CERT-004", f"Weak certificate key ({leaf.key_type} {leaf.key_bits})", "high",
                      "certificate", [f"{leaf.key_type} {leaf.key_bits}-bit public key"], "weak_key", C_CERT,
                      exploitability=0.5))
    weak_sigs = [(i, c) for i, c in enumerate(chain.certs) if (c.signature_hash or "").lower() in ("md5", "sha1")
                 and not (c.self_signed and i > 0)]   # a root's self-signature is not relied upon
    if weak_sigs:
        out.append(_f(sess, "SMS-CERT-005", "Weak certificate signature hash", "high", "certificate",
                      [f"cert #{i} ({c.subject}) signed with {c.signature_hash.upper()}" for i, c in weak_sigs],
                      "weak_sig", C_CERT, ["SHAttered"], exploitability=0.4))
    if chain.chain_links_ok is False:
        out.append(_f(sess, "SMS-CERT-006", "Broken or mis-ordered certificate chain", "medium", "certificate",
                      chain.issues[:3], "chain", C_CERT, exploitability=0.3))
    if chain.trusted is False and not chain.self_signed:
        out.append(_f(sess, "SMS-CERT-007", "Certificate does not chain to a trusted root", "medium", "certificate",
                      [chain.trust_detail or "path validation failed", f"issuer: {leaf.issuer}"], "untrusted",
                      C_CERT, exploitability=0.6))
    if leaf.is_ca or leaf.eku_server_auth is False:
        why = "leaf has BasicConstraints CA:TRUE" if leaf.is_ca else "leaf EKU lacks serverAuth"
        out.append(_f(sess, "SMS-CERT-008", "Certificate usage constraints wrong", "low", "certificate",
                      [why], "leaf_ca", C_CERT, exploitability=0.2))
    return out


def evaluate(sess: MailSession, hs: Optional[TlsHandshake], chain: Optional[ChainInfo]) -> list[Finding]:
    findings = _transport_rules(sess)
    if hs is not None:
        findings += _tls_rules(sess, hs)
    if chain is not None:
        findings += _cert_rules(sess, chain, hs)
    return findings


# ------------------------------------------------------------------ catalogue (used by docs and the report legend)
CATALOG = {
    "SMS-STRIP-001": ("STARTTLS stripping indicators", "critical"),
    "SMS-INJ-001": ("STARTTLS command/response injection", "critical"),
    "SMS-PLAIN-001": ("Server does not offer STARTTLS", "high / medium on relay"),
    "SMS-PLAIN-002": ("Client ignored offered STARTTLS", "medium"),
    "SMS-PLAIN-003": ("Session carried in cleartext", "medium"),
    "SMS-CRED-001": ("Credentials sent in cleartext", "critical"),
    "SMS-CRED-002": ("Challenge-response authentication in cleartext", "medium"),
    "SMS-DATA-001": ("Message content transmitted in cleartext", "high / medium on relay"),
    "SMS-TCP-001": ("TCP overlaps with conflicting data", "medium"),
    "SMS-PORT-001": ("Mail service on non-standard port", "low"),
    "SMS-TLS-001": ("Obsolete protocol version", "critical (SSL) / high (TLS 1.0/1.1)"),
    "SMS-TLS-002": ("Weak cipher suite", "critical / high"),
    "SMS-TLS-003": ("No forward secrecy", "medium"),
    "SMS-TLS-004": ("CBC-mode cipher negotiated", "low"),
    "SMS-TLS-005": ("Weak Diffie-Hellman group", "critical / high / medium"),
    "SMS-TLS-006": ("Client offers broken cipher suites", "low"),
    "SMS-TLS-007": ("TLS handshake failed", "medium / high"),
    "SMS-TLS-008": ("TLS compression enabled", "high"),
    "SMS-TLS-009": ("No secure renegotiation", "medium"),
    "SMS-TLS-010": ("Downgrade sentinel present", "high"),
    "SMS-TLS-011": ("Client fallback handshake", "low"),
    "SMS-TLS-012": ("No Extended Master Secret", "low"),
    "SMS-TLS-013": ("Weak elliptic curve", "medium"),
    "SMS-CERT-001": ("Certificate expired / not yet valid", "high"),
    "SMS-CERT-002": ("Self-signed certificate", "high / medium on relay"),
    "SMS-CERT-003": ("Certificate hostname mismatch", "high"),
    "SMS-CERT-004": ("Weak certificate key", "high"),
    "SMS-CERT-005": ("Weak certificate signature hash", "high"),
    "SMS-CERT-006": ("Broken or mis-ordered chain", "medium"),
    "SMS-CERT-007": ("Certificate does not chain to a trusted root", "medium"),
    "SMS-CERT-008": ("Certificate usage constraints wrong", "low"),
    "SMS-CERT-009": ("Certificate expires within 30 days", "low"),
    "SMS-CERT-010": ("Certificate not observable (TLS 1.3)", "info"),
    "SMS-BASE-001": ("STARTTLS vanished versus endpoint baseline (possible active MITM)", "critical"),
    "SMS-BASE-002": ("Certificate changed versus endpoint baseline (possible MITM)", "critical"),
    "SMS-BASE-003": ("Protocol/cipher downgrade versus endpoint baseline", "high"),
    "SMS-BASE-004": ("New server TLS fingerprint (JA3S) for endpoint", "low"),
    "SMS-ML-001": ("Statistical outlier session (isolation forest)", "medium"),
}
