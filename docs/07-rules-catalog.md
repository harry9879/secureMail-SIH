# 07 · Rules catalogue (stage 07, plus baseline and ML rules)

Every finding has a stable rule ID, the **evidence** that triggered it, a **configuration-level fix**
(Postfix and Dovecot directives), **references** (the attack or RFC that justifies the severity), and
an **indicative compliance mapping**. Severity is *intrinsic*; the priority order also weighs
exposure, exploitability and asset criticality (see [09](09-scoring-and-reports.md)).

Code: [`rules.py`](../securemailscope/rules.py) (`CATALOG` and `FIX` hold the canonical text),
[`baseline.py`](../securemailscope/baseline.py), [`ml.py`](../securemailscope/ml.py).

## Transport and STARTTLS

| Rule | Severity | Triggers when | Fix (summary) |
|---|---|---|---|
| `SMS-STRIP-001` | critical | a stripping indicator: capability rewritten to the same length (`XXXXXXXX`), upgrade refused (`454`, `NO`, `-ERR`), or upgrade accepted but cleartext continued | relay: MTA-STS `mode: enforce` and/or DANE; `smtp_tls_security_level = dane/encrypt`. Clients: implicit TLS, `smtpd_tls_security_level = encrypt`, Dovecot `ssl = required`, clients set to "TLS required". Investigate the path |
| `SMS-INJ-001` | critical | cleartext bytes between the accepted upgrade and the first TLS record, from the client (command injection) or the server (response injection) | patch the implementation (CVE-2011-0411 class; Poddebniak et al. 2021); prefer implicit TLS |
| `SMS-PLAIN-001` | high (client ports) / medium (port 25) | the server's capability list has no STARTTLS/STLS, and there's no sign of stripping | enable TLS and require it; on relays enable `may`, then publish MTA-STS/DANE |
| `SMS-PLAIN-002` | medium | the server offered the upgrade and the client did not use it | fix the client or sending MTA; require TLS server-side |
| `SMS-PLAIN-003` | medium | a cleartext session where server capabilities were never observed (e.g. HELO) | as PLAIN-001 |
| `SMS-CRED-001` | critical | `AUTH PLAIN/LOGIN`, IMAP `LOGIN`, POP3 `USER/PASS`, `XOAUTH2`/`OAUTHBEARER` outside TLS | `smtpd_tls_auth_only = yes`; Dovecot `disable_plaintext_auth = yes` (2.4: `auth_allow_cleartext = no`); **rotate the listed users' credentials** |
| `SMS-CRED-002` | medium | `CRAM-MD5`, `APOP` outside TLS (offline-crackable) | require TLS before AUTH; SCRAM-SHA-256 or OAUTHBEARER over TLS |
| `SMS-DATA-001` | high (client ports) / medium (port 25) | message bodies (`DATA`, `BDAT`, IMAP `FETCH`/`APPEND` literals, POP3 `RETR`/`TOP`) outside TLS | require TLS on that path; treat the messages as disclosed |
| `SMS-TCP-001` | medium | overlapping TCP segments carried **different** bytes | investigate the path; preserve the capture (evasion/injection technique) |
| `SMS-PORT-001` | low | a mail protocol identified by banner on a non-standard port | confirm it's sanctioned; inventory it or shut it down |

## TLS protocol and cipher

| Rule | Severity | Triggers when | Why (references) |
|---|---|---|---|
| `SMS-TLS-001` | critical (SSL) / high (TLS 1.0/1.1) | negotiated version, read from extension 43 when present | POODLE, BEAST, DROWN; RFC 8996, RFC 7568 |
| `SMS-TLS-002` | critical (anon/EXPORT/NULL) / high (RC4, 3DES/DES/IDEA, MD5 MAC) | negotiated suite has a broken property | RFC 7465 (RC4), Sweet32, FREAK, Logjam |
| `SMS-TLS-003` | medium | static RSA / static (EC)DH key transport | harvest-now-decrypt-later; ROBOT, DROWN surface |
| `SMS-TLS-004` | low | CBC suite (and nothing worse) | Lucky13, BEAST |
| `SMS-TLS-005` | critical ≤768 / high ≤1024 / medium <2048 | DHE prime size from ServerKeyExchange | Logjam |
| `SMS-TLS-006` | low | the **client** offers anon/EXPORT/NULL/RC4 suites | client hygiene |
| `SMS-TLS-007` | medium, high on `inappropriate_fallback` | fatal alert, or no ServerHello | failed negotiation; fallback defence fired |
| `SMS-TLS-008` | high | TLS compression negotiated | CRIME |
| `SMS-TLS-009` | medium | TLS ≤ 1.2 without renegotiation_info | RFC 5746 |
| `SMS-TLS-010` | high | DOWNGRD sentinel in ServerHello.random **and** the client offered TLS 1.3 | RFC 8446 §4.1.3: something removed 1.3 between two 1.3 peers |
| `SMS-TLS-011` | low | TLS_FALLBACK_SCSV in the ClientHello | RFC 7507: this is a retry at a lower version |
| `SMS-TLS-012` | low | TLS 1.2 without Extended Master Secret | RFC 7627 (triple handshake) |
| `SMS-TLS-013` | medium | ECDHE on secp192r1 / secp224r1 | weak curve |

Fix text for the cipher and version rules is in `FIX` in `rules.py`. For example:
`smtpd_tls_protocols = >=TLSv1.2`, `smtpd_tls_mandatory_ciphers = high`,
`smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, RC4, 3DES, MD5, DES, IDEA`, and Dovecot
`ssl_min_protocol = TLSv1.2`, `ssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!RC4:!3DES`.

## Certificates

| Rule | Severity | Triggers when |
|---|---|---|
| `SMS-CERT-001` | high | leaf expired or not yet valid **at capture time** |
| `SMS-CERT-002` | high / medium on port 25 / **critical** when baseline-escalated | self-signed leaf |
| `SMS-CERT-003` | high | RFC 6125 hostname mismatch against SNI or banner hostname |
| `SMS-CERT-004` | high | RSA/DSA < 2048 or EC < 256 |
| `SMS-CERT-005` | high | MD5/SHA-1 signature (roots' self-signatures excepted) |
| `SMS-CERT-006` | medium | a certificate in the chain doesn't sign its predecessor |
| `SMS-CERT-007` | medium | no valid path to a trusted root (not raised for self-signed, which CERT-002 covers) |
| `SMS-CERT-008` | low | leaf has CA:TRUE or lacks serverAuth EKU |
| `SMS-CERT-009` | low | expires within 30 days of capture |
| `SMS-CERT-010` | info | TLS 1.3: the certificate is encrypted, so not observable |

## Endpoint baseline (Part 3)

These need at least 3 clean peer observations of the same endpoint (server IP:port) from this
capture (leave-one-out) and/or the SQLite history.

| Rule | Severity | Triggers when | Escalates |
|---|---|---|---|
| `SMS-BASE-001` | critical | ≥80% of peers offered or used TLS, and this session had the capability absent or stripped | STRIP-001, PLAIN-001, PLAIN-003 → critical |
| `SMS-BASE-002` | critical | a certificate fingerprint never seen for this endpoint, which is also self-signed, untrusted, or from a new issuer | CERT-002, CERT-003, CERT-007 → critical |
| `SMS-BASE-003` | high | negotiated version (or cipher grade) below what ≥80% of peers negotiated | |
| `SMS-BASE-004` | low | a JA3S never seen for this endpoint (only when nothing stronger fired) | |
| `SMS-ML-001` | medium | isolation forest flags the session's feature vector as an outlier | |

## Compliance mapping: indicative, not an audit opinion

| Theme | References used |
|---|---|
| Protocol versions | NIST SP 800-52 Rev. 2 §3.1; RFC 8996; PCI DSS 4.0 Req. 4.2.1 |
| Cipher suites | NIST SP 800-52 Rev. 2 §3.3.1; PCI DSS 4.0 Req. 4.2.1; ISO/IEC 27001:2022 A.8.24 |
| Certificates | NIST SP 800-52 Rev. 2 §3.2; PCI DSS 4.0 Req. 4.2.1 (valid, unexpired certificates); A.8.24 |
| Credentials in transit | PCI DSS 4.0 Req. 8.3.2; RFC 8314 §3; ISO/IEC 27001:2022 A.8.5 |
| Cleartext transfer | RFC 8314; ISO/IEC 27001:2022 A.5.14, A.8.24 |
| Stripping, injection, MITM anomalies | RFC 3207 §6, RFC 8461, RFC 7672; **CERT-In Directions of 28 April 2022**: attacks on mail servers are reportable incidents, within 6 hours of noticing |

## Known attacks: why severities mean something

We never implement these. We cite them as the reason a version or suite is graded weak.

| Attack | Year | Exploits | Graded via |
|---|---|---|---|
| BEAST | 2011 | predictable CBC IVs in TLS 1.0 | TLS-001, TLS-004 |
| CRIME | 2012 | TLS compression length leak | TLS-008 |
| Lucky13 | 2013 | MAC-then-encrypt CBC timing | TLS-004 |
| POODLE | 2014 | SSL 3.0 CBC padding | TLS-001 |
| FREAK | 2015 | RSA_EXPORT suites | TLS-002 |
| Logjam | 2015 | DHE_EXPORT and weak DH groups | TLS-002, TLS-005 |
| DROWN | 2016 | SSLv2 sharing an RSA key | TLS-001, TLS-003 |
| Sweet32 | 2016 | 64-bit block ciphers (3DES) | TLS-002 |
| ROBOT | 2017 | RSA PKCS#1 v1.5 key-transport oracles | TLS-003 |
| **STARTTLS stripping** | ongoing | unauthenticated upgrade offer | STRIP-001, BASE-001 |
| **STARTTLS injection** | 2011 / 2021 | buffered cleartext across the upgrade | INJ-001 |
