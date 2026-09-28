# 05 · TLS: the largest concept block (stage 05)

Code: [`tls.py`](../securemailscope/tls.py), [`ciphers.py`](../securemailscope/ciphers.py) ·
Tests: [`test_tls.py`](../tests/test_tls.py)

## 1. Two framing layers: don't conflate them

```
record layer     [type:1][version:2][length:2][fragment ...]        type 22 = handshake
handshake layer  [msg_type:1][length:3][body ...]                   1 = ClientHello, 2 = ServerHello ...
```

- One handshake **message can span several records**. A ClientHello with a large key share, or a
  Certificate message with a long chain, is fragmented across records.
- One **record can carry several messages**. A TLS 1.2 server usually sends ServerHello +
  Certificate + ServerKeyExchange + ServerHelloDone in a single record.

The classic parser bug is to parse one message per record. The right way (`read_records()` then
`split_messages()`) is to **concatenate the fragments of every handshake record first, then split
messages**. Stop at the first ChangeCipherSpec (20) or ApplicationData (23) record, because
everything after it in that direction is encrypted. The demo generator deliberately does both:
it splits a ClientHello across two records and packs four server messages into one.

## 2. ClientHello and ServerHello, field by field

```
ClientHello: legacy_version(2) random(32) session_id<0..32> cipher_suites<2..> compression<1..> extensions<..>
ServerHello: legacy_version(2) random(32) session_id<0..32> cipher_suite(2)   compression(1)    extensions<..>
```

| Extension | Id | What we use it for |
|---|---|---|
| server_name (SNI) | 0 | hostname for certificate matching |
| supported_groups | 10 | curves offered (JA3 field 4); weak curves |
| ec_point_formats | 11 | JA3 field 5 |
| signature_algorithms | 13 | recorded |
| ALPN | 16 | recorded (rare in mail) |
| extended_master_secret | 23 | missing in TLS 1.2 → `SMS-TLS-012` |
| supported_versions | 43 | **the real version** (see below) |
| key_share | 51 | selected group in TLS 1.3 |
| renegotiation_info | 0xFF01 | or SCSV `0x00FF`; missing → `SMS-TLS-009` |

## 3. The trap: `legacy_version` is not the version

For middlebox compatibility, TLS 1.3 **pins `legacy_version` to 0x0303** (which means TLS 1.2) in
both hellos. The version actually negotiated is in the ServerHello's **supported_versions
extension (43)**. A parser that reads the version field reports every TLS 1.3 session as TLS 1.2.
`test_tls13_version_comes_from_supported_versions` asserts both values.

## 4. Cipher suites: derive, don't look up

IANA names encode the properties: `TLS_<kx>_<auth>_WITH_<enc>_<mac>`.

```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    └kx──┘└au┘     └──enc────┘ └mac/prf┘
TLS_AES_128_GCM_SHA256          ← TLS 1.3: no kx/auth in the name; always (EC)DHE + certificate
```

`ciphers.py` keeps only a code → name table and **parses the name** to get key exchange,
authentication, bulk cipher, MAC, forward secrecy and AEAD. That avoids a thousand-row property
table. Grades:

| Grade | Meaning | Example |
|---|---|---|
| **A** | forward secret **and** AEAD (every TLS 1.3 suite) | `ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` |
| **B** | forward secret, CBC | `ECDHE_RSA_WITH_AES_128_CBC_SHA` |
| **C** | no forward secrecy, otherwise sound | `RSA_WITH_AES_128_GCM_SHA256` |
| **F** | broken: anon, EXPORT, NULL, RC4, 64-bit block (3DES/DES/IDEA/RC2) | `RSA_WITH_3DES_EDE_CBC_SHA` |

### Forward secrecy

With **static RSA key transport**, the client encrypts the pre-master secret to the server's
long-term RSA key. Anyone who records the traffic today and obtains that key later (a breach, a
subpoena, a future cryptanalytic break) can decrypt **every recorded session**:
*harvest now, decrypt later*. **ECDHE/DHE** derive a fresh key per session and discard it, so a
later key compromise reveals nothing about past traffic.

### AEAD vs CBC + HMAC

AES-GCM and ChaCha20-Poly1305 encrypt and authenticate in one construction. TLS's CBC suites are
**MAC-then-encrypt**: the receiver decrypts, strips padding, then checks the MAC. The timing of those
steps leaks information about the padding (the **Lucky13** padding oracle). On TLS 1.0 a predictable
IV gives **BEAST**.

## 5. Versions

| Version | Verdict | Why |
|---|---|---|
| SSL 2/3 | critical | POODLE, DROWN; prohibited (RFC 6176, RFC 7568) |
| TLS 1.0 / 1.1 | high | deprecated by RFC 8996; no AEAD suites, SHA-1/MD5 PRF, BEAST on 1.0 |
| TLS 1.2 | acceptable | if the cipher, EMS and renegotiation are right |
| TLS 1.3 | best | 1-RTT, only AEAD suites, always forward-secret, key_share in the ClientHello, encrypted certificate |

**What TLS 1.3 changes for us:** everything after the ServerHello is encrypted, **including the
Certificate**. Passive X.509 extraction is impossible *by design*, so a pipeline must never assume
a certificate is present. We report it as `SMS-CERT-010` (info, "not observable") and fall back to
the endpoint baseline from any earlier TLS 1.2 sessions.

## 6. Key exchange strength

The TLS 1.2 **ServerKeyExchange** is in cleartext. For DHE it carries the prime *p*: if its size is
under 2048 bits, the **Logjam** precomputation attack applies (`SMS-TLS-005`: ≤768 critical,
≤1024 high, otherwise medium). For ECDHE it names the curve, and curves below 256 bits are flagged
(`SMS-TLS-013`).

## 7. GREASE (RFC 8701)

Modern clients insert random reserved values (`0x0A0A`, `0x1A1A`, … `0xFAFA`: both bytes equal,
low nibble `A`) into their cipher list, extensions, groups and versions. The point is to keep
servers from ossifying on exact lists. GREASE is random **per connection**, so unless you filter it
out, the same client gets a different fingerprint every time and the anomaly baseline is worthless.
`is_grease(v)` is `(v & 0x0F0F) == 0x0A0A and high byte == low byte`.
`test_ja3_filters_grease_and_matches_manual_md5` builds two hellos with different random GREASE and
asserts they produce the same JA3.

## 8. JA3 / JA3S fingerprints

```
JA3  = MD5( SSLVersion , Ciphers , Extensions , EllipticCurves , EllipticCurvePointFormats )
JA3S = MD5( SSLVersion , Cipher  , Extensions )
       decimal values, '-' within a field, ',' between fields, GREASE removed
```

JA3 identifies the client TLS library and config; JA3S identifies the server's response to it. The
baseline uses JA3S: a new server fingerprint on an endpoint that had one stable fingerprint is
`SMS-BASE-004` (low on its own, and suppressed when a stronger deviation already explains the
session).

**JA4/JA4S** (FoxIO, 2023) are better structured: human-readable prefixes, sorted lists (robust to
Chrome's extension shuffling), with ALPN and version included. They were deferred because JA3 is
enough for per-endpoint *consistency*: we compare a server against itself, not against a threat
intel feed. Adding JA4 is a self-contained change in `tls.py`.

## 9. Downgrade defences whose absence we can detect

| Mechanism | How it works | What we flag |
|---|---|---|
| **TLS_FALLBACK_SCSV** (RFC 7507, `0x5600`) | a client retrying at a lower version includes it; a server that supports higher answers `inappropriate_fallback` | its presence in a ClientHello (`SMS-TLS-011`: this is a retry); an `inappropriate_fallback` alert (`SMS-TLS-007` high: the defence fired, so a downgrade was attempted) |
| **DOWNGRD sentinel** (RFC 8446 §4.1.3) | a TLS 1.3-capable server negotiating ≤1.2 sets the last 8 bytes of ServerHello.random to `DOWNGRD\x01` / `\x00` | sentinel present **and** the client offered TLS 1.3 → `SMS-TLS-010` (high). Something between two TLS 1.3 peers removed 1.3 |
| **Transcript hash + Finished** | tamper-evidence for the whole handshake | not flaggable passively. It's why the attacks above target the *unauthenticated* STARTTLS layer instead |
