# 06 · Certificates and PKI (stage 06)

Code: [`certs.py`](../securemailscope/certs.py) · Tests: [`test_certs.py`](../tests/test_certs.py)

Certificates are only visible in TLS ≤ 1.2, in the cleartext `Certificate` handshake message: a
list of DER blobs, leaf first. We never hand-parse ASN.1. pyca/cryptography's
`load_der_x509_certificate` does that, but the mental model helps: DER is tag-length-value, a
certificate is `SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`, and everything we
read lives in `tbsCertificate`.

## What is checked, and why

| Check | Rule | Detail |
|---|---|---|
| Validity window | `SMS-CERT-001` / `009` | judged at **capture time**, not "now". A two-year-old capture is judged as of the day it was taken |
| Self-signed | `SMS-CERT-002` | subject == issuer **and** the signature verifies with its own key. Medium on the relay port (common, and DANE can pin it), high elsewhere, **critical** if the endpoint baseline shows a different cert before |
| Hostname | `SMS-CERT-003` | RFC 6125 against SNI, else the banner hostname. SAN first; CN only if there is no SAN |
| Key size | `SMS-CERT-004` | RSA/DSA < 2048, EC < 256 |
| Signature hash | `SMS-CERT-005` | MD5 or SHA-1 anywhere in the chain except a root's self-signature, which nobody relies on |
| Chain links | `SMS-CERT-006` | each certificate must actually sign its predecessor (`verify_directly_issued_by`) |
| Trust | `SMS-CERT-007` | path validation to a root store, see below |
| Usage | `SMS-CERT-008` | leaf with `CA:TRUE`, or an EKU without `serverAuth` |
| Revocation | (never a finding) | always **"unknown"**: passive analysis cannot query CRL/OCSP, and an OCSP staple is inside the handshake we can see only in TLS 1.2 |

## RFC 6125 wildcards: one label, exactly

```
*.example.com   matches   smtp.example.com
*.example.com   DOES NOT match   mail.corp.example.com     (two labels)
*.example.com   DOES NOT match   example.com               (zero labels)
*.com           never matches                               (wildcard directly under a TLD-like label)
```

Getting this wrong produces **silent false negatives**, which is the worst kind of bug in a security
tool. The demo capture includes a session to `mail.corp.example.com` served a `*.example.com`
certificate. It must raise `SMS-CERT-003`, and `test_rfc6125_wildcards` pins each case.

## A presented chain is not a verified chain

The server sends whatever it likes. We check two things separately:

1. **Chain links:** does certificate *n+1* actually sign certificate *n*? A mis-ordered or
   mismatched bundle is `SMS-CERT-006`.
2. **Trust:** is there a valid path from the leaf to a root we trust? This uses
   `cryptography.x509.verification` (`PolicyBuilder` + `Store`) at the capture time.

The trust verdict must not be contaminated by the hostname verdict. If we verified against the
wrong hostname, a name mismatch would show up as "untrusted" too, doubling one problem into two
findings. So path validation uses a name the leaf *does* carry, and hostname is judged separately.
`test_self_signed_and_wildcard_mismatch` asserts that a mismatched-but-properly-issued certificate
is `hostname_match=False` **and** `trusted=True`.

**Trust stores:** `--trust-store your-ca.pem` for an enterprise private CA; otherwise certifi's
Mozilla bundle when installed. The demo uses its own CA (`samples/demo-ca.pem`), which is exactly
the private-CA case.

## Algorithms the library refuses

Modern pyca refuses both to **create** and to **verify** SHA-1 signatures. The verification side
matters here: `_signed_by()` returns `None` ("can't tell") instead of `False` for an unsupported
algorithm. Otherwise every SHA-1 self-signed certificate would be misreported as "not self-signed"
and every SHA-1 chain as "broken". The weak-signature finding (`SMS-CERT-005`) reports the real
problem.

(For the demo's deliberately weak legacy certificate, `samples.py` signs with SHA-256, swaps the
same-length signature-algorithm OID for SHA-1's, and re-signs the patched TBS bytes with SHA-1
through the raw RSA API. The result is a genuine SHA-1 certificate that Wireshark and OpenSSL
parse normally.)

## Certificate Transparency

`CertInfo.has_sct` records whether the leaf embeds Signed Certificate Timestamps. Publicly trusted
certificates have had to carry SCTs since 2018, so a supposedly public certificate with none is a
mis-issuance signal. Private-CA certificates legitimately have none, which is why this is recorded
rather than graded.
