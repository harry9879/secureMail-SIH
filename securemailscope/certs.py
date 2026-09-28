"""Stage 06: X.509 certificate analysis with pyca/cryptography.

A *presented* chain is not a *verified* chain. We check, separately:
  * per-certificate hygiene   key size, signature hash, validity, extensions
  * hostname                  RFC 6125 - a wildcard covers exactly one label
  * chain links               does each certificate actually sign the previous one
  * trust                     path validation to a root store (certifi / --trust-store)
  * revocation                reported as *unknown*: passive analysis cannot query CRL/OCSP

Validity is judged at the capture time, not at analysis time: an analyst replaying
a two-year-old capture needs to know whether the cert was valid *then*.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import warnings
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .models import CertInfo, ChainInfo, TlsHandshake

_TRUST_CACHE: dict[str, list[x509.Certificate]] = {}


def load_trust_store(path: Optional[str] = None) -> list[x509.Certificate]:
    """Load a PEM bundle; default to certifi's Mozilla bundle when installed."""
    if path is None:
        try:
            import certifi  # optional
            path = certifi.where()
        except ImportError:
            return []
    if path not in _TRUST_CACHE:
        with open(path, "rb") as f, warnings.catch_warnings():
            warnings.simplefilter("ignore")   # a few long-lived roots carry non-RFC-5280 serials
            _TRUST_CACHE[path] = x509.load_pem_x509_certificates(f.read())
    return _TRUST_CACHE[path]


def _name(n: x509.Name) -> str:
    return n.rfc4514_string() or "(empty)"


def _key(cert: x509.Certificate) -> tuple[str, int]:
    k = cert.public_key()
    if isinstance(k, rsa.RSAPublicKey):
        return "RSA", k.key_size
    if isinstance(k, ec.EllipticCurvePublicKey):
        return f"EC-{k.curve.name}", k.curve.key_size
    if isinstance(k, dsa.DSAPublicKey):
        return "DSA", k.key_size
    if isinstance(k, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(k, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(k).__name__, 0


def _ext(cert: x509.Certificate, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def _signed_by(child: x509.Certificate, parent: x509.Certificate) -> Optional[bool]:
    """True/False, or None when the library will not verify the algorithm (e.g. SHA-1, MD5)."""
    try:
        child.verify_directly_issued_by(parent)
        return True
    except ValueError as e:
        if "Unsupported signature algorithm" in str(e) or "unsupported" in str(e).lower():
            return None
        return False
    except Exception:
        return False


def cert_info(cert: x509.Certificate) -> CertInfo:
    key_type, bits = _key(cert)
    san = _ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    sans = []
    if san is not None:
        sans = [f"DNS:{n}" for n in san.get_values_for_type(x509.DNSName)]
        sans += [f"IP:{n}" for n in san.get_values_for_type(x509.IPAddress)]
    bc = _ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    ku = _ext(cert, ExtensionOID.KEY_USAGE)
    ku_list = []
    if ku is not None:
        for attr in ("digital_signature", "key_encipherment", "key_agreement", "key_cert_sign", "crl_sign"):
            if getattr(ku, attr):
                ku_list.append(attr)
    eku = _ext(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    aia = _ext(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    crl = _ext(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    scts = _ext(cert, ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
    self_issued = cert.subject == cert.issuer
    return CertInfo(
        subject=_name(cert.subject), issuer=_name(cert.issuer), serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc.isoformat(), not_after=cert.not_valid_after_utc.isoformat(),
        key_type=key_type, key_bits=bits,
        signature_hash=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        sans=sans, is_ca=bool(bc and bc.ca),
        self_signed=self_issued and _signed_by(cert, cert) is not False,
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
        has_sct=scts is not None,
        eku_server_auth=None if eku is None else ExtendedKeyUsageOID.SERVER_AUTH in eku,
        key_usage=ku_list,
        aia=[d.access_location.value for d in aia] if aia else [],
        crl=[n.value for dp in crl for n in (dp.full_name or [])] if crl else [],
    )


def hostname_matches(hostname: str, cert: x509.Certificate) -> bool:
    """RFC 6125 matching. `*.a.com` matches `x.a.com`, not `x.y.a.com` and not `a.com`."""
    host = hostname.lower().rstrip(".")
    san = _ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if san is not None:
        if ip is not None:
            return ip in san.get_values_for_type(x509.IPAddress)
        names = san.get_values_for_type(x509.DNSName)
    else:
        # legacy fallback to CN only when no SAN is present
        names = [a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
    return any(_dns_match(host, str(n).lower().rstrip(".")) for n in names)


def _dns_match(host: str, pattern: str) -> bool:
    if "*" not in pattern:
        return host == pattern
    p_labels, h_labels = pattern.split("."), host.split(".")
    if len(p_labels) != len(h_labels) or p_labels[0] != "*" or len(p_labels) < 3:
        return False   # wildcard must be the whole left-most label, and cover exactly one label
    return p_labels[1:] == h_labels[1:]


def _verify_path(chain: list[x509.Certificate], roots: list[x509.Certificate], hostname: Optional[str],
                 when: dt.datetime) -> tuple[Optional[bool], str]:
    if not roots:
        return None, "no trust store available"
    try:
        from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
    except ImportError:
        return None, "cryptography too old for path validation"
    # Hostname is judged separately (hostname_match), so verify the path against a
    # name the leaf does carry; otherwise a name mismatch would masquerade as "untrusted".
    leaf = chain[0]
    subject = hostname if hostname and hostname_matches(hostname, leaf) else None
    if subject is None:
        san = _ext(leaf, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names = san.get_values_for_type(x509.DNSName) if san is not None else []
        subject = next((n for n in names if "*" not in n), None) or \
            (names[0].replace("*", "wildcard", 1) if names else None)
    if subject is None:
        return None, "leaf has no DNS subjectAltName; path validation skipped"
    builder = PolicyBuilder().store(Store(roots)).time(when)
    try:
        builder.build_server_verifier(x509.DNSName(subject)).verify(leaf, chain[1:])
        return True, "chains to a trusted root"
    except VerificationError as e:
        return False, str(e)
    except Exception as e:  # unsupported algorithms etc.
        return None, f"validation not possible: {e}"


def analyze(hs: Optional[TlsHandshake], hostname: Optional[str], capture_time: float,
            trust_store: Optional[str] = None, use_default_trust: bool = True) -> ChainInfo:
    info = ChainInfo()
    if hs is None or not hs.client_hello_seen:
        info.reason_absent = "no TLS handshake in this session"
        return info
    if hs.version == 0x0304:
        info.reason_absent = "TLS 1.3 encrypts the Certificate message; not observable passively"
        return info
    if not hs.certificates:
        info.reason_absent = "Certificate message not captured"
        return info

    certs: list[x509.Certificate] = []
    for der in hs.certificates:
        try:
            certs.append(x509.load_der_x509_certificate(der))
        except ValueError as e:
            info.issues.append(f"unparseable certificate: {e}")
    if not certs:
        info.reason_absent = "certificates present but unparseable"
        return info

    info.present = True
    info.certs = [cert_info(c) for c in certs]
    leaf = certs[0]
    when = dt.datetime.fromtimestamp(capture_time or dt.datetime.now(dt.timezone.utc).timestamp(), dt.timezone.utc)
    info.expired = when > leaf.not_valid_after_utc
    info.not_yet_valid = when < leaf.not_valid_before_utc
    info.days_to_expiry = (leaf.not_valid_after_utc - when).days
    info.self_signed = info.certs[0].self_signed
    links = [_signed_by(certs[i], certs[i + 1]) for i in range(len(certs) - 1)]
    info.chain_links_ok = all(l is not False for l in links) if links else None
    if None in links:
        info.issues.append("a chain signature uses an algorithm too weak for the library to verify")
    if len(certs) > 1 and not info.chain_links_ok:
        info.issues.append("presented chain is out of order or contains a certificate that does not sign its predecessor")

    info.hostname = hostname
    if hostname:
        info.hostname_match = hostname_matches(hostname, leaf)

    roots = load_trust_store(trust_store) if (trust_store or use_default_trust) else []
    if info.self_signed:
        info.trusted, info.trust_detail = False, "self-signed leaf certificate"
    else:
        info.trusted, info.trust_detail = _verify_path(certs, roots, hostname, when)
    return info
