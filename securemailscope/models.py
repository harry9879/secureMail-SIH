"""Handoff contracts between the three parts of the pipeline.

Part 1 (capture & protocol)  -> MailSession
Part 2 (crypto & rules)      -> TlsHandshake, ChainInfo, Finding
Part 3 (intelligence)        -> consumes the above, fills Finding.risk / priority

These field names are frozen: every module codes against them, so the three
parts can be built and tested independently.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")


def hostport(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.15, "info": 0.0}


# --------------------------------------------------------------------------- Part 1

@dataclass
class Packet:
    """One decoded TCP segment."""
    frame: int
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload: bytes

    @property
    def syn(self) -> bool: return bool(self.flags & 0x02)
    @property
    def ack_flag(self) -> bool: return bool(self.flags & 0x10)
    @property
    def fin(self) -> bool: return bool(self.flags & 0x01)
    @property
    def rst(self) -> bool: return bool(self.flags & 0x04)


@dataclass
class StreamStats:
    segments: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    overlaps_trimmed: int = 0
    overlap_conflicts: int = 0      # overlapping bytes that disagree (evasion signal)
    gaps: int = 0                   # missing bytes (capture loss)
    bytes: int = 0


@dataclass
class Flow:
    """A reassembled TCP conversation with the client side identified."""
    client: tuple[str, int]
    server: tuple[str, int]
    client_bytes: bytes
    server_bytes: bytes
    start_ts: float
    end_ts: float
    handshake_seen: bool
    client_stats: StreamStats
    server_stats: StreamStats
    client_role_reason: str
    frames: int = 0

    @property
    def key(self) -> str:
        return f"{self.client[0]}:{self.client[1]}->{self.server[0]}:{self.server[1]}"


@dataclass
class AuthEvent:
    """A credential exchange seen in cleartext. The secret itself is never stored."""
    mechanism: str                # LOGIN, PLAIN, USER/PASS, IMAP-LOGIN, CRAM-MD5, APOP, XOAUTH2 ...
    username: Optional[str]
    secret_exposed: bool          # True when a reusable password/token crossed the wire
    accepted: Optional[bool]      # server reply, when observable


@dataclass
class MailSession:
    session_id: str
    client: tuple[str, int]
    server: tuple[str, int]
    protocol: str                 # SMTP | IMAP | POP3 | UNKNOWN
    mode: str                     # plaintext | starttls | implicit | unknown
    start_ts: float
    end_ts: float
    banner: str = ""
    server_name: Optional[str] = None       # hostname from banner / greeting
    capabilities: list[str] = field(default_factory=list)
    starttls_offered: Optional[bool] = None
    starttls_requested: bool = False
    starttls_response: Optional[str] = None
    starttls_accepted: bool = False
    tls_client_offset: Optional[int] = None  # each direction switches at its own offset
    tls_server_offset: Optional[int] = None
    tls_client_bytes: bytes = b""
    tls_server_bytes: bytes = b""
    auth_events: list[AuthEvent] = field(default_factory=list)
    cleartext_commands: list[str] = field(default_factory=list)  # verbs only, no arguments
    cleartext_message_bytes: int = 0         # message bodies sent before/without TLS
    strip_indicators: list[str] = field(default_factory=list)
    injection_indicators: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    stream_quality: dict[str, Any] = field(default_factory=dict)

    @property
    def endpoint(self) -> str:
        return hostport(self.server_name or self.server[0], self.server[1])

    @property
    def tls_used(self) -> bool:
        return bool(self.tls_client_bytes or self.tls_server_bytes)


# --------------------------------------------------------------------------- Part 2

@dataclass
class TlsHandshake:
    complete: bool = False
    client_hello_seen: bool = False
    server_hello_seen: bool = False
    client_legacy_version: Optional[int] = None
    server_legacy_version: Optional[int] = None
    client_supported_versions: list[int] = field(default_factory=list)
    version: Optional[int] = None            # negotiated, from ext 43 when present
    version_name: str = "unknown"
    sni: Optional[str] = None
    alpn: list[str] = field(default_factory=list)
    client_ciphers: list[int] = field(default_factory=list)   # GREASE removed
    client_extensions: list[int] = field(default_factory=list)
    server_extensions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    cipher_suite: Optional[int] = None
    cipher_name: Optional[str] = None
    compression: Optional[int] = None
    selected_group: Optional[int] = None
    dh_bits: Optional[int] = None            # DHE prime size from ServerKeyExchange
    ecdhe_curve: Optional[int] = None
    fallback_scsv: bool = False
    secure_renegotiation: Optional[bool] = None
    extended_master_secret: Optional[bool] = None
    downgrade_sentinel: Optional[str] = None  # "TLS1.2" / "TLS1.1-or-below"
    hello_retry: bool = False
    certificates: list[bytes] = field(default_factory=list)   # DER, only visible <= TLS 1.2
    certificate_visible: bool = False
    alerts: list[tuple[int, int]] = field(default_factory=list)  # (level, description)
    ja3: Optional[str] = None
    ja3_string: Optional[str] = None
    ja3s: Optional[str] = None
    ja3s_string: Optional[str] = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["certificates"] = len(self.certificates)
        return d


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    key_type: str
    key_bits: int
    signature_hash: Optional[str]
    sans: list[str]
    is_ca: bool
    self_signed: bool
    sha256: str
    has_sct: bool
    eku_server_auth: Optional[bool]
    key_usage: list[str] = field(default_factory=list)
    aia: list[str] = field(default_factory=list)
    crl: list[str] = field(default_factory=list)


@dataclass
class ChainInfo:
    present: bool = False
    reason_absent: Optional[str] = None
    certs: list[CertInfo] = field(default_factory=list)
    hostname: Optional[str] = None
    hostname_match: Optional[bool] = None
    expired: Optional[bool] = None
    not_yet_valid: Optional[bool] = None
    days_to_expiry: Optional[int] = None
    self_signed: Optional[bool] = None
    chain_links_ok: Optional[bool] = None     # each issuer signs the next
    trusted: Optional[bool] = None            # None = no trust store available
    trust_detail: Optional[str] = None
    revocation: str = "unknown (passive analysis cannot check CRL/OCSP)"
    issues: list[str] = field(default_factory=list)

    @property
    def leaf(self) -> Optional[CertInfo]:
        return self.certs[0] if self.certs else None


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str                 # stripping | credentials | plaintext | protocol | cipher | certificate | anomaly | injection
    session_id: Optional[str]
    endpoint: str
    evidence: list[str]
    remediation: str
    compliance: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    exploitability: float = 0.5   # 1.0 = passive observer can exploit; lower = needs active attacker / offline work
    confidence: float = 0.9
    # filled by Part 3
    risk: Optional[float] = None
    priority: Optional[int] = None
    escalated_from: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionResult:
    """Everything known about one session after Parts 1-3."""
    session: MailSession
    tls: Optional[TlsHandshake]
    chain: Optional[ChainInfo]
    findings: list[Finding] = field(default_factory=list)
    features: dict[str, float] = field(default_factory=dict)
    model_risk: Optional[float] = None
    anomaly_score: Optional[float] = None
    risk: Optional[float] = None
    explanation: list[tuple[str, float]] = field(default_factory=list)
    baseline_deviations: list[str] = field(default_factory=list)
