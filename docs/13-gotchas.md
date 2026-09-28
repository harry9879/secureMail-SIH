# 13 · The ten gotchas, and where each is handled

The PDF lists ten gotchas that will bite. Each one maps to code and to a test that fails if it
regresses.

| # | Gotcha | Handled in | Guarded by |
|---|---|---|---|
| 1 | **`legacy_version` is not the version.** Read `supported_versions` (ext 43), or every TLS 1.3 session reports as 1.2 | `tls.parse_server_hello`: `version` comes from ext 43 when present | `test_tls13_version_comes_from_supported_versions` |
| 2 | **TLS 1.3 encrypts the Certificate.** Never assume a certificate is present | `tls.analyze` skips Certificate parsing for 1.3; `certs.analyze` returns `present=False` with a reason; rules emit info-level `SMS-CERT-010`; features treat a missing cert as neutral | `test_tls13_certificate_not_observable`, `test_tls13_sessions_report_certificate_unknown_not_valid` |
| 3 | **Handshake messages span records.** Concatenate the record payloads first, *then* split messages | `tls.read_records` → `tls.split_messages` | `test_handshake_message_spanning_two_records`, `test_tls12_certificate_and_ske_in_one_record` |
| 4 | **Each direction switches to TLS at a different byte offset.** Track two offsets | `MailSession.tls_client_offset` / `tls_server_offset`, set in `mailproto._switch_to_tls` | `test_smtp_starttls_each_direction_has_its_own_offset` |
| 5 | **Filter GREASE before JA3**, or fingerprints are random and the baseline is worthless | `ciphers.is_grease`, applied to ciphers, extensions, groups and versions in `tls.parse_client_hello` | `test_ja3_filters_grease_and_matches_manual_md5` (two hellos with different random GREASE give the same JA3) |
| 6 | **Sequence numbers wrap; segments retransmit and overlap.** Order by `(seq − isn) mod 2³²`, drop retransmissions, trim overlaps | `flows.reassemble` | `test_sequence_wraparound`, `test_pure_retransmission_dropped`, `test_partial_overlap_trimmed`, `test_conflicting_overlap_is_counted`, and the demo's ISN `0xFFFFFF00` and chaos sessions |
| 7 | **Never detect protocol by port.** Read the banner | `mailproto.identify` | `test_protocol_by_banner_not_port` (SMTP on port 110), the 2525 shadow-relay scenario, HTTPS on 443 ignored |
| 8 | **numpy scalars aren't JSON-serialisable.** `np.bool_` is rejected | `report._json_default` coerces with `.item()` | `test_json_handles_numpy_scalars`, `test_json_is_serialisable_and_privacy_preserving` |
| 9 | **Wildcards cover one label only.** Getting it wrong gives silent false negatives | `certs._dns_match` | `test_rfc6125_wildcards`, plus the demo's `mail.corp.example.com` vs `*.example.com` session |
| 10 | **Verify every sample against Wireshark.** It's the only cheap oracle | the generator writes standard PCAP/PCAPNG with valid checksums; [10](10-lab-and-verification.md) lists the tshark cross-checks | manual |

## Traps found while building this implementation

| Trap | What happened | Fix |
|---|---|---|
| **pyca refuses SHA-1** | cryptography 50 won't *create* SHA-1 signatures, so the demo's weak cert silently came out as SHA-256. It also won't *verify* them, which would mark every SHA-1 self-signed cert as "not self-signed" | generator: sign with SHA-256, swap the same-length OID, re-sign the TBS with SHA-1. Analyser: `_signed_by` returns `None` ("can't tell") for unsupported algorithms |
| **Trust and hostname conflated** | verifying the path against the SNI name made a name mismatch *also* show as "untrusted" | path validation uses a name the leaf carries; hostname is judged separately |
| **Downgrade sentinel false positives** | every TLS 1.3-capable server marks *any* ≤1.2 handshake, including ones with old clients | flag only when the client also offered TLS 1.3 |
| **"Client skipped STARTTLS" looked like MITM** | the first baseline version treated any cleartext on a TLS endpoint as stripping | require the capability to be absent or stripped, not merely unused |
| **Baseline poisoning** | a self-signed MITM session is "only high" before the baseline runs, so it was learned as clean | cleanliness is re-judged after escalation; sessions with critical or high findings or any deviation are never learned |
| **Explanations at saturation** | single-feature occlusion reads 0 for everything once the score is pinned at 100, and correlated "no TLS" columns blamed each other | exact Shapley over analyst-meaningful feature groups |
| **scikit-learn import time on Windows** | about 10 s cold, versus about 0.1 s of actual parsing | the web server keeps one process warm; the model is trained once and cached |
