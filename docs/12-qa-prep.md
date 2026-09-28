# 12 · Q&A preparation

Short, honest answers to the questions you will be asked.

### "Why isn't this already solved? What about MTA-STS / DANE?"
They declare policy for **relay-to-relay** mail, and only help senders that implement them.
TLS-RPT is delayed, aggregated self-reporting by *remote* senders. None of them looks at client
traffic (587/143/110), and none measures what was actually negotiated. SPF/DKIM/DMARC authenticate
the *message*, not the *channel*. See [01](01-overview.md).

### "Why is STARTTLS strippable when TLS isn't?"
TLS hashes the whole handshake into a transcript that the `Finished` messages authenticate under
the new keys, so tampering with any hello is detected. The STARTTLS offer happens before any key
exists and is outside that transcript, so nothing can authenticate it. This is **the single best
answer under questioning**; know it cold.

### "How do you detect stripping without seeing the original server response?"
Three kinds of positive evidence in one session: a same-length rewrite of the capability, a refused
upgrade, or an accepted upgrade with no TLS after it. Plus the strongest one across sessions: the
**endpoint baseline** shows this server offered STARTTLS before and doesn't now. A server that never
offered TLS is reported as a configuration issue, not as stripping.

### "Your ML is trained on labels from your own rules. Isn't that circular?"
Yes, and we say so. No labelled public corpus exists, so the rules engine bootstraps the labels.
The model still earns its place: smooth scores for unseen combinations, exact per-group
explanations, and a retraining slot for analyst-labelled captures. The genuinely data-driven parts
don't depend on labels at all: the **per-endpoint baseline** and the **isolation forest**.

### "Why gradient-boosted trees and not deep learning?"
Tabular mixed-type features, thousands of rows not millions, and every score must be explainable.
Trees handle all three natively and train in seconds. See [08](08-ml-and-baselining.md).

### "Why isolation forest? What about One-Class SVM or autoencoders?"
Isolation forest needs no feature scaling, is fast, and works with little data. We make its
contamination adaptive, because a fixed 10% on a 19-session capture forces false positives.
One-Class SVM is scaling and kernel sensitive; autoencoders need far more data and are hard to
explain.

### "How do you avoid alert fatigue?"
Positive evidence for critical findings; separate severities for configuration versus client versus
attack; the downgrade sentinel only when both sides offered TLS 1.3; ML outliers as medium,
low-confidence leads; unknowns reported as unknown. Ranking is by risk × exposure ×
exploitability × asset criticality, not by severity alone.

### "What can't you see?"
Certificates inside TLS 1.3 (encrypted by design), revocation status (needs network queries),
IP-fragmented segments (counted and skipped), and anything after the handshake. Each is reported as
**unknown**, never as fine.

### "Isn't reading passwords a privacy problem?"
We must parse them to *recognise* them, but we keep only the mechanism, the username and whether
the server accepted it. A test checks that the demo passwords (raw and base64) never appear in the
JSON output.

### "Why passive instead of scanning?"
Scanning shows what a server *could* negotiate; the wire shows what clients *did* negotiate,
including stripping, injection and which users leaked passwords. And analysing your own SOC's
capture needs no scanning authorisation.

### "Why not Scapy / pyshark / Zeek?"
Scapy is slow, needs Npcap and admin rights, and its TLS dissector isn't reliable for handshake
detail. pyshark drags in tshark. Hand-rolled `struct` parsing has zero native dependencies and full
control of the reassembly edge cases, and speed was never the bottleneck. Zeek was the documented
fallback if time ran short.

### "Why JA3 and not JA4?"
We compare an endpoint with **itself**, so JA3's job is consistency, and with GREASE filtered it's
stable. JA4 is better structured and robust to extension shuffling; it's a contained addition in
`tls.py`.

### "How does it scale?"
The analysis stages are linear in the number of packets; the demo's 687 frames parse in
milliseconds. For large captures the first steps would be streaming the reader instead of holding
every packet, and sharding by flow. The ML is per-session and tiny.

### "What stops an attacker poisoning the baseline?"
Endpoints are keyed by IP:port (the banner is attacker-controlled). Within a capture the comparison
is leave-one-out. Only sessions with no critical or high findings and no deviations are ever learned
into the database.

### "How do you know the parser is right?"
91 automated tests, including one for each of the ten gotchas. The demo captures are generated
byte-accurately so they open in Wireshark, and [10](10-lab-and-verification.md) lists the tshark
commands that cross-check versions, ciphers and JA3 against our output.
