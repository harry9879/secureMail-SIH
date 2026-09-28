# 11 · Demo script (about 7 minutes)

> **Web version:** `python -m securemailscope serve`, open http://127.0.0.1:8000 and click **Run the built-in demo capture**. Let the wire replay play, since the red links are the attacks. Then click S010 and step through its handshake replay: the `STARTTLS` → `XXXXXXXX` morph at the network path is the moment to pause on. Then S012, where the certificate is swapped at the path. The CLI walkthrough below covers the same story.

Prepare beforehand, so nothing is trained or generated live:

```bash
python -m securemailscope samples samples
python -m securemailscope train
python -m securemailscope analyze samples/healthy_baseline.pcap --trust-store samples/demo-ca.pem --baseline-db baseline.sqlite -o reports -q
```

Keep a terminal and a browser side by side.

---

**1. The problem (45 s).** "Most mail still starts in cleartext and *asks* to upgrade to TLS with
STARTTLS. That request is sent before any key exists, so anyone in the path can delete it, and the
client carries on in cleartext, password included. MTA-STS, DANE and TLS-RPT declare policy; none
of them tells you what actually happened on your wire. We do, passively, from a packet capture."

**2. Run it (45 s).**

```bash
python -m securemailscope analyze samples/demo_enterprise.pcap --trust-store samples/demo-ca.pem --baseline-db baseline.sqlite -o reports -f html,json,pdf
```

Point at: 19 mail sessions out of 20 flows (the HTTPS one was ignored because the protocol is
identified by banner, not port), posture F, the ranked list, and the sub-second analysis stages.

**3. The stripping story (90 s).** Open `reports/demo_enterprise.html`, look at "Act on these first".

- *Credentials sent in cleartext*: user `ananya.sharma@example.com`, accepted by the server. "We
  know whose password to rotate, and we never stored it."
- *STARTTLS stripping indicators*: the evidence shows `XXXXXXXX`, exactly the length of `STARTTLS`.
  "Stripping devices overwrite in place so they don't have to fix TCP sequence numbers."
- *STARTTLS vanished versus endpoint baseline*: "this server offered STARTTLS in every earlier
  session. This isn't a misconfiguration; someone is in the path."

**4. The baseline differentiator (60 s).** Find the relay session with the self-signed certificate.
"On its own, a self-signed cert on port 25 is Medium; lots of MTAs do it. But this endpoint
presented the same CA-issued cert in nine clean sessions. Against the baseline it's a possible
active MITM, Critical." Point at "Escalated from medium by the endpoint baseline".

**5. Explainability (45 s).** Sessions table, click the injection session: the explanation chart
shows *command injection* carrying the whole score. Click the downgrade session: baseline deviation
plus TLS negotiation anomalies. "Exact Shapley values over feature groups. They sum to the score,
so an analyst can defend it."

**6. Depth on demand (60 s).** Click the POP3 legacy session: TLS 1.0, 3DES, RSA key transport,
1024-bit SHA-1 expired certificate. Each finding has a Postfix/Dovecot fix and a compliance mapping.
Show the SMTPS session where `*.example.com` did **not** match `mail.corp.example.com`: "a wildcard
covers one label; get that wrong and you have silent false negatives."

**7. Engineering credibility (60 s).**

- "The parser is hand-rolled `struct`, with no native dependencies, so it runs on an air-gapped box.
  It handles PCAP and PCAPNG, Ethernet, VLAN stacks, Linux cooked, IPv6, sequence wrap,
  retransmission and overlap. Here's the reassembly stats line for the chaos session."
- `python -m pytest -q`: "91 tests, including one per gotcha."
- The report footer shows the SHA-256 of the input and `audit.log`: evidence integrity.

**Close (15 s).** "Passive, so it's deployable where scanning isn't allowed. Metadata-only, so the
report can be shared. And it finds the attack class the standards can't see."
