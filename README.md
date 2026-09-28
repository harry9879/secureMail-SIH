# SecureMailScope

**Passive email transport-security analysis from packet captures.**

Give SecureMailScope a `.pcap` or `.pcapng` and it reconstructs every SMTP, IMAP and POP3
conversation in it, then answers the questions a mail-security analyst actually has:

- Was TLS used at all, or did mail and passwords cross the network in cleartext?
- Was the STARTTLS upgrade **stripped** by someone in the path, or were commands
  **injected** around it?
- How strong was the TLS that was negotiated: protocol version, cipher suite, key exchange, certificate?
- Does this session look like the endpoint's normal behaviour, or is it a **possible active MITM**?

It produces a ranked findings list, each finding with its evidence, a Postfix/Dovecot fix and
a compliance mapping. It also gives a 0–100 posture score and a self-contained HTML dashboard,
plus JSON for a SIEM and an optional PDF.

It is **passive**: it never touches the network, so it can run anywhere a capture can be copied,
including an air-gapped forensic workstation. It is also **metadata-only**: passwords, tokens and
message bodies are never stored.

```
demo_enterprise.pcap  sha256:ad176de3d6e3e760...  19 mail sessions / 20 flows
Posture F (0/100)   critical 9  high 14  medium 6  low 7  info 5
    1. CRITICAL    80  Credentials sent in cleartext  [smtp.example.com:587]
    3. CRITICAL    76  STARTTLS vanished versus endpoint baseline - possible active MITM  [smtp.example.com:587]
    4. CRITICAL    76  STARTTLS stripping indicators  [smtp.example.com:587]
    5. CRITICAL    72  STARTTLS command/response injection  [smtp.example.com:587]
    8. CRITICAL    61  Certificate changed versus endpoint baseline - possible MITM  [mx.example.com:25]
    9. CRITICAL    58  Self-signed certificate (deviates from endpoint baseline: possible MITM ...)  [mx.example.com:25]
   14. HIGH        48  Certificate hostname mismatch  [203.0.113.11:465]
   15. HIGH        45  Protocol downgrade versus endpoint baseline  [smtp.example.com:587]
   ...
```

---

## Quick start

Requires Python 3.11+.

```bash
pip install -r requirements.txt
```

Generate the demo captures (real TCP/TLS bytes, a demo CA, every weakness class):

```bash
python -m securemailscope samples samples
```

Teach it what "normal" looks like from a clean week, then analyse the demo capture against that baseline:

```bash
python -m securemailscope analyze samples/healthy_baseline.pcap --trust-store samples/demo-ca.pem --baseline-db baseline.sqlite -o reports
```

```bash
python -m securemailscope analyze samples/demo_enterprise.pcap --trust-store samples/demo-ca.pem --baseline-db baseline.sqlite -o reports -f html,json,pdf
```

Open `reports/demo_enterprise.html` in a browser. Run the tests:

```bash
python -m pytest -q
```

Or use the web UI (upload a capture, get the report):

```bash
python -m securemailscope serve --trust-store samples/demo-ca.pem
```

Or use Docker (one container with the web UI on port 8000 and the samples built in):

```bash
docker build -t securemailscope . && docker run --rm -p 8000:8000 securemailscope
```

> The first analysis in a fresh environment trains the bootstrap risk model (a few seconds) and
> caches it under `~/.cache/securemailscope`. On Windows, importing scikit-learn can itself take
> around 10 s the first time. The analysis stages take well under a second for the demo capture.

## Commands

| Command | What it does |
|---|---|
| `analyze CAPTURE... [-o DIR] [-f html,json,pdf]` | Run the full pipeline and write reports plus `audit.log` |
| `  --trust-store PEM` | Trusted roots, e.g. your private CA (default: certifi's Mozilla bundle) |
| `  --baseline-db FILE` | SQLite memory of endpoint behaviour across captures |
| `  --no-learn` | Compare against the baseline without updating it |
| `  --assets JSON` | Asset criticality weights, e.g. `{"203.0.113.11:587": 1.5}` |
| `  --no-ml`, `--contamination X` | Rules and baseline only; isolation-forest contamination override |
| `  --fail-on SEVERITY` | Exit code 2 if any finding is at least this severe (for CI and cron) |
| `samples [DIR]` | Write the demo captures and the demo CA |
| `baseline --db FILE` | Show the learned endpoint profiles |
| `train` | Rebuild the bootstrap risk model and print its hold-out metrics |
| `serve [--port 8000]` | Web UI and `POST /api/analyze` JSON API |

## What it detects

| Class | Examples | Rules |
|---|---|---|
| STARTTLS stripping | capability rewritten to `XXXXXXXX`, `454 TLS not available`, upgrade accepted but no TLS | `SMS-STRIP-001` |
| STARTTLS injection | cleartext pipelined after `STARTTLS` (client) or after `220 Ready` (server) | `SMS-INJ-001` |
| Cleartext exposure | `AUTH LOGIN`/`PLAIN`, IMAP `LOGIN`, POP3 `USER/PASS`, message bodies | `SMS-CRED-*`, `SMS-DATA-001`, `SMS-PLAIN-*` |
| Protocol / cipher | SSLv3–TLS 1.1, RC4/3DES/EXPORT/NULL/anon, no forward secrecy, CBC, DH < 2048, compression, downgrade sentinel | `SMS-TLS-*` |
| Certificates | expired, self-signed, wildcard/hostname mismatch, RSA < 2048, SHA-1, broken chain, untrusted | `SMS-CERT-*` |
| Endpoint baseline | STARTTLS vanished, certificate changed, version/cipher downgrade, new JA3S | `SMS-BASE-*` |
| Statistical outlier | isolation forest over session feature vectors | `SMS-ML-001` |

The full catalogue, with triggers, fixes and compliance references, is in [docs/07-rules-catalog.md](docs/07-rules-catalog.md).

## Documentation

| Doc | Read it for |
|---|---|
| [01 Overview](docs/01-overview.md) | The problem, why it isn't already solved, what the tool does and doesn't do |
| [02 Architecture](docs/02-architecture.md) | The 12-stage pipeline, module map, the frozen handoff contracts, the three-part team split |
| [03 Capture and reassembly](docs/03-capture-and-reassembly.md) | PCAP/PCAPNG, link types, IP, TCP reassembly (the hardest correctness problem) |
| [04 Mail protocols and STARTTLS](docs/04-mail-protocols-and-starttls.md) | SMTP/IMAP/POP3, the STARTTLS state machine, stripping and injection detection |
| [05 TLS](docs/05-tls.md) | Record vs handshake layers, versions, cipher grading, GREASE, JA3, downgrade defences |
| [06 Certificates](docs/06-certificates.md) | X.509 checks, RFC 6125 wildcards, chain building vs validation, what passive analysis can't see |
| [07 Rules catalogue](docs/07-rules-catalog.md) | Every rule: trigger, severity, fix, compliance mapping |
| [08 ML and baselining](docs/08-ml-and-baselining.md) | Features, bootstrap labels, gradient boosting, group-Shapley explanations, isolation forest, per-endpoint baseline |
| [09 Scoring and reports](docs/09-scoring-and-reports.md) | Severity vs priority, posture score, outputs, evidence integrity |
| [10 Lab and verification](docs/10-lab-and-verification.md) | Demo captures, the Docker lab, verifying against Wireshark/openssl |
| [11 Demo script](docs/11-demo-script.md) | A 7-minute walkthrough for judges |
| [12 Q&A prep](docs/12-qa-prep.md) | The hard questions and honest answers |
| [13 Gotchas](docs/13-gotchas.md) | The PDF's ten gotchas, and where the code and tests handle each one |

## Repository layout

```
securemailscope/
  models.py      handoff contracts (MailSession, TlsHandshake, ChainInfo, Finding)
  pcapio.py      00-01  PCAP/PCAPNG reader, link/IP/TCP walk              Part 1
  flows.py       02     TCP reassembly, client/server roles              Part 1
  mailproto.py   03-04  banner protocol ID, STARTTLS state machine       Part 1
  tls.py         05     TLS handshake parser, JA3/JA3S                    Part 2
  ciphers.py     05b    cipher suite + version grading                   Part 2
  certs.py       06     X.509 analysis (pyca/cryptography)               Part 2
  rules.py       07     findings: evidence, fix, compliance              Part 2
  features.py    08     feature vectors + explanation groups             Part 3
  baseline.py    09     per-endpoint profiles, deviations, escalation    Part 3
  ml.py          10     bootstrap risk model, explanations, isolation forest  Part 3
  scoring.py     11     prioritisation, posture score                    Part 3
  report.py      12     JSON / HTML / PDF                                Part 3
  pipeline.py           runs stages 00-12
  cli.py, server.py     command line and web UI
  samples.py            byte-accurate demo capture generator
tests/           91 tests (pytest)
lab/             Postfix+Dovecot weak lab, stripping proxy, traffic + capture script
docs/            explanation docs
```

## Status and limits

- Tested: 91 automated tests. The whole pipeline runs on generated PCAP and PCAPNG captures
  (Ethernet, 802.1Q, Linux SLL, IPv6, sequence wrap, retransmission, reordering).
- The Docker lab in `lab/` is written, but it was not run in this environment because the
  Docker daemon wasn't running. Its stripping proxy logic is unit-tested.
- Passive analysis cannot see certificates inside TLS 1.3, check revocation, or reassemble
  IP fragments. Each of these is reported as "unknown", never as "fine". See [docs/01-overview.md](docs/01-overview.md#limits).
