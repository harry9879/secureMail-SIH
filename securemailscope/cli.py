"""Command-line interface.

    securemailscope analyze capture.pcap -o reports/ [--trust-store ca.pem] [--baseline-db base.sqlite]
    securemailscope samples samples/
    securemailscope baseline --db base.sqlite
    securemailscope train
    securemailscope serve --port 8000
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

from . import __version__

SEV = ["critical", "high", "medium", "low", "info"]
_COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}


def _c(text: str, sev: str, on: bool) -> str:
    return f"{_COLORS[sev]}{text}\033[0m" if on else text


def _audit(out_dir: str, entry: dict) -> None:
    """Append-only audit trail next to the reports (evidence integrity)."""
    with open(os.path.join(out_dir, "audit.log"), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def cmd_analyze(args: argparse.Namespace) -> int:
    from . import report
    from .pipeline import Options, analyze
    from .scoring import load_criticality

    opts = Options(trust_store=args.trust_store, use_default_trust=not args.no_default_trust,
                   baseline_db=args.baseline_db, learn=not args.no_learn, use_ml=not args.no_ml,
                   contamination=args.contamination, criticality=load_criticality(args.assets))
    os.makedirs(args.output, exist_ok=True)
    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    worst_rank = 99
    for path in args.pcap:
        a = analyze(path, opts)
        stem = os.path.splitext(os.path.basename(path))[0]
        written = []
        if "json" in formats:
            p = os.path.join(args.output, f"{stem}.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write(report.to_json(a))
            written.append(p)
        if "html" in formats:
            p = os.path.join(args.output, f"{stem}.html")
            with open(p, "w", encoding="utf-8") as f:
                f.write(report.to_html(a))
            written.append(p)
        if "pdf" in formats:
            p = os.path.join(args.output, f"{stem}.pdf")
            try:
                report.to_pdf(a, p)
                written.append(p)
            except RuntimeError as ex:
                print(f"  (pdf skipped: {ex})", file=sys.stderr)
        _audit(args.output, {"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                             "tool": a.meta["tool"], "input": os.path.abspath(path),
                             "sha256": a.meta["input_sha256"], "bytes": a.meta["input_bytes"],
                             "outputs": written, "posture": a.posture["score"], "counts": a.posture["counts"],
                             "options": {k: v for k, v in vars(opts).items() if k != "criticality"}})

        if not args.quiet:
            p = a.posture
            print(f"\n{a.meta['input']}  sha256:{a.meta['input_sha256'][:16]}...  "
                  f"{a.meta['mail_sessions']} mail sessions / {a.meta['flows']} flows  ({a.timings['total']:.2f}s)")
            print(f"Posture {p['grade']} ({p['score']}/100)   " +
                  "  ".join(_c(f"{s} {p['counts'][s]}", s, color) for s in SEV))
            seen = set()
            shown = 0
            for f in a.findings:
                key = (f.rule_id, f.endpoint)
                if key in seen or f.severity == "info":
                    continue
                seen.add(key)
                n = sum(1 for g in a.findings if (g.rule_id, g.endpoint) == key)
                print(f"  {f.priority:>3}. {_c(f'{f.severity.upper():<8}', f.severity, color)} {f.risk:>5.0f}  "
                      f"{f.title}  [{f.endpoint}]{f'  x{n}' if n > 1 else ''}")
                shown += 1
                if shown >= args.top:
                    break
            for w in written:
                print(f"  -> {w}")
        worst_rank = min(worst_rank, min((SEV.index(f.severity) for f in a.findings), default=99))

    if args.fail_on and worst_rank <= SEV.index(args.fail_on):
        return 2
    return 0


def cmd_samples(args: argparse.Namespace) -> int:
    from .samples import generate
    paths = generate(args.dir, seed=args.seed)
    print("Wrote:")
    for k, v in paths.items():
        print(f"  {k:<12} {v}")
    print("\nTry:\n"
          f"  python -m securemailscope analyze {paths['baseline']} --trust-store {paths['trust_store']} "
          f"--baseline-db baseline.sqlite -o reports\n"
          f"  python -m securemailscope analyze {paths['demo']} --trust-store {paths['trust_store']} "
          f"--baseline-db baseline.sqlite -o reports")
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    from .baseline import BaselineStore
    if not os.path.exists(args.db):
        print(f"no baseline database at {args.db}", file=sys.stderr)
        return 1
    store = BaselineStore(args.db)
    rows = store.summary()
    store.close()
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"{'endpoint':<30} {'sessions':>8} {'starttls':>9} {'tls':>5}  versions / certs / ja3s")
    for r in rows:
        print(f"{r['endpoint']:<30} {r['sessions']:>8} {str(r['starttls_rate']):>9} {str(r['tls_rate']):>5}  "
              f"{r['versions']} / {r['certificates']} / {r['ja3s']}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from .ml import load_model
    m = load_model(retrain=True)
    print(f"{type(m.model).__name__}: {m.trained_on}\n hold-out R2 {m.holdout_r2}, MAE {m.holdout_mae}, "
          f"explainer {m.explainer}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import create_app
    app = create_app(trust_store=args.trust_store, baseline_db=args.baseline_db)
    print(f"SecureMailScope web UI on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="securemailscope",
                                 description="Passive email transport-security analysis from packet captures.")
    ap.add_argument("--version", action="version", version=f"SecureMailScope {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyse one or more PCAP/PCAPNG files")
    a.add_argument("pcap", nargs="+")
    a.add_argument("-o", "--output", default="reports", help="output directory (default: reports)")
    a.add_argument("-f", "--format", default="html,json", help="comma list of html,json,pdf (default: html,json)")
    a.add_argument("--trust-store", help="PEM bundle of trusted roots (e.g. your private CA)")
    a.add_argument("--no-default-trust", action="store_true", help="do not fall back to certifi's Mozilla roots")
    a.add_argument("--baseline-db", help="SQLite file remembering endpoint behaviour across captures")
    a.add_argument("--no-learn", action="store_true", help="compare against the baseline but do not update it")
    a.add_argument("--no-ml", action="store_true", help="rules and baseline only")
    a.add_argument("--contamination", type=float, help="isolation forest contamination (default: adaptive)")
    a.add_argument("--assets", help='JSON asset criticality, e.g. {"203.0.113.11:587": 1.5, "default": 1.0}')
    a.add_argument("--fail-on", choices=SEV, help="exit 2 if any finding is at least this severe (for CI)")
    a.add_argument("--top", type=int, default=12, help="findings to print (default 12)")
    a.add_argument("-q", "--quiet", action="store_true")
    a.set_defaults(func=cmd_analyze)

    s = sub.add_parser("samples", help="write demo captures and a demo CA")
    s.add_argument("dir", nargs="?", default="samples")
    s.add_argument("--seed", type=int, default=2026)
    s.set_defaults(func=cmd_samples)

    b = sub.add_parser("baseline", help="show learned endpoint profiles")
    b.add_argument("--db", default="baseline.sqlite")
    b.add_argument("--json", action="store_true")
    b.set_defaults(func=cmd_baseline)

    t = sub.add_parser("train", help="rebuild the bootstrap risk model and print its hold-out metrics")
    t.set_defaults(func=cmd_train)

    w = sub.add_parser("serve", help="web UI: upload a capture, get the report")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8000)
    w.add_argument("--trust-store")
    w.add_argument("--baseline-db")
    w.set_defaults(func=cmd_serve)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
