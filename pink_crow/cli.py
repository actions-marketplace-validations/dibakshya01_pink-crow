"""pink-crow command-line interface.

    pink-crow scan [FILE|-] [--input|--output] [--format text|json|sarif] [--fail-on N] [--profile P]
    pink-crow redteam DIR  [--format text|json|sarif] [--fail-on N] [--profile P] [--glob PAT]
    pink-crow rules        [--format text|json]
    pink-crow serve        [--host H] [--port P]
    pink-crow version

Exit code is non-zero when a scanned event's score reaches ``--fail-on`` (default 60), so it works as a
CI gate.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from . import __version__
from .catalog import catalog
from .config import PROFILES
from .engine import Engine
from .models import ScanResult
from .sarif import to_sarif

_TEXT_EXT = {".txt", ".md", ".json", ".jsonl", ".yaml", ".yml", ".py", ".js", ".ts", ".csv", ".prompt", ".tmpl", ""}
_REDTEAM_MAX_BYTES = 4 * 1024 * 1024  # skip files larger than 4 MB (don't read a huge file whole)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return pathlib.Path(path).read_text(errors="replace")


def _scan_text(eng: Engine, text: str, output: bool) -> ScanResult:
    return eng.scan_output(text) if output else eng.scan_input(text)


def _print_result(uri: str, text: str, res: ScanResult, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(res.to_dict(), indent=2))
    elif fmt == "sarif":
        print(json.dumps(to_sarif([(uri, text, res)]), indent=2))
    else:
        print(f"# {uri}")
        print(res.explain())


def cmd_scan(args: argparse.Namespace) -> int:
    text = _read(args.file)
    uri = "<stdin>" if args.file == "-" else args.file
    eng = Engine(policy=args.profile)
    res = _scan_text(eng, text, args.output)
    _print_result(uri, text, res, args.format)
    return 1 if res.event_score >= args.fail_on else 0


def cmd_redteam(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.dir)
    files = sorted(p for p in root.rglob(args.glob) if p.is_file() and p.suffix.lower() in _TEXT_EXT)
    eng = Engine(policy=args.profile)
    items: list[tuple[str, str, ScanResult]] = []
    worst = 0.0
    hits = 0
    for p in files:
        if p.stat().st_size > _REDTEAM_MAX_BYTES:  # don't slurp a huge/extensionless file whole
            print(f"[skip] {p.relative_to(root)} ({p.stat().st_size} bytes > {_REDTEAM_MAX_BYTES})")
            continue
        text = p.read_text(errors="replace")
        res = _scan_text(eng, text, args.output)
        items.append((str(p.relative_to(root)), text, res))
        worst = max(worst, res.event_score)
        if res.event_score >= args.fail_on:
            hits += 1

    if args.format == "sarif":
        print(json.dumps(to_sarif(items), indent=2))
    elif args.format == "json":
        print(json.dumps({"files": len(items), "flagged": hits, "worst_score": worst,
                          "results": [{"file": u, **r.to_dict()} for u, _t, r in items]}, indent=2))
    else:
        for uri, _t, res in items:
            mark = "FLAG" if res.event_score >= args.fail_on else "ok  "
            codes = ",".join(sorted({c for f in res.findings for c in f.owasp_ids}))
            print(f"[{mark}] {res.event_score:5.1f}  {uri}  {codes}")
        print(f"\nscanned {len(items)} file(s); {hits} at/above fail-on={args.fail_on}; worst={worst:.1f}")
    return 1 if hits else 0


def cmd_rules(args: argparse.Namespace) -> int:
    rows = catalog()
    if args.format == "json":
        print(json.dumps(rows, indent=2))
    else:
        print(f"pink-crow rules ({len(rows)}):\n")
        for r in rows:
            print(f"  {r['rule_id']:<24} {','.join(r['owasp_ids']):<34} {r['description']}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        from .gateway.app import run
    except ImportError:
        print("The gateway needs extra deps. Install with:  pip install 'pink-crow[gateway]'", file=sys.stderr)
        return 2
    run(host=args.host, port=args.port, profile=args.profile)
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    print(f"pink-crow {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pink-crow", description="Deterministic session-risk gateway for AI chat/agents.")
    p.add_argument("--version", action="version", version=f"pink-crow {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--profile", choices=sorted(PROFILES), default="standard", help="policy profile")
        sp.add_argument("--format", choices=["text", "json", "sarif"], default="text")
        sp.add_argument("--fail-on", type=float, default=60.0, dest="fail_on", help="exit non-zero at/above this score")
        sp.add_argument("--output", action="store_true", help="treat input as model OUTPUT (egress checks)")

    sp = sub.add_parser("scan", help="scan a file or stdin")
    sp.add_argument("file", nargs="?", default="-", help="path or '-' for stdin")
    add_common(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("redteam", help="scan every text file under a directory")
    sp.add_argument("dir", help="directory to scan")
    sp.add_argument("--glob", default="*", help="glob pattern (default: *)")
    add_common(sp)
    sp.set_defaults(func=cmd_redteam)

    sp = sub.add_parser("rules", help="list all rules and their OWASP IDs")
    sp.add_argument("--format", choices=["text", "json"], default="text")
    sp.set_defaults(func=cmd_rules)

    sp = sub.add_parser("serve", help="run the HTTP gateway (needs [gateway] extra)")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8000)
    sp.add_argument("--profile", choices=sorted(PROFILES), default="standard")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("version", help="print version")
    sp.set_defaults(func=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
