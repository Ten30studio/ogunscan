"""OgunScan CLI entry point.

Free-tier commands live here: `scan`, `rules`, `version`. Shield-tier
commands (`shield activate`, `shield add`, ...) ship in v0.2.0 and live
under `src/ogunscan/shield/cli.py`, registered here behind the license
gate.
"""

import dataclasses
import json
import sys
from enum import Enum
from pathlib import Path

import argparse

from . import __version__
from .engine import OgunScanner
from .models import Severity
from .reporter import format_report
from .rules import load_builtin


AUTO_DETECT_PATHS = [
    Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
    Path.home() / ".cursor/mcp.json",
    Path.home() / ".config/mcp/config.json",
    Path("mcp.json"),
    Path(".mcp/config.json"),
]


def _resolve_targets(positional, recursive):
    out = []
    for raw in positional:
        p = Path(raw)
        if not p.exists():
            print(f"File not found: {p}", file=sys.stderr)
            continue
        if p.is_dir():
            pattern = "**/*.json" if recursive else "*.json"
            out.extend(sorted(p.glob(pattern)))
        else:
            out.append(p)
    return out


def cmd_scan(args):
    scanner = OgunScanner()
    color = not args.no_color and sys.stdout.isatty()
    ignore = set(args.ignore or [])

    targets = _resolve_targets(args.targets, args.recursive) if args.targets else []
    if not targets:
        targets = [p for p in AUTO_DETECT_PATHS if p.exists()]
        if not targets:
            print("No MCP config files found. Specify a file: ogunscan scan <path>", file=sys.stderr)
            sys.exit(0)

    all_results = []
    exit_code = 0

    for target in targets:
        result = scanner.scan_file(target)
        if ignore:
            result.findings = [f for f in result.findings if f.rule_id not in ignore]
        all_results.append(result)
        if result.critical or result.high:
            exit_code = 1
        if not args.json:
            print(format_report(result, color=color))

    if args.json:
        def to_dict(obj):
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return {f.name: to_dict(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, list):
                return [to_dict(i) for i in obj]
            if isinstance(obj, dict):
                return {k: to_dict(v) for k, v in obj.items()}
            return obj
        print(json.dumps([to_dict(r) for r in all_results], indent=2))

    sys.exit(exit_code)


def cmd_rules(args):
    """Print the loaded rule catalogue. Reads from bundled `builtin.json` —
    Shield's hot-updated signatures would surface here too when active."""
    sigs = load_builtin()
    rules = sigs.get("rules", [])
    print(f"\n⚔️  OgunScan — {len(rules)} detection rules\n")
    for rule in rules:
        sev = rule.get("severity", "INFO")
        rule_id = rule.get("id", "?")
        title = rule.get("title", "")
        desc = rule.get("description", "")
        print(f"  [{sev:8}] {rule_id} — {title}")
        print(f"             {desc}\n")


def cmd_version(args):
    print(f"OgunScan {__version__}")


def cli():
    KNOWN_VERBS = {"scan", "rules", "version", "-h", "--help", "--version"}
    argv = sys.argv[1:]
    if argv and argv[0] not in KNOWN_VERBS and not argv[0].startswith("-"):
        argv = ["scan"] + argv
    elif not argv:
        argv = ["scan"]

    parser = argparse.ArgumentParser(
        prog="ogunscan",
        description="⚔️  OgunScan — MCP Server Security Scanner by Ten30 Studio",
        epilog="Docs: https://ogunscan.dev/docs · Issues: https://github.com/Ten30studio/ogunscan/issues",
    )
    parser.add_argument("--version", action="version", version=f"OgunScan {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True, metavar="<command>")

    p_scan = sub.add_parser("scan", help="Scan an MCP config file or directory")
    p_scan.add_argument("targets", nargs="*", help="Config file(s) or directory. Empty = auto-detect.")
    p_scan.add_argument("-r", "--recursive", action="store_true", help="Recurse into directories")
    p_scan.add_argument("-j", "--json", action="store_true", help="Emit JSON instead of human report")
    p_scan.add_argument("--ignore", action="append", metavar="RULE",
                        help="Suppress a rule ID (repeatable, e.g. --ignore OGN-500)")
    p_scan.add_argument("--no-color", action="store_true", help="Disable color output")
    p_scan.set_defaults(func=cmd_scan)

    p_rules = sub.add_parser("rules", help="List all detection rules")
    p_rules.set_defaults(func=cmd_rules)

    p_version = sub.add_parser("version", help="Print version")
    p_version.set_defaults(func=cmd_version)

    args = parser.parse_args(argv)
    args.func(args)
