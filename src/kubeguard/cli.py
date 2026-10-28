"""Command line entry point.

``kubeguard scan`` is the one people will actually type, so it takes a directory
and figures the rest out. Exit codes are the CI contract:

    0  nothing at or above --fail-on
    1  at least one finding at or above --fail-on
    2  the scan itself failed (bad path, unreadable file)
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys

from . import __version__
from .analyze import Options, scan_files, scan_text
from .manifest import load_manifest_set
from .model import SEVERITY_ORDER, parse_severity
from .rbac import aggregate
from .render import render_graph, render_json, render_rbac, render_report, render_rules, use_color
from .rules import all_rules, count_by_severity
from .sarif import dumps as sarif_dumps

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_NO_COLOR = "--no-color"


def _stdout_utf8() -> None:
    """Windows consoles default to cp936 and choke on CJK rule text."""
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kubeguard",
        description="Layer-zero Kubernetes manifest audit: pod security, RBAC, and cross-resource rules.",
    )
    parser.add_argument("--version", action="version", version=f"kubeguard {__version__}")
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--no-color", action="store_true", help="disable ANSI colour (also honours NO_COLOR)")

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", parents=[parent], help="audit manifests at PATH (file or directory)")
    scan.add_argument("paths", nargs="*", default=["."], help="manifest file or directory (default: .)")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--min-severity", default="info", choices=SEVERITY_ORDER, help="hide findings below this level")
    scan.add_argument("--fail-on", default="none", choices=("none", *SEVERITY_ORDER), help="exit 1 when a finding reaches this level")
    scan.add_argument("--ignore", default="", help="comma-separated rule ids to skip, e.g. KG016,KG025")
    scan.add_argument("--output", default="", help="write the report to a file instead of stdout")

    rules = sub.add_parser("rules", parents=[parent], help="print the rule catalogue")
    rules.add_argument("--format", choices=("text", "json"), default="text")

    rbac = sub.add_parser("rbac", parents=[parent], help="effective permissions per subject")
    rbac.add_argument("paths", nargs="*", default=["."])
    rbac.add_argument("--format", choices=("text", "json"), default="text")

    graph = sub.add_parser("graph", parents=[parent], help="cross-resource relationship view")
    graph.add_argument("paths", nargs="*", default=["."])

    demo = sub.add_parser("demo", parents=[parent], help="write a deliberately broken manifest and audit it")
    demo.add_argument("--dir", default="kubeguard-demo", help="where to write the sample manifest")
    demo.add_argument("--format", choices=("text", "json"), default="text")

    return parser


def _emit(text: str, output: str = "") -> None:
    if output:
        directory = os.path.dirname(os.path.abspath(output))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        return
    sys.stdout.write(text + "\n")


def cmd_scan(args: argparse.Namespace) -> int:
    options = Options(min_severity=args.min_severity, ignore=[x for x in args.ignore.split(",") if x.strip()])
    paths = args.paths or ["."]
    for path in paths:
        if not os.path.exists(path):
            sys.stderr.write(f"kubeguard: no such path: {path}\n")
            return EXIT_ERROR
    report = scan_files(paths, options)
    color = use_color(not args.no_color)

    if args.format == "json":
        _emit(render_json(report), args.output)
    elif args.format == "sarif":
        _emit(sarif_dumps(report, version=__version__, min_severity=args.min_severity), args.output)
    else:
        _emit(render_report(report, color=color), args.output)

    if args.fail_on != "none":
        floor = SEVERITY_ORDER.index(parse_severity(args.fail_on))
        if any(f.rule.severity_rank >= floor for f in report.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    color = use_color(not args.no_color)
    if args.format == "json":
        _emit(render_json_catalogue())
    else:
        _emit(render_rules(color=color))
    return EXIT_OK


def render_json_catalogue() -> str:
    import json

    counts = count_by_severity()
    return json.dumps(
        {
            "tool": "kubeguard",
            "version": __version__,
            "rules": [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity,
                    "group": r.group,
                    "cwe": r.cwe,
                    "why": r.why,
                    "fix": r.fix,
                }
                for r in all_rules()
            ],
            "counts": counts,
            "total": len(all_rules()),
        },
        indent=2,
        ensure_ascii=False,
    )


def cmd_rbac(args: argparse.Namespace) -> int:
    color = use_color(not args.no_color)
    effective = {}
    for path in args.paths or ["."]:
        if not os.path.exists(path):
            sys.stderr.write(f"kubeguard: no such path: {path}\n")
            return EXIT_ERROR
        manifest = load_manifest_set(path)
        for key, value in aggregate(manifest.resources).items():
            if key in effective:
                existing = effective[key]
                existing.rules.extend(value.rules)
                existing.grants.extend(value.grants)
            else:
                effective[key] = value
    if args.format == "json":
        import json

        _emit(json.dumps({k: v.to_dict() for k, v in sorted(effective.items())}, indent=2, ensure_ascii=False))
    else:
        _emit(render_rbac(effective, color=color))
    return EXIT_OK


def cmd_graph(args: argparse.Namespace) -> int:
    color = use_color(not args.no_color)
    report = scan_files(args.paths or ["."], Options(min_severity="critical"))
    resources = []
    for path in args.paths or ["."]:
        resources.extend(load_manifest_set(path).resources)
    _emit(render_graph(report, resources, color=color))
    return EXIT_OK


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import DEMO_MANIFEST, write_demo

    path = write_demo(args.dir)
    color = use_color(not args.no_color)
    report = scan_text(DEMO_MANIFEST, path=path)
    if args.format == "json":
        _emit(render_json(report))
    else:
        _emit(f"wrote {path}\n")
        _emit(render_report(report, color=color))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    _stdout_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "scan": cmd_scan,
        "rules": cmd_rules,
        "rbac": cmd_rbac,
        "graph": cmd_graph,
        "demo": cmd_demo,
    }
    handler = handlers.get(args.command)
    if handler is None:  # pragma: no cover - argparse enforces choices
        parser.print_help()
        return EXIT_ERROR
    return handler(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
