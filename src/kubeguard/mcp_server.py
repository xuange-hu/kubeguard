"""MCP server: five tools over the same engine the CLI uses.

The tools take manifest *text*, not paths — an agent usually has the file open
already, and a server that reads arbitrary paths from an LLM prompt is a
capability you do not want to hand out. ``kubeguard_scan_path`` is the escape
hatch and is documented as such.
"""

from __future__ import annotations

from typing import Any

__all__ = ["main", "tool_manifest", "build_server"]

TOOLS = [
    {
        "name": "kubeguard_scan",
        "description": "Audit Kubernetes manifest text (YAML, multi-document) and return findings with file:line evidence.",
        "input": {"path": "str (label used in output)", "content": "str (YAML text)"},
    },
    {
        "name": "kubeguard_scan_path",
        "description": "Audit every YAML file under a local directory and return findings.",
        "input": {"path": "str (file or directory)"},
    },
    {
        "name": "kubeguard_rules",
        "description": "List the rule catalogue: id, title, severity, group, why, fix.",
        "input": {},
    },
    {
        "name": "kubeguard_rbac",
        "description": "Resolve RoleBindings and report what each subject can actually do, including escalation combinations.",
        "input": {"path": "str (file or directory)"},
    },
    {
        "name": "kubeguard_demo",
        "description": "Write a deliberately vulnerable sample manifest and audit it, as a self-check that the rules fire.",
        "input": {"directory": "str (optional, default kubeguard-demo)"},
    },
]


def tool_manifest() -> list[dict[str, Any]]:
    """The tool table, also printed by ``vehsec mcp --check``-style smoke tests."""
    return list(TOOLS)


def _scan_content(path: str, content: str) -> dict[str, Any]:
    from .analyze import scan_text

    report = scan_text(content, path=path or "<memory>")
    return report.to_dict()


def _scan_path(path: str) -> dict[str, Any]:
    from .analyze import Options, scan_path

    return scan_path(path, Options()).to_dict()


def _rules() -> dict[str, Any]:
    from .rules import all_rules, count_by_severity

    return {
        "total": len(all_rules()),
        "counts": count_by_severity(),
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "group": r.group,
                "why": r.why,
                "fix": r.fix,
                "cwe": r.cwe,
            }
            for r in all_rules()
        ],
    }


def _rbac(path: str) -> dict[str, Any]:
    from .manifest import load_manifest_set
    from .rbac import aggregate

    effective = aggregate(load_manifest_set(path).resources)
    return {key: value.to_dict() for key, value in sorted(effective.items())}


def _demo(directory: str) -> dict[str, Any]:
    from .analyze import scan_text
    from .demo import write_demo

    path = write_demo(directory or "kubeguard-demo")
    with open(path, encoding="utf-8") as handle:
        content = handle.read()
    return scan_text(content, path=path).to_dict()


def build_server():
    """Build the MCP server. Requires the optional ``mcp`` extra."""
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - only when the extra is missing
        raise SystemExit("kubeguard-mcp needs the mcp extra: pip install 'kubeguard[mcp]'") from exc

    server = FastMCP("kubeguard")

    @server.tool()
    def kubeguard_scan(path: str = "<memory>", content: str = "") -> dict:
        """Audit Kubernetes manifest text. Returns findings with path:line evidence."""
        return _scan_content(path, content)

    @server.tool()
    def kubeguard_scan_path(path: str = ".") -> dict:
        """Audit every YAML file under a local directory."""
        return _scan_path(path)

    @server.tool()
    def kubeguard_rules() -> dict:
        """List every rule with severity, rationale and fix."""
        return _rules()

    @server.tool()
    def kubeguard_rbac(path: str = ".") -> dict:
        """Effective permissions per subject after resolving all bindings."""
        return _rbac(path)

    @server.tool()
    def kubeguard_demo(directory: str = "kubeguard-demo") -> dict:
        """Write a vulnerable sample manifest and audit it."""
        return _demo(directory)

    return server


def main() -> None:
    server = build_server()
    server.run()


if __name__ == "__main__":  # pragma: no cover
    main()
