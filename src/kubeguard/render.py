"""Terminal rendering: findings grouped by file, then a one-screen verdict.

No ``rich``, no ``colorama`` — a scanner that runs inside a scratch container
cannot depend on a terminal library. ANSI is emitted only when stdout is a tty
*and* ``--no-color`` was not passed, which keeps piped JSON clean.
"""

from __future__ import annotations

import json
import os
import sys

from .manifest import Resource, selector_of, template_labels_of, workload_iter
from .model import SEVERITY_ORDER, Finding, Report
from .rules import all_rules

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_SEVERITY_COLOR = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[36m",
    "info": "\033[90m",
}


def use_color(enabled: bool = True) -> bool:
    if not enabled:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _paint(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def severity_tag(severity: str, color: bool = True) -> str:
    return _paint(severity.upper().ljust(8), _SEVERITY_COLOR.get(severity, ""), color)


def render_rules(color: bool = True) -> str:
    """The whole catalogue, grouped, for ``kubeguard rules``."""
    lines: list[str] = []
    groups: dict[str, list] = {}
    for rule in all_rules():
        groups.setdefault(rule.group, []).append(rule)
    lines.append(_paint("kubeguard rules", _BOLD, color))
    for group in ("pod", "rbac", "graph"):
        rules = groups.get(group, [])
        if not rules:
            continue
        label = {"pod": "Workload / PodSpec", "rbac": "RBAC", "graph": "Cross-resource"}[group]
        lines.append("")
        lines.append(_paint(f"{label}  ({len(rules)})", _BOLD, color))
        for rule in rules:
            lines.append(f"  {severity_tag(rule.severity, color)} {rule.id}  {rule.title}")
            if rule.cwe:
                lines.append(_paint(f"            {rule.cwe}", _DIM, color))
    lines.append("")
    total = len(all_rules())
    lines.append(f"{total} rules · 0 dependencies · deterministic")
    return "\n".join(lines)


def _finding_line(finding: Finding, color: bool) -> str:
    location = _paint(f"{finding.path}:{finding.line}", _DIM, color)
    head = f"  {severity_tag(finding.rule.severity, color)} {finding.rule.id}  {finding.rule.title}"
    body = f"      {location}  {finding.resource}"
    out = [head, body]
    if finding.detail:
        out.append(f"      {finding.detail}")
    if finding.snippet:
        out.append(_paint(f"      > {finding.snippet}", _DIM, color))
    out.append(_paint(f"      fix: {finding.rule.fix}", _DIM, color))
    return "\n".join(out)


def render_report(report: Report, color: bool = True, show_fix: bool = True) -> str:
    lines: list[str] = []
    findings = report.findings
    if not findings:
        lines.append(_paint("kubeguard: no findings.", _BOLD, color))
        lines.append(_render_footer(report, color))
        return "\n".join(lines)

    by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        by_file.setdefault(finding.path, []).append(finding)

    lines.append(_paint(f"kubeguard  {report.path}", _BOLD, color))
    for path, group in by_file.items():
        lines.append("")
        lines.append(_paint(path, _BOLD, color))
        for finding in group:
            block = _finding_line(finding, color)
            if not show_fix:
                block = "\n".join(line for line in block.splitlines() if not line.strip().startswith("fix:"))
            lines.append(block)

    lines.append("")
    lines.append(_render_footer(report, color))
    return "\n".join(lines)


def _render_footer(report: Report, color: bool) -> str:
    counts = report.counts()
    summary = report.summary
    parts = []
    for name in reversed(SEVERITY_ORDER):
        if counts[name]:
            parts.append(f"{counts[name]} {name}")
    tally = ", ".join(parts) if parts else "0 findings"
    bits = [
        f"{summary.resources} resources",
        f"{summary.workloads} workloads",
        f"{summary.containers} containers",
    ]
    if summary.runs_as_root:
        bits.append(f"{summary.runs_as_root} may run as root")
    head = f"{tally}  ·  " + "  ·  ".join(bits)
    verdict = f"risk {report.risk}/100  {report.grade}"
    painted = {
        "CRITICAL RISK": "\033[1;97;41m",
        "HIGH RISK": "\033[1;31m",
        "MEDIUM RISK": "\033[1;33m",
        "LOW RISK": "\033[36m",
        "CLEAN": "\033[1;32m",
    }[report.grade]
    lines = [head, _paint(verdict, painted, color)]
    if summary.errors:
        lines.append(_paint("parse errors: " + "; ".join(summary.errors[:3]), _DIM, color))
    return "\n".join(lines)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_rbac(effective: dict, color: bool = True) -> str:
    """The effective-permission table: ``kubeguard rbac``."""
    lines: list[str] = [_paint("kubeguard rbac — effective permissions", _BOLD, color)]
    if not effective:
        lines.append("  (no RoleBinding / ClusterRoleBinding found)")
        return "\n".join(lines)
    for subject in sorted(effective):
        eff = effective[subject]
        flags = []
        if eff.is_cluster_admin:
            flags.append("cluster-admin")
        if eff.has_wildcard:
            flags.append("wildcard")
        if eff.can_escalate:
            flags.append("CAN-ESCALATE")
        if eff.can_exec:
            flags.append("can-exec")
        if eff.can_read_secrets:
            flags.append("can-read-secrets")
        tag = _paint(" !! ", "\033[1;97;41m", color) if eff.can_escalate or eff.is_cluster_admin else "    "
        lines.append(f"{tag}{subject}")
        lines.append(_paint(f"      verbs     : {', '.join(sorted(eff.verbs)) or '-'}", _DIM, color))
        lines.append(_paint(f"      resources : {', '.join(sorted(eff.resources)) or '-'}", _DIM, color))
        lines.append(_paint(f"      flags     : {', '.join(flags) or 'none'}", _DIM, color))
    return "\n".join(lines)


def render_graph(report: Report, manifest_resources: list[Resource], color: bool = True) -> str:
    """The relationship report: ``kubeguard graph``."""
    lines: list[str] = [_paint("kubeguard graph — cross-resource view", _BOLD, color)]
    workloads = workload_iter(manifest_resources)
    for resource, _ in workloads:
        labels = template_labels_of(resource)
        pretty = "{" + ", ".join(f"{k}={v}" for k, v in sorted(labels.items())) + "}" if labels else "(none)"
        lines.append(f"  {resource.label}")
        lines.append(_paint(f"      template labels : {pretty}", _DIM, color))
    for service in (r for r in manifest_resources if r.kind.lower() == "service"):
        sel = selector_of(service)
        pretty = "{" + ", ".join(f"{k}={v}" for k, v in sorted(sel.items())) + "}" if sel else "(none)"
        lines.append(f"  Service/{service.name}")
        lines.append(_paint(f"      selector        : {pretty}", _DIM, color))
    for policy in (r for r in manifest_resources if r.kind.lower() == "networkpolicy"):
        lines.append(f"  NetworkPolicy/{policy.name}  ns={policy.namespace or 'default'}")
    return "\n".join(lines)
