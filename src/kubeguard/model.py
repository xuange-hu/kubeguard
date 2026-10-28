"""Data model: severity ordering, rules, findings, and the report summary.

Everything here is a plain dataclass with a ``to_dict()``. A cluster already has
enough moving parts; the data model should be the one thing you never have to
think about.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

GROUP_LABEL = {
    "pod": "workload",
    "rbac": "rbac",
    "graph": "cross-resource",
}


def parse_severity(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in SEVERITY_RANK:
        raise ValueError(f"unknown severity {value!r}; expected one of {SEVERITY_ORDER}")
    return v


def at_least(threshold: str) -> list[str]:
    """All severities at or above ``threshold``."""
    return SEVERITY_ORDER[SEVERITY_RANK[parse_severity(threshold)] :]


def parse_rule_ids(value: str) -> list[str]:
    """Parse ``--ignore KG001,kg002`` into a normalised list."""
    if not value:
        return []
    out: list[str] = []
    for chunk in value.replace(";", ",").split(","):
        rid = chunk.strip().upper()
        if rid and rid not in out:
            out.append(rid)
    return out


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    group: str
    why: str
    fix: str
    cwe: str = ""
    reference: str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK[self.severity]


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int
    resource: str
    snippet: str
    detail: str

    def location(self) -> str:
        """The one string a human pastes into an editor: ``path:line``."""
        return f"{self.path}:{self.line}"

    def to_dict(self) -> dict:
        return {
            "rule": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity,
            "group": self.rule.group,
            "path": self.path,
            "line": self.line,
            "location": self.location(),
            "resource": self.resource,
            "snippet": self.snippet,
            "detail": self.detail,
            "cwe": self.rule.cwe,
            "why": self.rule.why,
            "fix": self.rule.fix,
        }


@dataclass
class ManifestSummary:
    """What the manifest set *is*, independent of any finding."""

    files: int = 0
    resources: int = 0
    kinds: dict[str, int] = field(default_factory=dict)
    namespaces: list[str] = field(default_factory=list)
    workloads: int = 0
    containers: int = 0
    images: list[str] = field(default_factory=list)
    service_accounts: list[str] = field(default_factory=list)
    runs_as_root: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "files": self.files,
            "resources": self.resources,
            "kinds": dict(sorted(self.kinds.items())),
            "namespaces": self.namespaces,
            "workloads": self.workloads,
            "containers": self.containers,
            "images": self.images,
            "service_accounts": self.service_accounts,
            "runs_as_root": self.runs_as_root,
            "errors": self.errors,
        }


@dataclass
class Report:
    path: str
    findings: list[Finding]
    summary: ManifestSummary
    rules_run: int = 0

    def filtered(self, min_severity: str = "info") -> list[Finding]:
        floor = SEVERITY_RANK[parse_severity(min_severity)]
        return [f for f in self.findings if f.rule.severity_rank >= floor]

    def counts(self) -> dict[str, int]:
        out = {name: 0 for name in SEVERITY_ORDER}
        for f in self.findings:
            out[f.rule.severity] += 1
        return out

    def worst(self) -> str:
        if not self.findings:
            return "none"
        return max((f.rule.severity for f in self.findings), key=lambda s: SEVERITY_RANK[s])

    @property
    def risk(self) -> int:
        """0-100. Weighted count, capped, so one critical cannot hide forty lows."""
        weights = {"info": 0, "low": 2, "medium": 6, "high": 14, "critical": 30}
        raw = sum(weights[f.rule.severity] for f in self.findings)
        return min(100, raw)

    @property
    def grade(self) -> str:
        r = self.risk
        if r >= 80:
            return "CRITICAL RISK"
        if r >= 55:
            return "HIGH RISK"
        if r >= 30:
            return "MEDIUM RISK"
        if r >= 12:
            return "LOW RISK"
        return "CLEAN"

    def to_dict(self) -> dict:
        return {
            "tool": "kubeguard",
            "path": self.path,
            "summary": {
                "risk": self.risk,
                "grade": self.grade,
                "worst": self.worst(),
                "counts": self.counts(),
                "rules_run": self.rules_run,
                "manifest": self.summary.to_dict(),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
