"""SARIF 2.1.0 output, so findings land in GitHub code scanning.

Hand-rolled because pulling in a SARIF library for one document shape is how a
"zero dependencies" project quietly becomes five. ``runs[0].tool.driver.rules``
carries every rule that fired, which is what makes the code-scanning UI show
rule descriptions instead of bare ids.
"""

from __future__ import annotations

import json

from .model import SEVERITY_ORDER, Report

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def dumps(report: Report, version: str = "0.1.0", min_severity: str = "info") -> str:
    findings = report.filtered(min_severity)
    rules_seen = {f.rule.id: f.rule for f in findings}

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "kubeguard",
                        "version": version,
                        "informationUri": "https://github.com/xuange-hu/kubeguard",
                        "rules": [
                            {
                                "id": rule.id,
                                "name": rule.id,
                                "shortDescription": {"text": rule.title},
                                "fullDescription": {"text": f"{rule.why}\n\nFix: {rule.fix}"},
                                "help": {
                                    "text": rule.fix,
                                    "markdown": f"**{rule.title}**\n\n{rule.why}\n\n**Fix:** {rule.fix}",
                                },
                                "defaultConfiguration": {"level": _LEVEL[rule.severity]},
                                "properties": {
                                    "tags": ["kubernetes", "security", "rbac", rule.group],
                                    "precision": "high",
                                },
                            }
                            for rule in sorted(rules_seen.values(), key=lambda r: r.id)
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule.id,
                        "level": _LEVEL[f.rule.severity],
                        "message": {"text": f"{f.resource}: {f.detail or f.rule.title}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.path.replace("\\", "/")},
                                    "region": {"startLine": max(1, f.line), "snippet": {"text": f.snippet}},
                                }
                            }
                        ],
                        "properties": {
                            "severity": f.rule.severity,
                            "group": f.rule.group,
                            "resource": f.resource,
                            "cwe": f.rule.cwe,
                        },
                    }
                    for f in findings
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def counts(report: Report) -> dict[str, int]:
    return report.counts()


SEVERITIES = SEVERITY_ORDER
