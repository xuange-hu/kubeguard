"""Tests for suppression: ``--ignore`` and the inline ``# kubeguard: ignore`` marker.

A scanner without a suppression mechanism gets switched off the first time it
blocks a release. Both mechanisms here are file-local and reviewable in the
diff, which is the point.
"""

from __future__ import annotations

from kubeguard.analyze import Options, scan_text

POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
    - name: c
      image: nginx:latest
      securityContext:
        privileged: true
"""


def ids(text: str, options: Options | None = None) -> set[str]:
    return {f.rule.id for f in scan_text(text, path="p.yaml", options=options).findings}


def test_ignore_option_removes_one_rule():
    assert "KG001" in ids(POD)
    assert "KG001" not in ids(POD, Options(ignore=["KG001"]))


def test_ignore_option_is_case_insensitive():
    assert "KG001" not in ids(POD, Options(ignore=["kg001"]))


def test_inline_marker_on_the_finding_line():
    text = POD.replace("        privileged: true", "        privileged: true  # kubeguard: ignore=KG001")
    assert "KG001" not in ids(text)


def test_inline_marker_does_not_hide_other_rules():
    text = POD.replace("        privileged: true", "        privileged: true  # kubeguard: ignore=KG001")
    assert "KG015" in ids(text)


def test_bare_marker_on_the_finding_line_ignores_everything_there():
    text = POD.replace("        privileged: true", "        privileged: true  # kubeguard: ignore")
    found = ids(text)
    assert "KG001" not in found


def test_resource_level_marker_suppresses_the_whole_object():
    text = POD.replace("kind: Pod", "kind: Pod  # kubeguard: ignore")
    found = ids(text)
    assert "KG001" not in found
    assert "KG015" not in found


def test_marker_must_name_the_rule_to_apply():
    text = POD.replace("kind: Pod", "kind: Pod  # kubeguard: ignore=KG015")
    found = ids(text)
    assert "KG001" in found      # still reported
    assert "KG015" not in found  # suppressed


def test_min_severity_and_ignore_compose():
    report = scan_text(POD, path="p.yaml", options=Options(min_severity="high", ignore=["KG001"]))
    # KG006/KG007 are also high and survive; the point is KG001 is gone
    assert "KG001" not in {f.rule.id for f in report.findings}
    assert "KG015" not in {f.rule.id for f in report.findings}


def test_suppression_does_not_corrupt_the_summary():
    report = scan_text(POD, path="p.yaml", options=Options(ignore=["KG001", "KG015", "KG016"]))
    assert report.summary.containers == 1
