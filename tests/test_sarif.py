"""Tests for the SARIF export.

SARIF is what makes findings show up in GitHub code scanning, so the shapes
here are pinned to the 2.1.0 schema requirements rather than to our own taste.
"""

from __future__ import annotations

import json

from kubeguard.analyze import scan_text
from kubeguard.sarif import dumps

MANIFEST = """\
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


def test_schema_and_version():
    doc = json.loads(dumps(scan_text(MANIFEST, path="pod.yaml")))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")


def test_driver_carries_every_rule_that_fired():
    doc = json.loads(dumps(scan_text(MANIFEST, path="pod.yaml")))
    rules = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "KG001" in rules
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["help"]["text"]


def test_results_have_location_and_level():
    doc = json.loads(dumps(scan_text(MANIFEST, path="pod.yaml")))
    results = doc["runs"][0]["results"]
    assert results
    first = results[0]
    assert first["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert first["level"] in ("error", "warning", "note")


def test_severity_maps_to_level():
    doc = json.loads(dumps(scan_text(MANIFEST, path="pod.yaml")))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["KG001"] == "error"


def test_windows_path_is_turned_into_a_uri():
    doc = json.loads(dumps(scan_text(MANIFEST, path="manifests\\pod.yaml")))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_min_severity_narrows_results():
    report = scan_text(MANIFEST, path="pod.yaml")
    full = json.loads(dumps(report))
    critical = json.loads(dumps(report, min_severity="critical"))
    assert len(critical["runs"][0]["results"]) < len(full["runs"][0]["results"])


def test_empty_report_is_still_valid():
    doc = json.loads(dumps(scan_text("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: n\n", path="n.yaml")))
    assert doc["runs"][0]["results"] == []
