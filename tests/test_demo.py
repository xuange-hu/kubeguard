"""Tests for the demo manifest.

The demo is the first thing a visitor runs, so it has to exercise the whole
catalogue — a demo that fires four rules tells you nothing about the other
thirty-three.
"""

from __future__ import annotations

import os

from kubeguard.analyze import scan_text
from kubeguard.demo import DEMO_MANIFEST, write_demo
from kubeguard.rules import all_rules


def test_demo_fires_every_rule():
    fired = {f.rule.id for f in scan_text(DEMO_MANIFEST, path="deployment.yaml").findings}
    missing = sorted({r.id for r in all_rules()} - fired)
    assert missing == [], f"demo does not exercise: {missing}"


def test_demo_is_multi_document():
    assert DEMO_MANIFEST.count("\n---\n") >= 6


def test_write_demo_creates_the_file(tmp_path):
    target = tmp_path / "demo"
    path = write_demo(str(target))
    assert os.path.exists(path)
    with open(path, encoding="utf-8") as handle:
        assert handle.read() == DEMO_MANIFEST


def test_demo_manifest_parses_without_errors():
    report = scan_text(DEMO_MANIFEST, path="deployment.yaml")
    assert report.summary.errors == []


def test_demo_manifest_has_the_expected_shape():
    report = scan_text(DEMO_MANIFEST, path="deployment.yaml")
    assert report.summary.workloads >= 3
    assert report.summary.containers >= 4
    assert "Deployment" in report.summary.kinds
    assert "CronJob" in report.summary.kinds


def test_demo_risk_is_maxed():
    report = scan_text(DEMO_MANIFEST, path="deployment.yaml")
    assert report.risk == 100
    assert report.grade == "CRITICAL RISK"
