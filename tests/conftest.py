"""Shared test plumbing.

``src`` is put on ``sys.path`` here so `pytest` works without exporting
``PYTHONPATH`` — the same reason CI can run a bare `pytest` on Windows.
"""

from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from kubeguard.analyze import Options, scan_path, scan_text  # noqa: E402


def rule_ids(report) -> list[str]:
    return sorted({f.rule.id for f in report.findings})


def has(report, rule_id: str) -> bool:
    return rule_id in rule_ids(report)


@pytest.fixture
def scan():
    """``scan(text, path=...)`` -> Report."""
    return scan_text


@pytest.fixture
def scan_dir():
    return scan_path


@pytest.fixture
def opts():
    return Options
