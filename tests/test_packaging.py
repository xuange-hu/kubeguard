"""Packaging contract tests.

The console scripts are the only thing a user touches, so the modules they point
at must import with base dependencies alone. CI installs ``.[all]`` and would
therefore never notice an optional import leaking into a required path.

On Python 3.10 ``tomllib`` does not exist, so the reader falls back to
``tests/_pytoml.py`` instead of skipping: a guard that quietly switches itself
off is worse than no guard. ``tests/test_pytoml_parity.py`` diffs the fallback
against the real parser on 3.11+.
"""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python <= 3.10: tomllib landed in 3.11
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _pytoml as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
SRC = ROOT / "src"


def _config() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def test_version_matches_the_package():
    import kubeguard

    assert kubeguard.__version__ == _config()["project"]["version"]


def test_console_scripts_resolve():
    scripts = _config()["project"]["scripts"]
    assert "kubeguard" in scripts
    assert "kubeguard-mcp" in scripts
    for target in scripts.values():
        module, _, attr = target.partition(":")
        assert module.startswith("kubeguard.")
        assert attr


def test_core_modules_import_without_the_mcp_extra():
    import importlib

    for name in ("kubeguard.analyze", "kubeguard.cli", "kubeguard.manifest", "kubeguard.model", "kubeguard.rbac",
                 "kubeguard.render", "kubeguard.rules", "kubeguard.sarif", "kubeguard.yamlio", "kubeguard.demo"):
        assert importlib.import_module(name) is not None


def test_base_dependencies_are_empty():
    assert _config()["project"]["dependencies"] == []


def test_mcp_extra_pins_below_two():
    extra = _config()["project"]["optional-dependencies"]["mcp"]
    joined = " ".join(extra)
    assert "mcp>=" in joined
    assert "<2" in joined


def _pep508_name(spec: str) -> str:
    return re.split(r"[<>=!~;\[]", spec, maxsplit=1)[0].strip().lower()


def test_console_script_modules_only_import_declared_packages():
    """Every third-party import in a console-script module must be covered."""
    declared = {_pep508_name(d) for d in _config()["project"]["dependencies"]}
    declared |= {_pep508_name(d) for d in _config()["project"]["optional-dependencies"]["mcp"]}
    stdlib = {
        "argparse", "json", "os", "re", "sys", "typing", "dataclasses", "io", "pathlib",
        "importlib", "__future__", "contextlib", "collections",
    }
    offenders: list[str] = []
    for path in SRC.joinpath("kubeguard").glob("*.py"):
        for match in re.finditer(r"^(?:from|import)\s+([A-Za-z_][\w.]*)", path.read_text(encoding="utf-8"), re.M):
            top = match.group(1).split(".")[0]
            if top in stdlib or top == "kubeguard":
                continue
            if top not in declared:
                offenders.append(f"{path.name}: {top}")
    assert offenders == []


def test_readme_badge_matches_the_test_count():
    """The badge is the first number a visitor reads; it must not drift."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"tests-(\d+)%20passing", readme)
    assert match, "README is missing the tests badge"
    shown = int(match.group(1))
    collected = len(
        [line for line in _collect_output().splitlines() if "::" in line]
    )
    assert shown == collected, f"README says {shown}, pytest collects {collected}"


def _collect_output() -> str:
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "tests"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={"PYTHONPATH": str(SRC), **_env()},
    )
    return proc.stdout


def _env() -> dict:
    import os

    return dict(os.environ)


def test_rule_count_in_readme_matches_the_catalogue():
    from kubeguard.rules import all_rules

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"rules-(\d+)-", readme)
    assert match
    assert int(match.group(1)) == len(all_rules())
