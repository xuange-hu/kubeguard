"""Tests for the CLI: exit codes, formats, filters, and the demo path."""

from __future__ import annotations

import io
import json
import os
import sys

import pytest

from kubeguard import __version__
from kubeguard.cli import main

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


def run(argv, monkeypatch=None):
    """Run the CLI in-process and return ``(exit_code, stdout)``."""
    buffer = io.StringIO()
    old = sys.stdout
    sys.stdout = buffer
    try:
        code = main(argv)
    finally:
        sys.stdout = old
    return code, buffer.getvalue()


@pytest.fixture
def manifest_file(tmp_path):
    path = tmp_path / "pod.yaml"
    path.write_text(MANIFEST, encoding="utf-8")
    return str(path)


def test_version_flag():
    # argparse --version raises SystemExit before run() can return, so the
    # buffer has to be read outside the helper.
    buffer = io.StringIO()
    old = sys.stdout
    sys.stdout = buffer
    try:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
    finally:
        sys.stdout = old
    assert exc.value.code == 0
    assert __version__ in buffer.getvalue()


def test_scan_reports_findings(manifest_file):
    code, out = run(["scan", manifest_file, "--no-color"])
    assert code == 0
    assert "KG001" in out
    assert "Privileged container" in out


def test_scan_defaults_to_exit_zero(manifest_file):
    code, _ = run(["scan", manifest_file, "--no-color"])
    assert code == 0


def test_fail_on_high_exits_one(manifest_file):
    code, _ = run(["scan", manifest_file, "--no-color", "--fail-on", "high"])
    assert code == 1


def test_fail_on_info_exits_one(manifest_file):
    code, _ = run(["scan", manifest_file, "--no-color", "--fail-on", "info"])
    assert code == 1


def test_fail_on_none_never_fails(manifest_file):
    code, _ = run(["scan", manifest_file, "--no-color", "--fail-on", "none"])
    assert code == 0


def test_missing_path_exits_two():
    code, _ = run(["scan", "does-not-exist.yaml", "--no-color"])
    assert code == 2


def test_json_format_is_parseable(manifest_file):
    code, out = run(["scan", manifest_file, "--no-color", "--format", "json"])
    assert code == 0
    payload = json.loads(out)
    assert payload["tool"] == "kubeguard"
    assert payload["findings"][0]["rule"] == "KG001"
    assert payload["summary"]["manifest"]["containers"] == 1


def test_sarif_format_is_parseable(manifest_file):
    code, out = run(["scan", manifest_file, "--no-color", "--format", "sarif"])
    payload = json.loads(out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "kubeguard"
    assert payload["runs"][0]["results"]


def test_min_severity_filters(manifest_file):
    _, all_out = run(["scan", manifest_file, "--no-color"])
    _, critical_out = run(["scan", manifest_file, "--no-color", "--min-severity", "critical"])
    assert "KG001" in critical_out
    assert critical_out.count("KG") < all_out.count("KG")


def test_ignore_removes_a_rule(manifest_file):
    _, out = run(["scan", manifest_file, "--no-color", "--ignore", "KG001"])
    assert "KG001" not in out


def test_ignore_multiple(manifest_file):
    _, out = run(["scan", manifest_file, "--no-color", "--ignore", "KG001,KG015,KG016"])
    for rid in ("KG001", "KG015", "KG016"):
        assert rid not in out


def test_output_writes_to_file(manifest_file, tmp_path):
    target = tmp_path / "out" / "report.json"
    code, _ = run(["scan", manifest_file, "--no-color", "--format", "json", "--output", str(target)])
    assert code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["tool"] == "kubeguard"


def test_rules_command(manifest_file):
    code, out = run(["rules", "--no-color"])
    assert code == 0
    assert "KG001" in out and "KG045" in out


def test_rules_json():
    code, out = run(["rules", "--no-color", "--format", "json"])
    payload = json.loads(out)
    assert payload["total"] >= 37
    assert payload["rules"][0]["id"] == "KG001"


def test_scan_a_directory(tmp_path):
    (tmp_path / "a.yaml").write_text(MANIFEST, encoding="utf-8")
    (tmp_path / "b.yaml").write_text("apiVersion: v1\nkind: Service\nmetadata:\n  name: s\nspec:\n  selector:\n    app: x\n", encoding="utf-8")
    code, out = run(["scan", str(tmp_path), "--no-color"])
    assert code == 0
    assert "KG001" in out
    assert "KG041" in out


def test_scan_multiple_paths(manifest_file, tmp_path):
    other = tmp_path / "b.yaml"
    other.write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: q\nspec:\n  containers:\n    - name: c\n      image: n:1\n", encoding="utf-8")
    code, out = run(["scan", manifest_file, str(other), "--no-color"])
    assert code == 0
    assert out.count("KG001") >= 1


def test_scan_default_path_is_cwd(tmp_path, monkeypatch):
    (tmp_path / "pod.yaml").write_text(MANIFEST, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code, out = run(["scan", "--no-color"])
    assert code == 0
    assert "KG001" in out


def test_rbac_command(tmp_path):
    path = tmp_path / "rbac.yaml"
    path.write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: r\n"
        "rules:\n  - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    verbs: [\"get\"]\n"
        "---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: b\n"
        "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: r\n"
        "subjects:\n  - kind: ServiceAccount\n    name: bot\n    namespace: prod\n",
        encoding="utf-8",
    )
    code, out = run(["rbac", str(path), "--no-color"])
    assert code == 0
    assert "ServiceAccount/prod/bot" in out
    assert "can-read-secrets" in out


def test_rbac_json(tmp_path):
    path = tmp_path / "rbac.yaml"
    path.write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: b\n"
        "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\n"
        "subjects:\n  - kind: ServiceAccount\n    name: bot\n    namespace: prod\n",
        encoding="utf-8",
    )
    code, out = run(["rbac", str(path), "--no-color", "--format", "json"])
    payload = json.loads(out)
    assert payload["ServiceAccount/prod/bot"]["clusterAdmin"] is True


def test_graph_command(tmp_path):
    path = tmp_path / "web.yaml"
    path.write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: prod\nspec:\n"
        "  selector:\n    matchLabels:\n      app: web\n  template:\n    metadata:\n      labels:\n        app: web\n"
        "    spec:\n      containers:\n        - name: c\n          image: n:1\n",
        encoding="utf-8",
    )
    code, out = run(["graph", str(path), "--no-color"])
    assert code == 0
    assert "app=web" in out


def test_demo_command(tmp_path):
    target = tmp_path / "demo-run"
    code, out = run(["demo", "--dir", str(target), "--no-color"])
    assert code == 0
    assert os.path.exists(str(target / "deployment.yaml"))
    assert "KG001" in out


def test_no_color_environment_variable(manifest_file, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    code, out = run(["scan", manifest_file])
    assert code == 0
    assert "\033[" not in out


def test_clean_scan_says_so(tmp_path):
    path = tmp_path / "clean.yaml"
    path.write_text("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: demo\n", encoding="utf-8")
    code, out = run(["scan", str(path), "--no-color", "--min-severity", "high"])
    assert code == 0
    assert "no findings" in out


def test_unknown_severity_is_rejected(manifest_file):
    with pytest.raises(SystemExit):
        run(["scan", manifest_file, "--min-severity", "apocalyptic"])


def test_scan_text_output_has_file_and_line(manifest_file):
    _, out = run(["scan", manifest_file, "--no-color"])
    assert os.path.basename(manifest_file) in out
    assert ":8" in out or ":9" in out
