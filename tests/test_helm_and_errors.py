"""未渲染的 Helm 模板必须 fail closed，而不是变成 "CLEAN · 0 workloads"。

`{{- if .Values.enabled }}` 独占一行时，后面的 `apiVersion:` 会落进一个
裸标量文档，整份文件解析出 0 个资源。旧行为：

    0 findings · 0 resources · 0 workloads · risk 0/100 CLEAN   rc=0

一个装着 `privileged: true` 容器的清单被判干净 —— 这是本仓库最危险的
一类失败（骗，而不是吵）。现在必须：

    grade == "INCOMPLETE"，退出码 2，并且报错里点名 "helm template"。
"""

from __future__ import annotations

import pytest

from kubeguard.analyze import scan_text
from kubeguard.cli import cmd_scan
from kubeguard.yamlio import YamlError, load_documents

HELM = """\
{{- if .Values.enabled }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "chart.fullname" . }}
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.25
        securityContext:
          privileged: true
{{- end }}
"""


def test_unrendered_helm_raises():
    with pytest.raises(YamlError) as exc:
        load_documents(HELM)
    assert "helm template" in str(exc.value)


def test_unrendered_helm_is_reported_as_incomplete_not_clean():
    report = scan_text(HELM, path="chart.yaml")
    assert report.summary.errors, "解析失败必须记录，不能静默当 0 资源"
    assert report.grade == "INCOMPLETE"
    assert report.grade not in {"CLEAN", "LOW RISK"}


def test_single_line_template_expression_still_parses():
    """值位置的 `{{ }}`（name: {{ .Release.Name }}）是常见写法，不能一并拦掉。"""
    doc = load_documents(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n"
    )[0]
    assert doc["kind"] == "ConfigMap"
    assert "{{ .Release.Name }}" in str(doc["metadata"]["name"])


def test_parse_error_forces_exit_two(tmp_path, capsys):
    target = tmp_path / "broken.yaml"
    target.write_text("apiVersion: v1\nkind: [unclosed\n", encoding="utf-8")
    args = type(
        "A",
        (),
        {
            "paths": [str(target)],
            "format": "text",
            "output": None,
            "no_color": True,
            "min_severity": "info",
            "ignore": "",
            "fail_on": "none",
        },
    )()
    code = cmd_scan(args)
    assert code == 2, "解析失败时不能以 0 退出，否则 CI 把坏输入当通过"