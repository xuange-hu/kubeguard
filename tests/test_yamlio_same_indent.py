"""同缩进块序列：一条语法细节曾经废掉整个产品的安全结论。

YAML 允许块序列与父键同列：

    containers:
    - name: app

这是 kubectl 手写清单最常见的写法，也是 GitHub 上大量示例的默认风格。
旧实现里 `_child()` 用 `ind <= parent_indent` 一刀切返回 None，于是
`containers` 变成 None —— workload 计数为 0、容器级规则整体不执行，
包含 `privileged: true` 与 `/var/run/docker.sock` 挂载的 Deployment
被判成 "0 workloads · risk 0/100 CLEAN"。把同一份文件多缩进两格，
立刻变成 "2 critical · risk 100/100 CRITICAL"。

这里同时钉两层：
  1. 解析层：两种缩进必须给出同构结果（含行号）；
  2. 结论层：同一份清单的两种缩进必须给出同一份 report，
     风险分与 finding 集合逐项相等 —— 安全结论不允许随排版漂移。
"""

from __future__ import annotations

from kubeguard.analyze import scan_text
from kubeguard.yamlio import L, loads

SAME_INDENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: privileged-app
spec:
  template:
    spec:
      containers:
      - name: pwn
        image: alpine:3.19
        securityContext:
          privileged: true
        volumeMounts:
        - name: sock
          mountPath: /var/run/docker.sock
      volumes:
      - name: sock
        hostPath:
          path: /var/run/docker.sock
"""

DEEP_INDENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: privileged-app
spec:
  template:
    spec:
      containers:
        - name: pwn
          image: alpine:3.19
          securityContext:
            privileged: true
          volumeMounts:
            - name: sock
              mountPath: /var/run/docker.sock
      volumes:
        - name: sock
          hostPath:
            path: /var/run/docker.sock
"""


def test_same_indent_sequence_parses():
    doc = loads(SAME_INDENT)
    spec = doc["spec"]["template"]["spec"]
    assert isinstance(spec["containers"], L)
    assert spec["containers"][0]["name"] == "pwn"
    # 行号必须指向 `- name: pwn` 那一行（第 9 行），否则证据不可复核
    assert spec["containers"].ilines[0] == 9
    assert spec["volumes"][0]["hostPath"]["path"] == "/var/run/docker.sock"


def test_same_indent_matches_deep_indent_structurally():
    a, b = loads(SAME_INDENT), loads(DEEP_INDENT)
    a_spec, b_spec = a["spec"]["template"]["spec"], b["spec"]["template"]["spec"]
    assert list(a_spec["containers"]) == list(b_spec["containers"])
    assert list(a_spec["volumes"]) == list(b_spec["volumes"])


def test_sibling_items_are_not_nested():
    """修复不能让 `- a / - b` 的兄弟项被误当成子序列。"""
    doc = loads("items:\n- a\n- b\n")
    assert list(doc["items"]) == ["a", "b"]


def test_scan_conclusion_is_indentation_independent():
    """同一份清单，两种缩进 → 同一份报告（含风险分）。"""
    a = scan_text(SAME_INDENT, path="same.yaml")
    b = scan_text(DEEP_INDENT, path="deep.yaml")
    a_ids = sorted((f.rule.id, f.line) for f in a.findings)
    b_ids = sorted((f.rule.id, f.line) for f in b.findings)
    assert a_ids == b_ids
    assert a.summary.workloads == b.summary.workloads == 1
    assert a.summary.containers == b.summary.containers == 1
    a_fp = (a.worst(), a.counts())
    b_fp = (b.worst(), b.counts())
    assert a_fp == b_fp, f"安全结论随排版漂移: same={a_fp} deep={b_fp}"
    assert a.counts()["critical"] > 0, "privileged 容器必须至少产生一条 critical"
    assert {f.rule.id for f in a.findings}, "同一份清单不可能零结论"