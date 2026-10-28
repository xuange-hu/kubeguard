"""Tests for the manifest model: resource extraction and the PodSpec view."""

from __future__ import annotations

import os

import pytest

from kubeguard.manifest import (
    Resource,
    bool_of,
    containers_of,
    dig,
    iter_yaml_files,
    key_line,
    load_manifest_set,
    matches_selector,
    pod_spec_of,
    resource_from_body,
    selector_of,
    str_list,
    sval,
    template_labels_of,
    workload_iter,
)
from kubeguard.rbac import pod_service_account
from kubeguard.yamlio import loads


def res(text: str, path: str = "m.yaml") -> Resource:
    return resource_from_body(loads(text), path, 0)


def test_resource_fields():
    r = res("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: prod\n")
    assert (r.kind, r.name, r.namespace, r.api_version) == ("Deployment", "web", "prod", "apps/v1")
    assert r.label == "prod:Deployment/web"


def test_resource_without_kind_is_skipped():
    assert resource_from_body(loads("spec:\n  x: 1\n"), "m.yaml", 0) is None


def test_pod_spec_of_pod():
    r = res("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n")
    assert pod_spec_of(r) is not None


def test_pod_spec_of_deployment():
    r = res(
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: a\n"
    )
    assert pod_spec_of(r) is not None


def test_pod_spec_of_cronjob():
    r = res(
        "apiVersion: batch/v1\nkind: CronJob\nspec:\n  jobTemplate:\n    spec:\n      template:\n"
        "        spec:\n          containers:\n            - name: a\n"
    )
    assert pod_spec_of(r) is not None


def test_pod_spec_of_service_is_none():
    r = res("apiVersion: v1\nkind: Service\nspec:\n  selector:\n    app: web\n")
    assert pod_spec_of(r) is None


def test_containers_include_init_containers():
    r = res(
        "kind: Pod\nspec:\n  initContainers:\n    - name: init\n  containers:\n    - name: main\n"
    )
    spec = pod_spec_of(r)
    names = [(c.name, c.role) for c in containers_of(spec)]
    assert names == [("main", "container"), ("init", "initContainer")]


def test_container_lines_point_at_the_container():
    text = "kind: Pod\nspec:\n  containers:\n    - name: a\n      image: x:1\n    - name: b\n      image: y:1\n"
    spec = pod_spec_of(res(text))
    containers = containers_of(spec)
    assert containers[0].line == 4
    assert containers[1].line == 6


def test_selector_matchlabels_shape():
    r = res("kind: Deployment\nspec:\n  selector:\n    matchLabels:\n      app: web\n")
    assert selector_of(r) == {"app": "web"}


def test_selector_flat_shape():
    r = res("kind: Service\nspec:\n  selector:\n    app: web\n")
    assert selector_of(r) == {"app": "web"}


def test_template_labels_beat_metadata_labels():
    r = res(
        "kind: Deployment\nmetadata:\n  labels:\n    outer: yes\nspec:\n  template:\n    metadata:\n"
        "      labels:\n        app: web\n"
    )
    assert template_labels_of(r) == {"app": "web"}


def test_matches_selector_semantics():
    assert matches_selector({"app": "web", "tier": "a"}, {"app": "web"}) is True
    assert matches_selector({"app": "api"}, {"app": "web"}) is False
    assert matches_selector({"app": "web"}, {}) is False


def test_workload_iter_picks_every_workload():
    docs = [
        "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: a\n",
        "kind: Service\nspec:\n  selector:\n    app: a\n",
        "kind: Pod\nspec:\n  containers:\n    - name: b\n",
    ]
    resources = [res(d) for d in docs]
    assert len(workload_iter(resources)) == 2


def test_bool_of_tri_state():
    assert bool_of(True) is True
    assert bool_of("false") is False
    assert bool_of(None) is None
    assert bool_of("garbage", default=None) is None


def test_dig_and_sval():
    node = loads("a:\n  b:\n    c: 5\n")
    assert dig(node, "a", "b", "c") == 5
    assert dig(node, "a", "x") is None
    assert sval(None) == ""


def test_str_list_normalises():
    assert str_list("a") == ["a"]
    assert str_list(loads("x: [a, b]\n")["x"]) == ["a", "b"]
    assert str_list(None) == []


def test_pod_service_account_defaults_to_empty():
    r = res("kind: Pod\nspec:\n  containers:\n    - name: a\n")
    assert pod_service_account(r) == ("", 0)


def test_pod_service_account_reports_line():
    r = res("kind: Pod\nspec:\n  serviceAccountName: backup\n  containers:\n    - name: a\n")
    name, line = pod_service_account(r)
    assert name == "backup"
    assert line == 3


def test_iter_yaml_files_skips_noise(tmp_path):
    (tmp_path / "a.yaml").write_text("kind: Pod\n", encoding="utf-8")
    (tmp_path / "b.yml").write_text("kind: Pod\n", encoding="utf-8")
    (tmp_path / "c.txt").write_text("nope", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "d.yaml").write_text("kind: Pod\n", encoding="utf-8")
    found = [os.path.basename(p) for p in iter_yaml_files(str(tmp_path))]
    assert found == ["a.yaml", "b.yml"]


def test_load_manifest_set_accepts_a_file(tmp_path):
    path = tmp_path / "one.yaml"
    path.write_text("kind: Pod\nmetadata:\n  name: p\n", encoding="utf-8")
    manifest = load_manifest_set(str(path))
    assert len(manifest.resources) == 1
    assert manifest.files == [str(path)]


def test_key_line_falls_back_to_node_line():
    node = loads("a: 1\n")
    # an unknown key reports the mapping's own line — still a useful anchor
    assert key_line(node, "missing", 7) == 1
    assert key_line(node, "a", 7) == 1


def test_crlf_input_is_accepted(tmp_path):
    path = tmp_path / "crlf.yaml"
    path.write_bytes(b"kind: Pod\r\nspec:\r\n  containers:\r\n    - name: a\r\n")
    manifest = load_manifest_set(str(path))
    assert manifest.resources[0].kind == "Pod"


def test_broken_file_becomes_an_error_not_a_crash(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("kind: Pod\nspec:\n  - name: a\nthis is not a mapping line\n", encoding="utf-8")
    manifest = load_manifest_set(str(path))
    assert manifest.errors


@pytest.mark.parametrize("kind", ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"])
def test_every_workload_kind_is_detected(kind):
    text = f"kind: {kind}\nspec:\n  template:\n    spec:\n      containers:\n        - name: a\n"
    assert pod_spec_of(res(text)) is not None
