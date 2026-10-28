"""Tests for the RBAC pass and the effective-permission aggregation."""

from __future__ import annotations

from kubeguard.analyze import scan_text
from kubeguard.manifest import resource_from_body
from kubeguard.rbac import aggregate, policy_rules_of, unreferenced_service_accounts
from kubeguard.yamlio import loads


def res(text: str):
    return resource_from_body(loads(text), "rbac.yaml", 0)


def ids(text: str) -> set[str]:
    return {f.rule.id for f in scan_text(text, path="rbac.yaml").findings}


ROLE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sample
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
"""

WILDCARD = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sample
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""


def test_wildcard_verb():
    assert "KG030" in ids(WILDCARD)


def test_explicit_verbs_are_clean():
    assert "KG030" not in ids(ROLE)


def test_wildcard_resource_and_group():
    found = ids(WILDCARD)
    assert "KG031" in found


def test_wildcard_group_only():
    text = ROLE.replace('apiGroups: [""]', 'apiGroups: ["*"]')
    assert "KG031" in ids(text)


def test_secret_read():
    text = ROLE.replace('resources: ["pods"]', 'resources: ["secrets"]')
    assert "KG032" in ids(text)


def test_secret_write_only_does_not_fire():
    text = ROLE.replace('resources: ["pods"]', 'resources: ["secrets"]').replace('verbs: ["get", "list"]', 'verbs: ["create"]')
    assert "KG032" not in ids(text)


def test_pods_exec():
    text = ROLE.replace('resources: ["pods"]', 'resources: ["pods/exec"]').replace('verbs: ["get", "list"]', 'verbs: ["create"]')
    assert "KG033" in ids(text)


def test_escalate_verb():
    text = ROLE.replace('resources: ["pods"]', 'resources: ["clusterroles"]').replace('verbs: ["get", "list"]', 'verbs: ["escalate"]')
    assert "KG034" in ids(text)


def test_impersonate_verb():
    text = ROLE.replace('verbs: ["get", "list"]', 'verbs: ["impersonate"]')
    assert "KG034" in ids(text)


def test_cluster_admin_binding():
    text = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: ci
    namespace: default
"""
    assert "KG035" in ids(text)


def test_system_masters_group_binding():
    text = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - kind: Group
    name: system:masters
    apiGroup: rbac.authorization.k8s.io
"""
    assert "KG035" in ids(text)


def test_ordinary_binding_is_clean():
    text = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ok
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - kind: ServiceAccount
    name: ci
    namespace: default
"""
    assert "KG035" not in ids(text)


def test_policy_rules_keep_lines():
    rules = policy_rules_of(res(ROLE))
    assert len(rules) == 1
    assert rules[0].line == 6
    assert rules[0].resources == ["pods"]


def test_aggregate_resolves_clusterrolebinding():
    text = WILDCARD + """\
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: sample
subjects:
  - kind: ServiceAccount
    name: bot
    namespace: prod
"""
    resources = [resource_from_body(doc, "x.yaml", i) for i, doc in enumerate(_docs(text))]
    eff = aggregate(resources)
    assert "ServiceAccount/prod/bot" in eff
    entry = eff["ServiceAccount/prod/bot"]
    assert entry.has_wildcard is True
    assert entry.can_read_secrets is True
    assert entry.can_escalate is True


def test_aggregate_resolves_rolebinding_to_a_namespaced_role():
    role = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
  namespace: prod
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
"""
    binding = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: reader
subjects:
  - kind: ServiceAccount
    name: app
    namespace: prod
"""
    resources = [resource_from_body(d, "x.yaml", i) for i, d in enumerate(_docs(role + "---\n" + binding))]
    eff = aggregate(resources)["ServiceAccount/prod/app"]
    assert eff.resources == {"configmaps"}
    assert eff.can_escalate is False


def test_role_in_another_namespace_does_not_resolve():
    role = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
  namespace: other
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
"""
    binding = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: reader
subjects:
  - kind: ServiceAccount
    name: app
    namespace: prod
"""
    resources = [resource_from_body(d, "x.yaml", i) for i, d in enumerate(_docs(role + "---\n" + binding))]
    eff = aggregate(resources)["ServiceAccount/prod/app"]
    assert eff.resources == set()


def test_cluster_admin_builtin_is_modelled_as_full_power():
    text = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: bot
    namespace: prod
"""
    resources = [resource_from_body(d, "x.yaml", i) for i, d in enumerate(_docs(text))]
    eff = aggregate(resources)["ServiceAccount/prod/bot"]
    assert eff.is_cluster_admin is True
    assert eff.can_read_secrets is True


def test_exec_detection_uses_subresource_coverage():
    text = ROLE.replace('resources: ["pods"]', 'resources: ["pods/exec"]').replace('verbs: ["get", "list"]', 'verbs: ["create"]')
    resources = [res(text)]
    from kubeguard.rbac import policy_rules_of as _p

    assert _p(resources[0])[0].covers("pods/exec", "create") is True


def test_unreferenced_service_accounts():
    sa = "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: orphan\n  namespace: prod\n"
    resources = [resource_from_body(d, "x.yaml", i) for i, d in enumerate(_docs(sa))]
    assert unreferenced_service_accounts(resources) == [("ServiceAccount/prod/orphan", 2)]


def test_effective_to_dict_is_json_shaped():
    resources = [resource_from_body(d, "x.yaml", i) for i, d in enumerate(_docs(ROLE))]
    from kubeguard.rbac import aggregate as _agg

    # no bindings -> no subjects, but the shape must not explode
    assert _agg(resources) == {}


def _docs(text: str):
    from kubeguard.yamlio import load_documents

    return load_documents(text)
