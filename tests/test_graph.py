"""Tests for the cross-resource pass — the reason this tool exists.

Every test here is a fact about **two** objects. None of them can be expressed
by a rule that only reads one manifest at a time, which is exactly the gap in a
single-object linter.
"""

from __future__ import annotations

from kubeguard.analyze import scan_text


def ids(text: str) -> set[str]:
    return {f.rule.id for f in scan_text(text, path="m.yaml").findings}


DEPLOY = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: c
          image: nginx:1.25
"""


def test_workload_without_network_policy_fires():
    assert "KG040" in ids(DEPLOY)


def test_network_policy_with_matching_selector_covers_it():
    policy = """\
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-only
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes: ["Ingress"]
"""
    assert "KG040" not in ids(DEPLOY + policy)


def test_network_policy_in_another_namespace_does_not_cover():
    policy = """\
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-only
  namespace: staging
spec:
  podSelector:
    matchLabels:
      app: web
"""
    assert "KG040" in ids(DEPLOY + policy)


def test_empty_pod_selector_covers_everything_in_namespace():
    policy = """\
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: prod
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
"""
    assert "KG040" not in ids(DEPLOY + policy)


def test_service_selector_matching_nothing():
    service = """\
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: prod
spec:
  selector:
    app: web
"""
    assert "KG041" not in ids(DEPLOY + service)
    assert "KG041" in ids(DEPLOY + service.replace("app: web\n", "app: webby\n"))


def test_service_selector_is_namespace_scoped():
    service = """\
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: other
spec:
  selector:
    app: web
"""
    assert "KG041" in ids(DEPLOY + service)


def test_ingress_backend_service_missing():
    ingress = """\
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: prod
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: checkout
                port:
                  number: 80
"""
    assert "KG042" in ids(DEPLOY + ingress)


def test_ingress_backend_service_present():
    service = """\
---
apiVersion: v1
kind: Service
metadata:
  name: checkout
  namespace: prod
spec:
  selector:
    app: web
"""
    ingress = """\
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: prod
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: checkout
                port:
                  number: 80
"""
    assert "KG042" not in ids(DEPLOY + service + ingress)


def test_legacy_ingress_backend_shape():
    ingress = """\
---
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: web
  namespace: prod
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            backend:
              serviceName: checkout
              servicePort: 80
"""
    assert "KG042" in ids(DEPLOY + ingress)


def test_undefined_service_account():
    text = DEPLOY.replace("  template:\n", "  template:\n").replace(
        "    spec:\n      containers:", "    spec:\n      serviceAccountName: backup\n      containers:"
    )
    assert "KG043" in ids(text)


def test_defined_service_account_is_clean():
    sa = """\
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: backup
  namespace: prod
"""
    text = DEPLOY.replace("    spec:\n      containers:", "    spec:\n      serviceAccountName: backup\n      containers:")
    # the template labels live under spec.template.metadata, so patch there
    assert "KG043" not in ids(text + sa)


def test_default_service_account_is_never_missing():
    text = DEPLOY.replace("    spec:\n      containers:", "    spec:\n      serviceAccountName: default\n      containers:")
    assert "KG043" not in ids(text)


def test_escalation_combination_is_detected():
    text = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: writer
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["escalate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: writer
subjects:
  - kind: ServiceAccount
    name: bot
    namespace: prod
"""
    assert "KG044" in ids(text)


def test_escalation_needs_the_rbac_resource():
    text = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: writer
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["escalate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: writer
subjects:
  - kind: ServiceAccount
    name: bot
    namespace: prod
"""
    assert "KG044" not in ids(text)


def test_wildcard_alone_is_an_escalation_path():
    text = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: everything
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: everything
subjects:
  - kind: ServiceAccount
    name: bot
    namespace: prod
"""
    assert "KG044" in ids(text)


def test_resource_quota_missing():
    assert "KG045" in ids(DEPLOY)


def test_resource_quota_present():
    quota = """\
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: prod-quota
  namespace: prod
spec:
  hard:
    requests.cpu: "4"
"""
    assert "KG045" not in ids(DEPLOY + quota)


def test_graph_findings_report_the_workload_label():
    report = scan_text(DEPLOY, path="m.yaml")
    finding = next(f for f in report.findings if f.rule.id == "KG040")
    assert finding.resource == "prod:Deployment/web"


def test_cross_resource_requires_the_whole_set():
    # the Service is correct only when the Deployment is in the same scan
    service = """\
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: prod
spec:
  selector:
    app: web
"""
    assert "KG041" in ids(service)
    assert "KG041" not in ids(DEPLOY + "---\n" + service)
