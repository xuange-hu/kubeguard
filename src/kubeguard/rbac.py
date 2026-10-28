"""RBAC aggregation: from individual rules to what a subject can actually do.

This module exists because the interesting RBAC risk is never in one rule. A
Role that grants ``create`` on ``roles`` looks harmless; the same Role that also
grants ``escalate`` is a cluster takeover in two API calls. Reading rules one at
a time cannot see that — so we resolve RoleBindings into subjects, union every
permission each subject inherits, and then judge the *combination*.

Deliberately offline: no cluster, no ``kubectl auth can-i``. Everything is
derived from the manifests, which is what makes it usable in CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .manifest import Resource, dig, item_line, key_line, node_line, seq_items, str_list, sval

ESCALATE_VERBS = {"escalate", "bind", "impersonate"}
DANGEROUS_BUILTINS = {"cluster-admin"}
PRIV_RESOURCES = {"secrets"}
EXEC_SUBRESOURCES = {"pods/exec", "pods/attach"}
RBAC_RESOURCES = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}


@dataclass
class PolicyRule:
    """One entry of a Role/ClusterRole ``rules:`` list."""

    line: int
    api_groups: list[str]
    resources: list[str]
    verbs: list[str]
    resource_names: list[str]
    role: str  # "Role/ns/name" or "ClusterRole/name"

    def covers(self, resource: str, verb: str) -> bool:
        """True when this rule alone authorises ``verb`` on ``resource``.

        ``pods`` is taken to imply ``pods/exec``: the API server treats a
        subresource as covered by its parent resource, and pretending otherwise
        would under-report exactly the rule that matters most.
        """
        verbs = {v.lower() for v in self.verbs}
        if "*" not in verbs and verb.lower() not in verbs:
            return False
        resources = {x.lower() for x in self.resources}
        if "*" in resources:
            return True
        target = resource.lower()
        return any(res == target or target.startswith(res + "/") for res in resources)

    def to_dict(self) -> dict:
        return {
            "line": self.line,
            "role": self.role,
            "apiGroups": self.api_groups,
            "resources": self.resources,
            "verbs": self.verbs,
            "resourceNames": self.resource_names,
        }


@dataclass
class Grant:
    """A binding edge: subject <- role, with the line to edit."""

    subject_kind: str
    subject_name: str
    subject_namespace: str
    role_kind: str
    role_name: str
    line: int
    binding: str

    @property
    def subject_key(self) -> str:
        if self.subject_kind.lower() == "serviceaccount":
            return f"ServiceAccount/{self.subject_namespace or 'default'}/{self.subject_name}"
        return f"{self.subject_kind}/{self.subject_name}"

    def to_dict(self) -> dict:
        return {
            "subject": self.subject_key,
            "role": f"{self.role_kind}/{self.role_name}",
            "binding": self.binding,
            "line": self.line,
        }


@dataclass
class Effective:
    """What one subject can do after every binding is resolved."""

    subject: str
    rules: list[PolicyRule] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)

    @property
    def verbs(self) -> set[str]:
        out: set[str] = set()
        for r in self.rules:
            out.update(v.lower() for v in r.verbs)
        return out

    @property
    def resources(self) -> set[str]:
        out: set[str] = set()
        for r in self.rules:
            out.update(x.lower() for x in r.resources)
        return out

    @property
    def api_groups(self) -> set[str]:
        out: set[str] = set()
        for r in self.rules:
            out.update(x.lower() for x in r.api_groups)
        return out

    @property
    def is_cluster_admin(self) -> bool:
        return any(g.role_name in DANGEROUS_BUILTINS for g in self.grants)

    @property
    def has_wildcard(self) -> bool:
        return "*" in self.verbs or "*" in self.resources

    @property
    def can_escalate(self) -> bool:
        """True when the subject can grant itself powers it does not have.

        Kubernetes treats escalate/bind/impersonate as privileged verbs: holding
        one of them on RBAC resources (or on ``*``) is equivalent to being able
        to become cluster-admin.
        """
        if self.is_cluster_admin:
            return True
        for r in self.rules:
            verbs = {v.lower() for v in r.verbs}
            if not (verbs & ESCALATE_VERBS) and "*" not in verbs:
                continue
            resources = {x.lower() for x in r.resources}
            if "*" in resources or resources & RBAC_RESOURCES:
                return True
        return False

    @property
    def can_exec(self) -> bool:
        return any(r.covers("pods/exec", "create") or r.covers("pods/attach", "create") for r in self.rules)

    @property
    def can_read_secrets(self) -> bool:
        return any(r.covers("secrets", verb) for r in self.rules for verb in ("get", "list", "watch"))

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "grants": [g.to_dict() for g in self.grants],
            "verbs": sorted(self.verbs),
            "resources": sorted(self.resources),
            "apiGroups": sorted(self.api_groups),
            "clusterAdmin": self.is_cluster_admin,
            "wildcard": self.has_wildcard,
            "canEscalate": self.can_escalate,
            "canExec": self.can_exec,
            "canReadSecrets": self.can_read_secrets,
            "rules": [r.to_dict() for r in self.rules],
        }


def role_key(kind: str, namespace: str, name: str) -> str:
    if kind.lower() == "clusterrole":
        return f"ClusterRole/{name}"
    return f"Role/{namespace or 'default'}/{name}"


def policy_rules_of(resource: Resource) -> list[PolicyRule]:
    """Parse a Role/ClusterRole body into policy rules with line numbers."""
    out: list[PolicyRule] = []
    rules_node = dig(resource.body, "rules")
    role_label = f"{resource.kind}/{resource.namespace + '/' if resource.namespace else ''}{resource.name}"
    for index, item in seq_items(rules_node):
        if not isinstance(item, dict):
            continue
        line = item_line(rules_node, index, node_line(item, resource.line))
        out.append(
            PolicyRule(
                line=line,
                api_groups=[g.lower() for g in str_list(item.get("apiGroups"))] or [""],
                resources=str_list(item.get("resources")),
                verbs=str_list(item.get("verbs")),
                resource_names=str_list(item.get("resourceNames")),
                role=role_label,
            )
        )
    return out


def grants_of(resource: Resource) -> list[Grant]:
    """Parse a (Cluster)RoleBinding body into subject<-role edges."""
    out: list[Grant] = []
    subjects = dig(resource.body, "subjects")
    role_ref = dig(resource.body, "roleRef")
    role_kind = sval(role_ref.get("kind")) if isinstance(role_ref, dict) else ""
    role_name = sval(role_ref.get("name")) if isinstance(role_ref, dict) else ""
    ref_line = key_line(resource.body, "roleRef", resource.line)
    binding_label = f"{resource.kind}/{resource.namespace + '/' if resource.namespace else ''}{resource.name}"
    for index, item in seq_items(subjects):
        if not isinstance(item, dict):
            continue
        out.append(
            Grant(
                subject_kind=sval(item.get("kind")) or "ServiceAccount",
                subject_name=sval(item.get("name")),
                subject_namespace=sval(item.get("namespace")) or (resource.namespace if sval(item.get("kind")).lower() == "serviceaccount" else ""),
                role_kind=role_kind or "Role",
                role_name=role_name,
                line=item_line(subjects, index, ref_line),
                binding=binding_label,
            )
        )
    return out


def aggregate(resources: list[Resource]) -> dict[str, Effective]:
    """Resolve every binding in the manifest set into per-subject permissions."""
    roles: dict[str, list[PolicyRule]] = {}
    for res in resources:
        if res.kind.lower() in ("role", "clusterrole"):
            roles.setdefault(role_key(res.kind, res.namespace, res.name), []).extend(policy_rules_of(res))

    out: dict[str, Effective] = {}
    for res in resources:
        if res.kind.lower() not in ("rolebinding", "clusterrolebinding"):
            continue
        for grant in grants_of(res):
            eff = out.setdefault(grant.subject_key, Effective(subject=grant.subject_key))
            eff.grants.append(grant)
            # A ClusterRoleBinding points at a ClusterRole; a RoleBinding in ns N
            # can point at a Role in N **or** a ClusterRole (scoped down to N).
            ns = res.namespace if grant.role_kind.lower() == "role" else ""
            key = role_key(grant.role_kind, ns, grant.role_name)
            if grant.role_name in DANGEROUS_BUILTINS:
                # cluster-admin is not in this repo's manifests — synthesise the
                # one rule it stands for so downstream properties stay honest.
                eff.rules.append(
                    PolicyRule(
                        line=grant.line,
                        api_groups=["*"],
                        resources=["*"],
                        verbs=["*"],
                        resource_names=[],
                        role=f"{grant.role_kind}/{grant.role_name}",
                    )
                )
            eff.rules.extend(roles.get(key, []))
    return out


def service_accounts_in(resources: list[Resource]) -> set[str]:
    out: set[str] = set()
    for res in resources:
        if res.kind.lower() == "serviceaccount":
            out.add(f"ServiceAccount/{res.namespace or 'default'}/{res.name}")
    return out


def unreferenced_service_accounts(resources: list[Resource]) -> list[tuple[str, int]]:
    """ServiceAccounts defined but never bound — dead permission surface."""
    bound = set(aggregate(resources).keys())
    out: list[tuple[str, int]] = []
    for res in resources:
        if res.kind.lower() != "serviceaccount":
            continue
        key = f"ServiceAccount/{res.namespace or 'default'}/{res.name}"
        if key not in bound:
            out.append((key, res.line))
    return out


def pod_service_account(resource: Resource) -> tuple[str, int]:
    """``(serviceAccountName, line)`` of a pod spec; empty when unspecified."""
    for path in (("spec", "template", "spec"), ("spec", "jobTemplate", "spec", "template", "spec"), ("spec",)):
        spec = dig(resource.body, *path)
        if not isinstance(spec, dict):
            continue
        name = spec.get("serviceAccountName") or spec.get("serviceAccount")
        if name is None:
            continue
        line = key_line(spec, "serviceAccountName", 0) or key_line(spec, "serviceAccount", 0)
        return (sval(name), line or resource.line)
    return ("", 0)
