"""The rule engine: pod rules, RBAC rules, and the cross-resource pass.

Three passes, in order of how much context they need:

1. ``_check_workload``  — one resource at a time (privileged, probes, image tag…)
2. ``_check_rbac``      — one Role at a time, plus bindings to built-in admins
3. ``_check_graph``     — the whole manifest set at once

Pass 3 is the reason this tool exists. Kubernetes' default is *allow all*, so
"this Deployment is not covered by any NetworkPolicy" is a fact about the
**relationship** between two objects — no single-object linter can see it. Same
for "this ServiceAccount's permissions combine into cluster takeover": the
danger is in the union, not in any one rule.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from .manifest import (
    Container,
    ManifestSet,
    Resource,
    bool_of,
    containers_of,
    dig,
    is_map,
    item_line,
    key_line,
    load_manifest_set,
    matches_selector,
    node_line,
    pod_selector_of,
    pod_spec_of,
    resource_from_body,
    selector_of,
    seq_items,
    str_list,
    sval,
    template_labels_of,
    workload_iter,
)
from .model import SEVERITY_RANK, Finding, ManifestSummary, Report, parse_severity
from .rbac import (
    ESCALATE_VERBS,
    EXEC_SUBRESOURCES,
    PRIV_RESOURCES,
    aggregate,
    pod_service_account,
    policy_rules_of,
)
from .rules import RULES, all_rules
from .yamlio import load_documents

DANGEROUS_CAPABILITIES = {
    "ALL": "ALL",
    "SYS_ADMIN": "SYS_ADMIN",
    "SYS_PTRACE": "SYS_PTRACE",
    "SYS_MODULE": "SYS_MODULE",
    "NET_ADMIN": "NET_ADMIN",
    "DAC_READ_SEARCH": "DAC_READ_SEARCH",
    "SYS_RAWIO": "SYS_RAWIO",
}

RUNTIME_SOCKETS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/cri-dockerd.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
)

DEPRECATED_API_VERSIONS = {
    "extensions/v1beta1": "apps/v1",
    "apps/v1beta1": "apps/v1",
    "apps/v1beta2": "apps/v1",
    "networking.k8s.io/v1beta1": "networking.k8s.io/v1",
    "policy/v1beta1": "policy/v1",
    "batch/v1beta1": "batch/v1",
    "autoscaling/v2beta1": "autoscaling/v2",
    "autoscaling/v2beta2": "autoscaling/v2",
    "rbac.authorization.k8s.io/v1beta1": "rbac.authorization.k8s.io/v1",
    "rbac.authorization.k8s.io/v1alpha1": "rbac.authorization.k8s.io/v1",
    "scheduling.k8s.io/v1beta1": "scheduling.k8s.io/v1",
}

SECRET_KEY_HINT = re.compile(
    r"(PASSWD|PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|AUTH)",
    re.IGNORECASE,
)
REF_HINT = re.compile(r"^(\$\(|\$\{|vault:|secretKeyRef|<)", re.IGNORECASE)

RECOMMENDED_LABELS = ("app.kubernetes.io/name", "app.kubernetes.io/part-of")

SECCCOMP_ANNOTATION = "seccomp.security.alpha.kubernetes.io/pod"


@dataclass
class Options:
    min_severity: str = "info"
    ignore: list[str] = field(default_factory=list)

    def wants(self, rule_id: str) -> bool:
        return rule_id.upper() not in {i.upper() for i in self.ignore}


@dataclass
class _Ctx:
    """Per-resource scratch space: source text, accumulator, suppression state."""

    path: str
    lines: list[str]
    resource: Resource
    findings: list[Finding]
    options: Options
    suppressed: int = 0

    def snippet(self, line: int) -> str:
        if 0 < line <= len(self.lines):
            return self.lines[line - 1].strip()[:120]
        return ""

    def emit(self, rule_id: str, line: int, detail: str, resource_label: str | None = None) -> None:
        rule = RULES[rule_id]
        if not self.options.wants(rule_id):
            self.suppressed += 1
            return
        if self._suppressed(rule_id, line):
            self.suppressed += 1
            return
        self.findings.append(
            Finding(
                rule=rule,
                path=self.path,
                line=max(1, line or self.resource.line),
                resource=resource_label or self.resource.label,
                snippet=self.snippet(line),
                detail=detail,
            )
        )

    def _suppressed(self, rule_id: str, line: int) -> bool:
        """Honour ``# kubeguard: ignore=KG001,KG002`` on the finding or resource line."""
        candidates = {line, self.resource.line}
        for candidate in candidates:
            if not 0 < candidate <= len(self.lines):
                continue
            match = re.search(r"#\s*kubeguard:\s*ignore(?:=([A-Za-z0-9_,\s]+))?", self.lines[candidate - 1])
            if not match:
                continue
            ids = (match.group(1) or "").strip()
            if not ids:
                return True
            if rule_id in {part.strip().upper() for part in ids.split(",")}:
                return True
        return False


# -- effective securityContext -----------------------------------------------


def _sc_value(container: Container, pod_spec: Any, key: str) -> tuple[Any, int]:
    """Resolve a securityContext field, container first then pod, with its line.

    Kubernetes merges these two levels (container wins), so a rule that only
    looks at the container reports false positives on every manifest that
    configures the pod level — which is a very common, and correct, style.
    """
    csc = container.body.get("securityContext")
    if is_map(csc) and key in csc:
        return csc.get(key), key_line(csc, key, container.line)
    psc = pod_spec.get("securityContext") if is_map(pod_spec) else None
    if is_map(psc) and key in psc:
        return psc.get(key), key_line(psc, key, node_line(pod_spec, container.line))
    return None, container.line


def _is_true(value: Any) -> bool:
    """True only when the field is *explicitly* true.

    ``default=None`` is the whole point: Kubernetes' default for
    allowPrivilegeEscalation / privileged / hostNetwork is "unset", and an unset
    field must never be reported as a confident true.
    """
    return bool_of(value, default=None) is True


def _is_false(value: Any) -> bool:
    """True only when the field is *explicitly* false."""
    return bool_of(value, default=None) is False


# -- pass 1: workloads --------------------------------------------------------


def _image_parts(image: str) -> tuple[str, str, str]:
    """``(repository, tag, digest)`` from an image reference."""
    digest = ""
    ref = image
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    # a registry with a port looks like host:5000/x — split on the *last* colon
    # that is followed by something without a slash.
    tag = ""
    head, sep, tail = ref.rpartition(":")
    if sep and "/" not in tail:
        ref, tag = head, tail
    return ref, tag, digest


def _check_workload(ctx: _Ctx, resource: Resource, pod_spec: Any) -> None:
    containers = containers_of(pod_spec)

    # pod-level namespace sharing
    for key, rid, label in (
        ("hostPID", "KG003", "hostPID"),
        ("hostIPC", "KG004", "hostIPC"),
        ("hostNetwork", "KG005", "hostNetwork"),
    ):
        value = pod_spec.get(key)
        if _is_true(value):
            ctx.emit(rid, key_line(pod_spec, key, resource.line), f"spec.{label}: true — 与宿主共享 {label}")

    # hostPath volumes (runtime sockets get their own, louder rule)
    volumes = pod_spec.get("volumes")
    for index, volume in seq_items(volumes):
        if not is_map(volume):
            continue
        host_path = dig(volume, "hostPath", "path")
        if host_path is None:
            continue
        line = item_line(volumes, index, node_line(volume, resource.line))
        path = sval(host_path)
        if any(path.rstrip("/").endswith(sock.rsplit("/", 1)[-1]) or path.rstrip("/") == sock for sock in RUNTIME_SOCKETS):
            ctx.emit("KG002", line, f"挂载运行时 socket：{path}")
        else:
            ctx.emit("KG011", line, f"hostPath 卷：{path}")

    for container in containers:
        _check_container(ctx, resource, pod_spec, container)

    # service account wiring
    sa_name, sa_line = pod_service_account(resource)
    automount = pod_spec.get("automountServiceAccountToken")
    if not _is_false(automount):
        ctx.emit(
            "KG021",
            key_line(pod_spec, "automountServiceAccountToken", resource.line),
            "未设 automountServiceAccountToken: false，容器里会出现 SA token",
        )
    if not sa_name or sa_name == "default":
        ctx.emit("KG022", sa_line or resource.line, f"使用 ServiceAccount {sa_name or 'default'}")

    # deprecated apiVersion
    replacement = DEPRECATED_API_VERSIONS.get(resource.api_version)
    if replacement:
        ctx.emit(
            "KG024",
            key_line(resource.body, "apiVersion", resource.line),
            f"apiVersion {resource.api_version} 已废弃，应迁移到 {replacement}",
        )

    # recommended labels, on the template (what selectors actually read)
    labels = template_labels_of(resource)
    missing = [name for name in RECOMMENDED_LABELS if name not in labels]
    if missing:
        ctx.emit("KG025", resource.line, "缺少推荐标签：" + ", ".join(missing))


def _check_container(ctx: _Ctx, resource: Resource, pod_spec: Any, container: Container) -> None:
    label = f"{resource.label}[{container.label}]"

    sc = container.body.get("securityContext")
    sc_line = key_line(container.body, "securityContext", container.line)

    privileged, priv_line = _sc_value(container, pod_spec, "privileged")
    if _is_true(privileged):
        ctx.emit("KG001", priv_line, f"容器 {container.name or container.index} 以 privileged 运行", label)

    escalation, esc_line = _sc_value(container, pod_spec, "allowPrivilegeEscalation")
    if not _is_false(escalation):
        ctx.emit("KG006", esc_line, "allowPrivilegeEscalation 未显式关闭（默认允许 setuid 提权）", label)

    non_root, non_root_line = _sc_value(container, pod_spec, "runAsNonRoot")
    run_as_user, user_line = _sc_value(container, pod_spec, "runAsUser")
    uid = run_as_user if isinstance(run_as_user, int) else None
    if uid is None and sval(run_as_user).isdigit():
        uid = int(sval(run_as_user))
    if not _is_true(non_root) and not (isinstance(uid, int) and uid > 0):
        ctx.emit("KG007", non_root_line or user_line, "未限制 runAsNonRoot，容器可能以 root 运行", label)

    caps = sc.get("capabilities") if is_map(sc) else None
    added = str_list(caps.get("add")) if is_map(caps) else []
    dropped = str_list(caps.get("drop")) if is_map(caps) else []
    for cap in added:
        if cap.upper() in DANGEROUS_CAPABILITIES:
            ctx.emit(
                "KG008",
                key_line(caps, "add", sc_line) if is_map(caps) else sc_line,
                f"添加了高危 capability：{cap}",
                label,
            )
    if "ALL" not in {d.upper() for d in dropped} and "NET_RAW" not in {d.upper() for d in dropped}:
        ctx.emit(
            "KG009",
            key_line(caps, "drop", sc_line) if is_map(caps) else container.line,
            "默认 capability 集合中的 NET_RAW 未被 drop",
            label,
        )

    read_only, ro_line = _sc_value(container, pod_spec, "readOnlyRootFilesystem")
    if not _is_true(read_only):
        ctx.emit("KG010", ro_line, "根文件系统可写", label)

    seccomp, seccomp_line = _sc_value(container, pod_spec, "seccompProfile")
    annotations = dig(resource.body, "metadata", "annotations") or dig(resource.body, "spec", "template", "metadata", "annotations")
    has_annotation = is_map(annotations) and SECCCOMP_ANNOTATION in annotations
    if seccomp is None and not has_annotation:
        ctx.emit("KG020", seccomp_line, "未设 seccompProfile（默认 unconfined）", label)

    # ports
    ports = container.body.get("ports")
    for index, port in seq_items(ports):
        if not is_map(port):
            continue
        host_port = port.get("hostPort")
        if host_port is not None:
            ctx.emit(
                "KG012",
                item_line(ports, index, container.line),
                f"containerPort {sval(port.get('containerPort'))} 绑定 hostPort {sval(host_port)}",
                label,
            )

    # resources
    resources = container.body.get("resources")
    limits = resources.get("limits") if is_map(resources) else None
    requests = resources.get("requests") if is_map(resources) else None
    res_line = key_line(container.body, "resources", container.line)
    if not is_map(limits) or not (limits.get("cpu") or limits.get("memory")):
        ctx.emit("KG013", res_line, "resources.limits 缺少 cpu 或 memory", label)
    if not is_map(requests) or not (requests.get("cpu") or requests.get("memory")):
        ctx.emit("KG014", res_line, "resources.requests 缺少 cpu 或 memory", label)

    # image hygiene
    image = container.image
    if image:
        _, tag, digest = _image_parts(image)
        image_line = key_line(container.body, "image", container.line)
        # a digest makes the reference immutable even when the tag says latest
        mutable = not digest and (not tag or tag.lower() == "latest")
        if mutable:
            ctx.emit("KG015", image_line, f"镜像 tag 可变：{image}", label)
        if not digest:
            ctx.emit("KG016", image_line, f"镜像未用摘要锁定：{image}", label)
        if not digest:
            pull_policy = container.body.get("imagePullPolicy")
            # k8s defaults: Always for :latest/absent, IfNotPresent otherwise
            effective = sval(pull_policy) or ("Always" if mutable else "IfNotPresent")
            if not mutable and effective.lower() != "always":
                ctx.emit(
                    "KG017",
                    key_line(container.body, "imagePullPolicy", image_line),
                    f"imagePullPolicy = {effective}",
                    label,
                )

    # probes (init containers legitimately have neither)
    if container.role == "container":
        if container.body.get("readinessProbe") is None:
            ctx.emit("KG018", container.line, "缺少 readinessProbe", label)
        if container.body.get("livenessProbe") is None:
            ctx.emit("KG019", container.line, "缺少 livenessProbe", label)

    # plaintext secrets
    env = container.body.get("env")
    for index, entry in seq_items(env):
        if not is_map(entry):
            continue
        name = sval(entry.get("name"))
        value = entry.get("value")
        if value is None or not sval(value):
            continue
        if not SECRET_KEY_HINT.search(name):
            continue
        if REF_HINT.search(sval(value)):
            continue
        ctx.emit(
            "KG023",
            item_line(env, index, container.line),
            f"env {name} 疑似明文密钥（长度 {len(sval(value))}）",
            label,
        )


# -- pass 2: RBAC -------------------------------------------------------------


def _check_rbac(ctx: _Ctx, resource: Resource) -> None:
    kind = resource.kind.lower()
    if kind in ("role", "clusterrole"):
        for pr in policy_rules_of(resource):
            verbs = {v.lower() for v in pr.verbs}
            resources = {r.lower() for r in pr.resources}
            groups = {g.lower() for g in pr.api_groups}
            if "*" in verbs:
                ctx.emit("KG030", pr.line, "verbs 使用通配符 *")
            if "*" in resources or "*" in groups:
                ctx.emit("KG031", pr.line, "resources 或 apiGroups 使用通配符 *")
            if (resources & PRIV_RESOURCES or "*" in resources) and verbs & {"get", "list", "watch", "*"}:
                ctx.emit("KG032", pr.line, "可读取 secrets")
            if resources & EXEC_SUBRESOURCES:
                ctx.emit("KG033", pr.line, "可在容器内执行命令（pods/exec 或 attach）")
            if verbs & ESCALATE_VERBS:
                ctx.emit("KG034", pr.line, "持有提权动词：" + ", ".join(sorted(verbs & ESCALATE_VERBS)))
        return

    if kind in ("rolebinding", "clusterrolebinding"):
        role_ref = dig(resource.body, "roleRef")
        role_name = sval(role_ref.get("name")) if is_map(role_ref) else ""
        ref_line = key_line(resource.body, "roleRef", resource.line)
        if role_name in ("cluster-admin", "admin") and kind == "clusterrolebinding":
            ctx.emit("KG035", ref_line, f"ClusterRoleBinding 指向 {role_name}")
        subjects = dig(resource.body, "subjects")
        for index, subject in seq_items(subjects):
            if not is_map(subject):
                continue
            name = sval(subject.get("name"))
            sub_kind = sval(subject.get("kind")).lower()
            line = item_line(subjects, index, ref_line)
            if name == "cluster-admin" or (sub_kind == "group" and name == "system:masters"):
                ctx.emit("KG035", line, f"{sval(subject.get('kind'))} {name} 被授予集群管理员权限")


# -- pass 3: cross-resource ---------------------------------------------------


def _resource_by_name(resources: list[Resource], role_label: str) -> Resource | None:
    """Find the Role/ClusterRole a policy rule came from, by its printed label.

    ``PolicyRule.role`` is already formatted as ``ClusterRole/<name>`` or
    ``Role/<ns>/<name>``; matching on the name suffix is enough and keeps the
    rule object free of a back-pointer.
    """
    name = role_label.rsplit("/", 1)[-1]
    for resource in resources:
        if resource.kind.lower() in ("role", "clusterrole") and resource.name == name:
            return resource
    return None


def _dummy(label: str) -> Resource:
    """A stand-in resource for findings that belong to no single object."""
    return Resource(path="", doc_index=-1, line=1, kind="", api_version="", name=label, namespace="", body={})


def _check_graph(ctx_for, manifest: ManifestSet) -> None:
    """The cross-resource pass.

    ``ctx_for(resource)`` builds a fresh context per object, because a finding
    about two objects still has to point at the one a human edits — and the
    inline ``# kubeguard: ignore`` marker lives in that object's file.
    """
    resources = manifest.resources
    workloads = workload_iter(resources)
    policies = [r for r in resources if r.kind.lower() == "networkpolicy"]
    services = [r for r in resources if r.kind.lower() == "service"]
    quotas = {r.namespace for r in resources if r.kind.lower() == "resourcequota"}
    accounts = {(r.namespace, r.name) for r in resources if r.kind.lower() == "serviceaccount"}

    for resource, _pod_spec in workloads:
        ctx = ctx_for(resource)
        labels = template_labels_of(resource)
        covered = False
        for policy in policies:
            if policy.namespace != resource.namespace:
                continue
            selector = pod_selector_of(policy)
            if not selector or matches_selector(labels, selector):
                covered = True
                break
        if not covered:
            ctx.emit("KG040", resource.line, f"{resource.label} 没有任何 NetworkPolicy 选中它")

        sa_name, sa_line = pod_service_account(resource)
        if sa_name and sa_name != "default" and (resource.namespace, sa_name) not in accounts:
            ctx.emit("KG043", sa_line, f"引用了未定义的 ServiceAccount：{sa_name}")

    for service in services:
        selector = selector_of(service)
        if not selector:
            continue
        matched = any(
            matches_selector(template_labels_of(res), selector) and res.namespace == service.namespace
            for res, _ in workloads
        )
        if not matched:
            ctx_for(service).emit(
                "KG041",
                key_line(dig(service.body, "spec") or {}, "selector", service.line),
                f"Service {service.name} 的 selector 匹配不到任何工作负载",
            )

    for ingress in (r for r in resources if r.kind.lower() == "ingress"):
        ctx = ctx_for(ingress)
        rules_node = dig(ingress.body, "spec", "rules")
        for rule_index, rule in seq_items(rules_node):
            if not is_map(rule):
                continue
            rule_line = item_line(rules_node, rule_index, ingress.line)
            paths = dig(rule, "http", "paths")
            for path_index, path in seq_items(paths):
                if not is_map(path):
                    continue
                backend = path.get("backend")
                # networking.k8s.io/v1 uses backend.service.name; the v1beta1
                # shape is a flat backend.serviceName. Both are still deployed.
                name = sval(dig(backend, "service", "name")) if is_map(backend) else ""
                if not name:
                    name = sval(dig(backend, "serviceName")) if is_map(backend) else sval(dig(path, "backend", "serviceName"))
                if not name:
                    continue
                if any(s.name == name and s.namespace == ingress.namespace for s in services):
                    continue
                ctx.emit(
                    "KG042",
                    item_line(paths, path_index, rule_line),
                    f"Ingress 后端 Service 不存在：{name}",
                )

    for subject, eff in sorted(aggregate(resources).items()):
        if eff.is_cluster_admin:
            continue  # already reported as KG035 at the binding
        if not eff.can_escalate:
            continue
        # anchor on the first rule that carries the dangerous combination
        worst = min((r for r in eff.rules if r.line), key=lambda r: r.line, default=None)
        anchor = _resource_by_name(resources, worst.role) if worst else None
        (anchor and ctx_for(anchor) or ctx_for(_dummy(subject))).emit(
            "KG044",
            worst.line if worst else 1,
            f"{subject} 的权限组合可提权到集群控制面"
            + ("（含通配动词）" if eff.has_wildcard else "（escalate/bind/impersonate）"),
        )

    for namespace in sorted({r.namespace for r in resources if r.namespace}):
        if namespace in quotas:
            continue
        anchor = next((r for r in resources if r.namespace == namespace), None)
        ctx_for(anchor or _dummy(namespace)).emit("KG045", 1, f"namespace {namespace} 没有 ResourceQuota")


# -- orchestration ------------------------------------------------------------


def _summary(manifest: ManifestSet) -> ManifestSummary:
    summary = ManifestSummary(files=len(manifest.files))
    images: list[str] = []
    accounts: list[str] = []
    root = 0
    for resource in manifest.resources:
        summary.kinds[resource.kind] = summary.kinds.get(resource.kind, 0) + 1
        if resource.namespace and resource.namespace not in summary.namespaces:
            summary.namespaces.append(resource.namespace)
        if resource.kind.lower() == "serviceaccount":
            key = f"{resource.namespace or 'default'}/{resource.name}"
            if key not in accounts:
                accounts.append(key)
        pod_spec = pod_spec_of(resource)
        if pod_spec is None:
            continue
        summary.workloads += 1
        for container in containers_of(pod_spec):
            summary.containers += 1
            if container.image and container.image not in images:
                images.append(container.image)
            non_root = container.body.get("securityContext")
            run_as = dig(non_root, "runAsNonRoot") if is_map(non_root) else None
            uid = dig(non_root, "runAsUser") if is_map(non_root) else None
            uid_int = uid if isinstance(uid, int) else (int(sval(uid)) if sval(uid).isdigit() else None)
            if not _is_true(run_as) and not (isinstance(uid_int, int) and uid_int > 0):
                root += 1
    summary.resources = len(manifest.resources)
    summary.images = images
    summary.service_accounts = accounts
    summary.runs_as_root = root
    return summary


def scan_text(text: str, path: str = "<stdin>", options: Options | None = None) -> Report:
    """Scan one YAML document stream held in memory (used by the MCP tool)."""
    options = options or Options()
    lines = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    manifest = ManifestSet(files=[path])
    try:
        manifest.resources = _resources_from_text(text, path)
    except Exception as exc:
        manifest.errors.append(f"{path}: {exc}")
    return _run(manifest, {path: lines}, options, root=path)


def _resources_from_text(text: str, path: str) -> list[Resource]:
    out: list[Resource] = []
    for index, doc in enumerate(load_documents(text)):
        res = resource_from_body(doc, path, index)
        if res is not None:
            out.append(res)
    return out


def scan_path(root: str, options: Options | None = None) -> Report:
    """Scan a file or a directory tree."""
    options = options or Options()
    manifest = load_manifest_set(root)
    sources: dict[str, list[str]] = {}
    for path in manifest.files:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                sources[path] = handle.read().replace("\r\n", "\n").replace("\r", "\n").splitlines()
        except OSError:
            sources[path] = []
    return _run(manifest, sources, options, root=root)


def _run(manifest: ManifestSet, sources: dict[str, list[str]], options: Options, root: str) -> Report:
    findings: list[Finding] = []
    by_file: dict[str, list[Resource]] = {}
    for resource in manifest.resources:
        by_file.setdefault(resource.path, []).append(resource)

    for path, resources in by_file.items():
        for resource in resources:
            ctx = _Ctx(
                path=path,
                lines=sources.get(path, []),
                resource=resource,
                findings=findings,
                options=options,
            )
            pod_spec = pod_spec_of(resource)
            if pod_spec is not None:
                _check_workload(ctx, resource, pod_spec)
            if resource.kind.lower() in ("role", "clusterrole", "rolebinding", "clusterrolebinding"):
                _check_rbac(ctx, resource)

    # the cross-resource pass needs every file at once, so it runs once here
    def ctx_for(resource: Resource) -> _Ctx:
        return _Ctx(
            path=resource.path or root,
            lines=sources.get(resource.path, []),
            resource=resource,
            findings=findings,
            options=options,
        )

    _check_graph(ctx_for, manifest)

    # apply the global severity floor here so every output format agrees
    rank = SEVERITY_RANK[parse_severity(options.min_severity)]
    findings = [f for f in findings if f.rule.severity_rank >= rank]
    findings.sort(key=lambda f: (-f.rule.severity_rank, f.path, f.line, f.rule.id))

    summary = _summary(manifest)
    summary.errors = list(manifest.errors)
    return Report(path=root, findings=findings, summary=summary, rules_run=len(all_rules()))


def scan_files(paths: list[str], options: Options | None = None) -> Report:
    """Scan several roots and merge the results into one report."""
    options = options or Options()
    merged: Report | None = None
    for path in paths:
        report = scan_path(path, options)
        if merged is None:
            merged = report
            continue
        merged.findings.extend(report.findings)
        merged.summary.files += report.summary.files
        merged.summary.resources += report.summary.resources
        for kind, count in report.summary.kinds.items():
            merged.summary.kinds[kind] = merged.summary.kinds.get(kind, 0) + count
        merged.summary.workloads += report.summary.workloads
        merged.summary.containers += report.summary.containers
        for image in report.summary.images:
            if image not in merged.summary.images:
                merged.summary.images.append(image)
        for account in report.summary.service_accounts:
            if account not in merged.summary.service_accounts:
                merged.summary.service_accounts.append(account)
        merged.summary.runs_as_root += report.summary.runs_as_root
    if merged is None:
        merged = Report(path="", findings=[], summary=ManifestSummary())
    merged.findings.sort(key=lambda f: (-f.rule.severity_rank, f.path, f.line, f.rule.id))
    return merged


def relpath(path: str, root: str) -> str:
    if not root or os.path.isfile(root):
        return os.path.basename(path) if path != root else path
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path
