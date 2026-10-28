"""Manifest model: resources, the unified PodSpec view, and file discovery.

The one abstraction that earns its keep here is :func:`pod_spec_of`. Kubernetes
spreads "a pod" across nine kinds and four API groups, and every one of them
hides it at a different path:

    Pod                     spec
    Deployment/ReplicaSet   spec.template.spec
    DaemonSet/StatefulSet   spec.template.spec
    Job                     spec.template.spec
    CronJob                 spec.jobTemplate.spec.template.spec

Rather than hard-code (apiVersion, kind) pairs — which breaks the moment a beta
group shows up — this detects the shape: does ``spec`` itself carry containers,
or does a template somewhere under it? One rule implementation then covers all
workload kinds, forever.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .yamlio import L, M, load_documents

YAML_SUFFIXES = (".yaml", ".yml")
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "vendor",
}


@dataclass
class Resource:
    """One document of one file, reduced to what the rules need."""

    path: str
    doc_index: int
    line: int
    kind: str
    api_version: str
    name: str
    namespace: str
    body: Any

    @property
    def label(self) -> str:
        """``Deployment/web`` — the shortest unambiguous thing to print."""
        base = f"{self.kind}/{self.name}" if self.name else self.kind
        if self.namespace:
            base = f"{self.namespace}:{base}"
        return base

    @property
    def group_version(self) -> str:
        return self.api_version

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "doc": self.doc_index,
            "line": self.line,
            "kind": self.kind,
            "apiVersion": self.api_version,
            "name": self.name,
            "namespace": self.namespace,
        }


# -- generic accessors -------------------------------------------------------


def is_map(node: Any) -> bool:
    return isinstance(node, M)


def is_seq(node: Any) -> bool:
    return isinstance(node, L)


def dig(node: Any, *keys: str) -> Any:
    """Walk ``node`` through mapping keys, returning None on the first miss."""
    cur = node
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
        if cur is None:
            return None
    return cur


def node_line(node: Any, default: int = 0) -> int:
    """The source line of a node, or ``default`` for synthesised flow nodes."""
    line = getattr(node, "line", 0) or 0
    return line or default


def key_line(node: Any, key: str, default: int = 0) -> int:
    """The line where ``key:`` was written inside ``node``."""
    if isinstance(node, M):
        return node.klines.get(key) or node.line or default
    return node_line(node, default)


def item_line(node: Any, index: int, default: int = 0) -> int:
    """The line where sequence element ``index`` starts."""
    if isinstance(node, L):
        return node.ilines.get(index) or node.line or default
    return node_line(node, default)


def sval(node: Any) -> str:
    """Scalar as a plain str (``S`` is a str subclass; normalize anyway)."""
    if node is None:
        return ""
    if isinstance(node, bool):
        return "true" if node else "false"
    return str(node)


def bool_of(node: Any, default: bool | None = None) -> bool | None:
    """Kubernetes booleans arrive as Python bools from the reader."""
    if node is None:
        return default
    if isinstance(node, bool):
        return node
    text = sval(node).strip().lower()
    if text in ("true", "yes", "on"):
        return True
    if text in ("false", "no", "off"):
        return False
    return default


def seq_items(node: Any) -> list[tuple[int, Any]]:
    """``[(index, element)]`` for a sequence, empty for anything else."""
    if not isinstance(node, list):
        return []
    return list(enumerate(node))


def str_list(node: Any) -> list[str]:
    """Normalise a scalar-or-sequence field into a list of strings."""
    if node is None:
        return []
    if isinstance(node, list):
        return [sval(item) for item in node]
    if isinstance(node, str):
        return [sval(node)]
    return []


# -- resources ---------------------------------------------------------------


def resource_from_body(body: Any, path: str, doc_index: int) -> Resource | None:
    if not isinstance(body, M):
        return None
    kind = sval(body.get("kind")).strip()
    if not kind:
        return None
    meta = body.get("metadata")
    if not isinstance(meta, M):
        meta = M()
    return Resource(
        path=path,
        doc_index=doc_index,
        line=key_line(body, "kind", node_line(body, 1)),
        kind=kind,
        api_version=sval(body.get("apiVersion")).strip(),
        name=sval(meta.get("name")).strip(),
        namespace=sval(meta.get("namespace")).strip(),
        body=body,
    )


def load_file(path: str) -> list[Resource]:
    """Read one YAML file into resources. Unparseable files raise YamlError."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    out: list[Resource] = []
    for index, doc in enumerate(load_documents(text)):
        res = resource_from_body(doc, path, index)
        if res is not None:
            out.append(res)
    return out


def iter_yaml_files(root: str) -> list[str]:
    """Every YAML file under ``root``, deterministically ordered."""
    if os.path.isfile(root):
        return [root]
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune in place: os.walk honours mutations of dirnames
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.endswith(YAML_SUFFIXES):
                found.append(os.path.join(dirpath, name))
    return found


def load_path(root: str) -> list[Resource]:
    resources: list[Resource] = []
    for path in iter_yaml_files(root):
        resources.extend(load_file(path))
    return resources


# -- the unified PodSpec view ------------------------------------------------

WORKLOAD_TEMPLATE_PATHS = (
    ("spec", "template", "spec"),
    ("spec", "jobTemplate", "spec", "template", "spec"),
    ("template", "spec"),
)


def _has_containers(node: Any) -> bool:
    return isinstance(node, M) and isinstance(node.get("containers"), list)


def pod_spec_of(resource: Resource) -> Any:
    """The PodSpec of any workload kind, or None for non-workloads."""
    body = resource.body
    if _has_containers(dig(body, "spec")):
        return dig(body, "spec")
    for path in WORKLOAD_TEMPLATE_PATHS:
        node = dig(body, *path)
        if _has_containers(node):
            return node
    return None


@dataclass
class Container:
    """One container, with the line someone has to go edit."""

    index: int
    line: int
    name: str
    image: str
    body: Any
    role: str  # "container" | "initContainer" | "ephemeral"

    @property
    def label(self) -> str:
        return f"{self.role}/{self.name or self.index}"


def containers_of(pod_spec: Any) -> list[Container]:
    """All containers of a pod spec, init containers included.

    Init containers are audited too: they run before the app, with the same
    privileges, and are routinely forgotten by linters that only look at
    ``spec.containers``.
    """
    out: list[Container] = []
    for role, key in (("container", "containers"), ("initContainer", "initContainers")):
        node = pod_spec.get(key) if isinstance(pod_spec, M) else None
        if not isinstance(node, list):
            continue
        for index, item in enumerate(node):
            if not isinstance(item, M):
                continue
            out.append(
                Container(
                    index=index,
                    line=item_line(node, index, node_line(item, 0)),
                    name=sval(item.get("name")),
                    image=sval(item.get("image")),
                    body=item,
                    role=role,
                )
            )
    return out


# -- selectors (the join key of every cross-resource rule) -------------------


def selector_of(resource: Resource) -> dict[str, str]:
    """Label selector of a workload or Service, as a plain dict.

    Handles both shapes: ``spec.selector.matchLabels`` (set-based, apps/v1) and
    ``spec.selector`` (flat, Service and legacy).
    """
    spec = dig(resource.body, "spec")
    if not isinstance(spec, M):
        return {}
    sel = spec.get("selector")
    if isinstance(sel, M):
        match = sel.get("matchLabels")
        if isinstance(match, M):
            return {sval(k): sval(v) for k, v in match.items()}
        return {sval(k): sval(v) for k, v in sel.items() if k != "matchExpressions"}
    return {}


def pod_selector_of(resource: Resource) -> dict[str, str]:
    """``spec.podSelector`` of a NetworkPolicy; empty dict means "all pods"."""
    sel = dig(resource.body, "spec", "podSelector")
    if isinstance(sel, M):
        match = sel.get("matchLabels")
        if isinstance(match, M):
            return {sval(k): sval(v) for k, v in match.items()}
        return {sval(k): sval(v) for k, v in sel.items() if k != "matchExpressions"}
    return {}


def matches_selector(labels: dict[str, str], selector: dict[str, str]) -> bool:
    """True when ``selector`` selects a resource carrying ``labels``."""
    if not selector:
        return False
    return all(labels.get(k) == v for k, v in selector.items())


def labels_of(resource: Resource) -> dict[str, str]:
    meta = dig(resource.body, "metadata")
    if isinstance(meta, M):
        raw = meta.get("labels")
        if isinstance(raw, M):
            return {sval(k): sval(v) for k, v in raw.items()}
    return {}


def template_labels_of(resource: Resource) -> dict[str, str]:
    """Pod template labels — what a Service or NetworkPolicy actually matches."""
    for path in (("spec", "template", "metadata", "labels"), ("spec", "jobTemplate", "spec", "template", "metadata", "labels")):
        raw = dig(resource.body, *path)
        if isinstance(raw, M):
            return {sval(k): sval(v) for k, v in raw.items()}
    return labels_of(resource)


@dataclass
class ManifestSet:
    """Everything loaded from one scan root, grouped by kind."""

    resources: list[Resource] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def by_kind(self, *kinds: str) -> list[Resource]:
        wanted = {k.lower() for k in kinds}
        return [r for r in self.resources if r.kind.lower() in wanted]

    def namespaces(self) -> list[str]:
        seen: list[str] = []
        for res in self.resources:
            if res.namespace and res.namespace not in seen:
                seen.append(res.namespace)
        return seen


def load_manifest_set(root: str) -> ManifestSet:
    manifest = ManifestSet()
    if os.path.isfile(root):
        manifest.files = [root]
    else:
        manifest.files = iter_yaml_files(root)
    for path in manifest.files:
        try:
            manifest.resources.extend(load_file(path))
        except Exception as exc:  # a broken file must not abort the cluster scan
            manifest.errors.append(f"{path}: {exc}")
    return manifest


def workload_iter(resources: Iterable[Resource]) -> list[tuple[Resource, Any]]:
    """``[(resource, pod_spec)]`` for every resource that carries containers."""
    out: list[tuple[Resource, Any]] = []
    for res in resources:
        spec = pod_spec_of(res)
        if spec is not None:
            out.append((res, spec))
    return out
