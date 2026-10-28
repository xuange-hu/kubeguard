"""Tests for the workload/PodSpec pass — one block per rule, hit and miss.

Each rule gets a *negative* case too. A security rule that fires on a correct
manifest is worse than a rule that stays silent: it trains people to ignore the
output.
"""

from __future__ import annotations

import pytest

from kubeguard.analyze import scan_text


def pod(spec: str) -> str:
    return "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n" + spec


def ids(text: str, path: str = "p.yaml") -> set[str]:
    return {f.rule.id for f in scan_text(text, path=path).findings}


CONTAINER = "  containers:\n    - name: c\n      image: nginx:1.25\n"


def test_privileged_fires():
    text = pod(CONTAINER + "      securityContext:\n        privileged: true\n")
    assert "KG001" in ids(text)


def test_privileged_absent_when_false():
    text = pod(CONTAINER + "      securityContext:\n        privileged: false\n")
    assert "KG001" not in ids(text)


def test_privileged_is_read_from_the_pod_level_too():
    text = pod("  securityContext:\n    privileged: true\n" + CONTAINER)
    assert "KG001" in ids(text)


def test_runtime_socket_is_critical_not_medium():
    text = pod("  volumes:\n    - name: d\n      hostPath:\n        path: /var/run/docker.sock\n" + CONTAINER)
    found = ids(text)
    assert "KG002" in found
    assert "KG011" not in found


def test_containerd_socket_matches():
    text = pod("  volumes:\n    - name: d\n      hostPath:\n        path: /run/containerd/containerd.sock\n" + CONTAINER)
    assert "KG002" in ids(text)


def test_ordinary_hostpath_is_medium():
    text = pod("  volumes:\n    - name: c\n      hostPath:\n        path: /var/cache/app\n" + CONTAINER)
    found = ids(text)
    assert "KG011" in found
    assert "KG002" not in found


@pytest.mark.parametrize("key,rule", [("hostPID", "KG003"), ("hostIPC", "KG004"), ("hostNetwork", "KG005")])
def test_namespace_sharing_rules(key, rule):
    assert rule in ids(pod(f"  {key}: true\n" + CONTAINER))
    assert rule not in ids(pod(f"  {key}: false\n" + CONTAINER))
    assert rule not in ids(pod(CONTAINER))


def test_allow_privilege_escalation_defaults_to_a_finding():
    assert "KG006" in ids(pod(CONTAINER))


def test_allow_privilege_escalation_false_is_clean():
    text = pod(CONTAINER + "      securityContext:\n        allowPrivilegeEscalation: false\n")
    assert "KG006" not in ids(text)


def test_run_as_non_root_satisfies_kg007():
    text = pod(CONTAINER + "      securityContext:\n        runAsNonRoot: true\n")
    assert "KG007" not in ids(text)


def test_run_as_user_nonzero_satisfies_kg007():
    text = pod(CONTAINER + "      securityContext:\n        runAsUser: 10001\n")
    assert "KG007" not in ids(text)


def test_run_as_user_zero_still_fires_kg007():
    text = pod(CONTAINER + "      securityContext:\n        runAsUser: 0\n")
    assert "KG007" in ids(text)


def test_pod_level_run_as_non_root_covers_all_containers():
    text = pod("  securityContext:\n    runAsNonRoot: true\n" + CONTAINER)
    assert "KG007" not in ids(text)


@pytest.mark.parametrize("cap", ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL"])
def test_dangerous_capabilities(cap):
    text = pod(CONTAINER + "      securityContext:\n        capabilities:\n          add: [\"" + cap + "\"]\n")
    assert "KG008" in ids(text)


def test_harmless_capability_does_not_fire():
    text = pod(CONTAINER + "      securityContext:\n        capabilities:\n          add: [\"NET_BIND_SERVICE\"]\n")
    assert "KG008" not in ids(text)


def test_net_raw_drop_satisfies_kg009():
    text = pod(CONTAINER + "      securityContext:\n        capabilities:\n          drop: [\"NET_RAW\"]\n")
    assert "KG009" not in ids(text)


def test_drop_all_satisfies_kg009():
    text = pod(CONTAINER + "      securityContext:\n        capabilities:\n          drop: [\"ALL\"]\n")
    assert "KG009" not in ids(text)


def test_readonly_root_filesystem():
    text = pod(CONTAINER + "      securityContext:\n        readOnlyRootFilesystem: true\n")
    assert "KG010" not in ids(text)
    assert "KG010" in ids(pod(CONTAINER))


def test_host_port():
    text = pod("  containers:\n    - name: c\n      image: n:1\n      ports:\n        - containerPort: 80\n          hostPort: 80\n")
    assert "KG012" in ids(text)


def test_plain_container_port_is_fine():
    text = pod("  containers:\n    - name: c\n      image: n:1\n      ports:\n        - containerPort: 80\n")
    assert "KG012" not in ids(text)


def test_resources_limits_and_requests():
    good = pod(CONTAINER + "      resources:\n        limits:\n          cpu: 500m\n          memory: 256Mi\n        requests:\n          cpu: 100m\n          memory: 128Mi\n")
    found = ids(good)
    assert "KG013" not in found and "KG014" not in found
    assert {"KG013", "KG014"} <= ids(pod(CONTAINER))


def test_partial_limits_still_fires():
    text = pod(CONTAINER + "      resources:\n        limits:\n          cpu: 500m\n")
    found = ids(text)
    assert "KG013" not in found  # cpu present counts as limits present


def test_latest_tag_is_mutable():
    assert "KG015" in ids(pod("  containers:\n    - name: c\n      image: nginx:latest\n"))
    assert "KG015" in ids(pod("  containers:\n    - name: c\n      image: nginx\n"))


def test_digest_pin_suppresses_tag_and_pull_policy_rules():
    text = pod("  containers:\n    - name: c\n      image: nginx:1.25@sha256:" + "a" * 64 + "\n")
    found = ids(text)
    assert "KG016" not in found
    assert "KG015" not in found
    assert "KG017" not in found


def test_pull_policy_always_satisfies_kg017():
    text = pod("  containers:\n    - name: c\n      image: nginx:1.25\n      imagePullPolicy: Always\n")
    assert "KG017" not in ids(text)


def test_pull_policy_ifnotpresent_on_a_fixed_tag_fires():
    text = pod("  containers:\n    - name: c\n      image: nginx:1.25\n      imagePullPolicy: IfNotPresent\n")
    assert "KG017" in ids(text)


def test_probes():
    withprobe = pod(CONTAINER + "      readinessProbe:\n        httpGet:\n          path: /ready\n          port: 80\n      livenessProbe:\n        httpGet:\n          path: /live\n          port: 80\n")
    found = ids(withprobe)
    assert "KG018" not in found and "KG019" not in found
    assert {"KG018", "KG019"} <= ids(pod(CONTAINER))


def test_init_containers_are_not_nagged_about_probes():
    text = pod("  initContainers:\n    - name: i\n      image: busybox:1.36\n")
    found = ids(text)
    assert "KG018" not in found and "KG019" not in found


def test_seccomp_runtime_default_is_clean():
    text = pod(CONTAINER + "      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n")
    assert "KG020" not in ids(text)


def test_seccomp_annotation_is_accepted():
    text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  annotations:\n    seccomp.security.alpha.kubernetes.io/pod: runtime/default\nspec:\n" + CONTAINER
    assert "KG020" not in ids(text)


def test_automount_token_false_is_clean():
    assert "KG021" not in ids(pod("  automountServiceAccountToken: false\n" + CONTAINER))
    assert "KG021" in ids(pod(CONTAINER))


def test_default_service_account():
    assert "KG022" in ids(pod(CONTAINER))
    assert "KG022" not in ids(pod("  serviceAccountName: app\n" + CONTAINER))


def test_plaintext_secret_in_env():
    text = pod("  containers:\n    - name: c\n      image: n:1\n      env:\n        - name: DB_PASSWORD\n          value: hunter2\n")
    assert "KG023" in ids(text)


def test_secret_reference_is_not_a_plaintext_secret():
    text = pod("  containers:\n    - name: c\n      image: n:1\n      env:\n        - name: DB_PASSWORD\n          valueFrom:\n            secretKeyRef:\n              name: db\n              key: password\n")
    assert "KG023" not in ids(text)


def test_env_expansion_is_not_a_plaintext_secret():
    text = pod("  containers:\n    - name: c\n      image: n:1\n      env:\n        - name: TOKEN\n          value: $(SECRET_TOKEN)\n")
    assert "KG023" not in ids(text)


def test_deprecated_api_version():
    text = "apiVersion: extensions/v1beta1\nkind: Deployment\nspec:\n  template:\n    spec:\n" + "  containers:\n    - name: c\n      image: n:1\n"
    assert "KG024" in ids(text)


def test_current_api_version_is_clean():
    assert "KG024" not in ids(pod(CONTAINER))


def test_recommended_labels_on_metadata_also_count():
    """Charts often put the labels on metadata, not on the pod template.

    Both are the same intent; reporting "missing" when they are three lines
    above is how a scanner gets muted.
    """
    text = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  labels:\n"
        "    app.kubernetes.io/name: web\n    app.kubernetes.io/part-of: shop\nspec:\n"
        "  template:\n    metadata:\n      labels:\n        app: web\n    spec:\n" + CONTAINER
    )
    assert "KG025" not in ids(text)


def test_summary_agrees_with_kg007_on_pod_level_hardening():
    text = pod("  securityContext:\n    runAsNonRoot: true\n" + CONTAINER)
    report = scan_text(text)
    assert "KG007" not in rule_ids_of(report)
    assert report.summary.runs_as_root == 0


def rule_ids_of(report) -> set[str]:
    return {f.rule.id for f in report.findings}


def test_recommended_labels():
    text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  labels:\n    app.kubernetes.io/name: p\n    app.kubernetes.io/part-of: shop\nspec:\n" + CONTAINER
    assert "KG025" not in ids(text)
    assert "KG025" in ids(pod(CONTAINER))


def test_cronjob_pod_spec_is_audited():
    text = (
        "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: j\nspec:\n  jobTemplate:\n    spec:\n"
        "      template:\n        spec:\n          containers:\n            - name: c\n              image: n:1\n"
        "              securityContext:\n                privileged: true\n"
    )
    assert "KG001" in ids(text)


def test_finding_carries_path_line_and_snippet():
    text = pod(CONTAINER + "      securityContext:\n        privileged: true\n")
    report = scan_text(text, path="manifests/p.yaml")
    finding = next(f for f in report.findings if f.rule.id == "KG001")
    assert finding.path == "manifests/p.yaml"
    assert finding.line == 10
    assert "privileged: true" in finding.snippet
    assert finding.location() == "manifests/p.yaml:10"


def test_clean_manifest_has_no_high_or_above():
    text = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  labels:\n"
        "    app.kubernetes.io/name: web\n    app.kubernetes.io/part-of: shop\nspec:\n"
        "  template:\n    metadata:\n      labels:\n        app: web\n    spec:\n"
        "      automountServiceAccountToken: false\n      serviceAccountName: web\n"
        "      securityContext:\n        runAsNonRoot: true\n        seccompProfile:\n          type: RuntimeDefault\n"
        "      containers:\n        - name: c\n          image: nginx:1.25@sha256:" + "b" * 64 + "\n"
        "          imagePullPolicy: Always\n          readinessProbe:\n            httpGet:\n              path: /r\n              port: 80\n"
        "          livenessProbe:\n            httpGet:\n              path: /l\n              port: 80\n"
        "          securityContext:\n            allowPrivilegeEscalation: false\n            readOnlyRootFilesystem: true\n"
        "            capabilities:\n              drop: [\"ALL\"]\n"
        "          resources:\n            limits:\n              cpu: 500m\n              memory: 256Mi\n"
        "            requests:\n              cpu: 100m\n              memory: 128Mi\n"
    )
    report = scan_text(text)
    worst = [f.rule.id for f in report.findings if f.rule.severity in ("high", "critical")]
    assert worst == []
