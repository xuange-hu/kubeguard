"""The rule catalogue.

Every rule is a frozen dataclass, so ``kubeguard rules`` can print the whole
catalogue without executing a single check, and SARIF can attach the same text
to a result. ``why`` and ``fix`` are written to be read by someone who has never
seen the rule before — a finding that does not explain itself gets ignored.
"""

from __future__ import annotations

from .model import SEVERITY_RANK, Rule

CWE_PRIV = "CWE-250"
CWE_SOCKET = "CWE-269"
CWE_SECRET = "CWE-798"
CWE_DOS = "CWE-400"
CWE_SUPPLY = "CWE-1104"


def _rule(rid: str, title: str, severity: str, group: str, why: str, fix: str, cwe: str = "", ref: str = "") -> Rule:
    return Rule(id=rid, title=title, severity=severity, group=group, why=why, fix=fix, cwe=cwe, reference=ref)


RULES: dict[str, Rule] = {r.id: r for r in [
    # ------------------------------------------------------------------ pod
    _rule(
        "KG001", "Privileged container", "critical", "pod",
        "privileged: true 关闭了容器与宿主机之间几乎全部的隔离边界：容器内的 root 就是"
        "宿主机 root，能挂载 /dev、加载内核模块、读写其它容器的文件系统。",
        "删除 privileged: true，改用 capability 白名单（KG008）与 seccomp（KG020）。",
        CWE_PRIV,
    ),
    _rule(
        "KG002", "Container runtime socket mounted", "critical", "pod",
        "/var/run/docker.sock 或 containerd/cri-o 的 socket 被挂进容器，等于把"
        "宿主机的「任意容器创建」API 交给了工作负载——一条 curl 就能起一个 privileged 容器。",
        "删除该 hostPath 卷。构建镜像用 buildkit rootless 或 Kaniko 等无 socket 方案。",
        CWE_SOCKET,
    ),
    _rule(
        "KG003", "hostPID enabled", "high", "pod",
        "共享宿主机 PID namespace：容器能看到并 kill 宿主机上所有进程，也能读取"
        "/proc 里其它租户的环境变量。",
        "删除 hostPID: true。需要进程观测时用 eBPF 侧车。",
        CWE_PRIV,
    ),
    _rule(
        "KG004", "hostIPC enabled", "high", "pod",
        "共享宿主机 IPC namespace：共享内存段、信号量和 System V 队列全部暴露，"
        "历史上是容器逃逸的高频跳板。",
        "删除 hostIPC: true。",
        CWE_PRIV,
    ),
    _rule(
        "KG005", "hostNetwork enabled", "high", "pod",
        "共享宿主机网络栈：localhost 上监听的 kubelet 只读端口、云厂商 metadata 服务"
        "（169.254.169.254，可换临时凭证）全部对该容器可见。",
        "删除 hostNetwork: true，用 Service/Ingress 暴露端口。",
        CWE_PRIV,
    ),
    _rule(
        "KG006", "allowPrivilegeEscalation not disabled", "high", "pod",
        "默认允许 setuid/setcap 提权。即使以非 root 启动，容器里的一个 setuid-root"
        "二进制就能把权限抬回 root——这是 no_new_privs 存在的理由。",
        "在 securityContext 里设 allowPrivilegeEscalation: false。",
        CWE_PRIV,
    ),
    _rule(
        "KG007", "Container may run as root", "high", "pod",
        "runAsNonRoot 未设置且未指定非零 UID。root 容器 + 一个内核漏洞 = 宿主机失守；"
        "同时它也是很多合规基线（PCI-DSS、CIS）的硬性否决项。",
        "securityContext.runAsNonRoot: true 且 runAsUser 设为 >= 1000。",
        CWE_PRIV,
    ),
    _rule(
        "KG008", "Dangerous Linux capability added", "high", "pod",
        "SYS_ADMIN 近乎 root；SYS_PTRACE 可跨进程读写内存；NET_ADMIN 可改路由与"
        "iptables；SYS_MODULE 可加载内核模块。加进去的 capability 在容器整个生命周期有效。",
        "只保留必需项，并显式 capabilities.drop: [ALL] 后再 add。",
        CWE_PRIV,
    ),
    _rule(
        "KG009", "NET_RAW capability not dropped", "low", "pod",
        "默认 capability 集合含 NET_RAW，允许构造原始报文，可做同网段的 ARP/DNS 欺骗。",
        "securityContext.capabilities.drop: [ALL]（或至少 NET_RAW）。",
        CWE_PRIV,
    ),
    _rule(
        "KG010", "readOnlyRootFilesystem not enabled", "medium", "pod",
        "可写根文件系统让「下载恶意二进制并落地执行」成为一步操作，也让植入的"
        "后门能跨重启存活在容器层。",
        "securityContext.readOnlyRootFilesystem: true，临时目录挂 emptyDir。",
        CWE_PRIV,
    ),
    _rule(
        "KG011", "hostPath volume mounted", "medium", "pod",
        "hostPath 把宿主机目录直接暴露给工作负载。挂载 /etc、/var/lib/kubelet 时"
        "等同于拿到集群凭证与所有 Pod 的编排信息。",
        "改用 PVC；确需 hostPath 时限定到专属子目录并设为只读。",
        CWE_PRIV,
    ),
    _rule(
        "KG012", "hostPort bound", "medium", "pod",
        "hostPort 在宿主机上开真端口，绕过 NetworkPolicy 与 Service 的流量治理，"
        "且同节点调度会被端口冲突卡死。",
        "用 Service(NodePort/LoadBalancer) 或 Ingress 暴露。",
        CWE_PRIV,
    ),
    _rule(
        "KG013", "Resource limits missing", "medium", "pod",
        "没有 limits 的容器可以吃满节点内存，触发 OOMKiller 随机杀进程——"
        "这是「隔壁服务上线导致我被杀」的根本原因（ noisy neighbour）。",
        "resources.limits 至少设 cpu 与 memory。",
        CWE_DOS,
    ),
    _rule(
        "KG014", "Resource requests missing", "low", "pod",
        "没有 requests 的 Pod 落在 BestEffort QoS 等级，节点压力时第一个被驱逐，"
        "调度器也无法做合理装箱。",
        "resources.requests 设为常态用量。",
        CWE_DOS,
    ),
    _rule(
        "KG015", "Mutable image tag", "medium", "pod",
        "使用 :latest 或不写 tag。同一个 Deployment 在不同时间会拉到不同镜像，"
        "回滚不可复现，也无法回答「线上跑的是哪个 commit」。",
        "固定语义化版本 tag，并用摘要锁定（KG016）。",
        CWE_SUPPLY,
    ),
    _rule(
        "KG016", "Image not pinned by digest", "info", "pod",
        "tag 是可变的：registry 上重新 push 同 tag 镜像即可让下次拉起变成另一份代码。"
        "摘要是内容寻址，不可伪造。",
        "image: nginx@sha256:<digest>（可保留 tag 作注释）。",
        CWE_SUPPLY,
    ),
    _rule(
        "KG017", "imagePullPolicy not Always for a mutable tag", "low", "pod",
        "可变 tag + IfNotPresent 会让节点复用旧镜像（或反过来，同 tag 不同内容），"
        "节点之间跑的版本可能不一致。",
        "配 imagePullPolicy: Always，或改成不可变 tag。",
        CWE_SUPPLY,
    ),
    _rule(
        "KG018", "readinessProbe missing", "medium", "pod",
        "没有就绪探针，Pod 一启动就被塞进 Service 端点，滚动更新期间会把请求"
        "打到还没准备好的实例上。",
        "加 readinessProbe，指向真实的健康接口。",
        CWE_DOS,
    ),
    _rule(
        "KG019", "livenessProbe missing", "low", "pod",
        "没有存活探针，死锁进程会一直占着副本数但不再服务，且永远不会被重启。",
        "加 livenessProbe。注意与 readinessProbe 用不同阈值，避免抖动重启。",
        CWE_DOS,
    ),
    _rule(
        "KG020", "seccomp profile not set", "medium", "pod",
        "默认 unconfined：容器内可用全部 ~300 个 syscall。历史上多个容器逃逸"
        "（如 CVE-2022-0492）靠的就是默认不被限制的 syscall 面。",
        "securityContext.seccompProfile.type: RuntimeDefault。",
        CWE_PRIV,
    ),
    _rule(
        "KG021", "Service account token automounted", "medium", "pod",
        "不需要调 API 的工作负载却自动挂了 SA token。拿到任何一个容器的 RCE，"
        "第一件事就是读 /var/run/secrets/.../token 枚举集群。",
        "automountServiceAccountToken: false（Pod 或 ServiceAccount 级）。",
        CWE_SOCKET,
    ),
    _rule(
        "KG022", "Default service account in use", "low", "pod",
        "default SA 在每个 namespace 都存在，权限随集群膨胀而累积，且无法按"
        "工作负载单独收敛。",
        "为工作负载建专属 ServiceAccount 并最小化授权。",
        CWE_SOCKET,
    ),
    _rule(
        "KG023", "Plaintext secret-looking value in env", "high", "pod",
        "把口令/令牌直接写进 env.value。清单通常进 Git，等于把密钥提交进版本库，"
        "且 `kubectl get deploy -o yaml` 对任何有读权限的人可见。",
        "改用 env.valueFrom.secretKeyRef，或用 External Secrets / CSI driver 注入。",
        CWE_SECRET,
    ),
    _rule(
        "KG024", "Deprecated apiVersion", "medium", "pod",
        "该 API 组版本已在目标集群移除或即将移除，apply 会直接失败，或被静默"
        "转换出非预期的字段。",
        "迁移到当前稳定版本（如 apps/v1、networking.k8s.io/v1、policy/v1）。",
        CWE_SUPPLY,
    ),
    _rule(
        "KG025", "Recommended labels missing", "info", "pod",
        "缺少 app.kubernetes.io/* 系列标签。标签是 Service、NetworkPolicy、HPA 和"
        "可观测性的连接键；没有它，跨资源分析（含本工具的 KG040/041）无从下手。",
        "补 app.kubernetes.io/name、instance、version、part-of。",
    ),
    # ----------------------------------------------------------------- rbac
    _rule(
        "KG030", "RBAC wildcard verb", "critical", "rbac",
        "verbs: [\"*\"] 授予任意动作，包括 delete 与 de 破坏性操作；与任何资源"
        "组合都等于该资源的完全控制。",
        "显式列出所需 verbs（get/list/watch 或 create/update/patch）。",
        "CWE-269",
    ),
    _rule(
        "KG031", "RBAC wildcard resource or apiGroup", "high", "rbac",
        "resources/apiGroups 用 * 会跨越所有资源类型，包含未来新增的 CRD——"
        "授权范围随集群演进而无声扩大。",
        "显式列出资源与 apiGroups。",
        "CWE-269",
    ),
    _rule(
        "KG032", "RBAC grants secret read", "high", "rbac",
        "能 get/list secrets 的主体可以读出同 namespace（ClusterRole 则全集群）"
        "所有凭证：数据库口令、镜像拉取密钥、其它 SA 的 token。",
        "去掉 secrets 权限，或限定 resourceNames 到具体 Secret。",
        CWE_SECRET,
    ),
    _rule(
        "KG033", "RBAC grants pods/exec or attach", "critical", "rbac",
        "exec/attach 等于「在目标容器里执行任意命令」。若目标容器能挂 hostPath 或"
        "是 privileged，这就是一条完整的集群接管链。",
        "删除 exec/attach；排障走临时审计会话并留痕。",
        CWE_SOCKET,
    ),
    _rule(
        "KG034", "RBAC grants escalate, bind or impersonate", "critical", "rbac",
        "这是 Kubernetes 明文认定的三条提权动词：持有者可以给自己或他人授予"
        "任何自己当前没有的权限（含 cluster-admin）。",
        "删除这些动词；它们只应属于集群安装器这类控制面组件。",
        CWE_PRIV,
    ),
    _rule(
        "KG035", "Binding to cluster-admin or system:masters", "critical", "rbac",
        "cluster-admin / system:masters 绕过 RBAC 全部检查，是集群的 root。"
        "任何绑到它的 SA、用户或组都是单点失守目标。",
        "拆成最小权限 Role，或用能覆盖需求的最窄内置角色（view/edit/admin）。",
        CWE_PRIV,
    ),
    # ---------------------------------------------------------------- graph
    _rule(
        "KG040", "Workload not covered by any NetworkPolicy", "medium", "graph",
        "Kubernetes 默认全通。没有 NetworkPolicy 选中该工作负载时，集群里任何 Pod"
        "都能直连它的端口——横向移动不需要任何额外漏洞。",
        "加一条选中该 Pod 标签的 NetworkPolicy，先 default-deny 再逐条放行。",
        "CWE-923",
    ),
    _rule(
        "KG041", "Service selector matches no workload", "medium", "graph",
        "Service 的 selector 匹配不到任何 Pod 模板标签。要么是标签写错（服务实际上"
        "没有后端，流量黑洞），要么是残留对象。",
        "对齐 spec.selector 与 Pod 模板的 metadata.labels。",
        "CWE-1188",
    ),
    _rule(
        "KG042", "Ingress backend service missing", "medium", "graph",
        "Ingress 指向的 Service 在本次扫描范围内不存在。上线后表现为 503，"
        "或者更糟：被另一个 namespace 的同名 Service 顶替。",
        "补建 Service 或修正 backend.service.name/number。",
        "CWE-1188",
    ),
    _rule(
        "KG043", "ServiceAccount referenced but not defined", "low", "graph",
        "Pod 引用了一个清单里不存在的 ServiceAccount。若集群里也没有，Pod 会"
        "卡在 CreateContainerConfigError；若别人先建了它，权限就不在你的控制之下。",
        "在同一次 apply 里显式创建该 ServiceAccount。",
        "CWE-1188",
    ),
    _rule(
        "KG044", "Service account can escalate to cluster control", "critical", "graph",
        "把 Role/ClusterRole 经 RoleBinding 展开后，该 SA 拥有的权限组合足以拿到"
        "集群控制权：通配动词、或 escalate/bind 加上写角色的能力。这是单条 RBAC"
        "规则看不出来的风险——它只存在于权限的**组合**里。",
        "拆散组合：去掉通配与 escalate/bind，按工作负载实际调用面授权。",
        CWE_PRIV,
    ),
    _rule(
        "KG045", "Namespace without ResourceQuota", "info", "graph",
        "没有配额的 namespace 可以被单个工作负载吃满整个集群的资源，"
        "且没有 LimitRange 时缺省容器连 requests 都没有。",
        "为每个业务 namespace 建 ResourceQuota 与 LimitRange。",
        CWE_DOS,
    ),
]}


def rule(id_: str) -> Rule:
    """Fetch a rule by id; raises KeyError with a useful message if unknown."""
    try:
        return RULES[id_.upper()]
    except KeyError:
        raise KeyError(f"unknown rule {id_!r}") from None


def all_rules() -> list[Rule]:
    return sorted(RULES.values(), key=lambda r: r.id)


def rules_by_group() -> dict[str, list[Rule]]:
    out: dict[str, list[Rule]] = {}
    for r in all_rules():
        out.setdefault(r.group, []).append(r)
    return out


def count_by_severity() -> dict[str, int]:
    out = {name: 0 for name in SEVERITY_RANK}
    for r in RULES.values():
        out[r.severity] += 1
    return out


def to_dict() -> dict:
    return {r.id: r.__dict__ for r in all_rules()}
