# kubeguard

[![CI](https://github.com/xuange-hu/kubeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/kubeguard/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-199%20passing-brightgreen.svg)](tests/)
[![rules](https://img.shields.io/badge/rules-37-red.svg)](#rule-map)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)
[![mcp](https://img.shields.io/badge/MCP-5%20tools-blueviolet)](https://modelcontextprotocol.io)

**Kubernetes manifest audit that reads the relationships, not just the objects.**
37 deterministic rules · zero dependencies · every finding carries `file:line` ·
SARIF straight into GitHub code scanning · MCP server for Claude Code / Cursor.

```bash
kubeguard demo && kubeguard scan ./kubeguard-demo
```

---

## The one thing it does that nothing else does

Kubernetes' default is **allow all**, and most of its worst failures live in the
*space between two objects*:

```yaml
kind: Deployment          # L15: no NetworkPolicy selects these labels
spec:
  template:
    metadata:
      labels: {app: web}  # <- every pod in the cluster can reach it
---
kind: Service             # L24: selector says app: webby
spec:
  selector: {app: webby}  # <- typo. The Service has zero backends.
---
kind: ClusterRole         # L40: create on clusterroles
rules:
  - verbs: [create]
    resources: [clusterroles]
  - verbs: [escalate]     # <- harmless alone. With the line above: cluster takeover.
```

A single-object linter cannot see any of those three. `kubeguard` runs a third
pass over the whole manifest set — NetworkPolicy coverage, Service/Ingress
wiring, and RBAC resolved through every binding into what each subject can
*actually* do.

---

## Quick start (3 steps)

```bash
pip install kubeguard

kubeguard demo                      # 1. write a broken manifest, audit it
kubeguard scan .                    # 2. audit your own manifests
kubeguard scan . --fail-on high     # 3. CI gate: exit 1 on high or above
```

No cluster, no `kubectl`, no API server. It reads YAML files, which is what
makes it usable in a CI job that has none of those things.

## Output

```
kubeguard  deployment.yaml

deployment.yaml
  CRITICAL KG002  Container runtime socket mounted
      deployment.yaml:21  prod:Deployment/payments
      挂载运行时 socket：/var/run/docker.sock
      > - name: dockersock
      fix: 删除该 hostPath 卷。
  CRITICAL KG001  Privileged container
      deployment.yaml:38  prod:Deployment/payments[container/api]
      容器 api 以 privileged 运行
      > privileged: true
  HIGH     KG040  Workload not covered by any NetworkPolicy
      deployment.yaml:3   prod:Deployment/payments
      没有任何 NetworkPolicy 选中它

11 critical, 18 high, 28 medium, 17 low, 8 info  ·  9 resources  ·  4 workloads
risk 100/100  CRITICAL RISK
```

## Commands

| Command | What it does |
|---|---|
| `kubeguard scan [PATH...]` | audit files or directories; `--format text\|json\|sarif`, `--min-severity`, `--fail-on`, `--ignore`, `--output` |
| `kubeguard rules` | print the catalogue (`--format json` for machines) |
| `kubeguard rbac PATH` | resolve bindings → what each subject can actually do |
| `kubeguard graph PATH` | the cross-resource view: labels, selectors, policies |
| `kubeguard demo` | write a deliberately broken manifest and audit it |

Exit codes: `0` clean · `1` findings at/above `--fail-on` · `2` the scan failed.

## CI

```yaml
- run: pip install kubeguard
- run: kubeguard scan ./manifests --fail-on high --format sarif --output kubeguard.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: kubeguard.sarif
```

## Suppression

Two file-local mechanisms, both visible in a diff:

```yaml
      privileged: true   # kubeguard: ignore=KG001
```

```bash
kubeguard scan . --ignore KG016,KG025   # digest pinning / labels not our policy
```

## MCP server

```bash
uvx --from "kubeguard[mcp]" kubeguard-mcp
```

| Tool | Purpose |
|---|---|
| `kubeguard_scan` | audit manifest text, with evidence |
| `kubeguard_scan_path` | audit a directory |
| `kubeguard_rules` | the catalogue, with why/fix |
| `kubeguard_rbac` | effective permissions per subject |
| `kubeguard_demo` | self-check that the rules fire |

---

# 中文说明

**唯一读「对象之间关系」的 Kubernetes 清单审计器。** 37 条确定性规则 · 零依赖 ·
每条结论带 `文件:行号` · SARIF 直连 GitHub Code Scanning · 内置 MCP server。

## 为什么还要做一个

`kube-linter`（3.5k★）是 Go 写的，规则基本是**单对象**检查：看一个 Deployment，
判断它的 securityContext 对不对。但 Kubernetes 的默认策略是**全通**，真正的风险
往往只在两个对象的关系里成立：

1. **没有 NetworkPolicy 选中这个 Deployment** —— 集群里任何 Pod 都能直连它。
   单看 Deployment，它完全合规。
2. **Service 的 selector 打错了字** —— 服务零后端，单看 Service 也完全合规。
3. **一个 Role 里同时有 `create clusterroles` 和 `escalate`** —— 单独看每一条
   都像是日常权限，合起来是完整的集群接管链。

这三条，任何「一次只读一个对象」的 linter 都报不出来。kubeguard 因此跑**第三遍**扫描：
把 RoleBinding 解析成主体，把每个主体的权限取并集，再判断**组合**是否危险；同时做
NetworkPolicy 覆盖、Service/Ingress 连通性、ServiceAccount 存在性检查。

## 三步跑通

```bash
pip install kubeguard

kubeguard demo                      # 1. 写一份故意写错的清单并审计它
kubeguard scan .                    # 2. 审计自己的 manifests
kubeguard scan . --fail-on high     # 3. CI 闸门：命中 high 就 exit 1
```

不需要集群、不需要 kubectl、不需要连 API Server —— 它只读 YAML 文件。

## 设计取舍

- **零第三方依赖**。自带缩进式 YAML 读取器（`yamlio.py`），代价是不支持锚点/别名，
  收益是每个标量都保留自己所在的行号，结论才能指到 `deployment.yaml:38`。
- **PodSpec 归一化**。Pod / Deployment / StatefulSet / DaemonSet / Job / CronJob 的
  PodSpec 藏在六个不同路径下；这里按**形状**识别（哪里挂着 `containers`），
  不写死 (apiVersion, kind) 组合，所以 beta 组也能覆盖。
- **initContainer 一样审**。它先于应用运行、权限相同，最常被漏掉。
- **securityContext 两级合并**。容器级优先，pod 级兜底 —— 只查容器级会对
  「在 pod 级统一配置」这种正确写法大量误报。

## Rule map

| Group | Rules | Covers |
|---|---|---|
| `pod` (KG001–KG025) | 25 | privileged、运行时 socket、hostPID/IPC/Network、allowPrivilegeEscalation、runAsNonRoot、高危 capability、NET_RAW、只读根文件系统、hostPath、hostPort、limits/requests、可变 tag、摘要锁定、拉取策略、就绪/存活探针、seccomp、SA token 自动挂载、default SA、明文密钥、废弃 API、推荐标签 |
| `rbac` (KG030–KG035) | 6 | 通配 verbs/resources/apiGroups、secrets 读取、pods/exec、escalate·bind·impersonate、cluster-admin 绑定 |
| `graph` (KG040–KG045) | 6 | NetworkPolicy 覆盖、Service selector 落空、Ingress 后端缺失、SA 未定义、权限组合提权、namespace 无配额 |

`kubeguard rules` 打印完整目录（含每条的 why / fix / CWE）。

## 已知边界

- 不支持 YAML 锚点（`&x` / `*x`）与合并键（`<<:`）；遇到无法解析的行会直接报
  `YamlError` 并记进 `summary.errors`，**不会**静默跳过半份清单。
- RBAC 分析是**清单内**的：集群里已存在但不在本次扫描范围内的 Role 不在视野内。
  `cluster-admin` 等内置角色做了特判。
- 只做静态分析，不做 CVE 匹配、不做镜像扫描。

## 许可证

MIT
