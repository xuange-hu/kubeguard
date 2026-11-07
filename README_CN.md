# kubeguard · 中文说明

[English README](README.md) · Kubernetes 清单的零依赖静态审计器。

**一句话**：单看一个 YAML 看不出的风险，第三遍扫描才看得出来——安全组对外开放，
且公网实例正落在它里面。kubeguard 看的是对象之间的**关系**。

## 为什么存在

[kube-linter](https://github.com/stackrox/kube-linter)（约 3.5k★，Go）等主流工具
逐个对象检查：一个 Deployment 缺 `runAsNonRoot` 就报一条。
但 Kubernetes 的默认值几乎全通，真正出事的是组合：

- NetworkPolicy 存在，但 selector 没覆盖到那个带公网卡的 Pod；
- Service 有 selector，集群里没有任何 Pod 带这个标签（静默黑洞）；
- 一条 Role 只给 `get`，另一条 Role 只给 `list`，绑到同一个 ServiceAccount 之后
  合起来就是可读全部 Secret。

kube-linter 是 Go、且只看单对象；零依赖 Python 的赛道空着。

## 三步跑通

```bash
# 1) 安装（核心零运行时依赖，Python 3.10+）
pip install git+https://github.com/xuange-hu/kubeguard

# 2) 看规则 / 跑自带演示（不需要集群、不联网）
kubeguard rules
kubeguard demo            # 写出一份故意写坏的清单并审计，实测 rc=0

# 3) 扫自己的清单，达到阈值就退出 1
kubeguard scan ./k8s --fail-on high --format sarif > kubeguard.sarif
```

`kubeguard demo` 已在干净目录实测：写出 `kubeguard-demo/deployment.yaml`
并输出 398 行报告。

## 差异化

| 能力 | 说明 |
|---|---|
| **三遍扫描** | ① Workload / PodSpec 25 条 ② RBAC 6 条 ③ 跨资源关系 6 条，共 **37 规则** |
| **自写 YAML 子集读取器** | 不依赖 PyYAML，保留每个值的行号，结论可直接定位 |
| **证据式输出** | 每条 finding 带 `文件:行号` 与原始字段，不是一句「不安全」 |
| **MCP 5 工具** | `uvx --from "kubeguard[mcp]" kubeguard-mcp`，agent 不用开 shell |
| **CI 一等公民** | `--fail-on` 退出码 + SARIF 2.1.0，可直接进 GitHub Code Scanning |

## 命令

| 命令 | 作用 |
|---|---|
| `kubeguard scan PATH` | 审一个文件或一整个目录 |
| `kubeguard rules` | 打印规则目录（按 Workload / RBAC / graph 分组） |
| `kubeguard rbac` | 按 subject 汇总有效权限 |
| `kubeguard graph` | 跨资源关系视图 |
| `kubeguard demo` | 生成故意写坏的清单并审计，离线可跑 |

## 已知边界

- 静态工具，不连 apiserver，看不到 Admission Webhook 与运行时策略；
- YAML 子集解析器不覆盖全部 YAML 1.2 语法（锚点/别名等），遇到不支持的结构会显式说明；
- Helm / Kustomize 模板需先 render 成清单再扫。

贡献见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题见 [SECURITY.md](SECURITY.md)。MIT。
