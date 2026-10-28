"""``kubeguard demo``: write a deliberately broken manifest, then audit it.

The sample is not a toy. Everything in it is a pattern that shows up in real
clusters: a privileged sidecar that mounts the runtime socket "just for CI", a
ClusterRole that grew a wildcard because someone was in a hurry, a Service whose
selector drifted from the pod template after a rename. If the demo only fired
synthetic rules it would prove nothing.
"""

from __future__ import annotations

import os

DEMO_FILENAME = "deployment.yaml"

DEMO_MANIFEST = """\
# kubeguard demo — 这份清单故意写错，用来演示 37 条规则里的典型命中项。
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments
  namespace: prod
spec:
  replicas: 2
  selector:
    matchLabels:
      app: payments
  template:
    metadata:
      labels:
        app: payments
    spec:
      hostNetwork: true
      hostPID: true
      serviceAccountName: payments
      volumes:
        - name: dockersock
          hostPath:
            path: /var/run/docker.sock
        - name: cache
          hostPath:
            path: /var/cache/app
      containers:
        - name: api
          image: registry.example.com/payments:latest
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
              hostPort: 8080
          env:
            - name: DB_PASSWORD
              value: "hunter2-not-a-real-password"
          securityContext:
            privileged: true
            capabilities:
              add: ["SYS_ADMIN", "NET_ADMIN"]
          volumeMounts:
            - name: dockersock
              mountPath: /var/run/docker.sock
        - name: migrate
          image: busybox:1.36
          command: ["sh", "-c", "echo migrating"]
---
apiVersion: v1
kind: Service
metadata:
  name: payments
  namespace: prod
spec:
  selector:
    app: payment
  ports:
    - port: 80
      targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: payments
  namespace: prod
spec:
  rules:
    - host: pay.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: checkout
                port:
                  number: 80
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payments
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: payments-writer
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles", "rolebindings"]
    verbs: ["escalate", "bind", "create"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payments-writer-binding
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: payments-writer
subjects:
  - kind: ServiceAccount
    name: payments
    namespace: prod
  - kind: ServiceAccount
    name: reporter
    namespace: prod
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: reporter
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: payments-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: payments
    namespace: prod
---
# 这个 CronJob 演示三件常见的事：废弃 API、共享 IPC、以及引用一个不存在的 SA。
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: nightly-backup
  namespace: prod
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          hostIPC: true
          serviceAccountName: backup
          containers:
            - name: backup
              image: bitnami/kubectl:1.29
              env:
                - name: S3_SECRET_KEY
                  value: "AKIAEXAMPLEEXAMPLEEXAMPLE"
---
# 没有写 serviceAccountName 的裸 Pod —— 默认落在 default SA 上。
apiVersion: v1
kind: Pod
metadata:
  name: debug-shell
  namespace: prod
spec:
  containers:
    - name: shell
      image: alpine:3.19
      command: ["sleep", "infinity"]
"""


def write_demo(directory: str = "kubeguard-demo") -> str:
    """Write the sample manifest and return the path that was written."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, DEMO_FILENAME)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(DEMO_MANIFEST)
    return path
