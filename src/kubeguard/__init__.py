"""kubeguard — layer-zero Kubernetes manifest audit.

Three passes over a manifest set: workload/PodSpec rules, RBAC rules, and a
cross-resource pass that reads the relationships between objects. Zero
dependencies in the core; every finding carries ``file:line``.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
