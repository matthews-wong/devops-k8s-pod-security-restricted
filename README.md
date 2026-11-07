# k8s-pod-security-restricted

A namespace that enforces the Kubernetes Pod Security Standards `restricted`
profile, plus a small web workload written to pass it.

The point is to keep the two halves honest: the namespace labels reject
non-compliant pods at admission, and a local script checks the manifests
against the same rules before they ever reach a cluster.

## Layout

- `manifests/` namespace, service account, deployment, service
- `scripts/` the restricted-profile checker and its tests

Status: scaffolding, more to follow.
