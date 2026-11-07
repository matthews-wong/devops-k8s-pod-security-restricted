# k8s-pod-security-restricted

A namespace that enforces the Kubernetes Pod Security Standards `restricted`
profile, plus a small web workload written to pass it.

The namespace labels reject non-compliant pods at admission. A local script
checks the manifests against the same rules before they reach a cluster.

## Layout

- `manifests/` namespace, service account, deployment, service
- `scripts/check_restricted.py` the profile checker
- `scripts/test_check_restricted.py` one failing case per control

## What the workload does to pass

- non-root user, `seccompProfile: RuntimeDefault`
- `allowPrivilegeEscalation: false`, all capabilities dropped
- read-only root filesystem, with `emptyDir` mounts for the paths nginx writes
- no service account token mounted
- image pinned by digest, requests and limits, three probes

The namespace pins the profile version (`v1.31`) so a cluster upgrade cannot
change what is enforced.

## Validate

```sh
make validate
```

Runs `kubeconform -strict`, the profile checker, the unit tests and
`actionlint`. Needs `kubeconform`, `actionlint`, Python 3 and PyYAML.

## Limits

The checker covers the pod and container controls of the profile that can be
read from a manifest. It does not replace admission: only a cluster with the
Pod Security admission plugin enabled enforces the labels, and nothing here
was applied to a live cluster.
