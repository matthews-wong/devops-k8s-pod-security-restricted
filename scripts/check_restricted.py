#!/usr/bin/env python3
"""Fail when a manifest would be rejected by the Pod Security `restricted` profile.

Covers the pod-level and container-level controls of the profile for
Deployments, StatefulSets, DaemonSets, Jobs, CronJobs and Pods, and checks that
every Namespace enforces `restricted`.

Usage: scripts/check_restricted.py [file...]   (default: manifests/*.yaml)
"""
import glob
import sys

import yaml

ENFORCE_LABEL = "pod-security.kubernetes.io/enforce"
PROFILE = "restricted"
ALLOWED_ADD_CAPS = {"NET_BIND_SERVICE"}
ALLOWED_SECCOMP = {"RuntimeDefault", "Localhost"}
HOST_NAMESPACE_FIELDS = ("hostNetwork", "hostPID", "hostIPC")
# Volume types the restricted profile permits.
ALLOWED_VOLUMES = {
    "name", "configMap", "csi", "downwardAPI", "emptyDir", "ephemeral",
    "persistentVolumeClaim", "projected", "secret",
}
POD_SPEC_PATHS = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}


def dig(doc, path):
    for key in path:
        if not isinstance(doc, dict) or key not in doc:
            return None
        doc = doc[key]
    return doc


def check_container(container, pod_ctx):
    """Yield one message per violated control for a single container."""
    ctx = container.get("securityContext") or {}
    if ctx.get("privileged"):
        yield "privileged container"
    if ctx.get("allowPrivilegeEscalation") is not False:
        yield "allowPrivilegeEscalation must be false"
    caps = ctx.get("capabilities") or {}
    if "ALL" not in (caps.get("drop") or []):
        yield "capabilities.drop must include ALL"
    extra = set(caps.get("add") or []) - ALLOWED_ADD_CAPS
    if extra:
        yield f"capabilities.add may only contain {sorted(ALLOWED_ADD_CAPS)}, found {sorted(extra)}"
    if ctx.get("runAsNonRoot", pod_ctx.get("runAsNonRoot")) is not True:
        yield "runAsNonRoot must be true (container or pod)"
    if ctx.get("runAsUser", pod_ctx.get("runAsUser")) == 0:
        yield "runAsUser must not be 0"
    seccomp = (ctx.get("seccompProfile") or pod_ctx.get("seccompProfile") or {}).get("type")
    if seccomp not in ALLOWED_SECCOMP:
        yield f"seccompProfile.type must be one of {sorted(ALLOWED_SECCOMP)}, found {seccomp!r}"
    for port in container.get("ports") or []:
        if port.get("hostPort"):
            yield f"hostPort {port['hostPort']} is not allowed"


def check_pod_spec(spec):
    """Yield (container-or-pod name, message) for every violation in a pod spec."""
    for field in HOST_NAMESPACE_FIELDS:
        if spec.get(field):
            yield "pod", f"{field} must not be true"
    for volume in spec.get("volumes") or []:
        disallowed = set(volume) - ALLOWED_VOLUMES
        if disallowed:
            yield "pod", f"volume {volume.get('name')!r} uses {sorted(disallowed)}, not allowed"
    pod_ctx = spec.get("securityContext") or {}
    for key in ("containers", "initContainers"):
        for container in spec.get(key) or []:
            for message in check_container(container, pod_ctx):
                yield container.get("name", "?"), message


def check_document(doc):
    """Yield (subject, message) for every violation in one manifest document."""
    kind = doc.get("kind")
    name = (doc.get("metadata") or {}).get("name", "?")
    if kind == "Namespace":
        labels = (doc.get("metadata") or {}).get("labels") or {}
        if labels.get(ENFORCE_LABEL) != PROFILE:
            yield f"Namespace/{name}", f"{ENFORCE_LABEL} must be {PROFILE!r}, found {labels.get(ENFORCE_LABEL)!r}"
        return
    path = POD_SPEC_PATHS.get(kind)
    if path is None:
        return
    spec = dig(doc, path)
    if spec is None:
        yield f"{kind}/{name}", f"no pod spec found at {'.'.join(path)}"
        return
    for subject, message in check_pod_spec(spec):
        yield f"{kind}/{name}/{subject}", message


def main(argv):
    files = argv or sorted(glob.glob("manifests/*.yaml"))
    if not files:
        print("check-restricted: no manifests found", file=sys.stderr)
        return 2
    failures = 0
    for path in files:
        try:
            with open(path, encoding="utf-8") as handle:
                docs = [d for d in yaml.safe_load_all(handle) if isinstance(d, dict)]
        except (OSError, yaml.YAMLError) as err:
            print(f"check-restricted: cannot read {path}: {err}", file=sys.stderr)
            return 2
        for doc in docs:
            for subject, message in check_document(doc):
                print(f"check-restricted: {path}: {subject}: {message}", file=sys.stderr)
                failures += 1
    if failures:
        return 1
    print(f"check-restricted: ok ({len(files)} file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
