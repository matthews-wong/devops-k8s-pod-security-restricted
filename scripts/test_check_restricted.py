#!/usr/bin/env python3
"""Each case mutates the known-good deployment and expects one specific complaint."""
import copy
import pathlib
import unittest

import yaml

import check_restricted

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load(name):
    return yaml.safe_load((ROOT / "manifests" / name).read_text(encoding="utf-8"))


def messages(doc):
    return [message for _, message in check_restricted.check_document(doc)]


class RestrictedProfileTest(unittest.TestCase):
    def setUp(self):
        self.deployment = load("deployment.yaml")
        self.pod = self.deployment["spec"]["template"]["spec"]
        self.container = self.pod["containers"][0]

    def assert_flags(self, doc, fragment):
        found = messages(doc)
        self.assertTrue(any(fragment in m for m in found), f"{fragment!r} not in {found}")

    def test_shipped_manifests_pass(self):
        for path in sorted((ROOT / "manifests").glob("*.yaml")):
            self.assertEqual(messages(yaml.safe_load(path.read_text(encoding="utf-8"))), [], path.name)

    def test_privileged(self):
        self.container["securityContext"]["privileged"] = True
        self.assert_flags(self.deployment, "privileged container")

    def test_privilege_escalation_unset(self):
        del self.container["securityContext"]["allowPrivilegeEscalation"]
        self.assert_flags(self.deployment, "allowPrivilegeEscalation")

    def test_capabilities_not_dropped(self):
        self.container["securityContext"]["capabilities"] = {"drop": ["NET_RAW"]}
        self.assert_flags(self.deployment, "drop must include ALL")

    def test_extra_capability(self):
        self.container["securityContext"]["capabilities"]["add"] = ["SYS_ADMIN"]
        self.assert_flags(self.deployment, "SYS_ADMIN")

    def test_run_as_root(self):
        self.pod["securityContext"]["runAsUser"] = 0
        self.assert_flags(self.deployment, "runAsUser must not be 0")

    def test_run_as_non_root_missing(self):
        del self.pod["securityContext"]["runAsNonRoot"]
        del self.container["securityContext"]["runAsNonRoot"]
        self.assert_flags(self.deployment, "runAsNonRoot")

    def test_seccomp_unconfined(self):
        self.pod["securityContext"]["seccompProfile"] = {"type": "Unconfined"}
        self.assert_flags(self.deployment, "seccompProfile")

    def test_host_network(self):
        self.pod["hostNetwork"] = True
        self.assert_flags(self.deployment, "hostNetwork")

    def test_host_path_volume(self):
        self.pod["volumes"].append({"name": "host", "hostPath": {"path": "/"}})
        self.assert_flags(self.deployment, "hostPath")

    def test_host_port(self):
        self.container["ports"][0]["hostPort"] = 80
        self.assert_flags(self.deployment, "hostPort 80")

    def test_init_container_is_checked(self):
        init = copy.deepcopy(self.container)
        init["name"] = "init"
        init["securityContext"]["allowPrivilegeEscalation"] = True
        self.pod["initContainers"] = [init]
        self.assert_flags(self.deployment, "allowPrivilegeEscalation")

    def test_namespace_not_enforcing(self):
        namespace = load("namespace.yaml")
        namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] = "baseline"
        self.assert_flags(namespace, "must be 'restricted'")


if __name__ == "__main__":
    unittest.main()
