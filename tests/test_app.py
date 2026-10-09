import unittest
from app import scan_manifest, digest


class SecurityScannerTests(unittest.TestCase):
    def test_privileged_container_detected(self):
        yaml_text = """
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
"""
        rules = {f["rule"] for f in scan_manifest(yaml_text)}
        self.assertIn("PRIVILEGED_CONTAINER", rules)

    def test_wildcard_rbac_detected(self):
        yaml_text = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: broad
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""
        rules = {f["rule"] for f in scan_manifest(yaml_text)}
        self.assertIn("RBAC_WILDCARD_VERBS", rules)
        self.assertIn("RBAC_WILDCARD_RESOURCES", rules)

    def test_exposed_service_detected(self):
        yaml_text = """
apiVersion: v1
kind: Service
metadata:
  name: public
spec:
  type: LoadBalancer
"""
        rules = {f["rule"] for f in scan_manifest(yaml_text)}
        self.assertIn("EXPOSED_SERVICE", rules)

    def test_invalid_yaml_reported(self):
        result = scan_manifest("kind: [broken")
        self.assertEqual(result[0]["rule"], "INVALID_YAML")

    def test_digest_changes_when_content_changes(self):
        self.assertNotEqual(digest("privileged: true"),
                            digest("privileged: false"))


if __name__ == "__main__":
    unittest.main()
