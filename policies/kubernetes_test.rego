package kubernetes.admission

import rego.v1

test_privileged_pod_is_denied if {
    results := deny with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "bad-pod"},
        "spec": {"containers": [{
            "name": "app",
            "securityContext": {"privileged": true}
        }]}
    }
    some msg in results
    contains(msg, "privileged container")
}

test_root_container_is_denied if {
    results := deny with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "root-pod"},
        "spec": {"containers": [{
            "name": "app",
            "securityContext": {"runAsUser": 0}
        }]}
    }
    some msg in results
    contains(msg, "runs as root")
}

test_nodeport_service_is_flagged if {
    results := deny with input as {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "public"},
        "spec": {"type": "NodePort"}
    }
    some msg in results
    contains(msg, "NodePort")
}

test_wildcard_rbac_is_denied if {
    results := deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "broad"},
        "rules": [{
            "verbs": ["*"],
            "resources": ["*"]
        }]
    }
    count(results) >= 2
}

test_safe_pod_is_allowed if {
    results := deny with input as {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "safe-pod"},
        "spec": {"containers": [{
            "name": "app",
            "securityContext": {
                "privileged": false,
                "runAsUser": 10001
            }
        }]}
    }
    count(results) == 0
}
