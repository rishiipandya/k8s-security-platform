package kubernetes.admission

import rego.v1

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("CRITICAL: privileged container '%s' is forbidden", [container.name])
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf("HIGH: container '%s' explicitly runs as root", [container.name])
}

deny contains msg if {
    input.kind == "Service"
    input.spec.type == "NodePort"
    msg := sprintf("MEDIUM: NodePort service '%s' requires exposure review", [input.metadata.name])
}

deny contains msg if {
    input.kind == "Service"
    input.spec.type == "LoadBalancer"
    msg := sprintf("MEDIUM: LoadBalancer service '%s' requires exposure review", [input.metadata.name])
}

deny contains msg if {
    input.kind in {"Role", "ClusterRole"}
    rule := input.rules[_]
    "*" in rule.verbs
    msg := sprintf("HIGH: wildcard RBAC verbs in '%s'", [input.metadata.name])
}

deny contains msg if {
    input.kind in {"Role", "ClusterRole"}
    rule := input.rules[_]
    "*" in rule.resources
    msg := sprintf("HIGH: wildcard RBAC resources in '%s'", [input.metadata.name])
}
