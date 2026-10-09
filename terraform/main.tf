resource "kubernetes_config_map_v1" "security_policy_config" {
  metadata {
    name      = "security-policy-config"
    namespace = var.namespace

    labels = {
      app        = "security-platform"
      managed-by = "terraform"
    }
  }

  data = {
    "policy-mode"               = "enforce"
    "privileged-containers"     = "deny"
    "root-containers"           = "warn"
    "wildcard-rbac"             = "deny"
    "exposed-service-review"    = "required"
    "drift-response"            = "alert-and-stage-rollback"
    "automatic-production-fix"  = "false"
  }
}
