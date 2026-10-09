output "policy_configmap_name" {
  description = "Name of the managed Kubernetes policy ConfigMap"
  value       = kubernetes_config_map_v1.security_policy_config.metadata[0].name
}

output "policy_settings" {
  description = "Declarative policy settings"
  value       = kubernetes_config_map_v1.security_policy_config.data
}
