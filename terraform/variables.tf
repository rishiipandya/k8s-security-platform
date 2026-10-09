variable "kubeconfig_path" {
  description = "Path to the Kubernetes client configuration"
  type        = string
  default     = "~/.kube/config"
}

variable "namespace" {
  description = "Namespace where the platform is deployed"
  type        = string
  default     = "security-platform"
}
