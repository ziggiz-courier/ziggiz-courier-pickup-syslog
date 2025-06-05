variable "name" {
  description = "Name of the kind cluster"
  type        = string
  default     = "ziggiz-courier-syslog"
}

variable "kubeconfig_path" {
  description = "Path to the kubeconfig file"
  type        = string
  default     = null
}
