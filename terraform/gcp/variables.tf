variable "gcp_project" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
}

variable "container_image" {
  description = "Container image for the application"
  type        = string
}

variable "redis_address" {
  description = "Optional Redis host:port for distributed rate limiting"
  type        = string
  default     = ""
}

variable "redis_ca" {
  description = "Optional CA certificate for Redis TLS"
  type        = string
  default     = ""
}

variable "config_path" {
  description = "Path to the configuration file inside the container"
  type        = string
  default     = "config.yaml"
}

variable "allowlist_path" {
  description = "Path to the allowlist file inside the container"
  type        = string
  default     = "allowlist.yaml"
}

variable "denylist_path" {
  description = "Path to the denylist file inside the container"
  type        = string
  default     = "denylist.yaml"
}

