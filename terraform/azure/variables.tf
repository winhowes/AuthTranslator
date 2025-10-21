variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
}

variable "azure_region" {
  description = "Azure region"
  type        = string
}

variable "dns_name_label" {
  description = "DNS name label for the container"
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

