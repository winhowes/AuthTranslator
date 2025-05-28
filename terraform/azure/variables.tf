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

