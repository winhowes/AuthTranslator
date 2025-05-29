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

