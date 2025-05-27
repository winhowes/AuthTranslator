variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
}

variable "container_image" {
  description = "Container image for the application"
  type        = string
}

variable "execution_role_arn" {
  description = "IAM role ARN for ECS tasks"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the service"
  type        = list(string)
}

variable "security_group_id" {
  description = "Security group ID for the service"
  type        = string
}

variable "in_token" {
  description = "Token value for incoming auth"
  type        = string
}

variable "out_token" {
  description = "Token value for outgoing auth"
  type        = string
}
