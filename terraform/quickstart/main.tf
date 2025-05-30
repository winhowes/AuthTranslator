# Quick start using the Docker provider to run AuthTranslator locally

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 2.0"
    }
  }
  required_version = ">= 1.0"
}

provider "docker" {}

variable "container_image" {
  type        = string
  description = "Container image to run"
  default     = "ghcr.io/winhowes/authtranslator:latest"
}

resource "docker_image" "authtranslator" {
  name = var.container_image
}

resource "docker_container" "authtranslator" {
  image = docker_image.authtranslator.name
  name  = "authtranslator"
  ports {
    internal = 8080
    external = 8080
  }
}
