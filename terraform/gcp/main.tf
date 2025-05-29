terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.0"
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

resource "google_cloud_run_service" "this" {
  name     = "auth-translator"
  location = var.gcp_region

  template {
    spec {
      containers = [
        {
          image = var.container_image
          ports = [{
            name          = "http1"
            container_port = 8080
          }]
          args = concat(
            var.redis_address != "" ? ["-redis-addr", var.redis_address] : [],
            var.redis_ca != "" ? ["-redis-ca", var.redis_ca] : []
          )
        }
      ]
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }
}
