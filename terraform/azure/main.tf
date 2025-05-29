terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
  required_version = ">= 1.0"
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.azure_region
}

resource "azurerm_container_group" "this" {
  name                = "auth-translator"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  os_type             = "Linux"

  container {
    name   = "auth-translator"
    image  = var.container_image
    cpu    = "0.5"
    memory = "1.0"

    command = concat([
      "./authtranslator"
      ], var.redis_address != "" ? ["-redis-addr", var.redis_address] : [],
      var.redis_ca != "" ? ["-redis-ca", var.redis_ca] : [])

    ports {
      port     = 8080
      protocol = "TCP"
    }

  }

  ip_address_type = "public"
  dns_name_label  = var.dns_name_label
  exposed_port    = 8080
}
