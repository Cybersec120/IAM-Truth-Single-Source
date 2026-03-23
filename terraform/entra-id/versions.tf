terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.85"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # ── Azure WAF: Operational Excellence ─────────────────────────────────────
  # Remote state in Azure Storage: encrypted, locked, OIDC-authenticated.
  # Uncomment before first production apply.
  # backend "azurerm" {
  #   resource_group_name  = "rg-iam-terraform-state"
  #   storage_account_name = "stiamtfstate"
  #   container_name       = "iam-platform"
  #   key                  = "entra-id/terraform.tfstate"
  #   use_oidc             = true
  # }
}

# ── Entra ID (Azure AD) provider ──────────────────────────────────────────────
# In CI/CD: OIDC workload identity — zero stored credentials (WAF: Security).
# Locally: `az login` or ARM_TENANT_ID / ARM_CLIENT_ID / ARM_CLIENT_SECRET.
provider "azuread" {}

provider "azurerm" {
  features {}
  use_oidc = true
}
