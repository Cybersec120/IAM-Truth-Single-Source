# ─────────────────────────────────────────────────────────────────────────────
# locals.tf — enterprise-iam-platform / waf
# ─────────────────────────────────────────────────────────────────────────────

locals {
  prefix = "${var.organization}-iam-${var.environment}"

  common_tags = {
    Project                 = "enterprise-iam-platform"
    Environment             = var.environment
    ManagedBy               = "terraform"
    Owner                   = "iam-engineering"
    WellArchitectedFramework = "true"
    CostCenter              = "security-engineering"
  }
}

data "azurerm_client_config" "current" {}

# ── Shared resource group ─────────────────────────────────────────────────────

resource "azurerm_resource_group" "iam" {
  name     = "rg-${local.prefix}"
  location = var.location
  tags     = local.common_tags
}

# Secondary region resource group for geo-redundant resources
resource "azurerm_resource_group" "iam_secondary" {
  name     = "rg-${local.prefix}-secondary"
  location = var.location_secondary
  tags     = merge(local.common_tags, { Region = "secondary" })
}
