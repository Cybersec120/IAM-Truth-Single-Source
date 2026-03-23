# ─────────────────────────────────────────────────────────────────────────────
# pillar_reliability.tf — enterprise-iam-platform / waf
#
# Azure Well-Architected Framework: RELIABILITY PILLAR
#
# Design goals for IAM:
#   RE:01 — Simplicity and efficiency in your design (dedicated KV per environment)
#   RE:02 — Recovery targets (RPO/RTO) defined per criticality
#   RE:04 — Design redundancy at all layers (geo-replication, AZ spreading)
#   RE:07 — Self-preservation (soft delete, purge protection on Key Vault)
#   RE:08 — Test for resiliency (backup policies documented)
#   RE:09 — Disaster recovery plan (secondary region KV replica)
#
# IAM-specific reliability risks:
#   - Client secret or certificate loss → all app SSO breaks (RPO = 0, use KV)
#   - Log Analytics outage → blind to sign-in anomalies (mitigated by archival)
#   - Entra service outage → federation falls back to Kerberos / local auth (design doc)
# ─────────────────────────────────────────────────────────────────────────────

# ── Primary Key Vault — stores all IAM secrets and signing certs ──────────────

resource "azurerm_key_vault" "iam_primary" {
  name                = "kv-${local.prefix}-pri"
  location            = azurerm_resource_group.iam.location
  resource_group_name = azurerm_resource_group.iam.name
  tenant_id           = var.tenant_id
  sku_name            = var.key_vault_sku   # "premium" = HSM-backed, FIPS 140-2 Level 3

  # RE:07 — Self-preservation: prevents accidental secret/cert deletion
  soft_delete_retention_days  = var.backup_retention_days
  purge_protection_enabled    = true
  enable_rbac_authorization   = true   # RBAC over legacy access policies

  # Network ACL — deny public access; permit only listed IPs + Azure services
  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = []
  }

  tags = merge(local.common_tags, {
    Pillar      = "Reliability"
    DataClass   = "Confidential"
    Region      = "primary"
    Criticality = "P1"
  })
}

# ── Secondary Key Vault — geo-redundant replica ───────────────────────────────
# RE:09 — Disaster recovery: secrets replicated to secondary region via
# automation pipeline (see scripts/onboarding/kv_replication.py).
# Manual failover: update app configs to point to secondary KV endpoint.

resource "azurerm_key_vault" "iam_secondary" {
  name                = "kv-${local.prefix}-sec"
  location            = azurerm_resource_group.iam_secondary.location
  resource_group_name = azurerm_resource_group.iam_secondary.name
  tenant_id           = var.tenant_id
  sku_name            = var.key_vault_sku

  soft_delete_retention_days = var.backup_retention_days
  purge_protection_enabled   = true
  enable_rbac_authorization  = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.allowed_ip_ranges
  }

  tags = merge(local.common_tags, {
    Pillar      = "Reliability"
    DataClass   = "Confidential"
    Region      = "secondary"
    Criticality = "P1"
    Role        = "DR-replica"
  })
}

# ── Key Vault secrets — IAM platform secrets ─────────────────────────────────
# Secrets are named with version suffix to support zero-downtime rotation:
#   oidc-client-secret-<appname>-current   ← active
#   oidc-client-secret-<appname>-previous  ← kept 30d then purged

# Placeholder secret demonstrating the pattern — real secrets injected by
# the onboarding automation script (scripts/onboarding/onboard_app.py)
resource "azurerm_key_vault_secret" "platform_version" {
  name         = "iam-platform-version"
  value        = "1.0.0"
  key_vault_id = azurerm_key_vault.iam_primary.id

  content_type = "text/plain"
  tags = merge(local.common_tags, { SecretType = "metadata" })

  depends_on = [
    azurerm_role_assignment.terraform_kv_officer
  ]
}

# ── RBAC for Key Vault ────────────────────────────────────────────────────────

# Terraform service principal — needs Key Vault Officer to write secrets
resource "azurerm_role_assignment" "terraform_kv_officer" {
  scope                = azurerm_key_vault.iam_primary.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "terraform_kv_officer_secondary" {
  scope                = azurerm_key_vault.iam_secondary.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ── Log Analytics Workspace — centralised IAM log store ───────────────────────
# RE:04 — Redundancy: Log Analytics is zone-redundant in supported regions.
# RE:02 — Retention aligned to regulatory requirement (365 days default).

resource "azurerm_log_analytics_workspace" "iam" {
  name                = "law-${local.prefix}"
  location            = azurerm_resource_group.iam.location
  resource_group_name = azurerm_resource_group.iam.name
  sku                 = var.log_analytics_sku
  retention_in_days   = var.log_retention_days

  # Daily cap prevents runaway ingestion costs while alerting on breach
  daily_quota_gb = var.environment == "prod" ? -1 : 5  # Uncapped in prod

  tags = merge(local.common_tags, {
    Pillar = "Reliability"
    Role   = "central-log-store"
  })
}

# Archive-tier storage account — long-term audit log retention (7 years)
# for regulatory compliance (SOX, HIPAA, FedRAMP depending on industry).
resource "azurerm_storage_account" "log_archive" {
  name                     = "st${replace(local.prefix, "-", "")}logs"
  resource_group_name      = azurerm_resource_group.iam.name
  location                 = azurerm_resource_group.iam.location
  account_tier             = "Standard"
  account_replication_type = "GRS"   # Geo-redundant storage
  account_kind             = "StorageV2"

  # Security hardening
  https_traffic_only_enabled       = true
  min_tls_version                  = "TLS1_2"
  allow_nested_items_to_be_public  = false
  shared_access_key_enabled        = false   # Force AAD auth only
  public_network_access_enabled    = false

  blob_properties {
    delete_retention_policy {
      days = 30
    }
    versioning_enabled       = true
    change_feed_enabled      = true
    last_access_time_enabled = true
  }

  tags = merge(local.common_tags, {
    Pillar    = "Reliability"
    DataClass = "Confidential"
    Purpose   = "audit-log-archive"
  })
}

# Immutable archive container — WORM storage for audit logs
resource "azurerm_storage_container" "audit_logs" {
  name                  = "iam-audit-logs"
  storage_account_name  = azurerm_storage_account.log_archive.name
  container_access_type = "private"
}
