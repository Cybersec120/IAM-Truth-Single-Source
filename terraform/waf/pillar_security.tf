# ─────────────────────────────────────────────────────────────────────────────
# pillar_security.tf — enterprise-iam-platform / waf
#
# Azure Well-Architected Framework: SECURITY PILLAR
#
# SE:01 — Security baseline aligned to Microsoft cloud security benchmark
# SE:02 — Secured development lifecycle (Terraform linting, secrets scanning)
# SE:03 — Identities are the primary security perimeter → Entra Conditional Access
# SE:04 — Segment and perimeter the solution (private endpoints, network ACLs)
# SE:05 — Use identity controls on all datastores (RBAC on KV, Storage, Log Analytics)
# SE:06 — Encrypt data at rest and in transit (CMK via KV, TLS 1.2+ enforced)
# SE:07 — Protect credentials (no secrets in code, KV references everywhere)
# SE:08 — Harden all workloads (Defender for Cloud, security policies)
# SE:10 — Monitor security (Defender, diagnostic settings, KQL alert rules)
# SE:12 — Protect sensitive data (data classification tags, audit logging)
# ─────────────────────────────────────────────────────────────────────────────

# ── Microsoft Defender for Cloud ──────────────────────────────────────────────
# SE:08 / SE:10 — Enable Defender plans on the subscription for the IAM stack.
# Key plans for an IAM platform:
#   - Defender for Key Vault   → alerts on anomalous access (unusual IPs, mass export)
#   - Defender for Storage     → malware scanning on log archive
#   - Defender for DNS         → detect C2 beaconing via DNS

resource "azurerm_security_center_subscription_pricing" "key_vault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "dns" {
  tier          = "Standard"
  resource_type = "Dns"
}

# SE:10 — Security contact for high-severity Defender alerts
resource "azurerm_security_center_contact" "iam_security" {
  email               = var.security_contact_email
  phone               = var.security_contact_phone
  alert_notifications = true
  alerts_to_admins    = true
}

# ── Azure Policy — IAM guardrails ─────────────────────────────────────────────
# SE:01 — Enforce the security baseline via Azure Policy assignments.
# Policies are assigned at the resource group scope (principle of least blast radius).

# Deny Key Vault creation without soft delete (prevent accidental secret loss)
resource "azurerm_resource_group_policy_assignment" "kv_soft_delete" {
  name                 = "deny-kv-no-softdelete"
  resource_group_id    = azurerm_resource_group.iam.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d"
  display_name         = "IAM: Key vaults must have soft delete enabled"
  description          = "Prevents Key Vault resources without soft delete — aligns to RE:07 and SE:07"
  enforce              = true
}

# Deny Key Vault creation without purge protection
resource "azurerm_resource_group_policy_assignment" "kv_purge_protection" {
  name                 = "deny-kv-no-purge-protection"
  resource_group_id    = azurerm_resource_group.iam.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/0b60c0b2-2dc2-4e1c-b5c9-abbed971de53"
  display_name         = "IAM: Key vaults must have purge protection enabled"
  enforce              = true
}

# Require HTTPS on storage accounts (log archive)
resource "azurerm_resource_group_policy_assignment" "storage_https" {
  name                 = "require-storage-https"
  resource_group_id    = azurerm_resource_group.iam.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
  display_name         = "IAM: Storage accounts must use HTTPS"
  enforce              = true
}

# Require TLS 1.2 minimum on storage
resource "azurerm_resource_group_policy_assignment" "storage_tls" {
  name                 = "require-storage-tls12"
  resource_group_id    = azurerm_resource_group.iam.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/fe83a0eb-a853-422d-aac2-1bffd182c5d0"
  display_name         = "IAM: Storage accounts must use minimum TLS 1.2"
  enforce              = true
}

# Deny public network access to Key Vault
resource "azurerm_resource_group_policy_assignment" "kv_no_public" {
  name                 = "deny-kv-public-network"
  resource_group_id    = azurerm_resource_group.iam.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/405c5871-3e91-4644-8a63-58e19d68ff5b"
  display_name         = "IAM: Key vaults must deny public network access"
  enforce              = true
}

# ── Customer-Managed Keys ─────────────────────────────────────────────────────
# SE:06 — Encrypt data at rest using CMK for the log archive storage account.
# The encryption key lives in Key Vault (premium SKU = HSM-backed).

resource "azurerm_key_vault_key" "log_archive_cmk" {
  name         = "cmk-log-archive"
  key_vault_id = azurerm_key_vault.iam_primary.id
  key_type     = "RSA-HSM"   # Hardware-backed (requires premium KV SKU)
  key_size     = 4096

  key_opts = ["encrypt", "decrypt", "wrapKey", "unwrapKey"]

  # Key auto-rotation policy — SE:07, rotate annually
  rotation_policy {
    automatic {
      time_before_expiry = "P30D"   # Rotate 30 days before expiry
    }
    expire_after         = "P395D"  # 13-month validity (covers 1-year + buffer)
    notify_before_expiry = "P30D"
  }

  expiration_date = timeadd(timestamp(), "8760h")  # Initial: 1 year

  tags = merge(local.common_tags, {
    Pillar    = "Security"
    KeyPurpose = "log-archive-encryption"
  })

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [azurerm_role_assignment.terraform_kv_officer]
}

# Assign CMK to storage account
resource "azurerm_storage_account_customer_managed_key" "log_archive" {
  storage_account_id = azurerm_storage_account.log_archive.id
  key_vault_id       = azurerm_key_vault.iam_primary.id
  key_name           = azurerm_key_vault_key.log_archive_cmk.name

  depends_on = [
    azurerm_role_assignment.storage_kv_crypto_user
  ]
}

# Storage account managed identity for CMK access
resource "azurerm_user_assigned_identity" "storage_cmk" {
  name                = "id-${local.prefix}-storage-cmk"
  resource_group_name = azurerm_resource_group.iam.name
  location            = azurerm_resource_group.iam.location
  tags                = local.common_tags
}

resource "azurerm_role_assignment" "storage_kv_crypto_user" {
  scope                = azurerm_key_vault.iam_primary.id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_user_assigned_identity.storage_cmk.principal_id
}

# ── Diagnostic Settings — stream KV events to Log Analytics ──────────────────
# SE:10 — Audit every Key Vault operation for compliance and forensic readiness.

resource "azurerm_monitor_diagnostic_setting" "kv_primary" {
  name                       = "diag-${azurerm_key_vault.iam_primary.name}"
  target_resource_id         = azurerm_key_vault.iam_primary.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.iam.id
  storage_account_id         = azurerm_storage_account.log_archive.id

  enabled_log { category = "AuditEvent" }
  enabled_log { category = "AzurePolicyEvaluationDetails" }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "kv_secondary" {
  name                       = "diag-${azurerm_key_vault.iam_secondary.name}"
  target_resource_id         = azurerm_key_vault.iam_secondary.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.iam.id

  enabled_log { category = "AuditEvent" }
  metric { category = "AllMetrics"; enabled = true }
}

resource "azurerm_monitor_diagnostic_setting" "storage_archive" {
  name                       = "diag-${azurerm_storage_account.log_archive.name}"
  target_resource_id         = "${azurerm_storage_account.log_archive.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.iam.id

  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }
  metric { category = "Transaction"; enabled = true }
}

# ── Private Endpoints — SE:04 network segmentation ───────────────────────────
# Key Vault private endpoint prevents any public internet path to the vault.
# All access must traverse the private network or approved VNet integration.

resource "azurerm_private_dns_zone" "kv" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.iam.name
  tags                = local.common_tags
}

resource "azurerm_private_endpoint" "kv_primary" {
  name                = "pe-${azurerm_key_vault.iam_primary.name}"
  location            = azurerm_resource_group.iam.location
  resource_group_name = azurerm_resource_group.iam.name

  # Subnet reference — must be pre-created (managed by networking team)
  # In production, reference data source for the existing subnet:
  # subnet_id = data.azurerm_subnet.iam_services.id
  subnet_id = azurerm_subnet.iam_services.id

  private_service_connection {
    name                           = "psc-kv-primary"
    private_connection_resource_id = azurerm_key_vault.iam_primary.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }

  private_dns_zone_group {
    name                 = "kv-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.kv.id]
  }

  tags = merge(local.common_tags, { Pillar = "Security" })
}

# VNet + Subnet for IAM services private connectivity
resource "azurerm_virtual_network" "iam" {
  name                = "vnet-${local.prefix}"
  address_space       = ["10.100.0.0/16"]
  location            = azurerm_resource_group.iam.location
  resource_group_name = azurerm_resource_group.iam.name
  tags                = local.common_tags
}

resource "azurerm_subnet" "iam_services" {
  name                 = "snet-iam-services"
  resource_group_name  = azurerm_resource_group.iam.name
  virtual_network_name = azurerm_virtual_network.iam.name
  address_prefixes     = ["10.100.1.0/24"]

  # Disable network policies for private endpoint subnet
  private_endpoint_network_policies_enabled = false

  service_endpoints = ["Microsoft.KeyVault", "Microsoft.Storage"]
}
