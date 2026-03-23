# ─────────────────────────────────────────────────────────────────────────────
# outputs.tf — enterprise-iam-platform / waf
# ─────────────────────────────────────────────────────────────────────────────

output "resource_group_name" {
  description = "Primary IAM resource group name."
  value       = azurerm_resource_group.iam.name
}

output "resource_group_secondary" {
  description = "Secondary (DR) IAM resource group name."
  value       = azurerm_resource_group.iam_secondary.name
}

# ── Reliability ───────────────────────────────────────────────────────────────

output "key_vault_primary_uri" {
  description = "Primary Key Vault URI — use this for all app secret references."
  value       = azurerm_key_vault.iam_primary.vault_uri
}

output "key_vault_secondary_uri" {
  description = "Secondary (DR) Key Vault URI — failover target."
  value       = azurerm_key_vault.iam_secondary.vault_uri
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace resource ID — used for diagnostic setting targets."
  value       = azurerm_log_analytics_workspace.iam.id
}

output "log_analytics_workspace_key" {
  description = "Log Analytics primary shared key (for agent configuration)."
  sensitive   = true
  value       = azurerm_log_analytics_workspace.iam.primary_shared_key
}

output "log_archive_storage_account" {
  description = "Audit log archive storage account name."
  value       = azurerm_storage_account.log_archive.name
}

# ── Security ──────────────────────────────────────────────────────────────────

output "cmk_key_id" {
  description = "Customer-managed encryption key ID for log archive storage."
  value       = azurerm_key_vault_key.log_archive_cmk.id
}

output "private_endpoint_kv_ip" {
  description = "Private IP address for the Key Vault private endpoint."
  value       = azurerm_private_endpoint.kv_primary.private_service_connection[0].private_ip_address
}

output "vnet_id" {
  description = "IAM services VNet ID."
  value       = azurerm_virtual_network.iam.id
}

output "iam_services_subnet_id" {
  description = "IAM services subnet ID — reference for VM / container deployments."
  value       = azurerm_subnet.iam_services.id
}

# ── Cost Optimization ─────────────────────────────────────────────────────────

output "budget_id" {
  description = "Azure Cost Management budget resource ID."
  value       = azurerm_consumption_budget_resource_group.iam.id
}

# ── Operational Excellence ────────────────────────────────────────────────────

output "action_group_id" {
  description = "IAM oncall action group ID — use in all alert rule definitions."
  value       = azurerm_monitor_action_group.iam_oncall.id
}

output "alert_rule_ids" {
  description = "Map of alert rule names to their resource IDs."
  value = {
    brute_force          = azurerm_monitor_scheduled_query_rules_alert_v2.signin_brute_force.id
    impossible_travel    = azurerm_monitor_scheduled_query_rules_alert_v2.impossible_travel.id
    ca_policy_change     = azurerm_monitor_scheduled_query_rules_alert_v2.ca_policy_modification.id
    legacy_auth_bypass   = azurerm_monitor_scheduled_query_rules_alert_v2.legacy_auth_success.id
    kv_mass_access       = azurerm_monitor_scheduled_query_rules_alert_v2.kv_mass_secret_access.id
  }
}

output "workbook_id" {
  description = "IAM Operations Dashboard workbook resource ID."
  value       = azurerm_application_insights_workbook.iam_dashboard.id
}

# ── Quick reference portal links ──────────────────────────────────────────────

output "portal_links" {
  description = "Quick links for the WAF layer resources in Azure portal."
  value = {
    key_vault_primary    = "https://portal.azure.com/#@${var.tenant_id}/resource${azurerm_key_vault.iam_primary.id}"
    log_analytics        = "https://portal.azure.com/#@${var.tenant_id}/resource${azurerm_log_analytics_workspace.iam.id}/logs"
    defender_for_cloud   = "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0"
    cost_management      = "https://portal.azure.com/#blade/Microsoft_Azure_CostManagement/Menu/costanalysis"
    workbook_dashboard   = "https://portal.azure.com/#@${var.tenant_id}/resource${azurerm_application_insights_workbook.iam_dashboard.id}/workbook"
  }
}

# ── WAF Assessment summary ────────────────────────────────────────────────────

output "waf_coverage_summary" {
  description = "Summary of Azure Well-Architected Framework pillar coverage implemented."
  value = {
    reliability = {
      primary_key_vault          = azurerm_key_vault.iam_primary.name
      secondary_key_vault        = azurerm_key_vault.iam_secondary.name
      soft_delete_retention_days = var.backup_retention_days
      log_retention_days         = var.log_retention_days
      geo_redundant_storage      = true
      purge_protection           = true
    }
    security = {
      defender_key_vault  = "enabled"
      defender_storage    = "enabled"
      defender_dns        = "enabled"
      cmk_encryption      = true
      private_endpoint    = true
      rbac_authorization  = true
      policy_assignments  = 5
    }
    cost_optimization = {
      budget_cap_usd     = var.budget_amount_usd
      alert_thresholds   = var.budget_alert_thresholds
      lifecycle_rules    = "hot→cool@30d, cool→cold@90d, archive@180d"
      tagging_policies   = 3
      cost_export        = "daily"
    }
    operational_excellence = {
      kql_alert_rules   = 5
      action_group      = azurerm_monitor_action_group.iam_oncall.name
      workbook          = "IAM Platform Operations Dashboard"
      diagnostic_settings = 3
      saved_kql_queries = 4
    }
    performance_efficiency = {
      kv_availability_slo = "99.9%"
      kv_latency_slo_ms   = 100
      log_data_export     = "enabled"
      saved_kql_queries   = 4
      saturation_alerts   = true
    }
  }
}
