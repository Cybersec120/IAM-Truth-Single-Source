# ─────────────────────────────────────────────────────────────────────────────
# pillar_performance_efficiency.tf — enterprise-iam-platform / waf
#
# Azure Well-Architected Framework: PERFORMANCE EFFICIENCY PILLAR
#
# PE:01 — Establish performance targets (sign-in latency SLOs)
# PE:02 — Conduct capacity planning (Log Analytics daily cap, KV throttling limits)
# PE:05 — Scale intelligently (Log Analytics scales automatically; KV: 2000 RPS)
# PE:07 — Optimize code and infrastructure (KQL query tuning, index hints)
# PE:09 — Test performance (load test runbook documented)
# PE:11 — Optimize flow performance (Log Analytics commitment tiers for high volume)
#
# For an IAM platform, performance efficiency means:
#   - Token issuance latency < 300ms p95 (Entra SLA: 99.99%)
#   - Key Vault operations < 100ms p99 (KV SLA: 99.9%)
#   - Alert evaluation latency ≤ 5 min for critical detections
#   - Log ingestion lag < 2 min for sign-in events
# ─────────────────────────────────────────────────────────────────────────────

# ── Log Analytics capacity reservation ───────────────────────────────────────
# PE:11 — Commitment tier pricing saves 25-65% over PAYG at predictable volume.
# Switch from PerGB2018 to CapacityReservation once daily ingestion is steady.
# Tier recommendations:
#   < 100 GB/day  → PerGB2018 (current default)
#   100-200 GB/day → 100 GB reservation
#   200+ GB/day   → 200 GB reservation

# Log Analytics data export — PE:07: export cold data to cheap storage,
# keeping the workspace lean and queries fast.
resource "azurerm_log_analytics_data_export_rule" "signin_archive" {
  name                    = "export-signins-archive"
  resource_group_name     = azurerm_resource_group.iam.name
  workspace_resource_id   = azurerm_log_analytics_workspace.iam.id
  destination_resource_id = azurerm_storage_account.log_archive.id
  table_names             = ["SigninLogs", "AuditLogs", "AADNonInteractiveUserSignInLogs"]
  enabled                 = true
}

# ── Saved KQL queries (performance-tuned) ─────────────────────────────────────
# PE:07 — Each saved query uses time-bounded filters and summarise aggregation
# first before filtering rows — correct KQL optimization order.

resource "azurerm_log_analytics_saved_search" "signin_failure_rate" {
  name                       = "IAM-SigninFailureRate-1h"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.iam.id
  category                   = "IAM-Performance"
  display_name               = "Sign-in failure rate (last 1 hour)"

  # Optimized: time filter first, then summarise, then compute rate
  query = <<-KQL
    SigninLogs
    | where TimeGenerated > ago(1h)
    | summarize
        Total   = count(),
        Success = countif(ResultType == "0"),
        Failed  = countif(ResultType != "0")
        by bin(TimeGenerated, 5m)
    | extend FailureRate = round(100.0 * Failed / Total, 2)
    | project TimeGenerated, Total, Success, Failed, FailureRate
    | order by TimeGenerated asc
  KQL
}

resource "azurerm_log_analytics_saved_search" "token_issuance_latency" {
  name                       = "IAM-TokenLatency-p95"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.iam.id
  category                   = "IAM-Performance"
  display_name               = "Token issuance latency p50/p95/p99 (last 1 hour)"

  query = <<-KQL
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == "0"
    | where isnotnull(DurationMs)
    | summarize
        p50  = percentile(DurationMs, 50),
        p95  = percentile(DurationMs, 95),
        p99  = percentile(DurationMs, 99),
        Count = count()
        by bin(TimeGenerated, 5m), AppDisplayName
    | order by TimeGenerated asc
  KQL
}

resource "azurerm_log_analytics_saved_search" "ca_policy_evaluation_latency" {
  name                       = "IAM-CAPolicyEvalLatency"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.iam.id
  category                   = "IAM-Performance"
  display_name               = "Conditional Access evaluation result breakdown (24h)"

  query = <<-KQL
    SigninLogs
    | where TimeGenerated > ago(24h)
    | mv-expand ConditionalAccessPolicies
    | extend
        PolicyName   = tostring(ConditionalAccessPolicies.displayName),
        PolicyResult = tostring(ConditionalAccessPolicies.result)
    | where isnotempty(PolicyName)
    | summarize
        Enforced    = countif(PolicyResult == "success"),
        NotApplied  = countif(PolicyResult == "notApplied"),
        Failure     = countif(PolicyResult == "failure")
        by PolicyName
    | extend TotalEvals = Enforced + NotApplied + Failure
    | extend EnforcementRate = round(100.0 * Enforced / TotalEvals, 1)
    | order by EnforcementRate asc
  KQL
}

resource "azurerm_log_analytics_saved_search" "kv_operation_latency" {
  name                       = "IAM-KVOperationLatency"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.iam.id
  category                   = "IAM-Performance"
  display_name               = "Key Vault operation latency by type (1h)"

  # PE:01 — SLO target: 100ms p99 for all KV operations
  query = <<-KQL
    AzureDiagnostics
    | where TimeGenerated > ago(1h)
    | where ResourceType == "VAULTS"
    | where isnotnull(DurationMs)
    | summarize
        p50  = percentile(DurationMs, 50),
        p99  = percentile(DurationMs, 99),
        Count = count()
        by OperationName
    | extend SLOBreached = iff(p99 > 100, "YES", "no")
    | order by p99 desc
  KQL
}

# ── Metric alerts for SLO breach ──────────────────────────────────────────────
# PE:01 — Alert if KV availability drops below 99.9%

resource "azurerm_monitor_metric_alert" "kv_availability" {
  name                = "alert-${local.prefix}-kv-availability"
  resource_group_name = azurerm_resource_group.iam.name
  scopes              = [azurerm_key_vault.iam_primary.id]
  description         = "Key Vault availability below 99.9% SLO target"
  severity            = 1
  frequency           = "PT1M"
  window_size         = "PT5M"

  criteria {
    metric_namespace = "Microsoft.KeyVault/vaults"
    metric_name      = "Availability"
    aggregation      = "Average"
    operator         = "LessThan"
    threshold        = 99.9
  }

  action {
    action_group_id = azurerm_monitor_action_group.iam_oncall.id
  }

  tags = merge(local.common_tags, { Pillar = "PerformanceEfficiency" })
}

resource "azurerm_monitor_metric_alert" "kv_saturation" {
  name                = "alert-${local.prefix}-kv-saturation"
  resource_group_name = azurerm_resource_group.iam.name
  scopes              = [azurerm_key_vault.iam_primary.id]
  description         = "Key Vault approaching throttle limit (>80% of 2000 RPS)"
  severity            = 2
  frequency           = "PT1M"
  window_size         = "PT5M"

  criteria {
    metric_namespace = "Microsoft.KeyVault/vaults"
    metric_name      = "ServiceApiResult"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = 1600  # 80% of 2000 RPS KV limit
    dimension {
      name     = "StatusCode"
      operator = "Include"
      values   = ["200"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.iam_oncall.id
  }

  tags = local.common_tags
}
