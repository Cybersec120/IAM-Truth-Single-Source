# ─────────────────────────────────────────────────────────────────────────────
# monitoring.tf — enterprise-iam-platform / entra-id
#
# Azure WAF: Reliability + Operational Excellence
#
# Three layers of observability:
#   1. Log Analytics workspace — central sink for all Entra ID audit/sign-in logs
#   2. Diagnostic settings    — stream Entra logs into Log Analytics
#   3. Alert rules            — fire on risky sign-ins, CA policy failures,
#                               admin role changes, and MFA registration events
#
# WAF alignment:
#   Reliability        — proactive alerting before users are impacted
#   Operational Excel. — structured logs enable Sentinel SIEM integration
#   Security           — audit trail for all privileged identity operations
# ─────────────────────────────────────────────────────────────────────────────

# ── Resource group for supporting Azure resources ─────────────────────────────

resource "azurerm_resource_group" "iam_monitoring" {
  name     = "rg-${local.name_prefix}-monitoring"
  location = var.location
  tags     = local.common_tags
}

# ── Log Analytics workspace ───────────────────────────────────────────────────
# WAF: Reliability — centralised logging enables cross-resource correlation.
# WAF: Cost Opt.  — retention tuned via var.log_retention_days.

resource "azurerm_log_analytics_workspace" "iam" {
  name                = "law-${local.name_prefix}-iam"
  location            = azurerm_resource_group.iam_monitoring.location
  resource_group_name = azurerm_resource_group.iam_monitoring.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = local.common_tags
}

# ── Entra ID diagnostic settings → Log Analytics ──────────────────────────────
# Streams AuditLogs and SignInLogs for all CA policy evaluations,
# sign-in events, and directory changes.

resource "azurerm_monitor_aad_diagnostic_setting" "entra_logs" {
  name               = "ds-${local.name_prefix}-entra-to-law"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.iam.id

  # Sign-in logs — every authentication event
  enabled_log {
    category = "SignInLogs"
  }

  # Audit logs — directory changes, app registrations, role assignments
  enabled_log {
    category = "AuditLogs"
  }

  # Non-interactive sign-ins (service principals, daemon apps)
  enabled_log {
    category = "NonInteractiveUserSignInLogs"
  }

  # Service principal sign-ins (client credentials, app-to-app)
  enabled_log {
    category = "ServicePrincipalSignInLogs"
  }

  # Managed Identity sign-ins
  enabled_log {
    category = "ManagedIdentitySignInLogs"
  }

  # Risky users — Identity Protection detections
  enabled_log {
    category = "RiskyUsers"
  }

  # User risk events — leaked credentials, atypical travel
  enabled_log {
    category = "UserRiskEvents"
  }
}

# ── Action group — IAM alert notifications ────────────────────────────────────

resource "azurerm_monitor_action_group" "iam_alerts" {
  name                = "ag-${local.name_prefix}-iam-alerts"
  resource_group_name = azurerm_resource_group.iam_monitoring.name
  short_name          = "iam-alerts"
  tags                = local.common_tags

  email_receiver {
    name                    = "iam-engineering"
    email_address           = var.alert_action_group_email
    use_common_alert_schema = true
  }
}

# ── Alert rules (KQL-based scheduled queries) ─────────────────────────────────

# Alert 1: High-volume failed sign-ins (potential brute force / credential stuffing)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "failed_signins" {
  name                = "alert-${local.name_prefix}-failed-signins"
  location            = azurerm_resource_group.iam_monitoring.location
  resource_group_name = azurerm_resource_group.iam_monitoring.name
  description         = "Fires when a single account has >10 failed sign-ins in 10 minutes"
  severity            = 2
  enabled             = true
  evaluation_frequency = "PT10M"
  window_duration      = "PT10M"

  scopes = [azurerm_log_analytics_workspace.iam.id]

  criteria {
    query = <<-KQL
      SigninLogs
      | where ResultType != "0"
      | where ResultType !in ("50140", "50076", "50079") // Exclude MFA interrupts
      | summarize FailureCount = count() by UserPrincipalName, bin(TimeGenerated, 10m)
      | where FailureCount > 10
      | project TimeGenerated, UserPrincipalName, FailureCount
    KQL
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_alerts.id]
  }

  tags = local.common_tags
}

# Alert 2: Privileged role assignment outside business hours
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "offhours_role_assignment" {
  name                = "alert-${local.name_prefix}-offhours-role-assign"
  location            = azurerm_resource_group.iam_monitoring.location
  resource_group_name = azurerm_resource_group.iam_monitoring.name
  description         = "Fires when a privileged Azure AD role is assigned outside 07:00-19:00 UTC"
  severity            = 1
  enabled             = true
  evaluation_frequency = "PT15M"
  window_duration      = "PT15M"

  scopes = [azurerm_log_analytics_workspace.iam.id]

  criteria {
    query = <<-KQL
      AuditLogs
      | where OperationName == "Add member to role"
      | where Result == "success"
      | extend Hour = datetime_part("hour", TimeGenerated)
      | where Hour < 7 or Hour > 19
      | extend
          Actor = tostring(InitiatedBy.user.userPrincipalName),
          TargetUser = tostring(TargetResources[0].userPrincipalName),
          RoleName = tostring(TargetResources[1].displayName)
      | project TimeGenerated, Actor, TargetUser, RoleName
    KQL
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_alerts.id]
  }

  tags = local.common_tags
}

# Alert 3: Conditional access policy disabled
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "ca_policy_disabled" {
  name                = "alert-${local.name_prefix}-ca-policy-disabled"
  location            = azurerm_resource_group.iam_monitoring.location
  resource_group_name = azurerm_resource_group.iam_monitoring.name
  description         = "Fires when any CA policy is disabled — may indicate unauthorised change"
  severity            = 1
  enabled             = true
  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  scopes = [azurerm_log_analytics_workspace.iam.id]

  criteria {
    query = <<-KQL
      AuditLogs
      | where OperationName in ("Update conditional access policy", "Delete conditional access policy")
      | extend
          Actor = tostring(InitiatedBy.user.userPrincipalName),
          PolicyName = tostring(TargetResources[0].displayName),
          NewState = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)
      | where NewState has "disabled" or OperationName has "Delete"
      | project TimeGenerated, Actor, PolicyName, NewState, OperationName
    KQL
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_alerts.id]
  }

  tags = local.common_tags
}

# Alert 4: New app registration created (detect shadow IT / rogue apps)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "new_app_registration" {
  name                = "alert-${local.name_prefix}-new-app-registration"
  location            = azurerm_resource_group.iam_monitoring.location
  resource_group_name = azurerm_resource_group.iam_monitoring.name
  description         = "Fires when a new application is registered — confirm it was authorised"
  severity            = 3
  enabled             = true
  evaluation_frequency = "PT30M"
  window_duration      = "PT30M"

  scopes = [azurerm_log_analytics_workspace.iam.id]

  criteria {
    query = <<-KQL
      AuditLogs
      | where OperationName == "Add application"
      | extend
          Actor = tostring(InitiatedBy.user.userPrincipalName),
          AppName = tostring(TargetResources[0].displayName),
          AppId = tostring(TargetResources[0].id)
      | project TimeGenerated, Actor, AppName, AppId
    KQL
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_alerts.id]
  }

  tags = local.common_tags
}

# Alert 5: High-risk user detected by Identity Protection (P2)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "high_risk_user" {
  count = var.entra_p2_features_enabled ? 1 : 0

  name                = "alert-${local.name_prefix}-high-risk-user"
  location            = azurerm_resource_group.iam_monitoring.location
  resource_group_name = azurerm_resource_group.iam_monitoring.name
  description         = "Fires when Entra Identity Protection flags a user as High risk"
  severity            = 1
  enabled             = true
  evaluation_frequency = "PT15M"
  window_duration      = "PT15M"

  scopes = [azurerm_log_analytics_workspace.iam.id]

  criteria {
    query = <<-KQL
      RiskyUsers
      | where RiskLevel == "high"
      | where RiskState in ("atRisk", "confirmedCompromised")
      | project TimeGenerated, UserPrincipalName, RiskLevel, RiskState, RiskDetail
    KQL
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_alerts.id]
  }

  tags = local.common_tags
}
