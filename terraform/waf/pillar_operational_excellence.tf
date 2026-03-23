# ─────────────────────────────────────────────────────────────────────────────
# pillar_operational_excellence.tf — enterprise-iam-platform / waf
#
# Azure Well-Architected Framework: OPERATIONAL EXCELLENCE PILLAR
#
# OE:01 — DevOps culture (IaC via Terraform, GitOps, PR-gated deployments)
# OE:04 — Observability (structured logs, KQL alerts, dashboards)
# OE:05 — Deploy safely (staged rollout, ca_policy_state toggle in Entra module)
# OE:07 — Monitor system health (alert rules, action groups)
# OE:08 — Minimize operational overhead (runbooks via Azure Automation)
# OE:10 — Improve processes through incident data (alert → runbook → remediation)
# OE:12 — Routine operations through automation (onboarding scripts, lifecycle)
# ─────────────────────────────────────────────────────────────────────────────

# ── Action Group — alert routing ──────────────────────────────────────────────
# OE:07 — All IAM alerts funnel through a single action group.
# Supports email, webhook (PagerDuty/Slack), and ITSM connectors.

resource "azurerm_monitor_action_group" "iam_oncall" {
  name                = "ag-${local.prefix}-oncall"
  resource_group_name = azurerm_resource_group.iam.name
  short_name          = "IAMOncall"

  email_receiver {
    name                    = "iam-oncall-email"
    email_address           = var.alert_action_group_email
    use_common_alert_schema = true
  }

  dynamic "webhook_receiver" {
    for_each = var.alert_action_group_webhook != "" ? [1] : []
    content {
      name                    = "iam-webhook"
      service_uri             = var.alert_action_group_webhook
      use_common_alert_schema = true
    }
  }

  tags = merge(local.common_tags, { Pillar = "OperationalExcellence" })
}

# ── KQL Scheduled Query Alerts ────────────────────────────────────────────────
# OE:04 / OE:07 — Five production-grade KQL alerts for IAM operations.
# Each alert uses Entra sign-in + audit logs streamed to Log Analytics.

# ALERT 1: Brute-force / password spray — >20 failed sign-ins in 5 min from same IP
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "signin_brute_force" {
  name                = "alert-${local.prefix}-signin-bruteforce"
  resource_group_name = azurerm_resource_group.iam.name
  location            = azurerm_resource_group.iam.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"
  scopes               = [azurerm_log_analytics_workspace.iam.id]
  severity             = 1   # Critical

  criteria {
    query = <<-KQL
      SigninLogs
      | where TimeGenerated > ago(5m)
      | where ResultType != "0"
      | where ResultType in ("50126", "50053", "50055", "50057")
      | summarize FailedAttempts = count(), Users = dcount(UserPrincipalName)
          by IPAddress, bin(TimeGenerated, 5m)
      | where FailedAttempts > 20
      | project TimeGenerated, IPAddress, FailedAttempts, Users
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled          = false
  workspace_alerts_storage_enabled = false
  description                      = "Brute-force or password spray detected: >20 failed sign-ins in 5 min from a single IP."
  display_name                     = "IAM: Brute-force sign-in attempt"
  enabled                          = true
  skip_query_validation            = false

  action {
    action_groups = [azurerm_monitor_action_group.iam_oncall.id]
    custom_properties = {
      Severity   = "Critical"
      Runbook    = "https://wiki.contoso.com/runbooks/iam-brute-force"
      MITREAttack = "T1110.003"
    }
  }

  tags = merge(local.common_tags, { AlertType = "SecurityDetection" })
}

# ALERT 2: Impossible travel — same user from two distant locations within 1 hour
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "impossible_travel" {
  name                = "alert-${local.prefix}-impossible-travel"
  resource_group_name = azurerm_resource_group.iam.name
  location            = azurerm_resource_group.iam.location

  evaluation_frequency = "PT15M"
  window_duration      = "PT1H"
  scopes               = [azurerm_log_analytics_workspace.iam.id]
  severity             = 2   # High

  criteria {
    query = <<-KQL
      SigninLogs
      | where TimeGenerated > ago(1h)
      | where ResultType == "0"
      | where isnotempty(LocationDetails)
      | extend Country = tostring(LocationDetails.countryOrRegion)
      | summarize
          Countries = make_set(Country),
          IPs       = make_set(IPAddress),
          SigninCount = count()
          by UserPrincipalName, bin(TimeGenerated, 1h)
      | where array_length(Countries) > 1
      | project TimeGenerated, UserPrincipalName, Countries, IPs, SigninCount
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false
  description             = "User signed in from multiple countries within 1 hour — possible account compromise."
  display_name            = "IAM: Impossible travel detected"
  enabled                 = true

  action {
    action_groups = [azurerm_monitor_action_group.iam_oncall.id]
    custom_properties = {
      Runbook    = "https://wiki.contoso.com/runbooks/iam-account-compromise"
      MITREAttack = "T1078"
    }
  }

  tags = local.common_tags
}

# ALERT 3: Mass Conditional Access policy modification
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "ca_policy_modification" {
  name                = "alert-${local.prefix}-ca-policy-change"
  resource_group_name = azurerm_resource_group.iam.name
  location            = azurerm_resource_group.iam.location

  evaluation_frequency = "PT10M"
  window_duration      = "PT10M"
  scopes               = [azurerm_log_analytics_workspace.iam.id]
  severity             = 1   # Critical

  criteria {
    query = <<-KQL
      AuditLogs
      | where TimeGenerated > ago(10m)
      | where OperationName has "conditional access policy"
      | where ActivityDisplayName in (
          "Add conditional access policy",
          "Update conditional access policy",
          "Delete conditional access policy"
        )
      | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
      | extend PolicyName = tostring(TargetResources[0].displayName)
      | project TimeGenerated, Actor, ActivityDisplayName, PolicyName, CorrelationId
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false
  description             = "Conditional Access policy was added, modified, or deleted — review for unauthorised changes."
  display_name            = "IAM: Conditional Access policy modified"
  enabled                 = true

  action {
    action_groups = [azurerm_monitor_action_group.iam_oncall.id]
    custom_properties = {
      Severity = "Critical"
      Runbook  = "https://wiki.contoso.com/runbooks/iam-ca-change-review"
    }
  }

  tags = local.common_tags
}

# ALERT 4: MFA bypass or legacy auth success
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "legacy_auth_success" {
  name                = "alert-${local.prefix}-legacy-auth-success"
  resource_group_name = azurerm_resource_group.iam.name
  location            = azurerm_resource_group.iam.location

  evaluation_frequency = "PT10M"
  window_duration      = "PT10M"
  scopes               = [azurerm_log_analytics_workspace.iam.id]
  severity             = 1

  criteria {
    query = <<-KQL
      SigninLogs
      | where TimeGenerated > ago(10m)
      | where ResultType == "0"
      | where ClientAppUsed in (
          "Exchange ActiveSync",
          "IMAP4",
          "MAPI",
          "POP3",
          "SMTP",
          "Other clients"
        )
      | project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress,
                LocationDetails, ConditionalAccessStatus
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false
  description             = "Legacy auth sign-in succeeded — CA002 block-legacy policy may have a gap."
  display_name            = "IAM: Legacy authentication bypass detected"
  enabled                 = true

  action {
    action_groups = [azurerm_monitor_action_group.iam_oncall.id]
  }

  tags = local.common_tags
}

# ALERT 5: Key Vault secret mass access (potential exfiltration)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "kv_mass_secret_access" {
  name                = "alert-${local.prefix}-kv-mass-access"
  resource_group_name = azurerm_resource_group.iam.name
  location            = azurerm_resource_group.iam.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"
  scopes               = [azurerm_log_analytics_workspace.iam.id]
  severity             = 1

  criteria {
    query = <<-KQL
      AzureDiagnostics
      | where TimeGenerated > ago(5m)
      | where ResourceType == "VAULTS"
      | where OperationName == "SecretGet"
      | where ResultType == "Success"
      | summarize SecretReads = count(), SecretsAccessed = dcount(id_s)
          by CallerIPAddress, identity_claim_oid_g, bin(TimeGenerated, 5m)
      | where SecretReads > 20
      | project TimeGenerated, CallerIPAddress, identity_claim_oid_g, SecretReads, SecretsAccessed
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false
  description             = "More than 20 Key Vault secrets read in 5 minutes by a single identity — possible credential exfiltration."
  display_name            = "IAM: Key Vault mass secret access"
  enabled                 = true

  action {
    action_groups = [azurerm_monitor_action_group.iam_oncall.id]
    custom_properties = {
      Severity    = "Critical"
      Runbook     = "https://wiki.contoso.com/runbooks/iam-kv-exfil"
      MITREAttack = "T1552.001"
    }
  }

  tags = local.common_tags
}

# ── Azure Workbook — IAM Operations Dashboard ─────────────────────────────────
# OE:04 — Pre-built workbook surfaces sign-in health, CA policy coverage,
# MFA adoption, and risk events in a single pane.

resource "azurerm_application_insights_workbook" "iam_dashboard" {
  name                = "wkb-${local.prefix}-dashboard"
  resource_group_name = azurerm_resource_group.iam.name
  location            = azurerm_resource_group.iam.location
  display_name        = "IAM Platform Operations Dashboard"

  data_json = jsonencode({
    version = "Notebook/1.0"
    items = [
      {
        type = 1
        content = {
          json = "## IAM Platform — Operations Dashboard\n\nReal-time view of sign-in health, Conditional Access coverage, and MFA adoption."
        }
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = "SigninLogs | where TimeGenerated > ago(24h) | summarize Total = count(), Failed = countif(ResultType != '0'), Succeeded = countif(ResultType == '0') by bin(TimeGenerated, 1h) | render timechart"
          size    = 0
          title   = "Sign-in volume (24h) — success vs failure"
          queryType = 0
          resourceType = "microsoft.operationalinsights/workspaces"
        }
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = "SigninLogs | where TimeGenerated > ago(7d) | summarize MFACount = countif(AuthenticationRequirement == 'multiFactorAuthentication'), TotalCount = count() | extend MFARate = round(100.0 * MFACount / TotalCount, 1)"
          size    = 3
          title   = "MFA adoption rate (7d)"
          queryType = 0
          resourceType = "microsoft.operationalinsights/workspaces"
        }
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = "SigninLogs | where TimeGenerated > ago(24h) | where ConditionalAccessStatus == 'notApplied' | summarize count() by UserPrincipalName | order by count_ desc | take 20"
          size    = 1
          title   = "Top 20 users bypassing Conditional Access (24h)"
          queryType = 0
          resourceType = "microsoft.operationalinsights/workspaces"
        }
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = "AuditLogs | where TimeGenerated > ago(7d) | where Category == 'ApplicationManagement' | summarize count() by OperationName | order by count_ desc"
          size    = 1
          title   = "App registration changes (7d)"
          queryType = 0
          resourceType = "microsoft.operationalinsights/workspaces"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Pillar  = "OperationalExcellence"
    Purpose = "iam-ops-dashboard"
  })
}
