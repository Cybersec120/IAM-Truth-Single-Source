# ─────────────────────────────────────────────────────────────────────────────
# pillar_cost_optimization.tf — enterprise-iam-platform / waf
#
# Azure Well-Architected Framework: COST OPTIMIZATION PILLAR
#
# CO:01 — Develop cost-management discipline (budgets, alerts, governance)
# CO:02 — Design with a cost-efficiency mindset (right-size SKUs per env)
# CO:04 — Collect and review cost data (tags → Cost Management views)
# CO:05 — Optimize over time (lifecycle policies, log archival tiers)
# CO:06 — Align usage to billing increments (reserved capacity consideration)
# CO:07 — Optimize component costs (shared Log Analytics, standard KV in dev)
# CO:08 — Optimize environment costs (dev caps, prod uncapped)
# CO:09 — Optimize flow costs (GRS only for prod, LRS in dev)
# CO:11 — Optimize scaling costs (lifecycle rules auto-tier cold logs)
# ─────────────────────────────────────────────────────────────────────────────

# ── Monthly budget with tiered alerts ─────────────────────────────────────────
# CO:01 — Budget enforcement prevents runaway IAM platform costs.

resource "azurerm_consumption_budget_resource_group" "iam" {
  name              = "budget-${local.prefix}"
  resource_group_id = azurerm_resource_group.iam.id
  amount            = var.budget_amount_usd
  time_grain        = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", timestamp())
  }

  # Tiered alerts — notification at 75%, 90%, 100% of monthly cap
  dynamic "notification" {
    for_each = var.budget_alert_thresholds
    content {
      enabled        = true
      threshold      = notification.value
      operator       = "GreaterThan"
      threshold_type = "Actual"
      contact_emails = [var.budget_alert_email]
    }
  }

  # Forecasted overspend alert — early warning before month-end
  notification {
    enabled        = true
    threshold      = 110
    operator       = "GreaterThan"
    threshold_type = "Forecasted"
    contact_emails = [var.budget_alert_email]
  }

  lifecycle {
    ignore_changes = [time_period]
  }
}

# ── Tagging Policy — CO:04 cost allocation enforcement ───────────────────────
# All resources MUST have CostCenter, Project, and Environment tags.
# Without tags, Cost Management views are blind to team-level spend.

resource "azurerm_resource_group_policy_assignment" "require_tags_project" {
  name                 = "require-tag-project"
  resource_group_id    = azurerm_resource_group.iam.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/96670d01-0a4d-4649-9c89-2d3abc0a5025"
  display_name         = "IAM: Require Project tag on all resources"
  enforce              = true

  parameters = jsonencode({
    tagName = { value = "Project" }
  })
}

resource "azurerm_resource_group_policy_assignment" "require_tags_env" {
  name                 = "require-tag-environment"
  resource_group_id    = azurerm_resource_group.iam.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/96670d01-0a4d-4649-9c89-2d3abc0a5025"
  display_name         = "IAM: Require Environment tag on all resources"
  enforce              = true

  parameters = jsonencode({
    tagName = { value = "Environment" }
  })
}

resource "azurerm_resource_group_policy_assignment" "require_tags_cost_center" {
  name                 = "require-tag-costcenter"
  resource_group_id    = azurerm_resource_group.iam.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/96670d01-0a4d-4649-9c89-2d3abc0a5025"
  display_name         = "IAM: Require CostCenter tag on all resources"
  enforce              = true

  parameters = jsonencode({
    tagName = { value = "CostCenter" }
  })
}

# ── Storage lifecycle — CO:11 auto-tier cold audit logs ───────────────────────
# Audit logs transition from Hot → Cool → Archive on a schedule.
# This cuts storage costs ~70% for logs older than 90 days.

resource "azurerm_storage_management_policy" "log_archive" {
  storage_account_id = azurerm_storage_account.log_archive.id

  rule {
    name    = "iam-audit-log-tiering"
    enabled = true

    filters {
      prefix_match = ["iam-audit-logs/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        # CO:11 — Move to Cool after 30 days (75% cost reduction vs Hot)
        tier_to_cool_after_days_since_modification_greater_than = 30

        # CO:11 — Move to Cold after 90 days
        tier_to_cold_after_days_since_modification_greater_than = 90

        # CO:11 — Archive after 180 days (99% cost reduction vs Hot)
        tier_to_archive_after_days_since_modification_greater_than = 180
      }

      # Keep snapshots for 90 days then delete
      snapshot {
        delete_after_days_since_creation_greater_than = 90
      }

      # Clean up old versions after 365 days
      version {
        delete_after_days_since_creation = 365
      }
    }
  }

  # Log Analytics export blobs — 7-year retention per NIST 800-53
  rule {
    name    = "law-export-retention"
    enabled = true

    filters {
      prefix_match = ["law-export/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 90
        tier_to_archive_after_days_since_modification_greater_than = 365
        delete_after_days_since_modification_greater_than          = 2555  # 7 years
      }
    }
  }
}

# ── Cost Management export — CO:04 cost visibility ───────────────────────────
# Daily export of actual costs for the IAM resource group to the archive
# storage account. Feeds a Power BI / Grafana cost dashboard.

resource "azurerm_cost_management_export_resource_group" "iam" {
  name                         = "export-${local.prefix}-daily"
  resource_group_id            = azurerm_resource_group.iam.id
  recurrence_type              = "Daily"
  recurrence_period_start_date = "${formatdate("YYYY-MM-01", timestamp())}T00:00:00Z"
  recurrence_period_end_date   = "${formatdate("YYYY", timeadd(timestamp(), "17520h"))}-12-31T23:59:59Z"

  export_data_storage_location {
    container_id     = azurerm_storage_container.audit_logs.resource_manager_id
    root_folder_path = "/cost-exports"
  }

  export_data_options {
    type       = "ActualCost"
    time_frame = "Custom"
  }

  lifecycle {
    ignore_changes = [recurrence_period_start_date, recurrence_period_end_date]
  }
}
