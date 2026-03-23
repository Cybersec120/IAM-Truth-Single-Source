# ─────────────────────────────────────────────────────────────────────────────
# variables.tf — enterprise-iam-platform / waf
# All inputs for the five Azure Well-Architected Framework pillars.
# ─────────────────────────────────────────────────────────────────────────────

variable "location" {
  description = "Primary Azure region for all resources."
  type        = string
  default     = "eastus2"
}

variable "location_secondary" {
  description = "Secondary Azure region for geo-redundant resources (Reliability pillar)."
  type        = string
  default     = "centralus"
}

variable "environment" {
  description = "Deployment environment: dev | staging | prod."
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Must be dev, staging, or prod."
  }
}

variable "organization" {
  description = "Short organisation prefix used in resource naming."
  type        = string
  default     = "contoso"
}

variable "tenant_id" {
  description = "Azure AD tenant ID (GUID)."
  type        = string
}

variable "subscription_id" {
  description = "Azure subscription ID — used for policy scope assignments."
  type        = string
}

# ── Reliability ───────────────────────────────────────────────────────────────

variable "enable_availability_zones" {
  description = "Deploy Key Vault and Log Analytics across availability zones."
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain Key Vault soft-deleted objects."
  type        = number
  default     = 90
  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 90
    error_message = "Must be between 7 and 90 days."
  }
}

variable "log_retention_days" {
  description = "Log Analytics workspace retention period in days."
  type        = number
  default     = 365
}

# ── Security ──────────────────────────────────────────────────────────────────

variable "allowed_ip_ranges" {
  description = "IP ranges permitted to access the Key Vault management plane."
  type        = list(string)
  default     = []
}

variable "key_vault_sku" {
  description = "Key Vault SKU: standard or premium (premium supports HSM-backed keys)."
  type        = string
  default     = "premium"
  validation {
    condition     = contains(["standard", "premium"], var.key_vault_sku)
    error_message = "Must be standard or premium."
  }
}

variable "security_contact_email" {
  description = "Email address for Microsoft Defender for Cloud security alerts."
  type        = string
  default     = "security@contoso.com"
}

variable "security_contact_phone" {
  description = "Phone number for high-severity Microsoft Defender alerts."
  type        = string
  default     = "+15555550100"
}

# ── Cost Optimization ─────────────────────────────────────────────────────────

variable "budget_amount_usd" {
  description = "Monthly budget cap in USD for the IAM platform resource group."
  type        = number
  default     = 500
}

variable "budget_alert_thresholds" {
  description = "Percentage thresholds at which budget alerts are triggered."
  type        = list(number)
  default     = [75, 90, 100]
}

variable "budget_alert_email" {
  description = "Email address for budget threshold notifications."
  type        = string
  default     = "cloud-costs@contoso.com"
}

# ── Operational Excellence ────────────────────────────────────────────────────

variable "alert_action_group_email" {
  description = "Email address for operational alert notifications."
  type        = string
  default     = "iam-oncall@contoso.com"
}

variable "alert_action_group_webhook" {
  description = "Optional webhook URL for alert routing (e.g., Slack, PagerDuty)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_diagnostic_settings" {
  description = "Stream Entra sign-in and audit logs to Log Analytics."
  type        = bool
  default     = true
}

# ── Performance Efficiency ────────────────────────────────────────────────────

variable "log_analytics_sku" {
  description = "Log Analytics workspace pricing tier."
  type        = string
  default     = "PerGB2018"
}

variable "key_vault_soft_delete_enabled" {
  description = "Enable Key Vault soft delete (mandatory for production)."
  type        = bool
  default     = true
}
