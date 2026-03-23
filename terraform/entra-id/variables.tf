# ─────────────────────────────────────────────────────────────────────────────
# variables.tf — enterprise-iam-platform / entra-id
#
# Azure Well-Architected Framework alignment per variable group:
#   Security            — credential handling, CA policy state, required tags
#   Reliability         — connector counts, health thresholds
#   Operational Excel.  — environment gating, naming conventions
#   Cost Optimisation   — Entra P1 vs P2 feature flags
#   Performance Effic.  — token lifetime, cache settings
# ─────────────────────────────────────────────────────────────────────────────

# ── General ───────────────────────────────────────────────────────────────────

variable "tenant_id" {
  description = "Entra ID tenant GUID."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.tenant_id))
    error_message = "Must be a valid GUID."
  }
}

variable "environment" {
  description = "Deployment environment — controls CA policy state and resource naming."
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Must be dev, staging, or prod."
  }
}

variable "organization" {
  description = "Short organisation slug used in resource names and display names."
  type        = string
  default     = "contoso"
}

variable "location" {
  description = "Azure region for Log Analytics workspace and supporting resources."
  type        = string
  default     = "eastus"
}

# ── Azure WAF: Security — Conditional Access ──────────────────────────────────

variable "ca_policy_state" {
  description = <<-EOT
    State for all conditional access policies.
    Recommendation:
      dev     → "disabled"
      staging → "enabledForReportingButNotEnforced"  (audit-only, 2-week baseline)
      prod    → "enabled"
  EOT
  type    = string
  default = "enabledForReportingButNotEnforced"
  validation {
    condition     = contains(["enabled", "disabled", "enabledForReportingButNotEnforced"], var.ca_policy_state)
    error_message = "Must be enabled, disabled, or enabledForReportingButNotEnforced."
  }
}

variable "mfa_excluded_user_ids" {
  description = "Break-glass account object IDs excluded from MFA enforcement. Keep to ≤2."
  type        = list(string)
  default     = []
  sensitive   = false
}

variable "mfa_excluded_group_ids" {
  description = "Group object IDs excluded from MFA enforcement (service account groups)."
  type        = list(string)
  default     = []
}

variable "trusted_named_locations" {
  description = "Map of trusted IP locations (name → list of CIDR ranges). Used by CA006."
  type        = map(list(string))
  default = {
    "corporate-hq" = ["203.0.113.0/24"]
    "vpn-egress"   = ["198.51.100.0/24"]
  }
}

variable "blocked_country_codes" {
  description = "ISO 3166-1 alpha-2 country codes to block in CA006 (high-risk geofencing)."
  type        = list(string)
  default     = ["KP", "IR", "CU", "SY"]
}

# ── Azure WAF: Cost Optimisation — Licence feature flags ──────────────────────

variable "entra_p2_features_enabled" {
  description = <<-EOT
    Toggle Entra ID P2 features (Identity Protection risk policies, PIM).
    Set to false if tenant only has P1 licences to avoid plan errors.
    P2 features: sign-in risk CA policies, user risk policies, PIM role assignments.
  EOT
  type    = bool
  default = true
}

variable "pim_enabled" {
  description = "Enable Privileged Identity Management for admin role assignments. Requires P2."
  type        = bool
  default     = true
}

# ── OIDC app registrations ────────────────────────────────────────────────────

variable "oidc_apps" {
  description = "OIDC / OAuth 2.0 applications to register in Entra ID."
  type = map(object({
    display_name    = string
    redirect_uris   = list(string)
    logout_uri      = optional(string, "")
    api_permissions = optional(list(string), ["User.Read"])
    owners          = optional(list(string), [])
    description     = optional(string, "")
    group_ids       = optional(list(string), [])
  }))
  default = {
    "hr-portal" = {
      display_name  = "HR Self-Service Portal"
      redirect_uris = ["https://hr.contoso.com/auth/callback"]
      logout_uri    = "https://hr.contoso.com/auth/logout"
      description   = "Employee HR portal — OIDC authorization code + PKCE"
    }
    "expense-app" = {
      display_name  = "Expense Management"
      redirect_uris = ["https://expenses.contoso.com/signin-oidc"]
      logout_uri    = "https://expenses.contoso.com/signout-oidc"
      description   = "Corporate expense submission — OIDC"
    }
    "api-daemon" = {
      display_name    = "Backend API Daemon"
      redirect_uris   = []
      description     = "Server-to-server daemon — client credentials flow"
      api_permissions = ["User.Read.All", "GroupMember.Read.All"]
    }
  }
}

# ── SAML app registrations ────────────────────────────────────────────────────

variable "saml_apps" {
  description = "SAML 2.0 enterprise applications to configure SSO for."
  type = map(object({
    display_name      = string
    identifier_uris   = list(string)
    reply_urls        = list(string)
    attribute_mapping = optional(map(string), {})
    description       = optional(string, "")
    group_ids         = optional(list(string), [])
  }))
  default = {
    "salesforce" = {
      display_name    = "Salesforce CRM"
      identifier_uris = ["https://contoso.my.salesforce.com"]
      reply_urls      = ["https://contoso.my.salesforce.com/"]
      description     = "Salesforce CRM SSO — SAML 2.0"
      attribute_mapping = {
        "email"      = "user.mail"
        "givenname"  = "user.givenname"
        "surname"    = "user.surname"
        "employeeid" = "user.employeeid"
      }
    }
    "servicenow" = {
      display_name    = "ServiceNow ITSM"
      identifier_uris = ["https://contoso.service-now.com"]
      reply_urls      = ["https://contoso.service-now.com/navpage.do"]
      description     = "ServiceNow ITSM — SAML 2.0"
      attribute_mapping = {
        "email"    = "user.mail"
        "username" = "user.userprincipalname"
      }
    }
  }
}

# ── App Proxy ─────────────────────────────────────────────────────────────────

variable "app_proxy_apps" {
  description = "On-premises web applications to publish through Entra Application Proxy."
  type = map(object({
    display_name         = string
    internal_url         = string
    external_url_prefix  = string
    connector_group_name = optional(string, "default")
    pre_auth_type        = optional(string, "aadPreAuthentication")
  }))
  default = {
    "legacy-intranet" = {
      display_name        = "Corporate Intranet (Legacy)"
      internal_url        = "http://intranet.corp.contoso.local/"
      external_url_prefix = "intranet"
      connector_group_name = "on-prem-dc"
    }
  }
}

# ── Groups ────────────────────────────────────────────────────────────────────

variable "iam_groups" {
  description = "Security groups to manage — used for CA policy scoping and app assignment."
  type = map(object({
    display_name       = string
    description        = string
    assignable_to_role = optional(bool, false)
  }))
  default = {
    "iam-admins" = {
      display_name       = "IAM Platform Administrators"
      description        = "Full IAM administration — break-glass + IAM engineers"
      assignable_to_role = true
    }
    "ca-excluded" = {
      display_name = "CA Policy Exclusions"
      description  = "Break-glass and service accounts excluded from CA policies"
    }
    "privileged-users" = {
      display_name = "Privileged Users — strict CA scope"
      description  = "Admins subject to compliant device + trusted location requirement"
      assignable_to_role = true
    }
    "all-workforce" = {
      display_name = "All Workforce"
      description  = "All employee accounts — baseline MFA + SSPR policy scope"
    }
    "intune-compliant-required" = {
      display_name = "Intune Compliance Required"
      description  = "Users whose devices must be Intune-enrolled and compliant"
    }
  }
}

# ── Azure WAF: Reliability — monitoring ───────────────────────────────────────

variable "log_retention_days" {
  description = "Log Analytics workspace retention in days. 90 = default, 730 = compliance."
  type        = number
  default     = 90
  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 730
    error_message = "Retention must be between 30 and 730 days."
  }
}

variable "alert_action_group_email" {
  description = "Email address for IAM alert notifications (risky sign-ins, policy failures)."
  type        = string
  default     = "iam-alerts@contoso.com"
}

# ── Azure WAF: Performance Efficiency — token lifetimes ───────────────────────

variable "access_token_lifetime_minutes" {
  description = "Access token lifetime in minutes. Default 60 mins per Microsoft recommendation."
  type        = number
  default     = 60
  validation {
    condition     = var.access_token_lifetime_minutes >= 10 && var.access_token_lifetime_minutes <= 1440
    error_message = "Access token lifetime must be between 10 and 1440 minutes."
  }
}

variable "refresh_token_max_inactive_days" {
  description = "Sliding window in days before inactive refresh tokens expire."
  type        = number
  default     = 90
}

# ── Tagging (WAF: Cost Optimisation + Operational Excellence) ─────────────────

variable "cost_center" {
  description = "Cost centre code for billing allocation tags."
  type        = string
  default     = "SECURITY-001"
}

variable "owner_team" {
  description = "Team responsible for IAM platform resources."
  type        = string
  default     = "iam-engineering"
}
