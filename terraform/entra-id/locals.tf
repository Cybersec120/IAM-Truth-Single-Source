# ─────────────────────────────────────────────────────────────────────────────
# locals.tf — enterprise-iam-platform / entra-id
# ─────────────────────────────────────────────────────────────────────────────

locals {
  name_prefix = "${var.organization}-${var.environment}"

  # ── Well-known Microsoft constants ──────────────────────────────────────────
  msgraph_app_id = "00000003-0000-0000-c000-000000000000"

  # Microsoft Graph delegated permission GUIDs (stable across all tenants)
  msgraph_scopes = {
    "User.Read"          = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
    "User.Read.All"      = "a154be20-db9c-4678-8ab7-66f6cc099a59"
    "GroupMember.Read.All" = "bc024368-1153-4739-b217-4326f2e966d0"
    "profile"            = "14dad69e-099b-42c9-810b-d002981feec1"
    "openid"             = "37f7f235-527c-4136-accd-4a02d197296e"
    "email"              = "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0"
    "offline_access"     = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
  }

  # ── Azure WAF: Operational Excellence — common tags ───────────────────────
  # Applied via provider default_tags to all azurerm resources.
  # azuread resources use the tags input on each resource directly.
  common_tags = {
    Project     = "enterprise-iam-platform"
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = var.owner_team
    CostCenter  = var.cost_center
    Repository  = "enterprise-iam-platform"
    WAFPillar   = "Security,OperationalExcellence"
  }

  # ── Azure WAF: Cost Optimisation — licence tier annotations ─────────────
  # Documents which features require P1 vs P2 licensing.
  entra_licence_requirements = {
    conditional_access      = "P1"   # CA policies require Entra ID P1
    identity_protection     = "P2"   # Risk-based CA requires P2
    pim                     = "P2"   # Privileged Identity Management requires P2
    app_proxy               = "P1"   # Application Proxy requires P1
    sspr                    = "P1"   # Self-service password reset requires P1
    mfa                     = "Free" # Basic MFA is included in all tiers
    group_based_licensing   = "P1"
  }

  # ── CA policy name prefix convention ─────────────────────────────────────
  # CA{NNN} — {scope} — {control}
  ca_prefix = "CA"
}

# ── Current context ───────────────────────────────────────────────────────────
data "azuread_client_config" "current" {}
data "azuread_domains" "current" { only_default = true }

data "azuread_service_principal" "msgraph" {
  client_id = local.msgraph_app_id
}
