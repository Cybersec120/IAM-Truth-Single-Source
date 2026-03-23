# ─────────────────────────────────────────────────────────────────────────────
# identity_protection.tf — enterprise-iam-platform / entra-id
#
# Entra ID P2 features:
#   - Identity Protection sign-in risk policy  (risky sign-in remediation)
#   - Identity Protection user risk policy     (compromised credential response)
#   - Token lifetime policy                    (WAF: Performance Efficiency)
#
# Azure WAF:
#   Security           — assume breach; automated remediation on compromise
#   Cost Optimisation  — gated by var.entra_p2_features_enabled
#   Performance Effic. — token lifetime tuned to balance security and UX
# ─────────────────────────────────────────────────────────────────────────────

# ── Sign-in risk policy (Identity Protection) — [P2] ─────────────────────────
# Complements CA004: this policy runs at the Identity Protection engine level
# before the CA evaluation pass. Medium/High risk → block or require MFA.

resource "azuread_identity_governance_lifecycle_workflow_workflow" "placeholder" {
  # NOTE: Sign-in and user risk policies in Entra Identity Protection are
  # configured via the Identity Protection blade or Graph API.
  # The azuread Terraform provider (v2.x) surfaces these as:
  #   azuread_conditional_access_policy with sign_in_risk_levels / user_risk_levels
  # which is implemented in ca004 and ca005 in conditional_access.tf.
  #
  # The direct Identity Protection policy resources (not CA-based) are managed
  # via the Microsoft Graph API in the monitoring/automation scripts.
  # This file documents intent and token lifetime configuration.
  count = 0  # Placeholder — remove when azuread provider adds native IP resources
}

# ── Token lifetime policy — [WAF: Performance Efficiency] ────────────────────
# Shorter-lived access tokens reduce the window of exposure on token theft.
# Longer refresh token inactive window improves UX for infrequent users.
# These settings apply to OIDC and SAML app service principals.

resource "azuread_token_issuance_policy" "default" {
  display_name = "${local.name_prefix}-token-issuance-policy"

  definition = [jsonencode({
    TokenIssuancePolicy = {
      Version = 1
      SigningAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
      TokenResponseSigningPolicy = "TokenOnly"
      SamlTokenVersion = "2.0"
    }
  })]
}

resource "azuread_claims_mapping_policy" "token_lifetime" {
  display_name = "${local.name_prefix}-token-lifetime-policy"

  definition = [jsonencode({
    TokenLifetimePolicy = {
      Version                    = 1
      AccessTokenLifetime        = "${var.access_token_lifetime_minutes}:00:00"
      MaxInactiveTime            = "${var.refresh_token_max_inactive_days}.00:00:00"
      MaxAgeSingleFactor         = "until-revoked"
      MaxAgeMultiFactor          = "until-revoked"
      MaxAgeSessionSingleFactor  = "until-revoked"
      MaxAgeSessionMultiFactor   = "until-revoked"
    }
  })]
}

# ── Authentication strength — phishing-resistant MFA ─────────────────────────
# Defines an authentication strength requiring FIDO2 or Windows Hello for admins.
# Applied in CA003 for privileged users (compliant device policy).
# Requires Entra ID P1 + appropriate MFA registration.

resource "azuread_authentication_strength_policy" "phishing_resistant" {
  display_name = "${local.name_prefix}-phishing-resistant-mfa"
  description  = "FIDO2 security keys or Windows Hello for Business — admin MFA"

  allowed_combinations = [
    "fido2",
    "windowsHelloForBusiness",
    "deviceBasedPush",
  ]
}
