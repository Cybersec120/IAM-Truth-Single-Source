# ─────────────────────────────────────────────────────────────────────────────
# outputs.tf — enterprise-iam-platform / entra-id
# ─────────────────────────────────────────────────────────────────────────────

output "tenant_id" {
  description = "Entra ID tenant ID."
  value       = data.azuread_client_config.current.tenant_id
}

output "default_domain" {
  description = "Primary verified domain for the tenant."
  value       = data.azuread_domains.current.domains[0].domain_name
}

# ── OIDC apps ─────────────────────────────────────────────────────────────────

output "oidc_client_ids" {
  description = "OIDC app client (application) IDs — provide to app development teams."
  value = { for k, v in azuread_application.oidc : k => v.client_id }
}

output "oidc_discovery_urls" {
  description = "OIDC discovery document URLs — use for app SSO configuration."
  value = {
    for k, v in azuread_application.oidc :
    k => "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/v2.0/.well-known/openid-configuration"
  }
}

output "oidc_client_secrets" {
  description = "OIDC client secrets — SENSITIVE. Store immediately in Key Vault."
  sensitive   = true
  value       = { for k, v in azuread_application_password.oidc : k => v.value }
}

# ── SAML apps ─────────────────────────────────────────────────────────────────

output "saml_metadata_urls" {
  description = "SAML federation metadata URLs — provide to SAML service providers."
  value = {
    for k, v in azuread_service_principal.saml :
    k => "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid=${v.client_id}"
  }
}

output "saml_sso_urls" {
  description = "SAML SSO login URLs — configure as IdP SSO URL in service providers."
  value = {
    for k, _ in var.saml_apps :
    k => "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/saml2"
  }
}

output "saml_signing_thumbprints" {
  description = "SAML signing certificate thumbprints — configure in service providers."
  value = {
    for k, v in azuread_service_principal_token_signing_certificate.saml :
    k => v.thumbprint
  }
}

# ── App Proxy ─────────────────────────────────────────────────────────────────

output "app_proxy_external_urls" {
  description = "External HTTPS URLs for App Proxy applications."
  value = {
    for k, v in var.app_proxy_apps :
    k => "https://${v.external_url_prefix}.msappproxy.net/"
  }
}

# ── Groups ────────────────────────────────────────────────────────────────────

output "group_object_ids" {
  description = "Group object IDs — use in CA policy assignments and app role assignments."
  value       = { for k, v in azuread_group.iam : k => v.id }
}

# ── Conditional Access ────────────────────────────────────────────────────────

output "ca_policy_ids" {
  description = "Conditional Access policy IDs."
  value = {
    CA001_mfa_all_workforce   = azuread_conditional_access_policy.ca001_mfa_all.id
    CA002_block_legacy_auth   = azuread_conditional_access_policy.ca002_block_legacy.id
    CA003_privileged_device   = azuread_conditional_access_policy.ca003_privileged_device.id
    CA004_signin_risk         = var.entra_p2_features_enabled ? azuread_conditional_access_policy.ca004_signin_risk[0].id : "disabled"
    CA005_user_risk           = var.entra_p2_features_enabled ? azuread_conditional_access_policy.ca005_user_risk[0].id : "disabled"
    CA006_geo_block           = azuread_conditional_access_policy.ca006_geo_block.id
    CA007_sspr_registration   = azuread_conditional_access_policy.ca007_sspr_registration.id
  }
}

# ── Monitoring ────────────────────────────────────────────────────────────────

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID — use for Sentinel / additional diagnostic settings."
  value       = azurerm_log_analytics_workspace.iam.id
}

output "log_analytics_workspace_key" {
  description = "Log Analytics primary shared key — SENSITIVE."
  sensitive   = true
  value       = azurerm_log_analytics_workspace.iam.primary_shared_key
}

# ── Azure WAF: Operational Excellence — portal quick links ───────────────────

output "portal_links" {
  description = "Direct links to key Entra portal blades for post-deployment validation."
  value = {
    app_registrations     = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"
    enterprise_apps       = "https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview"
    conditional_access    = "https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies"
    identity_protection   = "https://portal.azure.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/Overview"
    app_proxy             = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/AppProxy"
    identity_secure_score = "https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/IdentitySecureScore"
    sign_in_logs          = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns"
    audit_logs            = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Audit"
    log_analytics         = "https://portal.azure.com/#@${data.azuread_client_config.current.tenant_id}/resource${azurerm_log_analytics_workspace.iam.id}/logs"
  }
}

# ── Azure WAF: Cost Optimisation — licence context ───────────────────────────

output "licence_requirements" {
  description = "Summary of Entra licence tier required per deployed feature."
  value = {
    features_deployed = {
      app_registrations_oidc     = { count = length(var.oidc_apps), licence = "Free/P1" }
      app_registrations_saml     = { count = length(var.saml_apps), licence = "P1" }
      app_proxy_apps             = { count = length(var.app_proxy_apps), licence = "P1" }
      conditional_access_p1      = { count = 5, licence = "P1" }
      conditional_access_p2      = { count = var.entra_p2_features_enabled ? 2 : 0, licence = "P2" }
      identity_protection        = { enabled = var.entra_p2_features_enabled, licence = "P2" }
    }
    recommendation = var.entra_p2_features_enabled ? "Entra ID P2 (or Microsoft 365 E5)" : "Entra ID P1"
  }
}
