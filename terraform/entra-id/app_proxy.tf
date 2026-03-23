# ─────────────────────────────────────────────────────────────────────────────
# app_proxy.tf — enterprise-iam-platform / entra-id
#
# Entra Application Proxy — publish on-premises web apps externally without
# inbound firewall rules. Connector agent runs on-prem, maintains outbound
# HTTPS tunnel to Entra.
#
# Architecture:
#   External user → Entra ID (pre-auth MFA) → App Proxy service
#   → Connector agent (on-prem Windows Server) → Internal web app
#
# Azure WAF:
#   Security     — Entra pre-auth gates all access; no public inbound ports
#   Reliability  — recommend ≥2 connectors per group for HA
#   Performance  — pass-through headers reduce double-auth latency
# ─────────────────────────────────────────────────────────────────────────────

# App registrations for each proxied application
resource "azuread_application" "app_proxy" {
  for_each = var.app_proxy_apps

  display_name     = each.value.display_name
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]

  web {
    # External URL is the Entra-issued msappproxy.net address
    redirect_uris = [
      "https://${each.value.external_url_prefix}.msappproxy.net/",
    ]
    implicit_grant {
      id_token_issuance_enabled = true
    }
  }

  tags = ["app-proxy", "on-premises", var.environment, "terraform-managed"]
}

resource "azuread_service_principal" "app_proxy" {
  for_each = var.app_proxy_apps

  client_id                    = azuread_application.app_proxy[each.key].client_id
  app_role_assignment_required = true   # WAF: Security — explicit user/group assignment
  owners                       = [data.azuread_client_config.current.object_id]

  feature_tags {
    enterprise = true
  }
}

# ── App Proxy configuration ───────────────────────────────────────────────────
# The azuread provider does not yet have a native azuread_application_proxy
# resource. Full proxy configuration (internalUrl, externalUrl, pre-auth
# type, cookie settings) is applied via:
#   a) The onboarding automation script  (scripts/onboarding/onboard_app.py)
#   b) The Graph API beta endpoint       (applications/{id}/onPremisesPublishing)
#
# The Terraform code above provisions the application registration and SP
# as the foundation; the script completes the proxy-specific settings.
#
# Graph API payload applied by the script:
#   {
#     "externalAuthenticationType": "aadPreAuthentication",
#     "internalUrl":  "<each.value.internal_url>",
#     "externalUrl":  "https://<prefix>.msappproxy.net/",
#     "isHttpOnlyCookieEnabled": true,
#     "isSecureCookieEnabled":   true,
#     "isPersistentCookieEnabled": false,
#     "isSslCertificateVerificationEnabled": true,
#     "isTranslateHostHeaderEnabled": true
#   }
#
# WAF: Reliability — connector group assignment ensures traffic uses
# the on-prem connector group closest to the internal app server.
#
# Required manual steps:
#   1. Install Application Proxy connector on ≥2 Windows Servers (for HA)
#   2. Register connectors in the Entra portal under App Proxy > Connectors
#   3. Create connector groups matching var.app_proxy_apps connector_group_name
#   4. Run: python scripts/onboarding/onboard_app.py --type proxy --config ...
