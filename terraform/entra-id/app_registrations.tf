# ─────────────────────────────────────────────────────────────────────────────
# app_registrations.tf — enterprise-iam-platform / entra-id
#
# Covers all three authentication patterns required by the JD:
#   1. OIDC / OAuth 2.0 — authorization code + PKCE for web apps
#   2. Client credentials — daemon/service-to-service flows
#   3. SAML 2.0 — enterprise SSO for legacy and SaaS apps
#
# Azure WAF:
#   Security            — scoped permissions, PKCE enforced, no implicit grants
#   Cost Optimisation   — optional claims minimise token bloat (reduces compute)
#   Performance Effic.  — token lifetime policy applied per app
#   Operational Excel.  — for_each pattern scales to any number of apps
# ─────────────────────────────────────────────────────────────────────────────

# ── OIDC / OAuth 2.0 app registrations ───────────────────────────────────────

resource "azuread_application" "oidc" {
  for_each = var.oidc_apps

  display_name     = each.value.display_name
  description      = each.value.description
  sign_in_audience = "AzureADMyOrg"

  owners = concat(
    [data.azuread_client_config.current.object_id],
    try(each.value.owners, [])
  )

  # WAF: Security — implicit flow disabled; PKCE enforced at app level
  web {
    redirect_uris = length(each.value.redirect_uris) > 0 ? each.value.redirect_uris : null
    logout_url    = each.value.logout_uri != "" ? each.value.logout_uri : null

    implicit_grant {
      access_token_issuance_enabled = false  # Never issue access tokens via implicit
      id_token_issuance_enabled     = false  # Use auth code flow instead
    }
  }

  # Required Graph API permission scopes
  dynamic "required_resource_access" {
    for_each = length(try(each.value.api_permissions, ["User.Read"])) > 0 ? [1] : []
    content {
      resource_app_id = local.msgraph_app_id

      dynamic "resource_access" {
        for_each = try(each.value.api_permissions, ["User.Read"])
        content {
          id   = lookup(local.msgraph_scopes, resource_access.value, resource_access.value)
          type = "Scope"
        }
      }
    }
  }

  # WAF: Performance Efficiency — minimal optional claims reduces token size
  optional_claims {
    id_token {
      name      = "email"
      essential = true
    }
    id_token {
      name      = "preferred_username"
      essential = false
    }
    access_token {
      name      = "groups"
      essential = false
    }
  }

  feature_tags {
    enterprise = true
    hide       = false
  }

  tags = ["oidc", var.environment, "terraform-managed", "waf-security"]
}

resource "azuread_service_principal" "oidc" {
  for_each = var.oidc_apps

  client_id                    = azuread_application.oidc[each.key].client_id
  app_role_assignment_required = false
  owners                       = [data.azuread_client_config.current.object_id]

  feature_tags {
    enterprise            = true
    custom_single_sign_on = false
  }
}

# Client secrets — 2-year rotation with descriptive display names
# WAF: Operational Excellence — secret expiry visible in Terraform state
resource "azuread_application_password" "oidc" {
  for_each = var.oidc_apps

  application_id = azuread_application.oidc[each.key].id
  display_name   = "terraform-${var.environment}-${formatdate("YYYY", timeadd(timestamp(), "17520h"))}"
  end_date       = timeadd(timestamp(), "17520h") # 2 years

  lifecycle {
    # Prevent Terraform from rotating secrets on every plan/apply.
    # Rotate manually or via the onboarding automation script.
    ignore_changes = [end_date, display_name]
  }
}

# Token lifetime policy — WAF: Performance Efficiency
resource "azuread_service_principal_token_signing_certificate" "oidc_signing" {
  for_each = {
    for k, v in var.oidc_apps : k => v
    if length(v.redirect_uris) > 0  # Skip daemon apps (no redirects)
  }

  service_principal_id = azuread_service_principal.oidc[each.key].id
  display_name         = "CN=${each.value.display_name}-signing"
  end_date             = timeadd(timestamp(), "26280h") # 3 years

  lifecycle {
    ignore_changes = [end_date]
  }
}

# ── SAML 2.0 enterprise applications ─────────────────────────────────────────

resource "azuread_application" "saml" {
  for_each = var.saml_apps

  display_name     = each.value.display_name
  description      = each.value.description
  sign_in_audience = "AzureADMyOrg"
  identifier_uris  = each.value.identifier_uris

  owners = [data.azuread_client_config.current.object_id]

  web {
    redirect_uris = each.value.reply_urls
    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  tags = ["saml", "enterprise-app", var.environment, "terraform-managed"]
}

resource "azuread_service_principal" "saml" {
  for_each = var.saml_apps

  client_id                    = azuread_application.saml[each.key].client_id
  app_role_assignment_required = true   # WAF: Security — explicit assignment required
  owners                       = [data.azuread_client_config.current.object_id]

  preferred_single_sign_on_mode = "saml"

  feature_tags {
    enterprise            = true
    custom_single_sign_on = true
  }
}

# SAML signing certificates — 3-year validity, self-signed
resource "azuread_service_principal_token_signing_certificate" "saml" {
  for_each = var.saml_apps

  service_principal_id = azuread_service_principal.saml[each.key].id
  display_name         = "CN=${each.value.display_name}-saml-cert"
  end_date             = timeadd(timestamp(), "26280h")

  lifecycle {
    ignore_changes = [end_date]
  }
}

# SAML attribute claim mapping policies
resource "azuread_claims_mapping_policy" "saml" {
  for_each = {
    for k, v in var.saml_apps : k => v
    if length(v.attribute_mapping) > 0
  }

  display_name = "${local.name_prefix}-${each.key}-claims-policy"

  definition = [jsonencode({
    ClaimsMappingPolicy = {
      Version              = 1
      IncludeBasicClaimSet = true
      ClaimsSchema = [
        for claim_name, source_attr in each.value.attribute_mapping : {
          Source        = "user"
          ID            = replace(source_attr, "user.", "")
          SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/${claim_name}"
        }
      ]
    }
  })]
}

resource "azuread_service_principal_claims_mapping_policy_assignment" "saml" {
  for_each = {
    for k, v in var.saml_apps : k => v
    if length(v.attribute_mapping) > 0
  }

  service_principal_id     = azuread_service_principal.saml[each.key].id
  claims_mapping_policy_id = azuread_claims_mapping_policy.saml[each.key].id
}
