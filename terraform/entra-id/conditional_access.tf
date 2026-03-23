# ─────────────────────────────────────────────────────────────────────────────
# conditional_access.tf — enterprise-iam-platform / entra-id
#
# Seven zero-trust conditional access policies following Microsoft's
# recommended CA policy framework (Identity Secure Score baseline):
#
#   CA001 — Require MFA for all workforce users              [P1]
#   CA002 — Block legacy authentication protocols            [Free]
#   CA003 — Require compliant device for privileged admins   [P1 + Intune]
#   CA004 — Sign-in risk: MFA step-up at Medium+             [P2]
#   CA005 — User risk: password change at High               [P2]
#   CA006 — Block sign-ins from high-risk countries          [P1]
#   CA007 — Require MFA for SSPR registration                [P1]
#
# Azure WAF:
#   Security           — zero-trust, verify explicitly, assume breach
#   Reliability        — policy state gated per environment; report-only first
#   Operational Excel. — all policies namespaced CA{NNN} for portal ordering
#   Cost Optimisation  — P2 policies gated by var.entra_p2_features_enabled
# ─────────────────────────────────────────────────────────────────────────────

# ── Named locations (trusted IPs for CA006 exclusion) ────────────────────────

resource "azuread_named_location" "trusted_ip" {
  for_each = var.trusted_named_locations

  display_name = "${local.name_prefix}-${each.key}"

  ip {
    ip_ranges_included = each.value
    trusted            = true
  }
}

# Country-based location block — high-risk countries
resource "azuread_named_location" "blocked_countries" {
  display_name = "${local.name_prefix}-high-risk-countries"

  country {
    countries_and_regions                 = var.blocked_country_codes
    include_unknown_countries_and_regions = false
  }
}

# ── CA001: Require MFA for all workforce — [P1] ───────────────────────────────

resource "azuread_conditional_access_policy" "ca001_mfa_all" {
  display_name = "CA001 — Require MFA — all workforce"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["browser", "mobileAppsAndDesktopClients"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_groups = [azuread_group.iam["all-workforce"].id]
      excluded_groups = concat(
        [azuread_group.iam["ca-excluded"].id],
        var.mfa_excluded_group_ids
      )
      excluded_users = var.mfa_excluded_user_ids
    }

    locations {
      included_locations = ["All"]
      excluded_locations = [for loc in azuread_named_location.trusted_ip : loc.id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# ── CA002: Block legacy auth — [Free/P1] ──────────────────────────────────────
# Single highest-impact policy: legacy auth bypasses MFA entirely.
# Blocks: Exchange ActiveSync, IMAP, POP3, SMTP AUTH, older MAPI clients.

resource "azuread_conditional_access_policy" "ca002_block_legacy" {
  display_name = "CA002 — Block legacy authentication"
  state        = var.ca_policy_state

  conditions {
    client_app_types = [
      "exchangeActiveSync",
      "other",
    ]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [azuread_group.iam["ca-excluded"].id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# ── CA003: Compliant device for privileged users — [P1 + Intune] ─────────────
# Admins and IAM engineers must sign in from Intune-enrolled, compliant devices.
# WAF: Security — assume breach; limit blast radius if admin creds are stolen.

resource "azuread_conditional_access_policy" "ca003_privileged_device" {
  display_name = "CA003 — Require compliant device — privileged users"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_groups = [
        azuread_group.iam["privileged-users"].id,
        azuread_group.iam["iam-admins"].id,
      ]
      excluded_groups = [azuread_group.iam["ca-excluded"].id]
    }
  }

  grant_controls {
    # AND: must satisfy BOTH MFA and compliant device
    operator          = "AND"
    built_in_controls = ["mfa", "compliantDevice"]
  }
}

# ── CA004: Sign-in risk → MFA step-up — [P2] ─────────────────────────────────
# Only created when P2 features are enabled (see variable cost annotation).
# WAF: Cost Optimisation — prevents accidental P2 plan errors on P1 tenants.

resource "azuread_conditional_access_policy" "ca004_signin_risk" {
  count = var.entra_p2_features_enabled ? 1 : 0

  display_name = "CA004 — Sign-in risk Medium/High — require MFA"
  state        = var.ca_policy_state

  conditions {
    client_app_types    = ["all"]
    sign_in_risk_levels = ["medium", "high"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [azuread_group.iam["ca-excluded"].id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# ── CA005: User risk → password change — [P2] ────────────────────────────────

resource "azuread_conditional_access_policy" "ca005_user_risk" {
  count = var.entra_p2_features_enabled ? 1 : 0

  display_name = "CA005 — User risk High — require password change"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]
    user_risk_levels = ["high"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [azuread_group.iam["ca-excluded"].id]
    }
  }

  grant_controls {
    # AND: re-authenticate with MFA AND perform password change
    operator          = "AND"
    built_in_controls = ["mfa", "passwordChange"]
  }
}

# ── CA006: Block high-risk country sign-ins — [P1] ───────────────────────────
# Blocks sign-ins originating from countries in var.blocked_country_codes.
# Excludes trusted named locations so VPN egress IPs remain unaffected.

resource "azuread_conditional_access_policy" "ca006_geo_block" {
  display_name = "CA006 — Block sign-ins from high-risk countries"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [azuread_group.iam["ca-excluded"].id]
    }

    locations {
      included_locations = [azuread_named_location.blocked_countries.id]
      excluded_locations = concat(
        ["AllTrusted"],
        [for loc in azuread_named_location.trusted_ip : loc.id]
      )
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# ── CA007: MFA required for SSPR registration — [P1] ─────────────────────────
# Users must be MFA-authenticated before registering new security info.
# Prevents attackers from registering their own MFA methods after phishing.

resource "azuread_conditional_access_policy" "ca007_sspr_registration" {
  display_name = "CA007 — SSPR / security info registration — require MFA"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_user_actions = ["urn:user:registerSecurityInfo"]
    }

    users {
      included_groups = [azuread_group.iam["all-workforce"].id]
      excluded_groups = [azuread_group.iam["ca-excluded"].id]
    }

    locations {
      included_locations = ["All"]
      excluded_locations = [for loc in azuread_named_location.trusted_ip : loc.id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}
