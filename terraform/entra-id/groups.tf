# ─────────────────────────────────────────────────────────────────────────────
# groups.tf — enterprise-iam-platform / entra-id
#
# Azure WAF: Security — groups are the primary CA policy scope mechanism.
# Using groups rather than individual users ensures consistent enforcement
# and simplifies onboarding/offboarding automation.
# ─────────────────────────────────────────────────────────────────────────────

resource "azuread_group" "iam" {
  for_each = var.iam_groups

  display_name       = each.value.display_name
  description        = each.value.description
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = try(each.value.assignable_to_role, false)
  owners             = [data.azuread_client_config.current.object_id]

  lifecycle {
    # Members managed by the onboarding automation scripts — not by Terraform.
    # Terraform manages group existence and properties only.
    ignore_changes = [members]
  }
}
