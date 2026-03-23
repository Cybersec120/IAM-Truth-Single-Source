# IAM Platform Runbook

**Project:** enterprise-iam-platform  
**Owner:** IAM Engineering  
**Classification:** Internal — Restricted

---

## Runbook 1: Onboard a new application

**Trigger:** App team requests SSO integration  
**SLA:** 2 business days from approved request  
**WAF:** Operational Excellence — repeatable procedure, no ad-hoc portal clicks

### OIDC application

```bash
# 1. Create config file from template
cp scripts/onboarding/configs/template_oidc.json \
   scripts/onboarding/configs/new-app.json

# 2. Edit the config — required fields:
#    display_name, redirect_uris, logout_uri

# 3. Dry run to validate
python scripts/onboarding/onboard_app.py \
  --type oidc \
  --config scripts/onboarding/configs/new-app.json \
  --dry-run

# 4. Create the app (audit record written to stdout)
python scripts/onboarding/onboard_app.py \
  --type oidc \
  --config scripts/onboarding/configs/new-app.json \
  --output onboarding-manifests/new-app-$(date +%Y%m%d).json

# 5. Store the client secret in Key Vault
CLIENT_SECRET=$(jq -r '.client_secret' onboarding-manifests/new-app-*.json)
az keyvault secret set \
  --vault-name kv-iam-prod \
  --name "oidc-new-app-client-secret" \
  --value "$CLIENT_SECRET"
unset CLIENT_SECRET

# 6. Provide the app team with:
#    - client_id  (from the manifest)
#    - issuer URL (https://login.microsoftonline.com/{tenant_id}/v2.0)
#    - discovery URL (issuer + /.well-known/openid-configuration)

# 7. Update Terraform to bring app under IaC management
#    Add entry to var.oidc_apps in terraform.tfvars
#    Run: terraform plan  →  terraform apply
```

### SAML application

```bash
# 1. Create config
cp scripts/onboarding/configs/template_saml.json \
   scripts/onboarding/configs/new-saml-app.json

# 2. Onboard (dry run first)
python scripts/onboarding/onboard_app.py \
  --type saml --config scripts/onboarding/configs/new-saml-app.json --dry-run

python scripts/onboarding/onboard_app.py \
  --type saml --config scripts/onboarding/configs/new-saml-app.json \
  --output onboarding-manifests/new-saml-app-$(date +%Y%m%d).json

# 3. Provide the SP with:
#    - Federation metadata URL (from manifest)
#    - SAML signing cert thumbprint (from manifest)
#    - SSO URL: https://login.microsoftonline.com/{tenant}/saml2
#    - Entity ID: https://sts.windows.net/{tenant}/
```

---

## Runbook 2: Onboard a new user

**Trigger:** HR system new-hire workflow  
**SLA:** Account ready on day 1  
**WAF:** Operational Excellence + Security — no manual account creation

```bash
# Config file created by HR integration (example)
cat > /tmp/new-user.json << 'EOF'
{
  "userPrincipalName": "jsmith@contoso.com",
  "displayName": "Jane Smith",
  "givenName": "Jane",
  "surname": "Smith",
  "mailNickname": "jsmith",
  "jobTitle": "Software Engineer",
  "department": "Engineering",
  "managerUpn": "manager@contoso.com",
  "usageLocation": "US",
  "groupIds": [
    "xxxxxxxx-xxxx-xxxx-xxxx-all-workforce-id",
    "xxxxxxxx-xxxx-xxxx-xxxx-engineering-id"
  ]
}
EOF

# Dry run
python scripts/onboarding/user_lifecycle.py onboard \
  --config /tmp/new-user.json --dry-run

# Execute (Duo enrollment email sent automatically if configured)
python scripts/onboarding/user_lifecycle.py onboard \
  --config /tmp/new-user.json \
  --output /tmp/onboard-audit-$(date +%Y%m%d-%H%M%S).json

# Verify
python scripts/onboarding/user_lifecycle.py status \
  --upn jsmith@contoso.com
```

---

## Runbook 3: Offboard a departing user

**Trigger:** HR system termination event  
**SLA:** Account disabled within 1 hour of HR notification  
**WAF:** Security — session revocation is the first action; no delay

```bash
# Check current state before offboarding
python scripts/onboarding/user_lifecycle.py status --upn jsmith@contoso.com

# Dry run
python scripts/onboarding/user_lifecycle.py offboard \
  --upn jsmith@contoso.com \
  --reason voluntary-termination \
  --dry-run

# Execute offboarding
python scripts/onboarding/user_lifecycle.py offboard \
  --upn jsmith@contoso.com \
  --reason voluntary-termination \
  --output /tmp/offboard-audit-$(date +%Y%m%d-%H%M%S).json

# Verify account is disabled
python scripts/onboarding/user_lifecycle.py status --upn jsmith@contoso.com
# Expected: "account_enabled": false, "duo_status": "disabled"
```

**Post-offboard checklist:**
- [ ] Account disabled in Entra (`account_enabled: false`)
- [ ] All group memberships removed
- [ ] All refresh tokens revoked (sessions_revoked: true)
- [ ] Duo disabled
- [ ] Audit record stored in retention system
- [ ] Manager notified to reassign work items

---

## Runbook 4: Respond to a CA policy disabled alert

**Alert:** `CA Policy Disabled — alert-{env}-ca-policy-disabled`  
**Severity:** 1 (Error)  
**WAF:** Reliability — automated detection; manual verification and remediation

```bash
# 1. Identify which policy was disabled and by whom
az monitor log-analytics query \
  --workspace /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace} \
  --analytics-query "
    AuditLogs
    | where OperationName in ('Update conditional access policy', 'Delete conditional access policy')
    | where TimeGenerated > ago(1h)
    | extend Actor = tostring(InitiatedBy.user.userPrincipalName),
             PolicyName = tostring(TargetResources[0].displayName)
    | project TimeGenerated, Actor, PolicyName, OperationName
    | order by TimeGenerated desc
    | limit 10
  "

# 2. If change was unauthorised — restore via Terraform
terraform plan -var-file=envs/prod.tfvars
# Confirm the plan shows restoring the disabled policy
terraform apply -var-file=envs/prod.tfvars -auto-approve

# 3. Verify policy is re-enabled in Entra portal:
#    Azure Portal → Entra ID → Security → Conditional Access → Policies

# 4. Investigate the Actor's account for compromise:
python scripts/onboarding/user_lifecycle.py status --upn <actor@contoso.com>
# If compromised: offboard immediately
```

---

## Runbook 5: IdP migration (Okta → Entra)

**Trigger:** Platform migration project  
**Duration:** Typically 2–4 weeks for large estates  
**WAF:** Reliability + Operational Excellence — phased migration with rollback

```bash
# Phase 1: Export from Okta
export OKTA_ORG_URL="https://contoso.okta.com"
export OKTA_API_TOKEN="<token>"

python scripts/migration/idp_migration.py export \
  --source okta \
  --output migration_export.json

echo "Exported $(jq '.app_count' migration_export.json) apps"

# Phase 2: Transform (normalise schema)
python scripts/migration/idp_migration.py transform \
  --input migration_export.json \
  --output migration_plan.json

# Phase 3: Validate against target Entra tenant
python scripts/migration/idp_migration.py validate \
  --input migration_plan.json \
  --output migration_validated.json

# Review failures before proceeding
jq '.apps[] | select(.migration_status == "validation_failed") | {name: .display_name, errors: .validation_errors}' \
  migration_validated.json

# Phase 4: Dry run import
python scripts/migration/idp_migration.py import \
  --input migration_validated.json \
  --dry-run

# Phase 5: Import (start with non-critical apps)
python scripts/migration/idp_migration.py import \
  --input migration_validated.json \
  --output migration_results.json

# Phase 6: Post-migration verification
python scripts/migration/idp_migration.py verify \
  --input migration_results.json \
  --output migration_verified.json

# Review results
jq '.apps | group_by(.migration_status) | map({status: .[0].migration_status, count: length})' \
  migration_verified.json
```

**Migration rollback procedure:**
If critical apps fail verification, the original Okta configuration remains active. Traffic can be kept on Okta until Entra is verified, then DNS/config cutover is performed app-by-app.

---

## Runbook 6: Break-glass account procedure

**Use:** When all CA policies need to be bypassed for emergency admin access  
**WAF:** Reliability — break-glass ensures lockout cannot block critical operations

**Prerequisites:**
- Two break-glass accounts exist, named `breakglass1@contoso.com` and `breakglass2@contoso.com`
- Both accounts are members of the `mfa-excluded` group
- Credentials are stored in a physical safe (not in a password manager)
- Both accounts are monitored by the `failed-signins` KQL alert

**Procedure:**
1. Retrieve credentials from physical safe — requires two-person authorisation
2. Sign in with the break-glass account
3. Perform the required emergency action
4. Sign out immediately
5. Rotate the credentials
6. File an incident report within 24 hours with justification

**Post-use:**
```bash
# Check if break-glass account was used (should generate an alert automatically)
az monitor log-analytics query \
  --analytics-query "
    SigninLogs
    | where UserPrincipalName in ('breakglass1@contoso.com', 'breakglass2@contoso.com')
    | where TimeGenerated > ago(24h)
    | project TimeGenerated, UserPrincipalName, ResultType, IPAddress, Location
  "
```

---

## Runbook 7: Rotate a SAML signing certificate

**Trigger:** Certificate approaching 60-day expiry (add expiry alert to monitoring.tf)  
**WAF:** Reliability — planned rotation avoids SSO outage

```bash
# 1. Terraform taint the existing cert resource
terraform taint "azuread_service_principal_token_signing_certificate.saml[\"salesforce\"]"

# 2. Plan and review
terraform plan -var-file=envs/prod.tfvars
# Confirm: 1 resource will be replaced (the cert)

# 3. Apply — this generates a NEW cert while the old one remains valid
#    (Entra supports multiple active certs during rotation window)
terraform apply -var-file=envs/prod.tfvars -auto-approve

# 4. Get the new thumbprint from outputs
terraform output saml_signing_cert_thumbprints

# 5. Update the SAML service provider's trusted certificate list
#    (Salesforce, Workday, etc.) with the new thumbprint BEFORE removing the old one

# 6. After SP is updated and tested — remove old cert from Entra portal:
#    Entra Portal → Enterprise Apps → [App] → Single sign-on → SAML Certificates

# 7. Test SSO works with the new certificate
```

---

*For escalations or emergency support, contact: iam-engineering@contoso.com*
