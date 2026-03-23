# Azure Well-Architected Framework Alignment

**Project:** enterprise-iam-platform  
**Framework:** [Microsoft Azure Well-Architected Framework](https://learn.microsoft.com/en-us/azure/well-architected/)  
**Version:** 2024  
**Pillars covered:** Security · Operational Excellence · Reliability · Cost Optimization · Performance Efficiency

---

## Pillar 1: Security

The Security pillar is the primary driver of this project. Every architectural decision is traceable to a Microsoft Zero Trust principle: **verify explicitly**, **use least privilege access**, and **assume breach**.

### Zero Trust implementation

| Zero Trust principle | Implementation | Resource |
|---|---|---|
| Verify explicitly | MFA required on every sign-in via CA001 | `conditional_access.tf` |
| Verify explicitly | Device compliance required for admins via CA003 | `conditional_access.tf` |
| Verify explicitly | Sign-in risk evaluated per session (Identity Protection) | `identity_protection.tf` |
| Least privilege | Scoped Graph API permissions per OIDC app | `app_registrations.tf` |
| Least privilege | App role assignment required for SAML apps | `app_registrations.tf` |
| Least privilege | IAM admin groups use `assignable_to_role = true` | `groups.tf` |
| Assume breach | Session revocation during offboarding takes seconds | `user_lifecycle.py` |
| Assume breach | Identity Protection auto-remediates high-risk users | `identity_protection.tf` |
| Assume breach | KQL alert fires on any CA policy being disabled | `monitoring.tf` |

### Conditional Access policy chain

```
User authenticates
      │
      ▼
CA002: Block legacy auth? ─── YES ──▶ BLOCK (no MFA bypass path)
      │ NO
      ▼
CA006: Admin from untrusted location? ─── YES ──▶ BLOCK
      │ NO
      ▼
CA004: Sign-in risk ≥ Medium? ─── YES ──▶ Require MFA step-up
      │ NO
      ▼
CA005: User risk = High? ─── YES ──▶ Require MFA + password change
      │ NO
      ▼
CA003: Privileged user? ─── YES ──▶ Require MFA + compliant device
      │ NO
      ▼
CA001: All workforce ─── YES ──▶ Require MFA
      │
      ▼
Access granted
```

### Authentication strength upgrade path

| Method | Risk level | Policy action |
|---|---|---|
| SMS / voice OTP | High (phishable) | Flag in MFA audit; prompt upgrade |
| TOTP authenticator app | Medium | Acceptable baseline |
| Authenticator app push | Medium | Acceptable baseline |
| FIDO2 security key | Low (phishing-resistant) | Required for privileged admins via `phishing_resistant` auth strength |
| Windows Hello for Business | Low (phishing-resistant) | Required for privileged admins |

### Secret management

- OIDC client secrets are **never stored in source control** — emitted as `sensitive` Terraform outputs only
- CI/CD uses **OIDC workload identity federation** — no `ARM_CLIENT_SECRET` in GitHub secrets
- Onboarding scripts emit secrets to stdout only; callers are responsible for storing in Key Vault
- `onboard_app.py` marks client secret outputs with a `STORE IN KEY VAULT` log warning

### WAF Security design decisions

| Decision | Rationale |
|---|---|
| `app_role_assignment_required = true` for SAML apps | Prevents unapproved users from accessing the app even if they authenticate |
| `forceChangePasswordNextSignInWithMfa = true` | New users must complete MFA before setting their permanent password |
| `sign_in_audience = "AzureADMyOrg"` on all apps | Restricts apps to the corporate tenant — prevents cross-tenant token issuance |
| Token access lifetime = 60 minutes (not default 1hr) | Aligned with recommendation; reduce further for high-risk apps |
| KQL alert: CA policy disabled | Any accidental or malicious policy disable is caught within 5 minutes |

---

## Pillar 2: Operational Excellence

The Operational Excellence pillar covers how the team builds, deploys, monitors, and continuously improves the IAM platform.

### Infrastructure as Code

Every Entra ID resource is declaratively managed in Terraform:

| Resource type | Terraform resource | File |
|---|---|---|
| App registrations (OIDC) | `azuread_application` | `app_registrations.tf` |
| Service principals | `azuread_service_principal` | `app_registrations.tf` |
| SAML signing certs | `azuread_service_principal_token_signing_certificate` | `app_registrations.tf` |
| Conditional Access policies | `azuread_conditional_access_policy` | `conditional_access.tf` |
| Named locations | `azuread_named_location` | `conditional_access.tf` |
| Authentication strength | `azuread_authentication_strength_policy` | `identity_protection.tf` |
| Security groups | `azuread_group` | `groups.tf` |
| Log Analytics workspace | `azurerm_log_analytics_workspace` | `monitoring.tf` |
| Diagnostic settings | `azurerm_monitor_aad_diagnostic_setting` | `monitoring.tf` |
| KQL alert rules (×5) | `azurerm_monitor_scheduled_query_rules_alert_v2` | `monitoring.tf` |
| Action group | `azurerm_monitor_action_group` | `monitoring.tf` |

### Automation scripts

| Script | Purpose | Schedule |
|---|---|---|
| `onboard_app.py` | OIDC/SAML/App Proxy app registration | On-demand via HR system webhook |
| `user_lifecycle.py` | User onboard/offboard | On-demand via HR system webhook |
| `idp_migration.py` | IdP migration pipeline (export/transform/validate/import/verify) | On-demand per migration project |
| `mfa_audit.py` | MFA coverage compliance report | Weekly via CI/CD schedule |

### Deployment pipeline (GitHub Actions)

```
PR opened
    │
    ├── Python lint (ruff)
    ├── Type check (mypy)
    ├── Unit tests (pytest)
    ├── SAST scan (bandit)
    ├── IaC scan (checkov + tfsec)
    ├── Terraform fmt check
    └── Terraform validate
          │
          ▼
    Terraform plan (OIDC auth — no long-lived secrets)
          │
          ▼
    Plan posted as PR comment
          │
PR merged to main
          │
          ▼
    Manual approval gate (prod environment)
          │
          ▼
    Terraform apply
```

### Observability

Five KQL-based alert rules provide operational visibility:

| Alert | Severity | Window | Trigger |
|---|---|---|---|
| High-volume failed sign-ins | 2 (Warning) | 10 min | >10 failures for single account |
| Privileged role assigned off-hours | 1 (Error) | 15 min | Role assignment 19:00–07:00 UTC |
| CA policy disabled | 1 (Error) | 5 min | Any CA policy disabled or deleted |
| New app registration | 3 (Info) | 30 min | Any new app registered |
| High-risk user detected | 1 (Error) | 15 min | Identity Protection: user risk = High |

### Runbook-driven operations

See [runbook.md](./runbook.md) for step-by-step procedures for:
- Onboarding a new application
- Offboarding a user
- Migrating apps from a legacy IdP
- Responding to a CA policy alert
- Break-glass account usage

---

## Pillar 3: Reliability

The Reliability pillar ensures the IAM platform remains available and recoverable under failure conditions.

### Design for failure

| Risk | Mitigation |
|---|---|
| Single CA policy misconfiguration locks out all users | Policy state starts as `enabledForReportingButNotEnforced`; monitor for 2 weeks before enforcing |
| Break-glass account locked by MFA policy | Break-glass group explicitly excluded from all CA policies via `mfa_excluded_group_ids` |
| Terraform state corruption | Remote state in Azure Blob Storage with soft-delete enabled + versioning |
| App registration deletion | Terraform `prevent_destroy = true` lifecycle for production app registrations |
| Log Analytics workspace deletion | 30-day soft-delete on workspace; alert on workspace deletion |
| SAML signing cert expiry | 3-year certificates; KQL alert fires 60 days before expiry (add to `monitoring.tf`) |
| Connector offline (App Proxy) | Multiple connectors per group; health monitored in Entra portal |

### Recovery procedures

| Scenario | Recovery action | RTO target |
|---|---|---|
| User locked out by CA policy | Temporary group exclusion via `mfa-excluded` group | < 5 minutes |
| CA policy accidentally deleted | `terraform apply` restores from state | < 10 minutes |
| App registration deleted | `terraform apply` re-creates; client secret reissued | < 15 minutes |
| SAML cert expired | `terraform taint` cert resource + `apply` | < 30 minutes |
| Log Analytics workspace deleted | Recreate via Terraform; historical data in 30-day soft-delete | < 1 hour |

### Idempotent automation

All Python scripts are designed to be safely re-run:

- `onboard_app.py` — checks for existing app by `displayName` before creating
- `user_lifecycle.py onboard` — `get_user()` before `post()`, updates if already exists
- `idp_migration.py import` — skips apps already marked `imported` or `verified`
- `mfa_audit.py` — read-only; generates a new report each run without modifying users

---

## Pillar 4: Cost Optimization

### Resource cost profile

This platform's Azure resources have near-zero running cost:

| Resource | Pricing model | Estimated monthly cost |
|---|---|---|
| Entra ID app registrations | Free (included in P1/P2) | $0 |
| Conditional Access policies | Included in Entra ID P1 | $0 |
| Identity Protection | Included in Entra ID P2 | $0 (P2 license already purchased) |
| Log Analytics workspace | Pay-per-GB ingested | ~$2–$10/month for IAM logs |
| Scheduled query alerts | Per-rule pricing | ~$0.10/rule/month = ~$0.50/month |
| Action group notifications | Free tier: 1,000 emails/month | ~$0 for alert volumes |

**Total estimated infrastructure cost: <$15/month**

The primary cost is the Entra ID P1/P2 per-user license, which is a pre-existing organizational spend.

### Cost guardrails

| Control | Implementation |
|---|---|
| `entra_p2_features_enabled` variable | Set `false` to skip P2-only resources (Identity Protection policies, PIM) in P1 tenants |
| `log_retention_days` variable | Tune retention to balance compliance requirements against Log Analytics ingestion cost |
| Per-environment Terraform state | Separate state files per environment prevent accidental apply to wrong environment |
| `prevent_destroy` lifecycle on production resources | Prevents accidental resource deletion that could cause incident remediation costs |

---

## Pillar 5: Performance Efficiency

### Token lifetime optimization

Token lifetimes are tuned to balance security and user experience:

| Token type | Configured lifetime | Rationale |
|---|---|---|
| Access token | 60 minutes (configurable via `access_token_lifetime_minutes`) | Default; reduce for high-risk apps |
| Refresh token max inactive | 90 days | Allows infrequent users to stay signed in without re-authenticating |
| Session single factor | Until revoked | Persistent browser session avoids repeated MFA prompts on trusted devices |
| Session multi factor | Until revoked | Persistent after MFA completion on compliant device |

### App Proxy connector sizing

| Tenant size | Recommended connectors per group |
|---|---|
| < 500 users | 2 (redundancy) |
| 500–10,000 users | 4 |
| > 10,000 users | 8+ with load-based auto-scaling |

### SAML vs OIDC performance comparison

| Protocol | Token size | Round trips | Recommended for |
|---|---|---|---|
| OIDC (JWT) | Small (~500 bytes) | 1 (implicit) or 2 (auth code) | New applications, SPAs, mobile |
| SAML 2.0 | Large (~2–8 KB XML) | 2 (POST binding) | Legacy enterprise apps, Salesforce, Workday |
| OAuth 2.0 Client Credentials | Small | 1 | Service-to-service, daemon apps |

New application onboarding defaults to OIDC for better performance and simpler implementation. SAML is used only where the service provider requires it (e.g., Salesforce, Workday) or where existing SAML integration cannot be migrated.

---

## WAF Assessment summary

| Pillar | Coverage | Key evidence |
|---|---|---|
| Security | Strong | Zero Trust CA chain, phishing-resistant MFA, session revocation, SAST in CI |
| Operational Excellence | Strong | Full IaC, 5 automation scripts, CI/CD with OIDC auth, observability |
| Reliability | Good | Break-glass exclusions, idempotent scripts, remote state, recovery procedures |
| Cost Optimization | Good | <$15/month infrastructure, feature flags for license tiers |
| Performance Efficiency | Good | Token lifetime policy, OIDC-first for new apps, App Proxy sizing guidance |

---

*This document is updated with each release. Last updated: 2026.*
