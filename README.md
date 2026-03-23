# enterprise-iam-platform

I am **El PUENTE...THE BRIDGE**.

I bridge the distance between business vision and technical execution.
I take the language of architecture, security, identity, and cloud, and translate it into outcomes that leaders, stakeholders, and builders can all understand.

Azure and AWS are only different working grounds.
Different pillars. Different chambers. Different systems.
But the work remains the same:
to bring order from complexity,
to align technology with purpose,
and to build solutions that are true to the mission.

I do not worship tools.
I use them.
I do not chase noise.
I seek understanding.
I trust, but verify.
I find the answer, refine the answer, and build until the architecture itself speaks clearly.

I am not becoming the bridge.

I am the bridge.

**El PUENTE....THE BRIDGE**

---

## Architecture

```
┌──────────────────────────── Microsoft Entra ID ────────────────────────────┐
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │  OIDC apps  │  │  SAML apps  │  │  App Proxy   │  │  Duo MFA         │ │
│  │  OAuth 2.0  │  │  Enterprise │  │  On-prem pub.│  │  Push + FIDO2    │ │
│  └─────────────┘  └─────────────┘  └──────────────┘  └──────────────────┘ │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Conditional Access Policies — CA001 through CA007                   │  │
│  │  CA001: MFA all users    CA002: Block legacy    CA003: Compliant dev  │  │
│  │  CA004: Sign-in risk     CA005: User risk        CA006: Geo-block     │  │
│  │  CA007: SSPR registration MFA                                         │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────┐  ┌────────────────────────────────────────────┐ │
│  │  Identity Protection   │  │  Log Analytics (WAF: OE + PE pillars)      │ │
│  │  Sign-in risk policy   │  │  5 KQL scheduled query alert rules         │ │
│  │  User risk policy      │  │  IAM Ops Dashboard workbook                │ │
│  └────────────────────────┘  └────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
                        │
           ┌────────────┴──────────────────────────────────┐
           │                                               │
┌──────────▼───────────────────────┐   ┌──────────────────▼──────────────────┐
│  WAF Infrastructure (terraform/waf)│   │  Automation Scripts (scripts/)      │
│                                  │   │                                     │
│  Reliability                     │   │  onboard_app.py   — OIDC/SAML/Proxy │
│    Primary + DR Key Vault        │   │  user_lifecycle.py — onboard/offboard│
│    Log Analytics (365d retain)   │   │  idp_migration.py — IdP export/import│
│    GRS archive storage           │   │  mfa_audit.py     — coverage report  │
│  Security                        │   │                                     │
│    Defender for Cloud (3 plans)  │   │  All scripts support --dry-run       │
│    5 Azure Policy assignments    │   │  Duo Admin API integration           │
│    CMK + private endpoints       │   │  Structured JSON audit logging       │
│  Cost Optimization               │   └─────────────────────────────────────┘
│    Monthly budget + alerts       │
│    Storage lifecycle rules       │
│    Cost Management export        │
│  Operational Excellence          │
│    5 KQL alert rules             │
│    Action group + workbook       │
│  Performance Efficiency          │
│    KV SLO alerts (99.9% / 100ms) │
│    Data export + saved queries   │
└──────────────────────────────────┘
```

---

## Azure Well-Architected Framework Alignment

### Reliability (RE)

| Principle | Implementation |
|---|---|
| RE:04 Redundancy | Primary + DR Key Vault across two Azure regions |
| RE:07 Self-preservation | KV purge protection + 90-day soft delete on all vaults |
| RE:09 Disaster recovery | GRS storage, secondary KV, documented failover runbook |
| RE:02 Recovery targets | 365-day log retention; 7-year WORM audit archive |

### Security (SE)

| Principle | Implementation |
|---|---|
| SE:01 Baseline | 5 Azure Policy assignments enforcing CIS controls at RG scope |
| SE:03 Identity perimeter | 7 CA policies: MFA, legacy block, risk, device compliance |
| SE:04 Segmentation | Private endpoint for Key Vault; dedicated subnet + service endpoints |
| SE:06 Encryption | CMK (RSA-HSM 4096-bit) with annual auto-rotation via KV rotation policy |
| SE:07 Credentials | All secrets in KV; zero-downtime rotation pattern; never in code |
| SE:08 Harden workloads | Defender for Key Vault, Storage, DNS enabled |
| SE:10 Monitor | 5 KQL alert rules: brute-force, impossible travel, CA change, legacy auth, KV exfil |
| SE:12 Sensitive data | Data classification tags; WORM immutable audit log storage |

### Cost Optimization (CO)

| Principle | Implementation |
|---|---|
| CO:01 Discipline | Monthly budget with alerts at 75%, 90%, 100%, 110% (forecasted) |
| CO:04 Visibility | 3 mandatory tags + daily Cost Management export |
| CO:11 Flow costs | Storage lifecycle: Hot→Cool@30d, Cold@90d, Archive@180d, delete@7yr |

### Operational Excellence (OE)

| Principle | Implementation |
|---|---|
| OE:01 DevOps | All resources as Terraform IaC; GitOps with PR-gated apply |
| OE:04 Observability | IAM Ops Workbook: sign-in volume, MFA rate, CA bypass, app changes |
| OE:05 Deploy safely | ca_policy_state variable — report-only mode before enforcement |
| OE:07 Health monitoring | 5 KQL alerts; KV availability + saturation metric alerts |
| OE:12 Automate | 4 Python scripts; Duo API; dry-run on all commands |

### Performance Efficiency (PE)

| Principle | Implementation |
|---|---|
| PE:01 Targets | KV availability SLO 99.9%; KV latency SLO 100ms p99 |
| PE:07 Optimize | KQL queries: time filter first, then summarise (correct execution order) |
| PE:11 Ingestion | Log Analytics data export offloads cold data to archive storage |

---

## Project Structure

```
enterprise-iam-platform/
├── terraform/
│   ├── entra-id/                    # Entra ID resources-as-code
│   │   ├── versions.tf              # AzureAD ~2.47 provider
│   │   ├── variables.tf             # All inputs with validation
│   │   ├── locals.tf                # Prefix, Graph API constants
│   │   ├── groups.tf                # IAM, MFA-excluded, CA-scoped groups
│   │   ├── app_registrations.tf     # OIDC + SAML apps, claim mappings
│   │   ├── conditional_access.tf    # CA001–CA007 policies
│   │   ├── app_proxy.tf             # Entra App Proxy for on-prem publishing
│   │   ├── identity_protection.tf   # Sign-in + user risk policies
│   │   ├── monitoring.tf            # Diagnostic settings → Log Analytics
│   │   └── outputs.tf
│   │
│   └── waf/                         # Azure WAF five-pillar layer
│       ├── pillar_reliability.tf    # KV (primary+DR), Log Analytics, GRS archive
│       ├── pillar_security.tf       # Defender, Policy, CMK, private endpoints
│       ├── pillar_cost_optimization.tf  # Budget, tags, lifecycle, cost export
│       ├── pillar_operational_excellence.tf  # 5 KQL alerts, workbook, action group
│       ├── pillar_performance_efficiency.tf  # SLO alerts, saved KQL, data export
│       └── outputs.tf               # WAF coverage summary
│
├── scripts/
│   ├── onboarding/
│   │   ├── onboard_app.py           # OIDC/SAML/App Proxy via Graph API
│   │   └── user_lifecycle.py        # Onboard/offboard + Duo enrollment
│   ├── migration/
│   │   └── idp_migration.py         # Export from Okta/ADFS, import to Entra
│   └── audit/
│       └── mfa_audit.py             # MFA coverage CSV + JSON report
│
├── configs/                         # Sample app onboarding JSON configs
├── docs/
│   └── waf-assessment.md            # WAF review checklist with evidence mapping
├── .github/workflows/ci-cd.yml      # Terraform + Checkov + Bandit CI/CD
└── requirements.txt
```

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Terraform | >= 1.6.0 | IaC |
| Azure CLI | >= 2.56 | Auth |
| Python | >= 3.12 | Automation scripts |

**Entra permissions** for the Terraform SP: `Application.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `Directory.ReadWrite.All`

**Azure RBAC** for the WAF module: `Contributor` + `Security Admin`

---

## Quick Start

```bash
# 1. Set credentials
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<client-id>
export AZURE_CLIENT_SECRET=<client-secret>
export ARM_TENANT_ID=$AZURE_TENANT_ID
export ARM_CLIENT_ID=$AZURE_CLIENT_ID
export ARM_CLIENT_SECRET=$AZURE_CLIENT_SECRET
export ARM_SUBSCRIPTION_ID=<subscription-id>

# 2. Deploy WAF layer first (shared infrastructure)
cd terraform/waf && terraform init && terraform apply

# 3. Deploy Entra ID resources
cd ../entra-id && terraform init && terraform apply

# 4. Onboard a OIDC app (dry-run first)
python scripts/onboarding/onboard_app.py \
  --type oidc --config configs/oidc-hr-portal.json --dry-run

# 5. After 2 weeks in report-only mode, enforce CA policies
# Set ca_policy_state = "enabled" in terraform.tfvars, then:
cd terraform/entra-id && terraform apply
```

---

## Conditional Access Policies

| Policy | Target | Condition | Control |
|---|---|---|---|
| CA001 | All workforce | Outside trusted IPs | Require MFA |
| CA002 | All users | Legacy auth clients | Block |
| CA003 | Privileged admins | Any | MFA + Compliant device |
| CA004 | All users | Sign-in risk Medium/High | Require MFA |
| CA005 | All users | User risk High | MFA + Password change |
| CA006 | IAM admins | Non-trusted locations | Block |
| CA007 | All workforce | SSPR registration | Require MFA |

---

## KQL Alert Rules

| Alert | Severity | Trigger | MITRE |
|---|---|---|---|
| Brute-force | P1 | >20 failures in 5 min from one IP | T1110.003 |
| Impossible travel | P2 | Same user, different countries within 1h | T1078 |
| CA policy modified | P1 | Any CA policy add/update/delete | T1556.006 |
| Legacy auth bypass | P1 | Successful IMAP/POP/SMTP sign-in | T1078.004 |
| KV mass access | P1 | >20 secrets read in 5 min | T1552.001 |

---

## IdP Migration Toolkit

```bash
# Export from Okta
python scripts/migration/idp_migration.py export \
  --source okta --output migration/export.json

# Import to Entra (dry-run)
python scripts/migration/idp_migration.py import \
  --input migration/export.json --target entra --dry-run
```
Supports Okta, PingFederate, and ADFS as source IdPs.
