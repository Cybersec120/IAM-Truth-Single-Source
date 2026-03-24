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

NOW ALLOW ME TO TRANSLATE THIS IDENTITY AND ACCESS MANAGEMENT PRODUCTION LEVEL ENVIRONMENT SOLUTION... INTO THE LANGUAGE OF MY BUSINESS STAKEHOLDERS... THE LANGUAGE OF SIMPLICITY.... WHAT PROBLEM DO WE HAVE? DOES THIS SOLUTION SOLVE THE PROBLEM WE HAVE? CAN OUR BUSINESS NOW MOVE FORWARD...HAS THE PROBLEM BEEN SOLVED..!

# enterprise-iam-platform

Engineering is building with purpose.

To me, engineering is not about pretending to have every answer already stored in your mind. It is about seeing the problem clearly, understanding the business objective behind it, and then building the architecture that becomes the solution.

I do not claim to be the man who walks in the room with every complicated answer already in his pocket. I am something different.

I am the one who knows how to trace the path.
I know how to find the answer.
I know how to verify the answer.
And I know how to take what is complex, hidden, and technical, and bring it to light so the people making business decisions can actually understand it.

That matters.

Because technology without business alignment is noise.
Security without clarity is confusion.
And architecture without purpose is just machinery with no soul.

In this era, AI is here and it is not going anywhere. Use it. Learn it. But trust and verify. Every tool has its place. The wise builder uses every working tool on the trestle board, but never surrenders judgment. The work must still be measured, squared, and proven true.

This project reflects that philosophy.

It is a production-grade **Enterprise Identity and Access Management platform** built on **Microsoft Entra ID**, designed to solve real business and security problems in a way that is structured, scalable, and understandable. It demonstrates how modern IAM can be deployed as code, governed with policy, monitored with precision, and aligned to the **five pillars of the Azure Well-Architected Framework**.

It is not just an identity lab.
It is not just a pile of scripts.
It is a complete operating model for secure access.

It shows how to:

- enable **OIDC, SAML 2.0, and OAuth 2.0**
- publish internal applications securely with **Entra Application Proxy**
- enforce **Conditional Access policies as code**
- integrate **Duo MFA**
- automate **user lifecycle management**
- support **IdP migration** from platforms like Okta, PingFederate, and ADFS
- monitor identity events with **KQL alerts, dashboards, and audit reporting**
- manage everything through **Terraform and automation scripts**

In plain words: this platform makes sure the right people get the right access to the right systems, under the right conditions, with the right protections in place.... USING A SINGLE SOURCE OF TRUTH!

---

## Why this project exists

A lot of business leaders know they need stronger security.
A lot of engineers know how to configure the technology.
But there is often a gap between those two worlds.

That gap is where I work best.

I am becoming the bridge between:

- the technical teams who speak in protocols, policies, tokens, logs, and infrastructure
- and the stakeholders who speak in risk, uptime, cost, compliance, operations, and business outcomes

This project was built to show that identity engineering is not only about authentication.
It is about business continuity.
It is about protecting trust.
It is about making access secure, manageable, auditable, and aligned with the mission.

---

## What this solution does

This solution is an **enterprise IAM platform** that controls how users sign in, what applications they can access, and what security checks must happen before access is granted.

Think of it like this:

A company has employees, admins, contractors, apps, internal systems, cloud systems, and security rules.
Without a strong IAM platform, access becomes messy, risky, and hard to control.

This platform fixes that by putting everything behind one organized identity system.

### It handles:

- **Authentication**  
  Verifies who a user is when they try to sign in.

- **Authorization**  
  Decides what that user is allowed to access.

- **MFA enforcement**  
  Adds extra proof, like a phone prompt or security key, before access is allowed.

- **Conditional Access**  
  Checks conditions before allowing sign-in, such as:
  - Is the user in a trusted location?
  - Is the device compliant?
  - Is the sign-in risky?
  - Is the user an admin?

- **Application onboarding**  
  Adds new apps into the identity system using standard protocols like OIDC and SAML.

- **App Proxy publishing**  
  Lets users securely access internal apps without exposing those apps directly to the internet.

- **Identity protection**  
  Detects risky behavior like suspicious sign-ins or impossible travel.

- **Monitoring and alerting**  
  Sends alerts when something dangerous or unusual happens.

- **Automation**  
  Reduces manual work for onboarding users, onboarding apps, auditing MFA coverage, and migrating identities.

---

## Explain it like you're 14

Imagine a school with:

- students
- teachers
- principals
- staff
- classrooms
- private offices
- computer labs

Now imagine nobody is checking who can go where.

Anyone could walk into the principal’s office.
Anyone could enter the server room.
Anyone could pretend to be a teacher.
That would be chaos.

This IAM platform is like giving the school:

- an ID card system
- security guards
- door rules
- visitor checks
- alarm systems
- audit logs
- and automatic reports

So now:

- students can enter student areas
- teachers can access teacher systems
- admins get stricter checks
- suspicious behavior gets flagged
- internal rooms stay protected
- and leadership can see what is happening

That is what this platform does for a business, but in the digital world.

It makes access organized, secure, and visible.

---

## Architecture overview

At the center of the platform is **Microsoft Entra ID**.

Entra ID acts like the main gatekeeper. It manages users, applications, access policies, identity risk, and authentication flows.

Around it, the platform includes:

- **OIDC and OAuth apps** for modern authentication
- **SAML enterprise apps** for older or enterprise-integrated systems
- **Application Proxy** for securely publishing internal apps
- **Duo MFA** for strong second-factor authentication
- **Conditional Access policies** to control how and when access is allowed
- **Identity Protection** to respond to risky sign-ins and compromised users
- **Log Analytics and KQL alerts** to monitor security events
- **Terraform infrastructure** to deploy and manage the environment as code
- **Python automation scripts** to onboard apps, manage users, migrate identity providers, and audit MFA status

---

## Why the Azure Well-Architected Framework matters here

This project is aligned to all five Azure WAF pillars because good IAM is not only about security. It also has to be reliable, cost-aware, observable, and efficient.

### 1. Reliability
The platform is designed so identity services and key secrets are protected and recoverable.

Examples:
- primary and disaster recovery Key Vault design
- soft delete and purge protection
- retained logs and immutable archives
- failover planning

### 2. Security
This is the heart of the platform.

Examples:
- Conditional Access policies
- MFA enforcement
- legacy authentication blocking
- device compliance checks
- encryption with customer-managed keys
- Defender for Cloud protections
- private endpoints
- audit logging and alert rules

### 3. Cost Optimization
Security should be strong, but not wasteful.

Examples:
- monthly budgets
- cost alerts
- storage lifecycle policies
- exports for cost visibility
- tagging for accountability

### 4. Operational Excellence
The environment should be maintainable and repeatable.

Examples:
- Terraform for infrastructure as code
- CI/CD validation
- report-only mode before enforcing access policies
- dashboards and scheduled alerts
- dry-run support for scripts

### 5. Performance Efficiency
The platform should operate cleanly and respond quickly.

Examples:
- Key Vault latency targets
- query optimization in KQL
- data export for cold storage
- efficient monitoring design

---

## Core components

### Terraform
Terraform builds the environment as code.

That means instead of clicking around manually in a portal and hoping everything is configured correctly, the system is defined in files. Those files can be reviewed, versioned, tested, and reused.

### Conditional Access policies
These policies are the rules that decide how users are allowed to sign in.

For example:
- all users may need MFA
- legacy auth can be blocked
- admins may need compliant devices
- risky users may be forced to change passwords
- logins from unsafe locations may be denied

### App onboarding automation
The onboarding scripts help bring new applications into the platform faster and more consistently.

Instead of doing everything by hand, the script can create and configure what the app needs based on a JSON config file.

### User lifecycle automation
Users join. Users leave. Roles change.

This part of the platform automates onboarding, offboarding, and security-related identity updates so that access is not forgotten or left behind.

### IdP migration toolkit
Organizations often move from one identity provider to another.

This toolkit helps export identity-related configurations from systems like Okta, PingFederate, or ADFS and prepare them for import into Entra.

### MFA audit tooling
This checks how much MFA coverage exists across the environment and helps identify gaps.

That is important because leadership may ask:
“Are all users protected?”
This script helps answer that with evidence.

### Monitoring and alerting
The platform watches for signs of trouble.

Examples include:
- brute-force login attempts
- impossible travel
- Conditional Access changes
- legacy auth usage
- unusual secret access in Key Vault

---

## In simple business language

This platform helps a company answer these questions:

- Who has access to what?
- How do we know users are really who they claim to be?
- How do we stop risky sign-ins?
- How do we protect internal apps?
- How do we onboard new apps safely?
- How do we prove our controls are working?
- How do we automate access without losing governance?

That is why IAM matters.

It is not just login security.
It is business protection.

---

## What this project says about me

This project represents the kind of engineer I am becoming.

Not just someone who can configure tools.
Not just someone who can read documentation.
But someone who can:

- understand the mission
- align the technology to the business objective
- build with structure
- verify with discipline
- and explain the whole thing in a way normal people can actually understand

That is the work.

To take what is hidden in complexity and bring it into order.
To square the stone.
To build what serves.
To make the system true.

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
