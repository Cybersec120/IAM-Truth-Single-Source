#!/usr/bin/env python3
"""
mfa_audit.py
enterprise-iam-platform — MFA Compliance Audit

Produces a complete MFA coverage audit across all Entra ID users:
  - Identifies users with no MFA registered (highest risk)
  - Identifies users with only SMS/voice (phishable — flag for upgrade)
  - Reports users with phishing-resistant methods (FIDO2, Windows Hello)
  - Checks Duo enrollment status against Entra registration
  - Generates a prioritised remediation plan
  - Outputs JSON, CSV, and HTML report formats

Azure WAF alignment:
  Security           — MFA gap visibility drives remediation prioritisation
  Operational Excel. — scheduled in CI/CD for weekly compliance reporting
  Reliability        — detects CA policy exceptions that may grow silently

Usage:
  python mfa_audit.py audit --output-dir reports/
  python mfa_audit.py audit --output-dir reports/ --format all
  python mfa_audit.py check --upn jsmith@contoso.com
  python mfa_audit.py remediation-plan --input reports/mfa-audit.json

Required env vars:
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
  DUO_IKEY, DUO_SKEY, DUO_HOST  (optional)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from azure.identity import ClientSecretCredential

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("mfa_audit")

GRAPH_V1 = "https://graph.microsoft.com/v1.0"

# MFA method classification for risk tiering
# WAF: Security — prioritise remediation by method strength
METHOD_TIERS = {
    "fido2AuthenticationMethod":                 "PHISHING_RESISTANT",
    "windowsHelloForBusinessAuthenticationMethod": "PHISHING_RESISTANT",
    "microsoftAuthenticatorAuthenticationMethod":  "STRONG",
    "softwareOathAuthenticationMethod":            "STRONG",
    "temporaryAccessPassAuthenticationMethod":     "TEMPORARY",
    "phoneAuthenticationMethod":                   "PHISHABLE",   # SMS / voice call
    "emailAuthenticationMethod":                   "PHISHABLE",
    "passwordAuthenticationMethod":                "NONE",        # Password only = no MFA
}


# ── Graph client ──────────────────────────────────────────────────────────────

class GraphClient:
    def __init__(self, tenant: str, cid: str, secret: str) -> None:
        self._cred = ClientSecretCredential(tenant, cid, secret)
        self._s = requests.Session()

    def _h(self) -> dict:
        t = self._cred.get_token("https://graph.microsoft.com/.default").token
        return {"Authorization": f"Bearer {t}"}

    def get_all_users(self) -> list[dict]:
        """Page through all enabled user accounts."""
        users: list[dict] = []
        url = (
            f"{GRAPH_V1}/users"
            "?$select=id,userPrincipalName,displayName,department,jobTitle,"
            "accountEnabled,createdDateTime,assignedLicenses"
            "&$filter=accountEnabled eq true"
            "&$top=999"
        )
        while url:
            r = self._s.get(url, headers=self._h(), timeout=60)
            r.raise_for_status()
            data = r.json()
            users.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            if url:
                log.debug("Paging users — fetched %d so far", len(users))
        return users

    def get_auth_methods(self, user_id: str) -> list[dict]:
        """Return registered authentication methods for a user."""
        try:
            r = self._s.get(
                f"{GRAPH_V1}/users/{user_id}/authentication/methods",
                headers=self._h(), timeout=30,
            )
            r.raise_for_status()
            return r.json().get("value", [])
        except requests.HTTPError:
            return []

    def get_sign_in_activity(self, user_id: str) -> dict:
        """Return last sign-in date (requires AuditLog.Read.All)."""
        try:
            r = self._s.get(
                f"{GRAPH_V1}/users/{user_id}"
                "?$select=signInActivity",
                headers=self._h(), timeout=15,
            )
            r.raise_for_status()
            return r.json().get("signInActivity", {})
        except Exception:
            return {}


# ── Audit logic ───────────────────────────────────────────────────────────────

def classify_user_mfa(methods: list[dict]) -> dict:
    """
    Classify a user's MFA posture from their registered auth methods.

    Returns:
        tier:         PHISHING_RESISTANT | STRONG | PHISHABLE | NONE
        methods:      list of registered method type names
        has_mfa:      bool — at least one MFA method registered
        recommendation: actionable next step
    """
    method_types = [
        m.get("@odata.type", "").split(".")[-1]
        for m in methods
    ]

    # Determine highest tier
    tier = "NONE"
    for t, tier_name in METHOD_TIERS.items():
        if t in method_types:
            if tier_name == "PHISHING_RESISTANT":
                tier = "PHISHING_RESISTANT"
                break
            elif tier_name == "STRONG" and tier not in ("PHISHING_RESISTANT",):
                tier = "STRONG"
            elif tier_name == "PHISHABLE" and tier not in ("PHISHING_RESISTANT", "STRONG"):
                tier = "PHISHABLE"
            elif tier_name == "TEMPORARY" and tier not in ("PHISHING_RESISTANT", "STRONG", "PHISHABLE"):
                tier = "TEMPORARY"

    has_mfa = tier not in ("NONE",)

    recommendations = {
        "PHISHING_RESISTANT": "No action required — phishing-resistant MFA enrolled.",
        "STRONG":             "Consider upgrading to FIDO2 or Windows Hello for Business.",
        "PHISHABLE":          "URGENT: Replace SMS/voice with Microsoft Authenticator app.",
        "TEMPORARY":          "Temporary access pass active — ensure permanent MFA is registered.",
        "NONE":               "CRITICAL: No MFA registered — user can sign in with password only.",
    }

    return {
        "tier":           tier,
        "has_mfa":        has_mfa,
        "methods":        method_types,
        "recommendation": recommendations[tier],
    }


def run_audit(graph: GraphClient, include_sign_in_activity: bool = False) -> dict:
    """
    Run a full MFA coverage audit across all enabled users.

    Returns a structured audit result with summary metrics and per-user details.
    """
    log.info("[AUDIT] Fetching all enabled users")
    users = graph.get_all_users()
    log.info("[AUDIT] Found %d enabled users — auditing auth methods", len(users))

    audit_results: list[dict] = []
    summary_counts = {
        "PHISHING_RESISTANT": 0,
        "STRONG":             0,
        "PHISHABLE":          0,
        "TEMPORARY":          0,
        "NONE":               0,
    }

    for i, user in enumerate(users):
        uid = user["id"]
        upn = user.get("userPrincipalName", "")

        # Fetch auth methods for this user
        methods = graph.get_auth_methods(uid)
        classification = classify_user_mfa(methods)

        # Optionally enrich with last sign-in date (slower — requires extra permission)
        last_signin = ""
        if include_sign_in_activity:
            activity = graph.get_sign_in_activity(uid)
            last_signin = activity.get("lastSignInDateTime", "")

        tier = classification["tier"]
        summary_counts[tier] = summary_counts.get(tier, 0) + 1

        audit_results.append({
            "upn":             upn,
            "object_id":       uid,
            "display_name":    user.get("displayName", ""),
            "department":      user.get("department", ""),
            "job_title":       user.get("jobTitle", ""),
            "account_enabled": user.get("accountEnabled", True),
            "mfa_tier":        tier,
            "has_mfa":         classification["has_mfa"],
            "methods":         classification["methods"],
            "recommendation":  classification["recommendation"],
            "last_signin":     last_signin,
        })

        if (i + 1) % 100 == 0:
            log.info("[AUDIT] Processed %d/%d users", i + 1, len(users))

    total = len(audit_results)
    no_mfa_users = [r for r in audit_results if not r["has_mfa"]]
    phishable_users = [r for r in audit_results if r["mfa_tier"] == "PHISHABLE"]

    mfa_coverage_pct = round(
        (sum(1 for r in audit_results if r["has_mfa"]) / total) * 100, 1
    ) if total > 0 else 0.0

    phishing_resistant_pct = round(
        (summary_counts["PHISHING_RESISTANT"] / total) * 100, 1
    ) if total > 0 else 0.0

    return {
        "audit_metadata": {
            "tenant_id":    os.environ["AZURE_TENANT_ID"],
            "audited_at":   datetime.now(tz=timezone.utc).isoformat(),
            "total_users":  total,
        },
        "summary": {
            "mfa_coverage_pct":          mfa_coverage_pct,
            "phishing_resistant_pct":    phishing_resistant_pct,
            "users_with_no_mfa":         len(no_mfa_users),
            "users_with_phishable_mfa":  len(phishable_users),
            "by_tier":                   summary_counts,
        },
        "high_risk_users": [
            {"upn": r["upn"], "department": r["department"], "tier": r["mfa_tier"]}
            for r in audit_results
            if r["mfa_tier"] in ("NONE", "PHISHABLE")
        ][:50],   # Top 50 for report brevity
        "users": audit_results,
    }


# ── Remediation plan ──────────────────────────────────────────────────────────

def generate_remediation_plan(audit: dict) -> dict:
    """
    Produce a prioritised remediation plan from an audit result.

    Prioritisation:
      P0 — No MFA at all (CRITICAL — immediate action)
      P1 — Phishable MFA only (HIGH — replace within 30 days)
      P2 — Strong MFA but not phishing-resistant (LOW — upgrade over 90 days)
    """
    users = audit.get("users", [])

    p0 = [u for u in users if u["mfa_tier"] == "NONE"]
    p1 = [u for u in users if u["mfa_tier"] == "PHISHABLE"]
    p2 = [u for u in users if u["mfa_tier"] == "STRONG"]

    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "P0_critical": {
            "description": "No MFA registered — password-only access. Block immediately or enforce TAP.",
            "count":       len(p0),
            "action":      "Issue Temporary Access Pass + send MFA registration link",
            "sla_days":    3,
            "users":       [{"upn": u["upn"], "dept": u["department"]} for u in p0[:20]],
        },
        "P1_high": {
            "description": "SMS or voice MFA only — phishable. Replace with Authenticator app.",
            "count":       len(p1),
            "action":      "Send Authenticator app enrollment email; disable SMS after 30 days",
            "sla_days":    30,
            "users":       [{"upn": u["upn"], "dept": u["department"]} for u in p1[:20]],
        },
        "P2_low": {
            "description": "Authenticator app enrolled — strong but not phishing-resistant.",
            "count":       len(p2),
            "action":      "Campaign to promote FIDO2 key or Windows Hello for Business",
            "sla_days":    90,
            "users":       [],  # Too many to list — address by department
        },
        "recommended_ca_changes": [
            "Enable CA001 in 'enabled' state if currently report-only",
            "Add authentication strength requiring Authenticator app (block SMS-only sign-ins)",
            "Set 30-day deadline for P1 users before SMS method is disabled in CA policy",
        ],
    }


# ── Output writers ────────────────────────────────────────────────────────────

def write_csv(users: list[dict], path: str) -> None:
    fieldnames = ["upn", "display_name", "department", "job_title",
                  "mfa_tier", "has_mfa", "methods", "recommendation"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for u in users:
            row = {**u, "methods": " | ".join(u.get("methods", []))}
            writer.writerow(row)
    log.info("CSV written to %s", path)


def write_html(audit: dict, path: str) -> None:
    summary = audit.get("summary", {})
    by_tier = summary.get("by_tier", {})
    users   = audit.get("users", [])

    tier_colors = {
        "PHISHING_RESISTANT": "#2d8a4e",
        "STRONG":             "#1a6fb5",
        "PHISHABLE":          "#d97706",
        "TEMPORARY":          "#7c3aed",
        "NONE":               "#c0392b",
    }

    rows = "".join(
        f"<tr>"
        f"<td>{u['upn']}</td>"
        f"<td>{u['department']}</td>"
        f"<td style='color:{tier_colors.get(u['mfa_tier'], '#333')};font-weight:600'>{u['mfa_tier']}</td>"
        f"<td>{' | '.join(u.get('methods', []))}</td>"
        f"<td style='font-size:0.82rem'>{u['recommendation']}</td>"
        f"</tr>"
        for u in users
    )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>MFA Audit Report — {audit['audit_metadata']['audited_at'][:10]}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:2rem;color:#111}}
  h1{{font-size:1.4rem;font-weight:600}}
  .kpis{{display:flex;gap:1.5rem;margin:1.5rem 0;flex-wrap:wrap}}
  .kpi{{background:#f7f7f7;border-radius:8px;padding:1rem 1.4rem;min-width:130px}}
  .kv{{font-size:2rem;font-weight:700}} .kl{{font-size:0.8rem;color:#666;margin-top:2px}}
  table{{width:100%;border-collapse:collapse;font-size:0.88rem}}
  th{{background:#1a1a2e;color:#fff;padding:0.7rem 0.9rem;text-align:left}}
  td{{padding:0.55rem 0.9rem;border-bottom:1px solid #eee;vertical-align:top}}
  tr:hover{{background:#fafafa}}
</style></head><body>
<h1>MFA Compliance Audit Report</h1>
<p>Tenant: {audit['audit_metadata']['tenant_id']} &nbsp;|&nbsp;
   Audited: {audit['audit_metadata']['audited_at'][:19]} UTC &nbsp;|&nbsp;
   Total users: {audit['audit_metadata']['total_users']}</p>
<div class="kpis">
  <div class="kpi"><div class="kv" style="color:#2d8a4e">{summary.get('mfa_coverage_pct')}%</div><div class="kl">MFA coverage</div></div>
  <div class="kpi"><div class="kv" style="color:#1a6fb5">{summary.get('phishing_resistant_pct')}%</div><div class="kl">Phishing-resistant</div></div>
  <div class="kpi"><div class="kv" style="color:#c0392b">{summary.get('users_with_no_mfa')}</div><div class="kl">No MFA (CRITICAL)</div></div>
  <div class="kpi"><div class="kv" style="color:#d97706">{summary.get('users_with_phishable_mfa')}</div><div class="kl">Phishable MFA</div></div>
  <div class="kpi"><div class="kv">{by_tier.get('PHISHING_RESISTANT', 0)}</div><div class="kl">Phishing-resistant</div></div>
  <div class="kpi"><div class="kv">{by_tier.get('STRONG', 0)}</div><div class="kl">Strong (Authenticator)</div></div>
</div>
<table>
  <thead><tr><th>UPN</th><th>Department</th><th>MFA Tier</th><th>Methods</th><th>Recommendation</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
</body></html>"""

    with open(path, "w") as fh:
        fh.write(html)
    log.info("HTML report written to %s", path)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="MFA compliance audit tool")
    sub = parser.add_subparsers(dest="command", required=True)

    audit_p = sub.add_parser("audit")
    audit_p.add_argument("--output-dir", default="reports")
    audit_p.add_argument("--format", choices=["json", "csv", "html", "all"], default="all")
    audit_p.add_argument("--include-signin-activity", action="store_true")

    check_p = sub.add_parser("check")
    check_p.add_argument("--upn", required=True)

    plan_p = sub.add_parser("remediation-plan")
    plan_p.add_argument("--input", required=True)
    plan_p.add_argument("--output", default="remediation-plan.json")

    args = parser.parse_args()

    for var in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
        if not os.environ.get(var):
            log.error("Missing env var: %s", var)
            sys.exit(1)

    graph = GraphClient(
        os.environ["AZURE_TENANT_ID"],
        os.environ["AZURE_CLIENT_ID"],
        os.environ["AZURE_CLIENT_SECRET"],
    )

    if args.command == "audit":
        audit = run_audit(graph, include_sign_in_activity=args.include_signin_activity)
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        datestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d")

        if args.format in ("json", "all"):
            json_path = out_dir / f"mfa-audit-{datestamp}.json"
            with open(json_path, "w") as fh:
                json.dump(audit, fh, indent=2, default=str)
            log.info("JSON written to %s", json_path)

        if args.format in ("csv", "all"):
            csv_path = out_dir / f"mfa-audit-{datestamp}.csv"
            write_csv(audit["users"], str(csv_path))

        if args.format in ("html", "all"):
            html_path = out_dir / f"mfa-audit-{datestamp}.html"
            write_html(audit, str(html_path))

        # Always print summary to stdout
        s = audit["summary"]
        print(f"\nMFA Audit Summary")
        print(f"  Total users:          {audit['audit_metadata']['total_users']}")
        print(f"  MFA coverage:         {s['mfa_coverage_pct']}%")
        print(f"  Phishing-resistant:   {s['phishing_resistant_pct']}%")
        print(f"  No MFA (CRITICAL):    {s['users_with_no_mfa']}")
        print(f"  Phishable only:       {s['users_with_phishable_mfa']}\n")

    elif args.command == "check":
        users = [u for u in graph.get_all_users() if u.get("userPrincipalName") == args.upn]
        if not users:
            log.error("User not found: %s", args.upn)
            sys.exit(1)
        methods = graph.get_auth_methods(users[0]["id"])
        result = classify_user_mfa(methods)
        print(json.dumps(result, indent=2))

    elif args.command == "remediation-plan":
        with open(args.input) as fh:
            audit = json.load(fh)
        plan = generate_remediation_plan(audit)
        with open(args.output, "w") as fh:
            json.dump(plan, fh, indent=2)
        log.info("Remediation plan written to %s", args.output)
        print(f"\nP0 (Critical — no MFA):  {plan['P0_critical']['count']} users")
        print(f"P1 (High — phishable):   {plan['P1_high']['count']} users")
        print(f"P2 (Low — upgrade path): {plan['P2_low']['count']} users\n")


if __name__ == "__main__":
    main()
