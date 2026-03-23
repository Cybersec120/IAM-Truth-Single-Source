#!/usr/bin/env python3
"""
kv_replication.py
enterprise-iam-platform — Key Vault Secret Replication

Replicates secrets from the primary Key Vault to the secondary (DR) vault.
Run on a schedule (daily or on-demand) to keep the DR vault in sync.

Supports:
  - Full sync: replicate all secrets (first-time setup or DR validation)
  - Delta sync: only replicate secrets updated since last run
  - Dry-run: show what would be replicated without writing

WAF Alignment:
  RE:04 — Redundancy at all layers (secrets available in secondary region)
  RE:09 — Disaster recovery (failover target is always current)

Usage:
  python kv_replication.py --primary kv-contoso-iam-prod-pri \
                           --secondary kv-contoso-iam-prod-sec
  python kv_replication.py --primary ... --secondary ... --delta --dry-run

Environment variables:
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
  (or use managed identity — remove credential construction below)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Iterator

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.keyvault.secrets import SecretClient, SecretProperties

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── KV client factory ─────────────────────────────────────────────────────────

def _make_client(vault_name: str, use_managed_identity: bool = False) -> SecretClient:
    """Return an authenticated SecretClient for the given vault."""
    vault_url = f"https://{vault_name}.vault.azure.net"
    if use_managed_identity:
        credential = DefaultAzureCredential()
    else:
        credential = ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
        )
    return SecretClient(vault_url=vault_url, credential=credential)


# ── Secret enumeration ────────────────────────────────────────────────────────

def _list_enabled_secrets(client: SecretClient) -> Iterator[SecretProperties]:
    """Yield properties for all enabled (non-deleted) secrets in a vault."""
    for props in client.list_properties_of_secrets():
        if props.enabled:
            yield props


def _list_secrets_updated_since(
    client: SecretClient, since: datetime
) -> Iterator[SecretProperties]:
    """Yield properties for secrets updated after `since` (UTC)."""
    for props in _list_enabled_secrets(client):
        updated = props.updated_on
        if updated and updated.replace(tzinfo=timezone.utc) > since.replace(tzinfo=timezone.utc):
            yield props


# ── Replication logic ─────────────────────────────────────────────────────────

def replicate(
    primary: SecretClient,
    secondary: SecretClient,
    secret_names: list[str],
    dry_run: bool,
) -> dict:
    """
    Copy secrets from primary to secondary vault.
    Returns a report dict with counts and any errors.
    """
    report = {
        "replicated": [],
        "skipped": [],
        "errors": [],
        "dry_run": dry_run,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    for name in secret_names:
        try:
            # Fetch the current value from primary
            secret = primary.get_secret(name)

            if dry_run:
                logger.info("[DRY RUN] Would replicate: %s (version=%s)", name, secret.properties.version)
                report["replicated"].append({"name": name, "action": "dry_run"})
                continue

            # Check if secondary already has this exact version
            try:
                existing = secondary.get_secret(name)
                if existing.value == secret.value:
                    logger.debug("Secret already current in secondary: %s", name)
                    report["skipped"].append(name)
                    continue
            except Exception:
                pass  # Secret doesn't exist in secondary yet — create it

            # Set secret in secondary, preserving content type and tags
            secondary.set_secret(
                name,
                secret.value,
                content_type=secret.properties.content_type,
                tags=secret.properties.tags or {},
                expires_on=secret.properties.expires_on,
                not_before=secret.properties.not_before,
            )
            logger.info("Replicated: %s", name)
            report["replicated"].append({"name": name, "action": "written"})

        except Exception as exc:
            logger.error("Failed to replicate %s: %s", name, exc)
            report["errors"].append({"name": name, "error": str(exc)})

    return report


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replicate Entra IAM platform Key Vault secrets to DR vault"
    )
    parser.add_argument("--primary",   required=True, help="Primary Key Vault name")
    parser.add_argument("--secondary", required=True, help="Secondary (DR) Key Vault name")
    parser.add_argument("--delta",     action="store_true",
                        help="Only replicate secrets updated in the last 24h")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Show what would be replicated — no writes")
    parser.add_argument("--managed-identity", action="store_true",
                        help="Use managed identity instead of service principal env vars")
    parser.add_argument("--output", default=None,
                        help="Write replication report to this JSON file path")
    args = parser.parse_args()

    if not args.managed_identity:
        for var in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
            if not os.environ.get(var):
                logger.error("Missing required environment variable: %s", var)
                sys.exit(1)

    primary_client   = _make_client(args.primary,   args.managed_identity)
    secondary_client = _make_client(args.secondary, args.managed_identity)

    logger.info("Source vault:      %s", args.primary)
    logger.info("Destination vault: %s", args.secondary)

    if args.delta:
        since = datetime.now(tz=timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        logger.info("Delta mode: replicating secrets updated since %s", since.isoformat())
        secret_props = list(_list_secrets_updated_since(primary_client, since))
    else:
        logger.info("Full sync mode: replicating all enabled secrets")
        secret_props = list(_list_enabled_secrets(primary_client))

    secret_names = [p.name for p in secret_props]
    logger.info("Secrets to process: %d", len(secret_names))

    if not secret_names:
        logger.info("Nothing to replicate.")
        return

    report = replicate(primary_client, secondary_client, secret_names, dry_run=args.dry_run)

    # Summary
    logger.info("─" * 60)
    logger.info("Replicated: %d  |  Skipped: %d  |  Errors: %d",
                len(report["replicated"]), len(report["skipped"]), len(report["errors"]))

    if report["errors"]:
        for err in report["errors"]:
            logger.error("  ERROR: %s — %s", err["name"], err["error"])

    report_json = json.dumps(report, indent=2, default=str)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report_json)
        logger.info("Report written to %s", args.output)
    else:
        print(report_json)

    # Exit non-zero if any errors occurred so CI/CD catches failures
    if report["errors"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
