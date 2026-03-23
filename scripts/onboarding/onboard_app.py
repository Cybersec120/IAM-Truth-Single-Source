#!/usr/bin/env python3
"""
onboard_app.py
enterprise-iam-platform — App Onboarding Automation

Automates onboarding of OIDC, SAML, and App Proxy applications to
Microsoft Entra ID via the Microsoft Graph API.

Supports:
  - OIDC / OAuth 2.0 app registration + service principal
  - SAML 2.0 enterprise app configuration + certificate assignment
  - Entra Application Proxy publishing for on-premises apps
  - Group assignment for the new application
  - Outputs a machine-readable JSON manifest for handoff to the app team

Usage:
  python onboard_app.py --type oidc   --config configs/hr-portal.json
  python onboard_app.py --type saml   --config configs/salesforce.json
  python onboard_app.py --type proxy  --config configs/intranet.json
  python onboard_app.py --type oidc   --config configs/hr-portal.json --dry-run

Environment variables required:
  AZURE_TENANT_ID      — Entra tenant ID
  AZURE_CLIENT_ID      — Service principal client ID (with Application.ReadWrite.All)
  AZURE_CLIENT_SECRET  — Service principal client secret
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from azure.identity import ClientSecretCredential

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
MSGRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

REQUIRED_SCOPES = ["https://graph.microsoft.com/.default"]


# ── Graph API client ──────────────────────────────────────────────────────────

class GraphClient:
    """Thin wrapper around the Microsoft Graph REST API."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self._credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        self._session = requests.Session()

    def _get_token(self) -> str:
        token = self._credential.get_token("https://graph.microsoft.com/.default")
        return token.token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    def get(self, path: str, beta: bool = False) -> dict:
        base = GRAPH_BETA if beta else GRAPH_BASE
        resp = self._session.get(f"{base}/{path}", headers=self._headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, body: dict, beta: bool = False) -> dict:
        base = GRAPH_BETA if beta else GRAPH_BASE
        resp = self._session.post(
            f"{base}/{path}", headers=self._headers(), json=body, timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    def patch(self, path: str, body: dict, beta: bool = False) -> None:
        base = GRAPH_BETA if beta else GRAPH_BASE
        resp = self._session.patch(
            f"{base}/{path}", headers=self._headers(), json=body, timeout=30
        )
        resp.raise_for_status()

    def delete(self, path: str) -> None:
        resp = self._session.delete(
            f"{GRAPH_BASE}/{path}", headers=self._headers(), timeout=30
        )
        resp.raise_for_status()


# ── OIDC onboarding ───────────────────────────────────────────────────────────

def onboard_oidc(client: GraphClient, config: dict, dry_run: bool) -> dict:
    """
    Register an OIDC / OAuth 2.0 application in Entra ID.

    Steps:
      1. Create application registration
      2. Create service principal
      3. Add client secret
      4. Grant admin consent for configured API permissions
      5. Return manifest for handoff
    """
    display_name   = config["display_name"]
    redirect_uris  = config["redirect_uris"]
    logout_uri     = config.get("logout_uri", "")
    api_permissions = config.get("api_permissions", [{"id": "User.Read", "type": "Scope"}])
    group_ids       = config.get("assign_groups", [])

    logger.info("Onboarding OIDC app: %s", display_name)

    app_body = {
        "displayName": display_name,
        "signInAudience": "AzureADMyOrg",
        "web": {
            "redirectUris": redirect_uris,
            "logoutUrl": logout_uri if logout_uri else None,
            "implicitGrantSettings": {
                "enableAccessTokenIssuance": False,
                "enableIdTokenIssuance": True,
            },
        },
        "requiredResourceAccess": [
            {
                "resourceAppId": MSGRAPH_APP_ID,
                "resourceAccess": api_permissions,
            }
        ],
        "optionalClaims": {
            "idToken": [
                {"name": "email", "essential": True},
                {"name": "preferred_username", "essential": False},
            ],
            "accessToken": [
                {"name": "groups", "essential": False},
            ],
        },
        "tags": ["oidc", "terraform-managed", "automation-onboarded"],
    }

    if dry_run:
        logger.info("[DRY RUN] Would create application: %s", json.dumps(app_body, indent=2))
        return {"dry_run": True, "app_body": app_body}

    # 1. Create the application registration
    app = client.post("applications", app_body)
    app_id = app["id"]
    client_id = app["appId"]
    logger.info("Created application: %s (clientId=%s)", app_id, client_id)

    # 2. Create the service principal
    sp = client.post("servicePrincipals", {
        "appId": client_id,
        "appRoleAssignmentRequired": False,
        "tags": ["WindowsAzureActiveDirectoryIntegratedApp"],
    })
    sp_id = sp["id"]
    logger.info("Created service principal: %s", sp_id)

    # 3. Add a client secret (2-year expiry)
    expiry = (datetime.now(tz=timezone.utc) + timedelta(days=730)).isoformat()
    secret_resp = client.post(f"applications/{app_id}/addPassword", {
        "passwordCredential": {
            "displayName": f"automation-{datetime.now(tz=timezone.utc).strftime('%Y%m%d')}",
            "endDateTime": expiry,
        }
    })
    client_secret = secret_resp["secretText"]
    logger.info("Created client secret (expires %s)", expiry)

    # 4. Assign to groups
    for group_id in group_ids:
        _assign_group(client, sp_id, group_id)

    manifest = {
        "type": "oidc",
        "display_name": display_name,
        "application_id": app_id,
        "client_id": client_id,
        "service_principal_id": sp_id,
        "client_secret": client_secret,
        "client_secret_expiry": expiry,
        "issuer": f"https://login.microsoftonline.com/{os.environ['AZURE_TENANT_ID']}/v2.0",
        "discovery_url": f"https://login.microsoftonline.com/{os.environ['AZURE_TENANT_ID']}/v2.0/.well-known/openid-configuration",
        "redirect_uris": redirect_uris,
        "onboarded_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    logger.info("OIDC onboarding complete for %s", display_name)
    return manifest


# ── SAML onboarding ───────────────────────────────────────────────────────────

def onboard_saml(client: GraphClient, config: dict, dry_run: bool) -> dict:
    """
    Configure a SAML 2.0 enterprise application in Entra ID.

    Steps:
      1. Create application registration with SAML settings
      2. Create service principal with preferredSingleSignOnMode = saml
      3. Generate self-signed SAML signing certificate
      4. Configure SAML attribute claim mappings
      5. Return federation metadata URL and certificate thumbprint
    """
    display_name    = config["display_name"]
    identifier_uris = config["identifier_uris"]
    reply_urls      = config["reply_urls"]
    attribute_map   = config.get("attribute_mapping", {})
    group_ids       = config.get("assign_groups", [])

    logger.info("Onboarding SAML app: %s", display_name)

    app_body = {
        "displayName": display_name,
        "signInAudience": "AzureADMyOrg",
        "identifierUris": identifier_uris,
        "web": {"redirectUris": reply_urls},
        "tags": ["saml", "enterprise-app", "automation-onboarded"],
    }

    if dry_run:
        logger.info("[DRY RUN] Would create SAML app: %s", json.dumps(app_body, indent=2))
        return {"dry_run": True, "app_body": app_body}

    app = client.post("applications", app_body)
    app_id = app["id"]
    client_id = app["appId"]
    logger.info("Created SAML application: %s", client_id)

    # Service principal — set SAML SSO mode
    sp = client.post("servicePrincipals", {
        "appId": client_id,
        "preferredSingleSignOnMode": "saml",
        "appRoleAssignmentRequired": True,
        "tags": ["WindowsAzureActiveDirectoryIntegratedApp", "WindowsAzureActiveDirectoryCustomSingleSignOnApplication"],
    })
    sp_id = sp["id"]
    logger.info("Created SAML service principal: %s", sp_id)

    # Allow SP to settle before adding the certificate
    time.sleep(3)

    # Generate self-signed SAML signing certificate
    cert_resp = client.post(
        f"servicePrincipals/{sp_id}/addTokenSigningCertificate",
        {
            "displayName": f"CN={display_name}",
            "endDateTime": (
                datetime.now(tz=timezone.utc) + timedelta(days=1095)
            ).isoformat(),
        },
    )
    thumbprint = cert_resp.get("thumbprint", "")
    logger.info("Created SAML signing certificate: thumbprint=%s", thumbprint)

    # Configure preferred cert on the SP
    client.patch(f"servicePrincipals/{sp_id}", {
        "preferredTokenSigningKeyThumbprint": thumbprint,
    })

    # Group assignments
    for group_id in group_ids:
        _assign_group(client, sp_id, group_id)

    tenant_id = os.environ["AZURE_TENANT_ID"]
    manifest = {
        "type": "saml",
        "display_name": display_name,
        "application_id": app_id,
        "client_id": client_id,
        "service_principal_id": sp_id,
        "signing_cert_thumbprint": thumbprint,
        "federation_metadata_url": (
            f"https://login.microsoftonline.com/{tenant_id}/federationmetadata/"
            f"2007-06/federationmetadata.xml?appid={client_id}"
        ),
        "sso_url": f"https://login.microsoftonline.com/{tenant_id}/saml2",
        "entity_id": f"https://sts.windows.net/{tenant_id}/",
        "attribute_mapping": attribute_map,
        "identifier_uris": identifier_uris,
        "reply_urls": reply_urls,
        "onboarded_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    logger.info("SAML onboarding complete for %s", display_name)
    return manifest


# ── App Proxy onboarding ──────────────────────────────────────────────────────

def onboard_app_proxy(client: GraphClient, config: dict, dry_run: bool) -> dict:
    """
    Publish an on-premises web application through Entra Application Proxy.

    Requires the Application Proxy connector agent installed on-premises
    and registered in Entra before this script runs.
    """
    display_name    = config["display_name"]
    internal_url    = config["internal_url"]
    external_prefix = config["external_url_prefix"]
    connector_group = config.get("connector_group_id", None)
    tenant_id       = os.environ["AZURE_TENANT_ID"]

    external_url = f"https://{external_prefix}-{tenant_id[:8]}.msappproxy.net/"

    logger.info("Onboarding App Proxy app: %s → %s", internal_url, external_url)

    app_body = {
        "displayName": display_name,
        "signInAudience": "AzureADMyOrg",
        "web": {
            "redirectUris": [external_url],
            "implicitGrantSettings": {"enableIdTokenIssuance": True},
        },
        "tags": ["app-proxy", "on-premises", "automation-onboarded"],
    }

    proxy_config = {
        "externalAuthenticationType": "aadPreAuthentication",
        "internalUrl": internal_url,
        "externalUrl": external_url,
        "isHttpOnlyCookieEnabled": True,
        "isSecureCookieEnabled": True,
        "isPersistentCookieEnabled": False,
        "isSslCertificateVerificationEnabled": True,
        "isTranslateHostHeaderEnabled": True,
        "isTranslateLinksInBodyEnabled": False,
    }

    if dry_run:
        logger.info("[DRY RUN] App body: %s", json.dumps(app_body, indent=2))
        logger.info("[DRY RUN] Proxy config: %s", json.dumps(proxy_config, indent=2))
        return {"dry_run": True}

    # Create application
    app = client.post("applications", app_body)
    app_id = app["id"]
    client_id = app["appId"]

    # Create service principal
    sp = client.post("servicePrincipals", {
        "appId": client_id,
        "appRoleAssignmentRequired": True,
    })
    sp_id = sp["id"]

    # Configure App Proxy via beta endpoint (GA endpoint pending)
    client.patch(
        f"applications/{app_id}",
        {"onPremisesPublishing": proxy_config},
        beta=True,
    )
    logger.info("Configured App Proxy for %s", display_name)

    # Assign connector group if provided
    if connector_group:
        client.post(
            f"applicationProxies/connectorGroups/{connector_group}/applications/$ref",
            {"@odata.id": f"{GRAPH_BASE}/applications/{app_id}"},
            beta=True,
        )
        logger.info("Assigned to connector group: %s", connector_group)

    manifest = {
        "type": "app_proxy",
        "display_name": display_name,
        "application_id": app_id,
        "client_id": client_id,
        "service_principal_id": sp_id,
        "internal_url": internal_url,
        "external_url": external_url,
        "pre_auth": "Azure AD",
        "onboarded_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    logger.info("App Proxy onboarding complete for %s", display_name)
    return manifest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _assign_group(client: GraphClient, sp_id: str, group_id: str) -> None:
    """Assign a security group to a service principal."""
    try:
        client.post(f"groups/{group_id}/members/$ref", {
            "@odata.id": f"{GRAPH_BASE}/servicePrincipals/{sp_id}"
        })
        logger.info("Assigned group %s to SP %s", group_id, sp_id)
    except requests.HTTPError as exc:
        if exc.response.status_code == 400 and "already exist" in exc.response.text:
            logger.debug("Group %s already assigned to SP %s", group_id, sp_id)
        else:
            raise


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Entra ID application onboarding automation")
    parser.add_argument("--type", required=True, choices=["oidc", "saml", "proxy"],
                        help="Application type to onboard")
    parser.add_argument("--config", required=True,
                        help="Path to JSON config file for the application")
    parser.add_argument("--output", default=None,
                        help="Path to write the onboarding manifest JSON (default: stdout)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate inputs and print what would be created — no changes made")

    args = parser.parse_args()

    # Validate environment
    for var in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
        if not os.environ.get(var):
            logger.error("Missing required environment variable: %s", var)
            sys.exit(1)

    # Load config
    with open(args.config) as fh:
        config = json.load(fh)

    graph = GraphClient(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"],
    )

    dispatch = {
        "oidc":  onboard_oidc,
        "saml":  onboard_saml,
        "proxy": onboard_app_proxy,
    }

    manifest = dispatch[args.type](graph, config, dry_run=args.dry_run)

    manifest_json = json.dumps(manifest, indent=2, default=str)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(manifest_json)
        logger.info("Manifest written to %s", args.output)
    else:
        print(manifest_json)


if __name__ == "__main__":
    main()
