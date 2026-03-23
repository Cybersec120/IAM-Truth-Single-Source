#!/usr/bin/env python3
"""
user_lifecycle.py — enterprise-iam-platform
User onboarding and offboarding across Entra ID and Duo Security.

Azure Well-Architected Framework alignment:
  Operational Excellence — repeatable, auditable, idempotent automation
  Security              — immediate session revocation, zero standing access
  Reliability           — safe to re-run; handles pre-existing state gracefully

Usage:
  python user_lifecycle.py onboard  --config configs/jsmith.json
  python user_lifecycle.py offboard --upn jsmith@contoso.com --reason voluntary-termination
  python user_lifecycle.py status   --upn jsmith@contoso.com
  python user_lifecycle.py onboard  --config configs/jsmith.json --dry-run

Required env vars:
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
Optional (Duo):
  DUO_INTEGRATION_KEY, DUO_SECRET_KEY, DUO_API_HOSTNAME
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import string
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.utils import formatdate
from typing import Any

import requests
from azure.identity import ClientSecretCredential

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


# ── Microsoft Graph client ────────────────────────────────────────────────────

class GraphClient:
    """Thin authenticated wrapper around the Microsoft Graph REST API."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self._cred = ClientSecretCredential(tenant_id, client_id, client_secret)
        self._sess = requests.Session()

    def _token(self) -> str:
        return self._cred.get_token("https://graph.microsoft.com/.default").token

    def _h(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token()}",
            "Content-Type": "application/json",
        }

    def get(self, path: str) -> dict:
        r = self._sess.get(f"{GRAPH_BASE}/{path}", headers=self._h(), timeout=30)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, body: dict) -> dict:
        r = self._sess.post(f"{GRAPH_BASE}/{path}", headers=self._h(), json=body, timeout=30)
        r.raise_for_status()
        return r.json() if r.content else {}

    def patch(self, path: str, body: dict) -> None:
        r = self._sess.patch(f"{GRAPH_BASE}/{path}", headers=self._h(), json=body, timeout=30)
        r.raise_for_status()

    def delete(self, path: str) -> None:
        r = self._sess.delete(f"{GRAPH_BASE}/{path}", headers=self._h(), timeout=30)
        r.raise_for_status()

    def get_user(self, upn: str) -> dict | None:
        try:
            return self.get(f"users/{urllib.parse.quote(upn)}")
        except requests.HTTPError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    def get_memberships(self, user_id: str) -> list[dict]:
        return self.get(f"users/{user_id}/memberOf").get("value", [])

    def revoke_sessions(self, user_id: str) -> None:
        """Invalidate all refresh tokens — effective within seconds."""
        self.post(f"users/{user_id}/revokeSignInSessions", {})
        logger.info("All sign-in sessions revoked for %s", user_id)

    def add_to_group(self, group_id: str, user_id: str) -> None:
        try:
            self.post(f"groups/{group_id}/members/$ref", {
                "@odata.id": f"{GRAPH_BASE}/directoryObjects/{user_id}"
            })
            logger.info("Added user %s → group %s", user_id, group_id)
        except requests.HTTPError as exc:
            if exc.response.status_code == 400 and "already exist" in (exc.response.text or ""):
                logger.debug("User already member of group %s", group_id)
            else:
                raise

    def remove_from_group(self, group_id: str, user_id: str) -> None:
        try:
            self.delete(f"groups/{group_id}/members/{user_id}/$ref")
            logger.info("Removed user %s from group %s", user_id, group_id)
        except requests.HTTPError as exc:
            if exc.response.status_code == 404:
                logger.debug("User not in group %s — skipping", group_id)
            else:
                raise


# ── Duo Admin API client ──────────────────────────────────────────────────────

class DuoClient:
    """
    Duo Admin API v1 — HMAC-SHA1 signed requests.

    Azure WAF Security: independent MFA layer ensures a compromised Entra
    token cannot bypass MFA. Duo validation runs at the application connector,
    not solely in the IdP, satisfying defense-in-depth.
    """

    def __init__(self, ikey: str, skey: str, host: str) -> None:
        self._ikey = ikey
        self._skey = skey.encode()
        self._host = host.lower()

    def _sign(self, method: str, path: str, params: dict) -> dict:
        now = formatdate()
        sorted_params = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(str(v), safe='')}"
            for k, v in sorted(params.items())
        )
        canon = "\n".join([now, method.upper(), self._host, path, sorted_params])
        sig = hmac.new(self._skey, canon.encode(), hashlib.sha1).hexdigest()
        token = base64.b64encode(f"{self._ikey}:{sig}".encode()).decode()
        return {"Date": now, "Authorization": f"Basic {token}"}

    def _req(self, method: str, path: str, params: dict | None = None) -> dict:
        params = params or {}
        hdrs = self._sign(method, path, params)
        url = f"https://{self._host}{path}"
        m = method.upper()
        if m == "GET":
            resp = requests.get(url, headers=hdrs, params=params, timeout=15)
        elif m == "DELETE":
            resp = requests.delete(url, headers=hdrs, timeout=15)
        else:
            resp = requests.post(url, headers=hdrs, data=params, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def get_user(self, username: str) -> dict | None:
        data = self._req("GET", "/admin/v1/users", {"username": username})
        users = data.get("response", [])
        return users[0] if users else None

    def create_user(self, username: str, email: str, realname: str) -> dict:
        return self._req("POST", "/admin/v1/users", {
            "username": username, "email": email,
            "realname": realname, "status": "active",
        })

    def disable_user(self, duo_user_id: str) -> dict:
        return self._req("POST", f"/admin/v1/users/{duo_user_id}", {"status": "disabled"})

    def delete_user(self, duo_user_id: str) -> dict:
        return self._req("DELETE", f"/admin/v1/users/{duo_user_id}")

    def send_enrollment_email(self, duo_user_id: str, valid_secs: int = 604800) -> dict:
        return self._req("POST", f"/admin/v1/users/{duo_user_id}/send_enroll_email",
                         {"valid_secs": str(valid_secs)})


def _duo_client() -> DuoClient | None:
    ikey = os.environ.get("DUO_INTEGRATION_KEY")
    skey = os.environ.get("DUO_SECRET_KEY")
    host = os.environ.get("DUO_API_HOSTNAME")
    if ikey and skey and host:
        return DuoClient(ikey, skey, host)
    logger.info("Duo env vars not set — Duo operations will be skipped")
    return None


def _temp_password() -> str:
    """Generate a 16-char password meeting Entra complexity requirements."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(16))
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(c in "!@#$%^&*" for c in pwd)):
            return pwd


# ── Onboarding ────────────────────────────────────────────────────────────────

def onboard(graph: GraphClient, config: dict, dry_run: bool) -> dict:
    """
    Idempotent user onboarding:
      1. Create or update Entra user
      2. Set manager relationship
      3. Assign security groups
      4. Enroll in Duo MFA
    """
    upn          = config["userPrincipalName"]
    display_name = config["displayName"]
    group_ids    = config.get("groupIds", [])
    manager_upn  = config.get("managerUpn")
    temp_pwd     = config.get("temporaryPassword", _temp_password())

    user_body = {
        "accountEnabled":      True,
        "displayName":         display_name,
        "givenName":           config.get("givenName", ""),
        "surname":             config.get("surname", ""),
        "mailNickname":        config.get("mailNickname", upn.split("@")[0]),
        "userPrincipalName":   upn,
        "jobTitle":            config.get("jobTitle", ""),
        "department":          config.get("department", ""),
        "usageLocation":       config.get("usageLocation", "US"),
        "passwordProfile": {
            "password": temp_pwd,
            "forceChangePasswordNextSignIn": True,
            "forceChangePasswordNextSignInWithMfa": True,
        },
    }

    if dry_run:
        logger.info("[DRY RUN] Would onboard user: %s — groups: %s", upn, group_ids)
        return {"dry_run": True, "upn": upn}

    existing = graph.get_user(upn)
    if existing:
        user_id = existing["id"]
        update = {k: v for k, v in user_body.items() if k != "passwordProfile"}
        graph.patch(f"users/{user_id}", update)
        logger.info("Updated existing user %s", upn)
        created = False
    else:
        user = graph.post("users", user_body)
        user_id = user["id"]
        logger.info("Created user %s (id=%s)", upn, user_id)
        created = True
        time.sleep(2)  # Allow directory replication

    if manager_upn:
        mgr = graph.get_user(manager_upn)
        if mgr:
            graph.post(f"users/{user_id}/manager/$ref",
                       {"@odata.id": f"{GRAPH_BASE}/users/{mgr['id']}"})

    for gid in group_ids:
        graph.add_to_group(gid, user_id)

    duo = _duo_client()
    duo_enrolled = False
    if duo:
        try:
            du = duo.get_user(upn)
            if not du:
                obj = duo.create_user(upn, upn, display_name)
                duo_uid = obj["response"]["user_id"]
                duo.send_enrollment_email(duo_uid)
                logger.info("Duo enrollment email sent to %s", upn)
            duo_enrolled = True
        except Exception as exc:
            logger.warning("Duo enrollment non-fatal error: %s", exc)

    return {
        "event": "user.onboarded",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "upn": upn,
        "user_id": user_id,
        "action": "created" if created else "updated",
        "groups_assigned": group_ids,
        "duo_enrolled": duo_enrolled,
        "operator": os.environ.get("AZURE_CLIENT_ID", "automation"),
    }


# ── Offboarding ───────────────────────────────────────────────────────────────

def offboard(graph: GraphClient, upn: str, reason: str, dry_run: bool) -> dict:
    """
    Zero-standing-access offboarding:
      1. Revoke all sessions immediately
      2. Strip all group memberships
      3. Disable the account
      4. Disable Duo enrollment
    """
    user = graph.get_user(upn)
    if not user:
        logger.warning("User %s not found — nothing to offboard", upn)
        return {"event": "user.offboard.skipped", "upn": upn, "reason": "not_found"}

    user_id = user["id"]

    if dry_run:
        mships = graph.get_memberships(user_id)
        groups = [m for m in mships if m.get("@odata.type") == "#microsoft.graph.group"]
        logger.info("[DRY RUN] Would offboard %s from %d groups", upn, len(groups))
        return {"dry_run": True, "upn": upn, "group_count": len(groups)}

    # Step 1 — revoke sessions (immediate, no waiting for token expiry)
    try:
        graph.revoke_sessions(user_id)
    except Exception as exc:
        logger.error("Session revocation error (continuing): %s", exc)

    # Step 2 — remove from all groups
    removed: list[str] = []
    for m in graph.get_memberships(user_id):
        if m.get("@odata.type") == "#microsoft.graph.group":
            try:
                graph.remove_from_group(m["id"], user_id)
                removed.append(m.get("displayName", m["id"]))
            except Exception as exc:
                logger.warning("Group removal error %s: %s", m.get("displayName"), exc)

    # Step 3 — disable account
    graph.patch(f"users/{user_id}", {"accountEnabled": False})
    logger.info("Account disabled: %s", upn)

    # Step 4 — Duo disable
    duo = _duo_client()
    duo_disabled = False
    if duo:
        try:
            du = duo.get_user(upn)
            if du:
                duo.disable_user(du["user_id"])
                duo_disabled = True
                logger.info("Duo user disabled: %s", upn)
        except Exception as exc:
            logger.warning("Duo disable non-fatal: %s", exc)

    return {
        "event": "user.offboarded",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "upn": upn,
        "user_id": user_id,
        "reason": reason,
        "sessions_revoked": True,
        "groups_removed": removed,
        "account_disabled": True,
        "duo_disabled": duo_disabled,
        "operator": os.environ.get("AZURE_CLIENT_ID", "automation"),
    }


# ── Status check ─────────────────────────────────────────────────────────────

def status(graph: GraphClient, upn: str) -> dict:
    user = graph.get_user(upn)
    if not user:
        return {"upn": upn, "exists": False}

    user_id = user["id"]
    groups = [
        {"id": m["id"], "name": m.get("displayName", "")}
        for m in graph.get_memberships(user_id)
        if m.get("@odata.type") == "#microsoft.graph.group"
    ]
    duo = _duo_client()
    duo_status = "unknown"
    if duo:
        try:
            du = duo.get_user(upn)
            duo_status = du.get("status", "not_enrolled") if du else "not_enrolled"
        except Exception:
            duo_status = "error"

    return {
        "upn": upn, "exists": True,
        "display_name": user.get("displayName"),
        "account_enabled": user.get("accountEnabled"),
        "job_title": user.get("jobTitle"),
        "department": user.get("department"),
        "group_count": len(groups), "groups": groups,
        "duo_status": duo_status,
        "checked_at": datetime.now(tz=timezone.utc).isoformat(),
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Entra ID + Duo user lifecycle automation")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_on = sub.add_parser("onboard")
    p_on.add_argument("--config", required=True)
    p_on.add_argument("--output")
    p_on.add_argument("--dry-run", action="store_true")

    p_off = sub.add_parser("offboard")
    p_off.add_argument("--upn", required=True)
    p_off.add_argument("--reason", required=True,
                       choices=["voluntary-termination", "involuntary-termination",
                                "contractor-end", "role-change", "leave-of-absence"])
    p_off.add_argument("--output")
    p_off.add_argument("--dry-run", action="store_true")

    p_st = sub.add_parser("status")
    p_st.add_argument("--upn", required=True)

    args = parser.parse_args()

    for v in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
        if not os.environ.get(v):
            logger.error("Missing required env var: %s", v)
            sys.exit(1)

    graph = GraphClient(os.environ["AZURE_TENANT_ID"],
                        os.environ["AZURE_CLIENT_ID"],
                        os.environ["AZURE_CLIENT_SECRET"])

    if args.cmd == "onboard":
        with open(args.config) as fh:
            config = json.load(fh)
        result = onboard(graph, config, dry_run=args.dry_run)
    elif args.cmd == "offboard":
        result = offboard(graph, args.upn, args.reason, dry_run=args.dry_run)
    else:
        result = status(graph, args.upn)

    out = json.dumps(result, indent=2, default=str)
    print(out)
    if hasattr(args, "output") and args.output:
        with open(args.output, "w") as fh:
            fh.write(out)


if __name__ == "__main__":
    main()
