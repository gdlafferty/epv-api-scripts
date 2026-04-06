"""
epv_api_common.py — CyberArk EPV API CRUD wrappers for Python 3.14.

Stateless functions that mirror the PowerShell EPV-API-Common module.
All functions accept pvwa_url and logon_header explicitly — no session state stored here.

Requires: CyberArk-Common/cyberark_common.py
"""

from __future__ import annotations

import pathlib
import sys
from dataclasses import dataclass, field

_HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(_HERE.parent / "CyberArk-Common"))

from cyberark_common import (  # noqa: E402
    CyberArkRestError,
    JsonDict,
    RestConfig,
    build_pvwa_urls,
    invoke_rest,
    url_encode,
    write_log,
)

# ---------------------------------------------------------------------------
# Type aliases (PEP 695)
# ---------------------------------------------------------------------------
type AccountId = str
type SafeName = str
type MemberName = str
type UserId = str
type PlatformId = str


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class AccountFilter:
    search: str = ""
    safe_name: SafeName = ""
    sort: str = ""
    offset: int = 0
    limit: int = 0

    def to_query_string(self) -> str:
        parts: list[str] = []
        if self.search:
            parts.append(f"search={url_encode(self.search)}")
        if self.safe_name:
            parts.append(f"filter=safename eq {url_encode(self.safe_name)}")
        if self.sort:
            parts.append(f"sort={url_encode(self.sort)}")
        if self.offset:
            parts.append(f"offset={self.offset}")
        if self.limit:
            parts.append(f"limit={self.limit}")
        return "&".join(parts)


@dataclass(slots=True)
class SafePermissions:
    use_accounts: bool = False
    retrieve_accounts: bool = False
    list_accounts: bool = False
    add_accounts: bool = False
    update_account_content: bool = False
    update_account_properties: bool = False
    initialize_cpm_account_management_operations: bool = False
    specify_next_account_content: bool = False
    rename_accounts: bool = False
    delete_accounts: bool = False
    unlock_accounts: bool = False
    manage_safe: bool = False
    manage_safe_members: bool = False
    backup_safe: bool = False
    view_audit_log: bool = False
    view_safe_members: bool = False
    create_folders: bool = False
    delete_folders: bool = False
    move_accounts_and_folders: bool = False
    request_and_confirm_access: bool = False
    access_without_confirmation: bool = False

    def to_dict(self) -> JsonDict:
        return {
            "useAccounts": self.use_accounts,
            "retrieveAccounts": self.retrieve_accounts,
            "listAccounts": self.list_accounts,
            "addAccounts": self.add_accounts,
            "updateAccountContent": self.update_account_content,
            "updateAccountProperties": self.update_account_properties,
            "initializeCPMAccountManagementOperations": self.initialize_cpm_account_management_operations,
            "specifyNextAccountContent": self.specify_next_account_content,
            "renameAccounts": self.rename_accounts,
            "deleteAccounts": self.delete_accounts,
            "unlockAccounts": self.unlock_accounts,
            "manageSafe": self.manage_safe,
            "manageSafeMembers": self.manage_safe_members,
            "backupSafe": self.backup_safe,
            "viewAuditLog": self.view_audit_log,
            "viewSafeMembers": self.view_safe_members,
            "createFolders": self.create_folders,
            "deleteFolders": self.delete_folders,
            "moveAccountsAndFolders": self.move_accounts_and_folders,
            "requestAndConfirmAccess": self.request_and_confirm_access,
            "accessWithoutConfirmation": self.access_without_confirmation,
        }


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------
def new_session(
    pvwa_url: str,
    username: str,
    password: str,
    auth_type: str = "cyberark",
    *,
    pcloud_subdomain: str | None = None,
    otp: str | None = None,
    concurrent_session: bool = True,
    cfg: RestConfig | None = None,
) -> dict[str, str]:
    """
    Wraps cyberark_common.logon; handles PCloud subdomain URL construction.
    Returns logon header dict.
    """
    # Import here to avoid circular at module level
    from cyberark_common import logon, AuthType  # noqa: PLC0415

    if pcloud_subdomain:
        pvwa_url = f"https://{pcloud_subdomain}.privilegecloud.cyberark.cloud/PasswordVault"

    return logon(
        pvwa_url,
        username,
        password,
        auth_type,  # type: ignore[arg-type]
        otp=otp,
        concurrent_session=concurrent_session,
        cfg=cfg,
    )


# ---------------------------------------------------------------------------
# Account operations
# ---------------------------------------------------------------------------
def get_accounts(
    pvwa_url: str,
    logon_header: dict[str, str],
    *,
    filters: AccountFilter | None = None,
    cfg: RestConfig | None = None,
) -> list[JsonDict]:
    """Retrieve accounts matching optional filters. Returns list of account dicts."""
    urls = build_pvwa_urls(pvwa_url)
    uri = urls["accounts"]
    if filters:
        qs = filters.to_query_string()
        if qs:
            uri = f"{uri}?{qs}"

    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if isinstance(response, dict):
        return response.get("value", [])  # type: ignore[return-value]
    return []


def get_account(
    pvwa_url: str,
    logon_header: dict[str, str],
    account_id: AccountId,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Retrieve a single account by ID."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['accounts']}/{account_id}"
    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def create_account(
    pvwa_url: str,
    logon_header: dict[str, str],
    account: JsonDict,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Create a new account. Returns the created account dict."""
    urls = build_pvwa_urls(pvwa_url)
    uri = urls["accounts"]
    response = invoke_rest("POST", uri, headers=logon_header, body=account, cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def update_account(
    pvwa_url: str,
    logon_header: dict[str, str],
    account_id: AccountId,
    patches: list[dict[str, str]],
    cfg: RestConfig | None = None,
) -> JsonDict:
    """
    Update account properties via JSON Patch array.
    Each patch dict: {"op": "replace", "path": "/address", "value": "new-value"}
    """
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['accounts']}/{account_id}"
    response = invoke_rest("PATCH", uri, headers=logon_header, body=patches, cfg=cfg)  # type: ignore[arg-type]
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def delete_account(
    pvwa_url: str,
    logon_header: dict[str, str],
    account_id: AccountId,
    cfg: RestConfig | None = None,
) -> None:
    """Delete an account by ID."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['accounts']}/{account_id}"
    invoke_rest("DELETE", uri, headers=logon_header, cfg=cfg)
    write_log(f"Account {account_id} deleted.", "Info")


def get_account_password(
    pvwa_url: str,
    logon_header: dict[str, str],
    account_id: AccountId,
    *,
    reason: str = "",
    ticketing_system: str = "",
    ticket_id: str = "",
    cfg: RestConfig | None = None,
) -> str:
    """Retrieve the current password for an account."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['accounts']}/{account_id}/Password/Retrieve"
    body: JsonDict = {}
    if reason:
        body["reason"] = reason
    if ticketing_system:
        body["TicketingSystemName"] = ticketing_system
    if ticket_id:
        body["TicketId"] = ticket_id
    response = invoke_rest("POST", uri, headers=logon_header, body=body, cfg=cfg)
    if isinstance(response, str):
        return response.strip('"')
    raise CyberArkRestError(0, "Unexpected response type for password retrieval", uri)


def set_account_password(
    pvwa_url: str,
    logon_header: dict[str, str],
    account_id: AccountId,
    new_password: str,
    cfg: RestConfig | None = None,
) -> None:
    """Set a new password for an account."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['accounts']}/{account_id}/Password/Update"
    invoke_rest("POST", uri, headers=logon_header, body={"NewCredentials": new_password}, cfg=cfg)
    write_log(f"Password updated for account {account_id}.", "Info")


# ---------------------------------------------------------------------------
# Safe operations
# ---------------------------------------------------------------------------
def get_safes(
    pvwa_url: str,
    logon_header: dict[str, str],
    *,
    search: str = "",
    cfg: RestConfig | None = None,
) -> list[JsonDict]:
    """Retrieve all safes, optionally filtered by search string."""
    urls = build_pvwa_urls(pvwa_url)
    uri = urls["safes"]
    if search:
        uri = f"{uri}?search={url_encode(search)}"
    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if isinstance(response, dict):
        return response.get("value", [])  # type: ignore[return-value]
    return []


def get_safe(
    pvwa_url: str,
    logon_header: dict[str, str],
    safe_name: SafeName,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Retrieve a single safe by name."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['safes']}/{url_encode(safe_name)}"
    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def create_safe(
    pvwa_url: str,
    logon_header: dict[str, str],
    safe: JsonDict,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Create a new safe. Returns the created safe dict."""
    urls = build_pvwa_urls(pvwa_url)
    uri = urls["safes"]
    response = invoke_rest("POST", uri, headers=logon_header, body=safe, cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def update_safe(
    pvwa_url: str,
    logon_header: dict[str, str],
    safe_name: SafeName,
    updates: JsonDict,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Update safe properties."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['safes']}/{url_encode(safe_name)}"
    response = invoke_rest("PUT", uri, headers=logon_header, body=updates, cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def export_safe(
    pvwa_url: str,
    logon_header: dict[str, str],
    safe_name: SafeName,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Export safe data."""
    return get_safe(pvwa_url, logon_header, safe_name, cfg)


# ---------------------------------------------------------------------------
# Safe member operations
# ---------------------------------------------------------------------------
def get_safe_members(
    pvwa_url: str,
    logon_header: dict[str, str],
    safe_name: SafeName,
    cfg: RestConfig | None = None,
) -> list[JsonDict]:
    """Retrieve all members of a safe."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['safes']}/{url_encode(safe_name)}/Members"
    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if isinstance(response, dict):
        return response.get("value", [])  # type: ignore[return-value]
    return []


def add_safe_member(
    pvwa_url: str,
    logon_header: dict[str, str],
    safe_name: SafeName,
    member: JsonDict,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Add a member to a safe."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['safes']}/{url_encode(safe_name)}/Members"
    response = invoke_rest("POST", uri, headers=logon_header, body=member, cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def set_safe_member(
    pvwa_url: str,
    logon_header: dict[str, str],
    safe_name: SafeName,
    member_name: MemberName,
    perms: SafePermissions,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Update permissions for an existing safe member."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['safes']}/{url_encode(safe_name)}/Members/{url_encode(member_name)}"
    response = invoke_rest("PUT", uri, headers=logon_header, body=perms.to_dict(), cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def remove_safe_member(
    pvwa_url: str,
    logon_header: dict[str, str],
    safe_name: SafeName,
    member_name: MemberName,
    cfg: RestConfig | None = None,
) -> None:
    """Remove a member from a safe."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['safes']}/{url_encode(safe_name)}/Members/{url_encode(member_name)}"
    invoke_rest("DELETE", uri, headers=logon_header, cfg=cfg)
    write_log(f"Member {member_name} removed from safe {safe_name}.", "Info")


# ---------------------------------------------------------------------------
# User / Group operations
# ---------------------------------------------------------------------------
def get_vault_users(
    pvwa_url: str,
    logon_header: dict[str, str],
    *,
    search: str = "",
    cfg: RestConfig | None = None,
) -> list[JsonDict]:
    """Retrieve vault users."""
    urls = build_pvwa_urls(pvwa_url)
    uri = urls["users"]
    if search:
        uri = f"{uri}?search={url_encode(search)}"
    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if isinstance(response, dict):
        return response.get("Users", response.get("value", []))  # type: ignore[return-value]
    return []


def add_vault_user(
    pvwa_url: str,
    logon_header: dict[str, str],
    user: JsonDict,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Create a new vault user."""
    urls = build_pvwa_urls(pvwa_url)
    uri = urls["users"]
    response = invoke_rest("POST", uri, headers=logon_header, body=user, cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def remove_vault_user(
    pvwa_url: str,
    logon_header: dict[str, str],
    user_id: UserId,
    cfg: RestConfig | None = None,
) -> None:
    """Delete a vault user by ID."""
    urls = build_pvwa_urls(pvwa_url)
    uri = f"{urls['users']}/{user_id}"
    invoke_rest("DELETE", uri, headers=logon_header, cfg=cfg)
    write_log(f"Vault user {user_id} removed.", "Info")


def get_identity_users(
    pvwa_url: str,
    logon_header: dict[str, str],
    *,
    search: str = "",
    cfg: RestConfig | None = None,
) -> list[JsonDict]:
    """Retrieve Identity users."""
    base = build_pvwa_urls(pvwa_url)["api"]
    uri = f"{base}/Users?userType=EPVUser"
    if search:
        uri += f"&search={url_encode(search)}"
    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if isinstance(response, dict):
        return response.get("Users", response.get("value", []))  # type: ignore[return-value]
    return []


def get_identity_groups(
    pvwa_url: str,
    logon_header: dict[str, str],
    *,
    search: str = "",
    cfg: RestConfig | None = None,
) -> list[JsonDict]:
    """Retrieve Identity groups (vault groups)."""
    base = build_pvwa_urls(pvwa_url)["api"]
    uri = f"{base}/UserGroups"
    if search:
        uri += f"?search={url_encode(search)}"
    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if isinstance(response, dict):
        return response.get("value", [])  # type: ignore[return-value]
    return []


# ---------------------------------------------------------------------------
# Discovery operations
# ---------------------------------------------------------------------------
def get_discovered_accounts(
    pvwa_url: str,
    logon_header: dict[str, str],
    *,
    filter_expr: str = "",
    cfg: RestConfig | None = None,
) -> list[JsonDict]:
    """Retrieve discovered accounts."""
    urls = build_pvwa_urls(pvwa_url)
    uri = urls["discovered_accounts"]
    if filter_expr:
        uri = f"{uri}?filter={url_encode(filter_expr)}"
    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if isinstance(response, dict):
        return response.get("value", [])  # type: ignore[return-value]
    return []


def add_discovered_account(
    pvwa_url: str,
    logon_header: dict[str, str],
    account: JsonDict,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Add a discovered account."""
    urls = build_pvwa_urls(pvwa_url)
    uri = urls["discovered_accounts"]
    response = invoke_rest("POST", uri, headers=logon_header, body=account, cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def start_discovered_account_onboard(
    pvwa_url: str,
    logon_header: dict[str, str],
    account_id: AccountId,
    safe_name: SafeName,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Onboard a discovered account into a safe."""
    base = build_pvwa_urls(pvwa_url)["api"]
    uri = f"{base}/DiscoveredAccounts/{account_id}/onboard"
    response = invoke_rest(
        "POST",
        uri,
        headers=logon_header,
        body={"safeName": safe_name},
        cfg=cfg,
    )
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


# ---------------------------------------------------------------------------
# System health / Platform
# ---------------------------------------------------------------------------
def get_system_health(
    pvwa_url: str,
    logon_header: dict[str, str],
    cfg: RestConfig | None = None,
) -> JsonDict:
    """Retrieve component monitoring summary."""
    urls = build_pvwa_urls(pvwa_url)
    uri = urls["health"]
    response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
    if not isinstance(response, dict):
        raise CyberArkRestError(0, "Unexpected response type", uri)
    return response


def get_platform(
    pvwa_url: str,
    logon_header: dict[str, str],
    platform_id: PlatformId = "",
    *,
    system_type: str = "",
    cfg: RestConfig | None = None,
) -> list[JsonDict]:
    """Retrieve platforms, optionally filtered."""
    urls = build_pvwa_urls(pvwa_url)
    if platform_id:
        uri = f"{urls['platforms']}/{url_encode(platform_id)}"
        response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
        return [response] if isinstance(response, dict) else []
    else:
        uri = urls["platforms"]
        if system_type:
            uri = f"{uri}?systemType={url_encode(system_type)}"
        response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
        if isinstance(response, dict):
            return response.get("value", [])  # type: ignore[return-value]
        return []
