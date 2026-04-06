#!/usr/bin/env python3
"""
onboard_dependent_accounts.py — Bulk onboard dependent accounts from CSV via PVWA API.

Standalone script. Run with: python onboard_dependent_accounts.py --help

Requires: CyberArk-Common/cyberark_common.py
"""

from __future__ import annotations

import argparse
import csv
import pathlib
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

_HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(_HERE.parent / "CyberArk-Common"))

from cyberark_common import (  # noqa: E402
    CyberArkError,
    JsonDict,
    LogConfig,
    RestConfig,
    configure_logging,
    invoke_rest,
    join_exception_message,
    logoff,
    logon,
    write_log,
)

# ---------------------------------------------------------------------------
# Type aliases (PEP 695)
# ---------------------------------------------------------------------------
type OnboardStatus = Literal[
    "alreadyExists", "addedAccount", "addedAsPending", "updatedPending", "updatedAccount"
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class DependencyRow:
    """One row from the CSV file. Mirrors the PS dependency object."""
    username: str
    address: str
    platform_type: str
    domain: str
    dependency_name: str
    dependency_address: str
    dependency_type: str
    task_folder: str = ""


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------
def read_csv(
    path: pathlib.Path,
    *,
    delimiter: str | None = None,
) -> list[DependencyRow]:
    """
    Parse CSV with auto-detected delimiter (comma or tab).
    Header row must contain: username, address, platformType, domain,
    dependencyName, dependencyAddress, dependencyType, [taskFolder]
    """
    raw = path.read_text(encoding="utf-8-sig")

    if delimiter is None:
        try:
            dialect = csv.Sniffer().sniff(raw[:2048])
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = ","

    rows: list[DependencyRow] = []
    reader = csv.DictReader(raw.splitlines(), delimiter=delimiter)
    for row in reader:
        if not any(row.values()):
            continue
        rows.append(DependencyRow(
            username=row.get("username", row.get("userName", "")).strip(),
            address=row.get("address", "").strip(),
            platform_type=row.get("platformType", row.get("platform_type", "")).strip(),
            domain=row.get("domain", "").strip(),
            dependency_name=row.get("dependencyName", row.get("dependency_name", "")).strip(),
            dependency_address=row.get("dependencyAddress", row.get("dependency_address", "")).strip(),
            dependency_type=row.get("dependencyType", row.get("dependency_type", "")).strip(),
            task_folder=row.get("taskFolder", row.get("task_folder", "")).strip(),
        ))
    return rows


# ---------------------------------------------------------------------------
# Account search
# ---------------------------------------------------------------------------
def find_master_account(
    pvwa_url: str,
    logon_header: dict[str, str],
    username: str,
    address: str,
    safe_name: str = "",
    *,
    cfg: RestConfig | None = None,
) -> str | None:
    """
    Search accounts by keywords, return account ID or None.
    Mirrors Find-MasterAccount.
    """
    from cyberark_common import build_pvwa_urls, url_encode  # noqa: PLC0415
    urls = build_pvwa_urls(pvwa_url)
    keywords = f"{username} {address}"
    uri = f"{urls['accounts']}?search={url_encode(keywords)}"
    if safe_name:
        uri += f"&filter=safename eq {url_encode(safe_name)}"

    write_log(f"Accounts filter: {uri}", "Debug")
    try:
        response = invoke_rest("GET", uri, headers=logon_header, cfg=cfg)
        if not isinstance(response, dict) or response.get("count", 0) == 0:
            write_log(f"Account {username}@{address} not found.", "Debug")
            return None

        for item in response.get("value", []):
            if item.get("userName") == username and item.get("address") == address:
                write_log(f"Account {username}@{address} exists (id={item['id']}).", "Info")
                return str(item["id"])

        return None
    except CyberArkError as e:
        write_log(f"Error searching for master account: {e}", "Error")
        return None


# ---------------------------------------------------------------------------
# Account dependency onboarding
# ---------------------------------------------------------------------------
def add_account_dependency(
    pvwa_url: str,
    logon_header: dict[str, str],
    row: DependencyRow,
    master_id: str | None,
    *,
    cfg: RestConfig | None = None,
) -> tuple[bool, OnboardStatus | None]:
    """
    POST to /DiscoveredAccounts.
    Returns (success, status_string).
    Mirrors Add-AccountDependency.
    """
    from cyberark_common import build_pvwa_urls  # noqa: PLC0415

    urls = build_pvwa_urls(pvwa_url)
    discovery_uri = f"{urls['api']}/DiscoveredAccounts"
    accounts_uri = f"{urls['accounts']}"

    body: JsonDict = {
        "userName": row.username,
        "address": row.address,
        "domain": row.domain,
        "discoveryDateTime": int(datetime.now().timestamp()),
        "accountEnabled": True,
        "platformType": row.platform_type,
        "privileged": True,
        "Dependencies": [{
            "name": row.dependency_name,
            "address": row.dependency_address,
            "type": row.dependency_type,
            "taskFolder": row.task_folder,
        }],
    }

    # If master found, fetch details and merge corrections
    if master_id:
        try:
            details = invoke_rest(
                "GET",
                f"{accounts_uri}/{master_id}",
                headers=logon_header,
                cfg=cfg,
            )
            if isinstance(details, dict):
                if details.get("userName") and details["userName"] != row.username:
                    body["userName"] = details["userName"]
                if details.get("address") and details["address"] != row.address:
                    body["address"] = details["address"]
                    body["domain"] = details["address"]
        except CyberArkError as e:
            write_log(f"Could not fetch master account details: {e}", "Warning")

    try:
        result = invoke_rest("POST", discovery_uri, headers=logon_header, body=body, cfg=cfg)
    except CyberArkError as e:
        write_log(f"Error onboarding dependency {row.dependency_name}: {e}", "Error")
        return False, None

    if not isinstance(result, dict):
        write_log(f"No result returned for {row.dependency_name}", "Error")
        return False, None

    status = result.get("status")
    match status:
        case "alreadyExists":
            write_log(
                f"Account {row.username} or dependency {row.dependency_name} already exists.",
                "Info",
            )
            return False, "alreadyExists"
        case "addedAccount":
            write_log(
                f"{row.username}@{row.address} successfully onboarded to vault.",
                "Success",
            )
            return True, "addedAccount"
        case "addedAsPending":
            write_log(
                f"Dependency {row.dependency_name} successfully onboarded to Pending Accounts.",
                "Success",
            )
            return True, "addedAsPending"
        case "updatedPending":
            write_log(
                f"Dependency {row.dependency_name} successfully updated in Pending Accounts.",
                "Success",
            )
            return True, "updatedPending"
        case "updatedAccount":
            write_log(
                f"{row.username}@{row.address} successfully updated in the vault.",
                "Success",
            )
            return True, "updatedAccount"
        case None:
            write_log(f"No status returned for {row.dependency_name}", "Error")
            return False, None
        case other:
            write_log(f"Dependency {row.dependency_name} status: {other}", "Info")
            return False, other  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Main run function
# ---------------------------------------------------------------------------
def run(
    pvwa_url: str,
    csv_path: pathlib.Path,
    logon_header: dict[str, str],
    *,
    cfg: RestConfig | None = None,
) -> tuple[int, int]:
    """
    Process CSV rows, return (vaulted_count, total_count).
    """
    rows = read_csv(csv_path)
    total = len(rows)
    write_log(f"Starting to onboard {total} dependent accounts.", "Info", sub_header=True)

    counter = 0
    for account in rows:
        if not account.username:
            continue

        master_id: str | None = None
        try:
            master_id = find_master_account(
                pvwa_url, logon_header, account.username, account.address, cfg=cfg
            )
        except Exception as exc:
            write_log(
                f"Error searching for master account: {join_exception_message(exc)}",
                "Error",
            )

        success, _ = add_account_dependency(pvwa_url, logon_header, account, master_id, cfg=cfg)
        if success:
            counter += 1

    return counter, total


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bulk onboard dependent accounts from a CSV file via PVWA REST API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--pvwa-url", required=True, help="PVWA URL (e.g. https://pvwa.lab/PasswordVault)")
    parser.add_argument("--auth-type", default="cyberark", choices=["cyberark", "ldap", "radius"],
                        help="Authentication type (default: cyberark)")
    parser.add_argument("--username", help="PVWA username (prompted if omitted)")
    parser.add_argument("--password", help="PVWA password (prompted if omitted)")
    parser.add_argument("--logon-token", help="Pre-existing logon token (skips login/logoff)")
    parser.add_argument("--csv-path", required=True, help="Path to the CSV file")
    parser.add_argument("--disable-ssl-verify", action="store_true",
                        help="Disable SSL certificate verification (testing only)")
    parser.add_argument("--log-file", type=pathlib.Path, default=None,
                        help="Log file path (default: DependentAccounts_Onboard_Utility.log in script dir)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    log_file = args.log_file or (_HERE / "DependentAccounts_Onboard_Utility.log")
    configure_logging(LogConfig(log_file=log_file, debug=args.debug))
    cfg = RestConfig(verify_ssl=not args.disable_ssl_verify)

    write_log("Welcome to Accounts Dependencies Onboard Utility", "Info", header=True)

    # Auth
    owns_session = True
    if args.logon_token:
        logon_header: dict[str, str] = {"Authorization": args.logon_token}
        owns_session = False
    else:
        if not args.username:
            args.username = input("Enter your username: ")
        if not args.password:
            import getpass
            args.password = getpass.getpass("Enter your password: ")
        try:
            logon_header = logon(
                args.pvwa_url, args.username, args.password, args.auth_type, cfg=cfg
            )
        except Exception as exc:
            write_log(f"Error logging on: {join_exception_message(exc)}", "Error")
            sys.exit(1)

    try:
        csv_path = pathlib.Path(args.csv_path)
        if not csv_path.exists():
            write_log(f"CSV file not found: {csv_path}", "Error")
            sys.exit(1)

        count, total = run(args.pvwa_url, csv_path, logon_header, cfg=cfg)
    finally:
        if owns_session:
            logoff(args.pvwa_url, logon_header, cfg=cfg)

    write_log(
        f"Vaulted {count} out of {total} dependent accounts successfully.",
        "Info",
        footer=True,
    )


if __name__ == "__main__":
    main()
