#!/usr/bin/env python3
"""
optimize_addresses.py — DNS validation and bulk address update for PVWA accounts.

Standalone script. Run with: python optimize_addresses.py --help

Queries account addresses against DNS to validate them, and optionally updates
the address field so account discovery works correctly.

Requires: CyberArk-Common/cyberark_common.py, EPV-API-Common/epv_api_common.py,
          Identity Authentication/identity_auth.py
"""

from __future__ import annotations

import argparse
import csv
import pathlib
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

_HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(_HERE.parent / "CyberArk-Common"))
sys.path.insert(0, str(_HERE.parent / "EPV-API-Common"))
sys.path.insert(0, str(_HERE.parent / "Identity Authentication"))

from cyberark_common import (  # noqa: E402
    CyberArkError,
    LogConfig,
    RestConfig,
    configure_logging,
    join_exception_message,
    logoff,
    logon,
    write_log,
)
from epv_api_common import (  # noqa: E402
    AccountFilter,
    get_accounts,
    update_account,
)
from identity_auth import (  # noqa: E402
    clear_identity_session,
    get_identity_header,
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class OptimizeResult:
    account_name: str
    username: str
    address: str
    status: str = "Not Processed"
    success: bool = False
    found: bool = False
    updated: bool = False


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------
def resolve_dns_name(address: str) -> str | None:
    """
    DNS lookup for address. Returns canonical hostname or None.
    Mirrors PowerShell: Resolve-DnsName | NameHost
    """
    if not address:
        return None
    try:
        # Resolve to IP then back to hostname
        ip = socket.gethostbyname(address)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.gaierror:
        # Try direct reverse lookup
        try:
            hostname, _, _ = socket.gethostbyaddr(address)
            return hostname
        except socket.herror:
            return None
    except (socket.herror, OSError):
        return None


# ---------------------------------------------------------------------------
# Single account optimisation
# ---------------------------------------------------------------------------
def optimize_account(
    account: dict,
    logon_header: dict[str, str],
    pvwa_url: str,
    *,
    update_accounts: bool = False,
    cfg: RestConfig | None = None,
) -> OptimizeResult:
    """
    Resolve DNS for one account and optionally PATCH its address.
    Returns an OptimizeResult dataclass.
    Mirrors the Optimize-Account PowerShell function.
    """
    result = OptimizeResult(
        account_name=str(account.get("name", "")),
        username=str(account.get("userName", "")),
        address=str(account.get("address", "")),
    )

    resolved = resolve_dns_name(result.address)

    if not resolved:
        result.status = "No Address Found, manual update required"
        return result

    result.found = True

    if resolved.lower() != result.address.lower():
        result.status = "Address found in DNS"
        if update_accounts:
            try:
                update_account(
                    pvwa_url,
                    logon_header,
                    str(account["id"]),
                    [{"op": "replace", "path": "/address", "value": resolved.lower()}],
                    cfg=cfg,
                )
                result.status = (
                    f"Address updated to DNS value: "
                    f'Old: "{result.address}" New: "{resolved.lower()}"'
                )
                result.updated = True
                result.success = True
            except CyberArkError as e:
                result.status = (
                    f"Address update failed: "
                    f'Old: "{result.address}" New: "{resolved.lower()}" Error: {e}'
                )
        else:
            result.success = True
    else:
        result.status = "Address on account matches DNS"
        result.success = True

    return result


# ---------------------------------------------------------------------------
# Main run function
# ---------------------------------------------------------------------------
def run(
    *,
    pvwa_url: str | None = None,
    logon_header: dict[str, str] | None = None,
    identity_username: str | None = None,
    identity_tenant_url: str | None = None,
    pcloud_subdomain: str | None = None,
    pvwa_credentials: tuple[str, str] | None = None,
    safes: list[str] | None = None,
    update_accounts: bool = False,
    show_all_results: bool = False,
    suppress_error_results: bool = False,
    export_to_csv: bool = False,
    csv_path: pathlib.Path = pathlib.Path("Optimize-Addresses-Results.csv"),
    cfg: RestConfig | None = None,
) -> list[OptimizeResult]:
    """
    Main entrypoint. Handles auth dispatch, fetches Windows accounts,
    runs optimisation in a ThreadPoolExecutor (mirrors PS -Parallel -ThrottleLimit 50).
    """
    owns_session = logon_header is None
    identity_session = False

    # Auth dispatch
    if logon_header is not None:
        pass  # pre-existing token, use as-is
    elif identity_username and pcloud_subdomain:
        pcloud_url = f"https://{pcloud_subdomain}.privilegecloud.cyberark.cloud"
        logon_header = get_identity_header(
            identity_username=identity_username,
            pcloud_url=pcloud_url,
            identity_tenant_url=identity_tenant_url,
            cfg=cfg,
        )
        identity_session = True
        pvwa_url = pvwa_url or f"{pcloud_url}/PasswordVault"
    elif pvwa_credentials and pvwa_url:
        logon_header = logon(pvwa_url, pvwa_credentials[0], pvwa_credentials[1], cfg=cfg)
    else:
        raise ValueError(
            "Must supply logon_header, identity_username+pcloud_subdomain, or pvwa_credentials+pvwa_url"
        )

    assert logon_header is not None
    assert pvwa_url is not None

    try:
        # Fetch Windows accounts (filter by platform type like the PS script)
        write_log("Fetching accounts...", "Info")
        all_accounts = get_accounts(pvwa_url, logon_header, cfg=cfg)

        # Optionally filter by safes
        if safes:
            all_accounts = [a for a in all_accounts if a.get("safeName") in safes]

        write_log(f"Processing {len(all_accounts)} accounts.", "Info")

        # Parallel DNS resolution + optional update (mirrors ForEach-Object -Parallel -ThrottleLimit 50)
        results: list[OptimizeResult] = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(
                    optimize_account,
                    account,
                    logon_header,
                    pvwa_url,
                    update_accounts=update_accounts,
                    cfg=cfg,
                ): account
                for account in all_accounts
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    account = futures[future]
                    write_log(
                        f"Error optimizing {account.get('name', '?')}: {join_exception_message(exc)}",
                        "Error",
                    )

        # Sort: success desc, found desc, updated desc, status, address
        results.sort(key=lambda r: (not r.success, not r.found, not r.updated, r.status, r.address))

        # Display results
        for res in results:
            if show_all_results:
                _print_result(res)
            elif not suppress_error_results and not res.success:
                _print_result(res)

        # CSV export
        if export_to_csv:
            _export_csv(results, csv_path)
            write_log(f"Results exported to: {csv_path}", "Info")

        found_count = sum(1 for r in results if r.found)
        updated_count = sum(1 for r in results if r.updated)
        write_log(f"{found_count} out of {len(all_accounts)} addresses found in DNS", "Info")
        write_log(f"{updated_count} out of {len(all_accounts)} addresses updated", "Info")

    finally:
        if owns_session and not identity_session and pvwa_url:
            logoff(pvwa_url, logon_header, cfg=cfg)
        if identity_session:
            clear_identity_session()

    return results


def _print_result(res: OptimizeResult) -> None:
    level = "Success" if res.success else "Warning" if res.found else "Error"
    write_log(
        f"  [{res.account_name}] {res.username}@{res.address} → {res.status}",
        level,
    )


def _export_csv(results: list[OptimizeResult], path: pathlib.Path) -> None:
    fields = ["success", "found", "updated", "address", "username", "status", "account_name"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "success": r.success,
                "found": r.found,
                "updated": r.updated,
                "address": r.address,
                "username": r.username,
                "status": r.status,
                "account_name": r.account_name,
            })


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Review and update account addresses via DNS validation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    auth = parser.add_mutually_exclusive_group(required=True)
    auth.add_argument("--logon-token", help="Pre-existing logon/session token")
    auth.add_argument("--identity-username", help="Identity username (requires --pcloud-subdomain)")
    auth.add_argument("--pvwa-credentials", nargs=2, metavar=("USERNAME", "PASSWORD"),
                      help="PVWA username and password")

    parser.add_argument("--pvwa-url", help="PVWA URL (required unless using --identity-username)")
    parser.add_argument("--identity-tenant-url", help="Identity tenant URL (auto-discovered if omitted)")
    parser.add_argument("--pcloud-subdomain", help="Privilege Cloud subdomain")
    parser.add_argument("--safes", nargs="+", help="Limit to specific safe names")
    parser.add_argument("--update-accounts", action="store_true",
                        help="Update account addresses in PVWA to match DNS")
    parser.add_argument("--show-all-results", action="store_true",
                        help="Show all results including already-optimized accounts")
    parser.add_argument("--suppress-error-results", action="store_true",
                        help="Suppress display of accounts that could not be optimized")
    parser.add_argument("--export-to-csv", action="store_true",
                        help="Export results to a CSV file")
    parser.add_argument("--csv-path", type=pathlib.Path,
                        default=pathlib.Path("Optimize-Addresses-Results.csv"),
                        help="Path for CSV export (default: Optimize-Addresses-Results.csv)")
    parser.add_argument("--disable-ssl-verify", action="store_true",
                        help="Disable SSL certificate verification (testing only)")
    parser.add_argument("--log-file", type=pathlib.Path,
                        help="Log file path")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    configure_logging(LogConfig(
        log_file=args.log_file or (_HERE / "Optimize-Addresses.log"),
        debug=args.debug,
    ))
    cfg = RestConfig(verify_ssl=not args.disable_ssl_verify)

    write_log("Optimize Addresses — starting.", "Info", header=True)

    # Resolve auth kwargs
    kwargs: dict = {
        "pvwa_url": args.pvwa_url,
        "identity_tenant_url": args.identity_tenant_url,
        "pcloud_subdomain": args.pcloud_subdomain,
        "safes": args.safes,
        "update_accounts": args.update_accounts,
        "show_all_results": args.show_all_results,
        "suppress_error_results": args.suppress_error_results,
        "export_to_csv": args.export_to_csv,
        "csv_path": args.csv_path,
        "cfg": cfg,
    }

    if args.logon_token:
        kwargs["logon_header"] = {"Authorization": args.logon_token}
    elif args.identity_username:
        kwargs["identity_username"] = args.identity_username
    elif args.pvwa_credentials:
        kwargs["pvwa_credentials"] = tuple(args.pvwa_credentials)

    run(**kwargs)
    write_log("Done.", "Info", footer=True)


if __name__ == "__main__":
    main()
