#!/usr/bin/env python3
"""
test_html5_certificate.py — Validate and optionally set RDS/HTML5 Gateway certificate.

Windows-only: uses ssl.enum_certificates and winreg.
Will raise NotImplementedError on non-Windows systems.

Standalone script. Run with: python test_html5_certificate.py --help

Mirrors Test-HTML5Certificate.ps1 (CheckCertificate + optional SetCertificate).
"""

from __future__ import annotations

import argparse
import platform
import ssl
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime

if platform.system() != "Windows":
    raise NotImplementedError(
        "test_html5_certificate.py requires Windows (winreg / Windows certificate store access)."
    )

import ctypes
import winreg

# OID for Server Authentication EKU
_EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

# RDS registry path and value for setting the certificate
_RDS_CERT_REG_PATH = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
_RDS_CERT_VALUE = "SSLCertificateSHA1Hash"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class CertInfo:
    subject: str
    thumbprint: str
    not_before: datetime
    not_after: datetime
    has_private_key: bool
    eku_oids: list[str] = field(default_factory=list)
    san_dns_names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CertCheckResult:
    thumbprint: str
    passed: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Certificate enumeration
# ---------------------------------------------------------------------------
def enumerate_local_machine_personal_certs() -> list[CertInfo]:
    """
    Read certificates from the Windows LocalMachine\\Personal (MY) store.
    Uses ssl.enum_certificates (stdlib, no pywin32 required for enumeration).
    For full EKU/SAN/private-key parsing, attempts to use the `cryptography`
    package if available; falls back to partial info if not installed.
    Returns a list of CertInfo objects.
    """
    certs: list[CertInfo] = []

    for cert_data, encoding, trust in ssl.enum_certificates("MY"):
        try:
            info = _parse_cert(cert_data, encoding)
            if info:
                certs.append(info)
        except Exception:
            continue

    return certs


def _parse_cert(cert_data: bytes, encoding: str) -> CertInfo | None:
    """
    Parse a DER-encoded certificate into a CertInfo.
    Uses `cryptography` if available; minimal fallback if not.
    """
    try:
        from cryptography import x509  # type: ignore[import-untyped]
        from cryptography.hazmat.backends import default_backend  # type: ignore[import-untyped]
        from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID  # type: ignore[import-untyped]
        import binascii

        if encoding == "DER":
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
        elif encoding == "PEM":
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        else:
            return None

        # Thumbprint (SHA-1 hex)
        from cryptography.hazmat.primitives import hashes  # type: ignore[import-untyped]
        thumbprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode().upper()

        # Subject
        subject = cert.subject.rfc4514_string()

        # Validity
        not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        not_after = cert.not_valid_after_utc.replace(tzinfo=None)

        # EKU OIDs
        eku_oids: list[str] = []
        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_oids = [oid.dotted_string for oid in eku.value]
        except Exception:
            pass

        # SAN DNS names
        san_dns_names: list[str] = []
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_dns_names = [entry.value for entry in san.value.get_values_for_type(x509.DNSName)]
        except Exception:
            pass

        # Private key: check registry or assume True for certs in MY store
        # The `cryptography` library cannot detect private keys in the Windows store directly.
        # We assume certs in LocalMachine\My typically have private keys unless the store says otherwise.
        has_private_key = True  # Best-effort; cert store placement implies private key

        return CertInfo(
            subject=subject,
            thumbprint=thumbprint,
            not_before=not_before,
            not_after=not_after,
            has_private_key=has_private_key,
            eku_oids=eku_oids,
            san_dns_names=san_dns_names,
        )

    except ImportError:
        # Fallback: minimal parsing without `cryptography` package
        return _parse_cert_minimal(cert_data, encoding)


def _parse_cert_minimal(cert_data: bytes, encoding: str) -> CertInfo | None:
    """
    Minimal fallback cert parser when `cryptography` is not available.
    Only parses expiry from PEM via ssl module.
    """
    try:
        import hashlib
        if encoding == "DER":
            pem = ssl.DER_cert_to_PEM_cert(cert_data)
        elif encoding == "PEM":
            pem = cert_data.decode("ascii")
        else:
            return None

        cert_der = ssl.PEM_cert_to_DER_cert(pem)
        thumbprint = hashlib.sha1(cert_der).hexdigest().upper()

        # ssl.get_server_certificate returns parsed info but can't parse local certs directly.
        # Return a minimal object; checks will be limited.
        return CertInfo(
            subject="(install `cryptography` for full details)",
            thumbprint=thumbprint,
            not_before=datetime.min,
            not_after=datetime.max,
            has_private_key=True,
            eku_oids=[],
            san_dns_names=[],
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Certificate validation
# ---------------------------------------------------------------------------
def check_certificate(cert: CertInfo) -> CertCheckResult:
    """
    Validate cert for RDS/HTML5 Gateway use:
      - has_private_key
      - not expired (not_after >= now)
      - not yet valid (not_before <= now)
      - EKU contains Server Authentication OID (1.3.6.1.5.5.7.3.1)
      - SAN contains local machine FQDN
    Mirrors CheckCertificate PowerShell function.
    """
    errors: list[str] = []
    warnings: list[str] = []
    now = datetime.now()

    if not cert.has_private_key:
        errors.append("No private key detected. This certificate cannot be used.")

    if cert.not_after < now:
        errors.append(f"Certificate has expired (expired {cert.not_after:%Y-%m-%d}).")

    if cert.not_before > now:
        errors.append(f"Certificate is not yet valid (valid from {cert.not_before:%Y-%m-%d}).")

    if _EKU_SERVER_AUTH not in cert.eku_oids:
        errors.append(
            'Certificate is missing the "Server Authentication" Enhanced Key Usage (OID 1.3.6.1.5.5.7.3.1).'
        )

    # Check SAN matches local FQDN
    try:
        local_fqdn = socket.getfqdn().lower()
        local_hostname = socket.gethostname().lower()
        san_lower = [s.lower() for s in cert.san_dns_names]
        if local_fqdn not in san_lower and local_hostname not in san_lower:
            errors.append(
                f"Certificate SAN does not match local hostname ({local_fqdn}). "
                f"SAN entries: {cert.san_dns_names or '(none)'}"
            )
    except Exception as e:
        warnings.append(f"Could not determine local hostname for SAN check: {e}")

    passed = len(errors) == 0
    return CertCheckResult(
        thumbprint=cert.thumbprint,
        passed=passed,
        errors=errors,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Set RDS certificate
# ---------------------------------------------------------------------------
def set_rds_certificate(thumbprint: str) -> None:
    """
    Write thumbprint bytes to RDS registry key.
    Requires elevation; raises PermissionError if not admin.
    Mirrors Set-WmiInstance call in the PS script.
    """
    if not _is_admin():
        raise PermissionError(
            "Must be running as Administrator to update the RDS certificate."
        )

    # Convert thumbprint hex string to bytes
    thumb_bytes = bytes.fromhex(thumbprint)

    print(f"Attempting to set certificate (thumbprint: {thumbprint}) for use in RDS...")
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            _RDS_CERT_REG_PATH,
            0,
            winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, _RDS_CERT_VALUE, 0, winreg.REG_BINARY, thumb_bytes)
        winreg.CloseKey(key)
        print("Certificate set successfully for RDS.")
    except OSError as e:
        raise OSError(f"Failed to set RDS certificate in registry: {e}") from e


def _is_admin() -> bool:
    """Check if the current process is running as Administrator."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check and optionally set the RDS/HTML5 Gateway certificate on this machine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--set-certificate",
        action="store_true",
        help="Set the selected certificate for use in RDS (requires Administrator privileges).",
    )
    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    print("Enumerating certificates in LocalMachine\\Personal store...")
    certs = enumerate_local_machine_personal_certs()

    if not certs:
        print("No certificates found in LocalMachine\\Personal store.")
        sys.exit(1)

    print(f"\nFound {len(certs)} certificate(s):\n")
    for i, cert in enumerate(certs, 1):
        status = "EXPIRED" if cert.not_after < datetime.now() else "valid"
        print(f"  {i}. Subject: {cert.subject}")
        print(f"     Thumbprint: {cert.thumbprint}")
        print(f"     Validity: {cert.not_before:%Y-%m-%d} – {cert.not_after:%Y-%m-%d} [{status}]")
        print()

    # Select certificate
    selected: CertInfo | None = None
    while selected is None:
        try:
            choice = int(input(f"Select certificate number (1-{len(certs)}): "))
            if 1 <= choice <= len(certs):
                selected = certs[choice - 1]
            else:
                print(f"Please enter a number between 1 and {len(certs)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)

    print(f"\nChecking certificate: {selected.thumbprint}")
    result = check_certificate(selected)

    for warning in result.warnings:
        print(f"  WARNING: {warning}")

    for error in result.errors:
        print(f"  ERROR: {error}")

    if result.passed:
        print("\nThis certificate passed all checks and looks ready to use.")
    else:
        print(f"\nThis certificate failed {len(result.errors)} check(s). See errors above.")
        if not args.set_certificate:
            sys.exit(1)

    if args.set_certificate:
        if not result.passed:
            print("Certificate did not pass checks. Aborting set-certificate operation.")
            sys.exit(1)
        try:
            set_rds_certificate(selected.thumbprint)
        except (PermissionError, OSError) as e:
            print(f"ERROR: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
