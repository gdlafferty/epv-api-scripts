"""
cyberark_common.py — CyberArk shared utilities for Python 3.14.

Provides logging, HTTP, authentication, and error-handling primitives
imported by all other CyberArk Python scripts in this repository.

No imports from sibling scripts — this is the foundation layer.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import pathlib
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Literal

import httpx

# ---------------------------------------------------------------------------
# Python 3.14 type aliases (PEP 695)
# ---------------------------------------------------------------------------
type LogLevel = Literal["Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly"]
type HttpMethod = Literal["GET", "POST", "PATCH", "DELETE", "PUT"]
type AuthType = Literal["cyberark", "ldap", "radius"]
type JsonDict = dict[str, object]

# ---------------------------------------------------------------------------
# ANSI colour codes for console output
# ---------------------------------------------------------------------------
_RESET = "\033[0m"
_GREY = "\033[37m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_MAGENTA = "\033[35m"

# ---------------------------------------------------------------------------
# Sensitive-data masking
# ---------------------------------------------------------------------------
_SENSITIVE_RE: re.Pattern[str] = re.compile(
    r'((?:password|credentials|secret|token)\s*[:="]{1,}\s*["]?)([\w`~!@#$%^&*()\-_=+\\/|;:.,\[\]{}]+)',
    re.IGNORECASE,
)


def mask_sensitive(msg: str) -> str:
    """Replace password/secret/token values with **** in log output."""
    return _SENSITIVE_RE.sub(lambda m: m.group(1) + "****", msg)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------
class CyberArkError(Exception):
    """Base class for all CyberArk errors."""


class CyberArkRestError(CyberArkError):
    """Raised when a REST call returns an HTTP error."""

    def __init__(self, status_code: int, message: str, uri: str) -> None:
        self.status_code = status_code
        self.uri = uri
        super().__init__(f"HTTP {status_code} on {uri}: {message}")


class CyberArkAuthError(CyberArkError):
    """Raised when authentication fails."""


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class LogConfig:
    log_file: pathlib.Path | None = None
    debug: bool = False
    verbose: bool = False
    max_bytes: int = 100 * 1024 * 1024  # 100 MB
    backup_count: int = 1


class _ColorFormatter(logging.Formatter):
    """Console formatter that adds ANSI colour based on the cyberark level tag."""

    _COLORS: dict[str, str] = {
        "INFO": _GREY,
        "SUCCESS": _GREEN,
        "WARNING": _YELLOW,
        "ERROR": _RED,
        "DEBUG": _GREY,
        "VERBOSE": _GREY,
        "HEADER": _MAGENTA,
    }

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        level_tag = getattr(record, "cyberark_level", record.levelname)
        color = self._COLORS.get(level_tag.upper(), _GREY)
        msg = super().format(record)
        return f"{color}{msg}{_RESET}"


# Module-level logger — configured once via configure_logging()
_logger: logging.Logger = logging.getLogger("cyberark")
_logger.setLevel(logging.DEBUG)
_log_config: LogConfig = LogConfig()


def configure_logging(cfg: LogConfig) -> logging.Logger:
    """
    Wire up the CyberArk logger: colour console handler + optional rotating file handler.
    Call once at script startup before any write_log() calls.
    """
    global _log_config
    _log_config = cfg

    logger = logging.getLogger("cyberark")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(_ColorFormatter("%(message)s"))
    logger.addHandler(ch)

    # File handler
    if cfg.log_file is not None:
        cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            cfg.log_file,
            maxBytes=cfg.max_bytes,
            backupCount=cfg.backup_count,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("[%(asctime)s]\t%(message)s", "%Y-%m-%d %H:%M:%S"))
        logger.addHandler(fh)

    return logger


def write_log(
    msg: str,
    level: LogLevel = "Info",
    *,
    header: bool = False,
    sub_header: bool = False,
    footer: bool = False,
    logger: logging.Logger | None = None,
) -> None:
    """
    Write a log message to console and/or file.
    Drop-in equivalent of PowerShell Write-LogMessage.
    """
    log = logger or _logger
    masked = mask_sensitive(msg or "N/A")

    sep_line = "======================================="
    sub_sep = "------------------------------------"

    def _emit(text: str, tag: str, lvl: int, console_only: bool = False) -> None:
        record = log.makeRecord(
            log.name, lvl, "", 0, text, (), None
        )
        record.__dict__["cyberark_level"] = tag
        if console_only:
            for h in log.handlers:
                if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
                    h.emit(record)
        else:
            log.handle(record)

    if header:
        _emit(sep_line, "HEADER", logging.INFO)
    elif sub_header:
        _emit(sub_sep, "HEADER", logging.INFO)

    match level:
        case "Info":
            _emit(f"[INFO]\t{masked}", "INFO", logging.INFO)
        case "LogOnly":
            # file only — emit to file handlers directly
            for h in log.handlers:
                if isinstance(h, logging.FileHandler):
                    record = log.makeRecord(log.name, logging.INFO, "", 0, f"[INFO]\t{masked}", (), None)
                    h.emit(record)
        case "Success":
            _emit(f"[SUCCESS]\t{masked}", "SUCCESS", logging.INFO)
        case "Warning":
            _emit(f"[WARNING]\t{masked}", "WARNING", logging.WARNING)
        case "Error":
            _emit(f"[ERROR]\t{masked}", "ERROR", logging.ERROR)
        case "Debug":
            if _log_config.debug or _log_config.verbose:
                _emit(f"[Debug]\t{masked}", "DEBUG", logging.DEBUG)
        case "Verbose":
            if _log_config.verbose:
                _emit(f"[VERBOSE]\t{masked}", "VERBOSE", logging.DEBUG)

    if footer:
        _emit(sep_line, "HEADER", logging.INFO)


# ---------------------------------------------------------------------------
# Exception formatting
# ---------------------------------------------------------------------------
def join_exception_message(exc: BaseException) -> str:
    """
    Walk the __cause__/__context__ chain and return a single formatted string.
    Mirrors PowerShell Join-ExceptionMessage.
    """
    parts: list[str] = []
    current: BaseException | None = exc
    while current is not None:
        parts.append(f"Type:{type(current).__name__}; Message: {current}")
        nxt = current.__cause__ or current.__context__
        if nxt is current:
            break
        current = nxt
    return "\n\t->".join(parts)


# ---------------------------------------------------------------------------
# REST configuration and HTTP client
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class RestConfig:
    timeout: float = 2700.0
    verify_ssl: bool = True
    retries: int = 3
    retry_statuses: frozenset[int] = field(default_factory=lambda: frozenset({429, 500, 502, 503, 504}))


def build_client(cfg: RestConfig | None = None) -> httpx.Client:
    """
    Return a configured synchronous httpx.Client.
    When cfg.verify_ssl is False, emit a WARNING before disabling verification.
    """
    c = cfg or RestConfig()
    if not c.verify_ssl:
        write_log(
            "SSL certificate verification is DISABLED. Use for testing only.",
            "Warning",
        )
    return httpx.Client(
        timeout=c.timeout,
        verify=c.verify_ssl,
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )


def build_async_client(cfg: RestConfig | None = None) -> httpx.AsyncClient:
    """Return a configured asynchronous httpx.AsyncClient."""
    c = cfg or RestConfig()
    if not c.verify_ssl:
        write_log(
            "SSL certificate verification is DISABLED. Use for testing only.",
            "Warning",
        )
    return httpx.AsyncClient(
        timeout=c.timeout,
        verify=c.verify_ssl,
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )


def invoke_rest(
    method: HttpMethod,
    uri: str,
    *,
    headers: dict[str, str] | None = None,
    body: JsonDict | str | None = None,
    client: httpx.Client | None = None,
    cfg: RestConfig | None = None,
) -> JsonDict | str | None:
    """
    Synchronous REST wrapper. Mirrors PowerShell Invoke-Rest / Invoke-RestMethod.
    Returns parsed JSON dict, raw text, or None on non-fatal errors.
    Raises CyberArkRestError on HTTP 4xx/5xx.
    """
    c = cfg or RestConfig()
    write_log(f"Invoke-Rest {method} {uri}", "Verbose")

    request_body: str | None = None
    if body is not None:
        request_body = body if isinstance(body, str) else json.dumps(body)

    owned_client = client is None
    _client = client or build_client(c)

    last_exc: Exception | None = None
    try:
        for attempt in range(max(1, c.retries)):
            try:
                response = _client.request(
                    method,
                    uri,
                    headers=headers,
                    content=request_body,
                )
                write_log(f"Response status: {response.status_code}", "Verbose")

                if response.status_code in c.retry_statuses and attempt < c.retries - 1:
                    backoff = 2 ** attempt
                    write_log(f"HTTP {response.status_code}; retrying in {backoff}s (attempt {attempt + 1})", "Warning")
                    time.sleep(backoff)
                    continue

                if response.status_code >= 400:
                    raise CyberArkRestError(response.status_code, response.text, uri)

                if not response.content:
                    return None

                try:
                    return response.json()
                except Exception:
                    return response.text

            except CyberArkRestError:
                raise
            except httpx.TimeoutException as e:
                write_log(f"Timeout on {method} {uri}: {e}", "Error")
                last_exc = e
                if attempt < c.retries - 1:
                    time.sleep(2 ** attempt)
            except httpx.RequestError as e:
                write_log(f"Request error on {method} {uri}: {e}", "Error")
                last_exc = e
                break
    finally:
        if owned_client:
            _client.close()

    if last_exc:
        raise CyberArkError(f"REST call failed after {c.retries} attempts: {last_exc}") from last_exc
    return None


async def invoke_rest_async(
    method: HttpMethod,
    uri: str,
    *,
    headers: dict[str, str] | None = None,
    body: JsonDict | str | None = None,
    client: httpx.AsyncClient | None = None,
    cfg: RestConfig | None = None,
) -> JsonDict | str | None:
    """
    Async variant of invoke_rest. Used by pvwa_load_test.py.
    Does NOT retry — callers handle retry logic at the task level.
    """
    request_body: str | None = None
    if body is not None:
        request_body = body if isinstance(body, str) else json.dumps(body)

    owned = client is None
    _client = client or build_async_client(cfg)

    try:
        response = await _client.request(
            method,
            uri,
            headers=headers,
            content=request_body,
        )
        if response.status_code >= 400:
            raise CyberArkRestError(response.status_code, response.text, uri)
        if not response.content:
            return None
        try:
            return response.json()
        except Exception:
            return response.text
    finally:
        if owned:
            await _client.aclose()


# ---------------------------------------------------------------------------
# Auth header builder
# ---------------------------------------------------------------------------
def get_logon_header(token: str) -> dict[str, str]:
    """Return {'Authorization': token}. Mirrors Get-LogonHeader output."""
    return {"Authorization": token}


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
def build_pvwa_urls(pvwa_url: str) -> dict[str, str]:
    """
    Construct the standard PVWA URL dictionary.
    Strips trailing slash, appends /api, /auth/{auth_type}/Logon, etc.
    """
    base = pvwa_url.rstrip("/")
    api = base + "/api"
    auth = api + "/auth"
    return {
        "base": base,
        "api": api,
        "auth": auth,
        "logon_cyberark": auth + "/cyberark/Logon",
        "logon_ldap": auth + "/ldap/Logon",
        "logon_radius": auth + "/radius/Logon",
        "logoff": auth + "/Logoff",
        "accounts": api + "/Accounts",
        "safes": api + "/Safes",
        "users": api + "/Users",
        "discovered_accounts": api + "/DiscoveredAccounts",
        "platforms": api + "/Platforms",
        "health": api + "/ComponentsMonitoringSummary",
    }


def url_encode(text: str) -> str:
    """URL-encode text. Equivalent of PowerShell [URI]::EscapeDataString."""
    if text.strip():
        return urllib.parse.quote(text, safe="")
    return text


# ---------------------------------------------------------------------------
# Session logon / logoff
# ---------------------------------------------------------------------------
def logon(
    pvwa_url: str,
    username: str,
    password: str,
    auth_type: AuthType = "cyberark",
    *,
    otp: str | None = None,
    concurrent_session: bool = True,
    cfg: RestConfig | None = None,
) -> dict[str, str]:
    """
    Authenticate to PVWA and return a logon header dict.
    For radius auth, appends OTP to password as PowerShell scripts do.
    Returns {'Authorization': '<token>'}.
    """
    urls = build_pvwa_urls(pvwa_url)
    logon_url = urls[f"logon_{auth_type}"]

    actual_password = password
    if auth_type == "radius" and otp:
        actual_password = f"{password}{otp}"

    body: JsonDict = {
        "username": username,
        "password": actual_password,
        "concurrentSession": concurrent_session,
    }

    write_log(f"Logging on to {pvwa_url} as {username} ({auth_type})", "Info")

    response = invoke_rest("POST", logon_url, body=body, cfg=cfg)

    if not isinstance(response, str):
        raise CyberArkAuthError(f"Unexpected logon response type: {type(response)}")

    # Strip surrounding quotes if present
    token = response.strip('"')
    write_log("Logon successful.", "Success")
    return {"Authorization": token}


def logoff(
    pvwa_url: str,
    logon_header: dict[str, str],
    *,
    cfg: RestConfig | None = None,
) -> None:
    """
    POST to /auth/Logoff. Silent on failure (mirrors PS behaviour).
    """
    urls = build_pvwa_urls(pvwa_url)
    try:
        invoke_rest("POST", urls["logoff"], headers=logon_header, cfg=cfg)
        write_log("Logoff successful.", "Info")
    except Exception as e:
        write_log(f"Logoff failed (ignored): {e}", "Verbose")
