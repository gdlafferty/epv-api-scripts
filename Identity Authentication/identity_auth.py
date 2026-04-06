"""
identity_auth.py — CyberArk Identity authentication module for Python 3.14.

Supports OAuth client credentials, Username/Password, MFA (OTP/Push/SMS/Email),
and OOBAUTHPIN (SAML+PIN) authentication flows.

Module-level session cache mirrors PowerShell $script:CurrentSession.

Requires: CyberArk-Common/cyberark_common.py
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

_HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(_HERE.parent / "CyberArk-Common"))

from cyberark_common import (  # noqa: E402
    CyberArkAuthError,
    CyberArkError,
    JsonDict,
    RestConfig,
    build_client,
    write_log,
)

import httpx  # noqa: E402

# ---------------------------------------------------------------------------
# Type aliases (PEP 695)
# ---------------------------------------------------------------------------
type IdentityAuthMethod = Literal["OAuth", "UP", "MFA", "OOBAUTHPIN"]


# ---------------------------------------------------------------------------
# Session dataclass
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class IdentitySession:
    token: str
    token_expiry: datetime
    identity_url: str
    pcloud_url: str
    username: str
    auth_method: IdentityAuthMethod
    session_id: str | None = None
    refresh_token: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None  # stored for auto-refresh

    @property
    def is_expired(self) -> bool:
        return datetime.now() >= self.token_expiry

    def is_expiring_soon(self, threshold_seconds: int = 60) -> bool:
        from datetime import timedelta
        return datetime.now() >= self.token_expiry - timedelta(seconds=threshold_seconds)

    def to_headers(self) -> dict[str, str]:
        if self.is_expired:
            raise CyberArkAuthError("Session token has expired. Re-authenticate.")
        return {
            "Authorization": f"Bearer {self.token}",
            "X-IDAP-NATIVE-CLIENT": "true",
        }


# ---------------------------------------------------------------------------
# Module-level session cache (mirrors $script:CurrentSession)
# ---------------------------------------------------------------------------
_current_session: IdentitySession | None = None


def get_identity_session() -> IdentitySession | None:
    """Return current cached session or None."""
    return _current_session


def clear_identity_session(*, no_logout: bool = False) -> None:
    """
    Clear module-level session, optionally calling logout endpoint first.
    Mirrors Clear-IdentitySession.
    """
    global _current_session
    if _current_session is None:
        write_log("No active Identity session to clear.", "Verbose")
        return

    if not no_logout and _current_session.identity_url:
        try:
            logout_url = f"{_current_session.identity_url}/Security/logout"
            with build_client() as c:
                c.post(logout_url, headers=_current_session.to_headers())
            write_log("Identity logout successful.", "Verbose")
        except Exception as e:
            write_log(f"Identity logout call failed (continuing): {e}", "Verbose")

    _current_session = None
    write_log("Identity session cleared.", "Verbose")


# ---------------------------------------------------------------------------
# URL discovery
# ---------------------------------------------------------------------------
def get_identity_url(pcloud_url: str, *, cfg: RestConfig | None = None) -> str:
    """
    Discover Identity tenant URL via HTTP redirect from PCloud URL.
    Uses httpx follow_redirects=False to capture the Location header.
    Mirrors Get-IdentityURL.
    """
    import re
    match = re.match(
        r'^(?:https?://)(?P<sub>.*)(.privilegecloud).cyberark.(?P<top>cloud|com)/(privilegecloud|passwordvault)/?$',
        pcloud_url.lower(),
    )
    if match:
        pcloud_base = f"https://{match.group('sub')}.cyberark.{match.group('top')}"
    else:
        # Fallback: use the URL as-is stripped of path
        from urllib.parse import urlparse
        parsed = urlparse(pcloud_url)
        pcloud_base = f"{parsed.scheme}://{parsed.netloc}"

    write_log(f"Discovering Identity URL from: {pcloud_base}", "Verbose")

    c = cfg or RestConfig()
    try:
        with httpx.Client(timeout=30.0, verify=c.verify_ssl, follow_redirects=True) as client:
            response = client.get(pcloud_base)
            identity_host = str(response.url.host)
            identity_url = f"https://{identity_host}"
            write_log(f"Discovered Identity URL: {identity_url}", "Verbose")
            return identity_url
    except Exception as e:
        raise CyberArkAuthError(f"Failed to discover Identity URL from {pcloud_base}: {e}") from e


# ---------------------------------------------------------------------------
# OAuth flow
# ---------------------------------------------------------------------------
def _oauth_flow(
    client_id: str,
    client_secret: str,
    identity_url: str,
    pcloud_url: str,
    *,
    cfg: RestConfig | None = None,
) -> IdentitySession:
    """POST to /oauth2/platformtoken with client_credentials grant."""
    token_url = f"{identity_url}/oauth2/platformtoken"
    body = f"grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}"

    write_log(f"OAuth authentication for client_id={client_id}", "Verbose")

    c = cfg or RestConfig()
    try:
        with httpx.Client(timeout=30.0, verify=c.verify_ssl) as client:
            response = client.post(
                token_url,
                content=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        raise CyberArkAuthError(f"OAuth token request failed: {e.response.status_code} {e.response.text}") from e
    except Exception as e:
        raise CyberArkAuthError(f"OAuth token request error: {e}") from e

    token = data.get("access_token", "")
    if not token:
        raise CyberArkAuthError("OAuth response did not contain access_token")

    expires_in = int(data.get("expires_in", 3600))
    expiry = datetime.fromtimestamp(time.time() + expires_in)

    return IdentitySession(
        token=token,
        token_expiry=expiry,
        identity_url=identity_url,
        pcloud_url=pcloud_url,
        username=client_id,
        auth_method="OAuth",
        refresh_token=data.get("refresh_token"),
        oauth_client_id=client_id,
        oauth_client_secret=client_secret,
    )


# ---------------------------------------------------------------------------
# Interactive authentication flows
# ---------------------------------------------------------------------------
def _start_authentication(
    username: str,
    identity_url: str,
    *,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """POST to /Security/StartAuthentication. Mirrors StartAuthentication call."""
    url = f"{identity_url}/Security/StartAuthentication"
    body = json.dumps({"User": username, "Version": "1.0"})
    headers = {
        "Content-Type": "application/json",
        "X-IDAP-NATIVE-CLIENT": "true",
        "OobIdPAuth": "true",
    }
    c = cfg or RestConfig()
    try:
        with httpx.Client(timeout=30.0, verify=c.verify_ssl) as client:
            response = client.post(url, content=body, headers=headers)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        raise CyberArkAuthError(f"StartAuthentication failed: {e.response.status_code} {e.response.text}") from e


def _advance_authentication(
    session_id: str,
    mechanism: dict,
    identity_url: str,
    *,
    up_creds: tuple[str, str] | None = None,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """
    POST to /Security/AdvanceAuthentication.
    Handles Text (OTP/password) and StartTextOob (push) answer types.
    Polls for push approval with 2-second sleep intervals.
    """
    advance_url = f"{identity_url}/Security/AdvanceAuthentication"
    mechanism_id = mechanism.get("MechanismId", "")
    answer_type = mechanism.get("AnswerType", "")
    mechanism_name = mechanism.get("Name", "")

    c = cfg or RestConfig()

    if answer_type == "StartTextOob":
        # Push notification flow: start OOB, then poll
        start_body = json.dumps({
            "SessionId": session_id,
            "MechanismId": mechanism_id,
            "Action": "StartOOB",
        })
        with httpx.Client(timeout=30.0, verify=c.verify_ssl) as client:
            resp = client.post(advance_url, content=start_body, headers={"Content-Type": "application/json"})
            resp.raise_for_status()
            response = resp.json()

        write_log("Waiting for push notification approval...", "Info")
        while (response.get("Result") or {}).get("Summary") == "OobPending":
            time.sleep(2)
            write_log("Polling for push approval...", "Verbose")
            poll_body = json.dumps({
                "SessionId": session_id,
                "MechanismId": mechanism_id,
                "Action": "Poll",
            })
            with httpx.Client(timeout=30.0, verify=c.verify_ssl) as client:
                resp = client.post(advance_url, content=poll_body, headers={"Content-Type": "application/json"})
                resp.raise_for_status()
                response = resp.json()

        return response

    elif answer_type == "Text":
        # Text answer (password, OTP, etc.)
        if mechanism_name == "UP" and up_creds:
            write_log("Using stored UP credentials.", "Verbose")
            answer = up_creds[1]
        else:
            prompt_text = (
                "Password" if mechanism_name == "UP"
                else "OTP code" if mechanism_name == "OTP"
                else f"Answer for {mechanism_name}"
            )
            import getpass
            answer = getpass.getpass(f"Enter {prompt_text}: ")

        answer_body = json.dumps({
            "SessionId": session_id,
            "MechanismId": mechanism_id,
            "Action": "Answer",
            "Answer": answer,
        })
        with httpx.Client(timeout=30.0, verify=c.verify_ssl) as client:
            resp = client.post(advance_url, content=answer_body, headers={"Content-Type": "application/json"})
            resp.raise_for_status()
            return resp.json()

    else:
        raise CyberArkAuthError(f"Unsupported AnswerType: {answer_type}")


def _invoke_challenge(
    idaptive_response: JsonDict,
    identity_url: str,
    *,
    up_creds: tuple[str, str] | None = None,
    cfg: RestConfig | None = None,
) -> JsonDict:
    """
    Iterate challenges array and call _advance_authentication for each.
    Prompts user on stdin when MFA input is required.
    Mirrors Invoke-Challenge.
    """
    result = idaptive_response.get("Result") or {}
    session_id = str(result.get("SessionId", ""))
    challenges = result.get("Challenges") or []

    write_log(f"Processing challenges for session: {session_id}", "Verbose")
    answer_response: JsonDict = {}

    for i, challenge in enumerate(challenges, 1):
        write_log(f"Challenge {i}", "Info")
        mechanisms = challenge.get("mechanisms") or []
        mech_count = len(mechanisms)

        if mech_count > 1:
            write_log(f"There are {mech_count} options to choose from:", "Info")
            for j, mech in enumerate(mechanisms, 1):
                write_log(f"  {j} - {mech.get('Name')} - {mech.get('PromptMechChosen', mech.get('PromptSelectMech', ''))}", "Info")
            selected_mech = None
            while selected_mech is None:
                try:
                    choice = int(input(f"Please enter option number (1-{mech_count}): "))
                    if 1 <= choice <= mech_count:
                        selected_mech = mechanisms[choice - 1]
                except ValueError:
                    write_log("Invalid input. Please enter a number.", "Warning")
        else:
            selected_mech = mechanisms[0]
            write_log(f"  {selected_mech.get('Name')} - {selected_mech.get('PromptMechChosen', '')}", "Info")

        answer_response = _advance_authentication(
            session_id,
            selected_mech,
            identity_url,
            up_creds=up_creds,
            cfg=cfg,
        )

        write_log(f"Challenge response success: {answer_response.get('success')}", "Verbose")

        # Check if we received a token
        result_data = answer_response.get("Result") or {}
        if answer_response.get("success") and result_data.get("Token"):
            write_log("Token received successfully.", "Verbose")
            return answer_response

    if not answer_response.get("success"):
        msg = answer_response.get("Message", "Unknown error")
        raise CyberArkAuthError(f"Authentication failed: {msg}")

    return answer_response


def _oobauthpin_flow(
    idaptive_response: JsonDict,
    identity_url: str,
    pcloud_url: str,
    username: str,
    *,
    pin: str | None = None,
    cfg: RestConfig | None = None,
) -> IdentitySession:
    """
    Handle SAML+PIN flow: display IdpRedirectShortUrl, collect PIN, POST Answer.
    Mirrors Invoke-OOBAUTHPIN.
    """
    result = idaptive_response.get("Result") or {}
    idp_redirect_url = str(result.get("IdpRedirectShortUrl", ""))
    session_id = str(result.get("SessionId", ""))
    idp_login_session_id = str(result.get("IdpLoginSessionId", ""))

    if not idp_redirect_url:
        raise CyberArkAuthError("IdpRedirectShortUrl is empty. Cannot proceed with OOBAUTHPIN.")

    write_log("", "Info")
    write_log("=" * 60, "Info")
    write_log("OOBAUTHPIN Authentication Required", "Info")
    write_log("=" * 60, "Info")
    write_log(f"  1. Open this URL: {idp_redirect_url}", "Info")
    write_log("  2. Complete SAML authentication", "Info")
    write_log("  3. You will receive a PIN via email/SMS", "Info")
    write_log("  4. Enter the PIN below", "Info")
    write_log("", "Info")

    if not pin:
        import getpass
        while True:
            pin_input = getpass.getpass("Enter PIN code (numbers only): ").strip()
            if pin_input.isdigit():
                pin = pin_input
                break
            write_log("Invalid input. Please enter numbers only.", "Warning")

    advance_url = f"{identity_url}/Security/AdvanceAuthentication"
    pin_body = json.dumps({
        "SessionId": idp_login_session_id,
        "MechanismId": "OOBAUTHPIN",
        "Action": "Answer",
        "Answer": pin,
    })

    c = cfg or RestConfig()
    try:
        with httpx.Client(timeout=30.0, verify=c.verify_ssl) as client:
            resp = client.post(advance_url, content=pin_body, headers={"Content-Type": "application/json"})
            resp.raise_for_status()
            pin_response = resp.json()
    except httpx.HTTPStatusError as e:
        raise CyberArkAuthError(f"OOBAUTHPIN PIN submission failed: {e.response.status_code}") from e

    result_data = pin_response.get("Result") or {}
    token = result_data.get("Token", "")
    if not pin_response.get("success") or not token:
        raise CyberArkAuthError(f"OOBAUTHPIN authentication failed: {pin_response.get('Message', 'Unknown error')}")

    token_lifetime = int(result_data.get("TokenLifetime", 3600))
    expiry = datetime.fromtimestamp(time.time() + token_lifetime)

    return IdentitySession(
        token=str(token),
        token_expiry=expiry,
        identity_url=identity_url,
        pcloud_url=pcloud_url,
        username=username,
        auth_method="OOBAUTHPIN",
        session_id=session_id,
        refresh_token=result_data.get("RefreshToken"),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------
def test_identity_token(token: str) -> bool:
    """
    Validate token format (JWT 3-part check) and expiry from JWT payload.
    Mirrors Test-IdentityToken.
    """
    if not token:
        return False

    parts = token.split(".")
    if len(parts) != 3:
        return False

    try:
        payload_b64 = parts[1]
        # Restore standard base64 padding
        payload_b64 = payload_b64.replace("-", "+").replace("_", "/")
        padding = (4 - len(payload_b64) % 4) % 4
        payload_b64 += "=" * padding
        payload_bytes = base64.b64decode(payload_b64)
        claims = json.loads(payload_bytes)

        exp = claims.get("exp")
        if exp:
            if time.time() > int(exp):
                write_log("Token has expired.", "Verbose")
                return False

        return True
    except Exception as e:
        write_log(f"Token validation error: {e}", "Verbose")
        return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def get_identity_header(
    *,
    identity_username: str | None = None,
    up_creds: tuple[str, str] | None = None,       # (username, password)
    oauth_creds: tuple[str, str] | None = None,    # (client_id, client_secret)
    pcloud_url: str,
    identity_tenant_url: str | None = None,
    pin: str | None = None,
    force_new_session: bool = False,
    cfg: RestConfig | None = None,
) -> dict[str, str]:
    """
    Main authentication entry point.
    Returns headers dict with Authorization (Bearer) and X-IDAP-NATIVE-CLIENT keys.
    Caches session in module-level singleton.

    Auth dispatch:
      - oauth_creds provided → OAuth client credentials flow
      - up_creds provided    → Username/Password + challenge flow
      - identity_username    → Interactive + challenge flow

    Mirrors Get-IdentityHeader.
    """
    global _current_session

    # Use cached session if valid
    if not force_new_session and _current_session is not None:
        if not _current_session.is_expired:
            write_log("Using existing Identity session token.", "Verbose")
            return _current_session.to_headers()
        else:
            write_log("Identity session expired, re-authenticating.", "Verbose")

    # Resolve Identity URL
    if not identity_tenant_url:
        identity_tenant_url = get_identity_url(pcloud_url, cfg=cfg)

    if not identity_tenant_url.startswith("https://"):
        identity_tenant_url = f"https://{identity_tenant_url}"

    write_log(f"Identity URL: {identity_tenant_url}", "Verbose")

    # Auth flow dispatch
    match (oauth_creds, up_creds, identity_username):
        case ((client_id, client_secret), None, None):
            write_log("Using OAuth authentication.", "Verbose")
            session = _oauth_flow(client_id, client_secret, identity_tenant_url, pcloud_url, cfg=cfg)

        case (None, (uname, pwd), None):
            write_log(f"Using Username/Password authentication for {uname}.", "Verbose")
            idaptive_response = _start_authentication(uname, identity_tenant_url, cfg=cfg)
            result = idaptive_response.get("Result") or {}
            if result.get("IdpRedirectShortUrl"):
                session_result = _oobauthpin_flow(
                    idaptive_response, identity_tenant_url, pcloud_url, uname, pin=pin, cfg=cfg
                )
                session = session_result
            else:
                answer_response = _invoke_challenge(
                    idaptive_response, identity_tenant_url, up_creds=(uname, pwd), cfg=cfg
                )
                result_data = answer_response.get("Result") or {}
                token = str(result_data.get("Token", ""))
                if not token:
                    raise CyberArkAuthError(f"Authentication failed: {answer_response.get('Message', 'No token')}")
                token_lifetime = int(result_data.get("TokenLifetime", 3600))
                session = IdentitySession(
                    token=token,
                    token_expiry=datetime.fromtimestamp(time.time() + token_lifetime),
                    identity_url=identity_tenant_url,
                    pcloud_url=pcloud_url,
                    username=uname,
                    auth_method="UP",
                    session_id=str((idaptive_response.get("Result") or {}).get("SessionId", "")),
                    refresh_token=result_data.get("RefreshToken"),  # type: ignore[arg-type]
                )

        case (None, None, uname) if uname:
            write_log(f"Interactive authentication for {uname}.", "Verbose")
            idaptive_response = _start_authentication(uname, identity_tenant_url, cfg=cfg)
            result = idaptive_response.get("Result") or {}
            if result.get("IdpRedirectShortUrl"):
                session_result = _oobauthpin_flow(
                    idaptive_response, identity_tenant_url, pcloud_url, uname, pin=pin, cfg=cfg
                )
                session = session_result
            else:
                answer_response = _invoke_challenge(
                    idaptive_response, identity_tenant_url, cfg=cfg
                )
                result_data = answer_response.get("Result") or {}
                token = str(result_data.get("Token", ""))
                if not token:
                    raise CyberArkAuthError(f"Authentication failed: {answer_response.get('Message', 'No token')}")
                token_lifetime = int(result_data.get("TokenLifetime", 3600))
                session = IdentitySession(
                    token=token,
                    token_expiry=datetime.fromtimestamp(time.time() + token_lifetime),
                    identity_url=identity_tenant_url,
                    pcloud_url=pcloud_url,
                    username=uname,
                    auth_method="MFA",
                    session_id=str((idaptive_response.get("Result") or {}).get("SessionId", "")),
                    refresh_token=result_data.get("RefreshToken"),  # type: ignore[arg-type]
                )

        case _:
            raise CyberArkAuthError(
                "Must supply one of: oauth_creds, up_creds, or identity_username."
            )

    _current_session = session
    write_log(f"Identity authentication successful for {session.username}.", "Success")
    return session.to_headers()
