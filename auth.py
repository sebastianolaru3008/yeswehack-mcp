"""
YesWeHack authentication.

Two modes:
  1. API login  — POST /login with email + password (+ optional TOTP).
                  No browser required. Use this normally.
  2. Browser login — Playwright Chromium fallback (kept for edge cases).
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import jwt

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".config" / "yeswehack-mcp"
TOKEN_FILE = CONFIG_DIR / "token.json"
BROWSER_PROFILE_DIR = CONFIG_DIR / "browser-profile"
EXTENSIONS_CONFIG = CONFIG_DIR / "extensions.json"

API_BASE = "https://api.yeswehack.com"
LOGIN_URL = "https://yeswehack.com/sign-in"
POLL_INTERVAL = 1.0   # seconds
POLL_TIMEOUT = 300.0  # 5 minutes

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ensure_config_dir():
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    BROWSER_PROFILE_DIR.mkdir(parents=True, exist_ok=True)


def _save_token(token: str, exp: float):
    _ensure_config_dir()
    # Owner-only: the file holds a bearer token. fchmod also tightens a file
    # that an older version created world-readable.
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(json.dumps({"token": token, "exp": exp}))


def load_token() -> str | None:
    """Return the stored bearer token if it exists and is not expired.

    Resolution order:
      1. YWH_TOKEN or YWH_PAT environment variable (used as-is, no expiry check).
      2. Token file (~/.config/yeswehack-mcp/token.json).
    """
    env_token = os.environ.get("YWH_TOKEN", "").strip() or os.environ.get("YWH_PAT", "").strip()
    if env_token:
        return env_token

    if not TOKEN_FILE.exists():
        return None
    try:
        data = json.loads(TOKEN_FILE.read_text())
        exp = float(data.get("exp", 0))
        if time.time() >= exp - 60:
            return None  # expired (or about to expire)
        return data["token"]
    except Exception:
        return None


def _decode_exp(token: str) -> float:
    """Decode JWT and return the exp claim as a Unix timestamp."""
    if token.count(".") != 2 and not token.startswith("eyJ"):
        # Personal Access Tokens are opaque and YesWeHack validates expiry
        # server-side. Keep them locally until the API rejects them.
        return time.time() + (10 * 365 * 24 * 60 * 60)
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return float(payload.get("exp", 0))
    except Exception:
        return time.time() + 86400


def _format_result(token: str) -> str:
    exp = _decode_exp(token)
    _save_token(token, exp)
    exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logger.info("Token stored. Expires: %s", exp_dt)
    return f"Authenticated successfully. Token valid until {exp_dt}."


# ---------------------------------------------------------------------------
# Mode 0: Direct token
# ---------------------------------------------------------------------------

def direct_token_auth(token: str) -> str:
    """Store a pre-obtained bearer token directly, skipping credential login."""
    token = token.strip()
    if not token:
        raise ValueError("Token must not be empty.")
    exp = _decode_exp(token)
    _save_token(token, exp)
    exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logger.info("Direct token stored. Expires: %s", exp_dt)
    return f"Token stored directly. Valid until {exp_dt}."


# ---------------------------------------------------------------------------
# Mode 1: API login
# ---------------------------------------------------------------------------

class TotpRequired(Exception):
    """Raised when the server requires a TOTP code to complete login."""


async def api_login(
    email: str,
    password: str,
    totp: str | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    """
    Authenticate via the JWT session flow used by the official SDK:
      1. POST /login {email, password}
         -> {"token": <jwt>}            when 2FA is off
         -> {"totp_token": <opaque>}    when 2FA is on
      2. POST /account/totp {token: <totp_token>, code: <6 digits>}
         -> {"token": <jwt>}
    Raises TotpRequired when step 2 is needed but no code was given.
    """
    async with httpx.AsyncClient(base_url=API_BASE, timeout=15.0, transport=transport) as http:
        resp = await http.post("/login", json={"email": email, "password": password})
        data = _json_or_empty(resp)

        if resp.status_code == 401:
            raise ValueError(f"Login failed: {data.get('message', 'Invalid credentials.')}")
        if resp.status_code not in (200, 201):
            raise ValueError(f"Login error {resp.status_code}: {data.get('message', resp.text)}")

        token = data.get("token")
        totp_token = data.get("totp_token")

        if not token and totp_token:
            if not totp:
                raise TotpRequired("TOTP required. Call authenticate again with the totp argument.")
            resp = await http.post("/account/totp", json={"token": totp_token, "code": totp})
            data = _json_or_empty(resp)
            if resp.status_code != 200:
                raise ValueError(f"TOTP failed: {data.get('message', resp.text)}")
            token = data.get("token")

    if not token:
        raise ValueError(f"No token in response. Keys: {list(data.keys())}")

    return _format_result(token)


def _json_or_empty(resp: httpx.Response) -> dict:
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# Mode 2: Browser login (Playwright fallback)
# ---------------------------------------------------------------------------

def _find_extensions() -> list[str]:
    """Extensions listed explicitly in ~/.config/yeswehack-mcp/extensions.json (absolute dirs)."""
    paths: list[str] = []

    if EXTENSIONS_CONFIG.exists():
        try:
            user_exts = json.loads(EXTENSIONS_CONFIG.read_text())
            if isinstance(user_exts, list):
                for p in user_exts:
                    ep = Path(p)
                    if ep.is_dir():
                        paths.append(str(ep))
                    else:
                        logger.warning("Configured extension path not found: %s", p)
        except Exception as e:
            logger.warning("Could not read extensions config: %s", e)

    return paths


async def browser_login() -> str:
    """
    Open a Chromium browser window, wait for the user to log in to YesWeHack,
    capture the JWT from localStorage, store it, and return a confirmation message.
    """
    display = os.environ.get("DISPLAY", "")
    if not display and sys.platform == "linux":
        wayland = os.environ.get("WAYLAND_DISPLAY", "")
        if not wayland:
            raise RuntimeError(
                "No display found (DISPLAY and WAYLAND_DISPLAY are not set). "
                "Browser-based auth requires WSLg or a running X server."
            )

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise RuntimeError(
            "Playwright is not installed. Run: uv run playwright install chromium"
        )

    _ensure_config_dir()

    print(
        "\n[yeswehack-mcp] Opening browser — please log in to YesWeHack.\n"
        "The window will close automatically once your session is captured.\n",
        file=sys.stderr,
    )

    extensions = _find_extensions()
    extra_args = ["--no-sandbox"]
    if extensions:
        ext_list = ",".join(extensions)
        extra_args += [
            f"--load-extension={ext_list}",
            f"--disable-extensions-except={ext_list}",
        ]
        logger.info("Loading %d extension(s)", len(extensions))

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(BROWSER_PROFILE_DIR),
            headless=False,
            args=extra_args,
        )

        page = context.pages[0] if context.pages else await context.new_page()

        try:
            await page.goto(LOGIN_URL, wait_until="commit", timeout=15000)
        except Exception as nav_err:
            logger.warning("page.goto failed (%s) — asking user to navigate manually.", nav_err)
            print(
                f"\n[yeswehack-mcp] Auto-navigation failed. "
                f"Please manually type this URL in the browser:\n  {LOGIN_URL}\n",
                file=sys.stderr,
            )

        token: str | None = None
        elapsed = 0.0

        while elapsed < POLL_TIMEOUT:
            try:
                value = await page.evaluate("""() => {
                    const known = localStorage.getItem('access_token');
                    if (known && known.length > 20) return known;
                    for (let i = 0; i < localStorage.length; i++) {
                        const k = localStorage.key(i);
                        const v = localStorage.getItem(k);
                        if (v && v.startsWith('eyJ') && v.length > 50) return v;
                    }
                    return null;
                }""")
                if value and isinstance(value, str) and len(value) > 20:
                    token = value
                    break
            except Exception:
                pass

            await asyncio.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        await context.close()

    if not token:
        raise RuntimeError(
            "Authentication timed out after 5 minutes. "
            "Please call authenticate again and complete login within the time limit."
        )

    return _format_result(token)
