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

# Well-known extension IDs to auto-detect from Windows Chrome/Edge/Brave in WSL2.
_KNOWN_EXTENSION_IDS: dict[str, str] = {
    "aeblfdkhhhdcdjpifhhbdiojplfjncoa": "1Password (Chrome)",
    "dppgmdbiimibapkepcbdbmkaabgiofem": "1Password (Edge)",
    "khgocmkkpikpnmmkgmdnfckapcdkgfaf": "1Password X",
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "fhgenkpocbhhddlgkjnpjkfeclcneobp": "Bitwarden",
}

# Windows Chrome/Edge/Brave extension directories accessible from WSL2
_WIN_EXTENSION_DIRS: list[Path] = []
for _user_dir in Path("/mnt/c/Users").glob("*"):
    if not _user_dir.is_dir() or _user_dir.name in {"All Users", "Default", "Default User", "Public"}:
        continue
    for _browser_path in [
        _user_dir / "AppData/Local/Google/Chrome/User Data/Default/Extensions",
        _user_dir / "AppData/Local/Microsoft/Edge/User Data/Default/Extensions",
        _user_dir / "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Extensions",
    ]:
        if _browser_path.is_dir():
            _WIN_EXTENSION_DIRS.append(_browser_path)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    BROWSER_PROFILE_DIR.mkdir(parents=True, exist_ok=True)


def _save_token(token: str, exp: float):
    _ensure_config_dir()
    TOKEN_FILE.write_text(json.dumps({"token": token, "exp": exp}))


def load_token() -> str | None:
    """Return the stored bearer token if it exists and is not expired."""
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
# Mode 1: API login
# ---------------------------------------------------------------------------

class TotpRequired(Exception):
    """Raised when the server requires a TOTP code to complete login."""


async def api_login(email: str, password: str, totp: str | None = None) -> str:
    """
    Authenticate via POST /login.  Handles the two-step TOTP flow:
      - First call: email + password only.
      - If the server returns {"totp": true}, raise TotpRequired.
      - Second call: email + password + totp code.
    """
    payload: dict = {"email": email, "password": password}
    if totp:
        payload["otp"] = totp

    async with httpx.AsyncClient(base_url=API_BASE, timeout=15.0) as http:
        resp = await http.post("/login", json=payload)

    data = resp.json()

    if resp.status_code == 401:
        msg = data.get("message", "Invalid credentials.")
        raise ValueError(f"Login failed: {msg}")

    if resp.status_code not in (200, 201):
        raise ValueError(f"Login error {resp.status_code}: {data.get('message', resp.text)}")

    # TOTP required — server may return 200 with a flag or 401 with a specific message
    if data.get("otp") or data.get("totp"):
        raise TotpRequired("TOTP required. Call authenticate again with the totp argument.")

    token = data.get("token") or data.get("access_token")
    if not token:
        raise ValueError(f"No token in response. Keys: {list(data.keys())}")

    return _format_result(token)


# ---------------------------------------------------------------------------
# Mode 2: Browser login (Playwright fallback)
# ---------------------------------------------------------------------------

def _find_extensions() -> list[str]:
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

    for ext_dir in _WIN_EXTENSION_DIRS:
        for ext_id, name in _KNOWN_EXTENSION_IDS.items():
            ext_base = ext_dir / ext_id
            if not ext_base.is_dir():
                continue
            versions = sorted(ext_base.iterdir(), reverse=True)
            if versions:
                paths.append(str(versions[0]))
                logger.info("Auto-detected extension '%s' at %s", name, versions[0])

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
