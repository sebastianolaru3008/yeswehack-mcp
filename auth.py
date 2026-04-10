"""
YesWeHack browser-based authentication using Playwright.

Opens a real Chromium window so the user can log in through the YesWeHack
web UI (including 2FA). The JWT is captured from localStorage automatically.
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import jwt

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".config" / "yeswehack-mcp"
TOKEN_FILE = CONFIG_DIR / "token.json"
BROWSER_PROFILE_DIR = CONFIG_DIR / "browser-profile"

LOGIN_URL = "https://yeswehack.com/sign-in"
POLL_INTERVAL = 1.0   # seconds
POLL_TIMEOUT = 300.0  # 5 minutes


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
        # If we can't decode, set exp to 24h from now as a safe default
        return time.time() + 86400


async def browser_login() -> str:
    """
    Open a Chromium browser window, wait for the user to log in to YesWeHack,
    capture the JWT from localStorage, store it, and return a confirmation message.
    """
    # Check for display availability in WSL2
    display = os.environ.get("DISPLAY", "")
    if not display and sys.platform == "linux":
        # WSLg may set WAYLAND_DISPLAY even without DISPLAY
        wayland = os.environ.get("WAYLAND_DISPLAY", "")
        if not wayland:
            raise RuntimeError(
                "No display found (DISPLAY and WAYLAND_DISPLAY are not set). "
                "Browser-based auth requires WSLg or a running X server. "
                "Run: export DISPLAY=:0  or ensure WSLg is enabled."
            )

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise RuntimeError(
            "Playwright is not installed. Run: uv run playwright install chromium"
        )

    _ensure_config_dir()

    logger.info("Launching Chromium for YesWeHack login...")
    print(
        "\n[yeswehack-mcp] Opening browser — please log in to YesWeHack.\n"
        "The window will close automatically once your session is captured.\n",
        file=sys.stderr,
    )

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(BROWSER_PROFILE_DIR),
            headless=False,
            args=["--no-sandbox"],
        )

        page = context.pages[0] if context.pages else await context.new_page()
        await page.goto(LOGIN_URL)

        token: str | None = None
        elapsed = 0.0

        while elapsed < POLL_TIMEOUT:
            try:
                value = await page.evaluate("localStorage.getItem('access_token')")
                if value and isinstance(value, str) and len(value) > 20:
                    token = value
                    break
            except Exception:
                pass  # page may be navigating; keep polling

            await asyncio.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        await context.close()

    if not token:
        raise RuntimeError(
            "Authentication timed out after 5 minutes. "
            "Please call authenticate again and complete login within the time limit."
        )

    exp = _decode_exp(token)
    _save_token(token, exp)

    exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logger.info("Token captured and stored. Expires: %s", exp_dt)
    return f"Authenticated successfully. Token valid until {exp_dt}."
