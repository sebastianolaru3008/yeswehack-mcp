"""
YesWeHack MCP Server

Exposes YesWeHack API functionality to Claude via the Model Context Protocol.
Run with: uv run server.py
"""

import json
import logging
import sys

import httpx
from mcp.server.fastmcp import FastMCP

from auth import TotpRequired, api_login, browser_login, direct_token_auth, load_token
from client import NotAuthenticatedError, NotFoundError, YesWeHackClient

logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = FastMCP("yeswehack")

AUTH_ERROR = (
    "Not authenticated. Call the `authenticate` tool first, "
    "or your token has expired and you need to log in again."
)


def _client() -> YesWeHackClient:
    token = load_token()
    if not token:
        raise ValueError(AUTH_ERROR)
    return YesWeHackClient(token)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def authenticate(
    email: str = "",
    password: str = "",
    totp: str = "",
    access_token: str = "",
) -> str:
    """
    Authenticate with YesWeHack and store the session token locally.
    Call this first before using any other tool, or when a tool reports
    that authentication is required.

    Option 1 — Direct token: provide access_token to skip credential login entirely.
    Option 2 — API login: provide email + password for a fast, browser-free login.
      If your account has 2FA enabled, the first call will ask for a TOTP code;
      call again with the same email/password and add the totp argument.
    Option 3 — Browser: call with no arguments to open a browser window instead.

    You can also set the YWH_TOKEN environment variable to avoid calling this tool
    at all; it takes precedence over stored credentials.

    Args:
        access_token: A pre-obtained YesWeHack JWT/bearer token (highest priority).
        email:        Your YesWeHack account email.
        password:     Your YesWeHack account password.
        totp:         6-digit TOTP code (only needed when 2FA is enabled).
    """
    if access_token:
        try:
            return direct_token_auth(access_token)
        except ValueError as e:
            return str(e)

    if email and password:
        try:
            return await api_login(email, password, totp or None)
        except TotpRequired as e:
            return str(e)
        except ValueError as e:
            return str(e)

    return await browser_login()


@mcp.tool()
async def get_current_user() -> str:
    """
    Return the profile of the currently authenticated YesWeHack user.
    """
    try:
        client = _client()
        async with client:
            user = await client.get("/user")
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR

    lines = [
        f"Username : {user.get('username', 'N/A')}",
        f"Email    : {user.get('email', 'N/A')}",
        f"Rank     : {user.get('rank', 'N/A')}",
        f"Reputation: {user.get('reputation', 'N/A')}",
    ]
    return "\n".join(lines)


@mcp.tool()
async def list_programs(
    all_pages: bool = True,
    page: int = 1,
    private_only: bool = False,
) -> str:
    """
    List bug bounty programs you have access to, including private invite-only programs.

    Args:
        all_pages: If True (default), fetch all pages and return the complete list.
        page: Specific page to fetch when all_pages is False.
        private_only: If True, return only private (invite-only) programs.
    """
    try:
        client = _client()
        async with client:
            if all_pages:
                programs = await client.get_all_pages("/programs")
            else:
                data = await client.get("/programs", params={"page": page})
                programs = data.get("items", [])
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR

    if private_only:
        programs = [p for p in programs if not p.get("public", True)]

    if not programs:
        return "No programs found."

    lines = []
    for p in programs:
        slug = p.get("slug", "?")
        title = p.get("title", slug)
        status = p.get("status", "?")
        is_public = p.get("public", True)
        visibility = "PUBLIC" if is_public else "PRIVATE"
        bounty = p.get("bounty", False)
        bounty_tag = " [bounty]" if bounty else ""
        lines.append(f"[{visibility}] {title} (slug: {slug}, status: {status}){bounty_tag}")

    header = f"Found {len(programs)} program(s)"
    if private_only:
        header += " (private only)"
    return header + ":\n" + "\n".join(lines)


@mcp.tool()
async def get_program(slug: str) -> str:
    """
    Get full details for a specific program, including scope and reward ranges.

    Args:
        slug: The program slug/identifier (e.g. 'acme-corp'). Use list_programs to find slugs.
    """
    try:
        client = _client()
        async with client:
            try:
                p = await client.get(f"/programs/{slug}")
            except NotFoundError:
                # Fallback: search in the full program list
                programs = await client.get_all_pages("/programs")
                matches = [x for x in programs if x.get("slug") == slug]
                if not matches:
                    return f"Program '{slug}' not found. Use list_programs to see available slugs."
                p = matches[0]
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR

    scopes = p.get("scopes", [])
    scope_lines = "\n".join(
        f"  [{s.get('scope_type', '?')}] {s.get('scope', '?')}"
        for s in scopes
    ) or "  (none listed)"

    reward = p.get("reward_policy", {}) or {}
    rewards_info = (
        f"min: {reward.get('min_reward', 'N/A')} / max: {reward.get('max_reward', 'N/A')}"
        if reward
        else "N/A"
    )

    return "\n".join([
        f"Title   : {p.get('title', slug)}",
        f"Slug    : {slug}",
        f"Status  : {p.get('status', 'N/A')}",
        f"Public  : {p.get('public', '?')}",
        f"Bounty  : {p.get('bounty', False)}",
        f"Rewards : {rewards_info}",
        f"Scopes:\n{scope_lines}",
    ])


@mcp.tool()
async def list_reports(program_slug: str, status: str = "") -> str:
    """
    List vulnerability reports submitted to a program.

    Args:
        program_slug: The program slug identifier.
        status: Optional status filter (e.g. 'accepted', 'informative', 'duplicate',
                'wont_fix', 'new', 'triaged', 'not_applicable').
    """
    try:
        client = _client()
        async with client:
            params: dict = {}
            if status:
                params["status"] = status
            data = await client.get(f"/programs/{program_slug}/reports", params=params or None)
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError:
        return f"Program '{program_slug}' not found."

    reports = data.get("items", [])
    if not reports:
        label = f" with status '{status}'" if status else ""
        return f"No reports found for '{program_slug}'{label}."

    lines = []
    for r in reports:
        rid = r.get("id", "?")
        local_id = r.get("local_id", "")
        title = r.get("title", "(no title)")
        rstatus = r.get("status", "?")
        severity = r.get("severity", "?")
        lines.append(f"[{rid}] {local_id} — {title} | {rstatus} | {severity}")

    return f"{len(reports)} report(s) for '{program_slug}':\n" + "\n".join(lines)


@mcp.tool()
async def get_report(report_id: int) -> str:
    """
    Get full details of a specific vulnerability report.

    Args:
        report_id: The numeric report ID (from list_reports output).
    """
    try:
        client = _client()
        async with client:
            r = await client.get(f"/reports/{report_id}")
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError:
        return f"Report {report_id} not found."

    program = r.get("program", {}) or {}
    return "\n".join([
        f"ID       : {report_id}",
        f"Local ID : {r.get('local_id', 'N/A')}",
        f"Title    : {r.get('title', 'N/A')}",
        f"Status   : {r.get('status', 'N/A')}",
        f"Severity : {r.get('severity', 'N/A')}",
        f"CVSS     : {r.get('cvss_vector', 'N/A')}",
        f"Program  : {program.get('title', 'N/A')} ({program.get('slug', 'N/A')})",
        f"Hunter   : {r.get('hunter', {}).get('username', 'N/A')}",
        f"Bounty   : {r.get('reward', 'N/A')} {r.get('currency', '')}".strip(),
        "",
        "Description:",
        r.get("description", "(empty)"),
    ])


@mcp.tool()
async def get_hacktivity(page: int = 1) -> str:
    """
    Get the public YesWeHack hacktivity feed (publicly disclosed reports).
    No authentication required.

    Args:
        page: Page number (default 1).
    """
    try:
        async with httpx.AsyncClient(
            base_url="https://api.yeswehack.com", timeout=30.0
        ) as http:
            resp = await http.get("/hacktivity", params={"page": page})
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        return f"Error fetching hacktivity: {e}"

    items = data.get("items", [])
    if not items:
        return f"No hacktivity entries found on page {page}."

    lines = []
    for item in items:
        r = item.get("report", item)
        hunter = (r.get("hunter") or {}).get("username", "?")
        title = r.get("title", "?")
        program = (r.get("program") or {}).get("title", "?")
        severity = r.get("severity", "?")
        reward = r.get("reward", "")
        currency = r.get("currency", "")
        reward_str = f" | {reward} {currency}".strip() if reward else ""
        lines.append(f"[{hunter}] {title} @ {program} ({severity}){reward_str}")

    nb_pages = data.get("pagination", {}).get("nb_pages", "?")
    return f"Hacktivity page {page}/{nb_pages}:\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
