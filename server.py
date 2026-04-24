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
from client import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    NotAuthenticatedError,
    NotFoundError,
    YesWeHackClient,
)

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


def _as_json(data: object) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)


def _parse_params(params_json: str) -> dict:
    if not params_json.strip():
        return {}
    try:
        data = json.loads(params_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"params_json must be a JSON object: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("params_json must be a JSON object.")
    return data


def _items_from(data: object, keys: tuple[str, ...] = ()) -> list:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    if isinstance(data.get("items"), list):
        return data["items"]
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return value
    return []


def _compact(value: object) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (str, int, float)):
        return str(value)
    return _as_json(value)


def _first_present(data: dict, *keys: str) -> object:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None


async def _get_with_fallback(
    client: YesWeHackClient,
    paths: list[str],
    *,
    params: dict | None = None,
) -> tuple[str, object]:
    errors = []
    for path in paths:
        try:
            return path, await client.get(path, params=params)
        except (NotFoundError, ForbiddenError) as e:
            errors.append(f"{path}: {e}")
            continue
    raise NotFoundError("No candidate endpoint worked. Tried:\n" + "\n".join(errors))


async def _post_with_fallback(
    client: YesWeHackClient,
    paths: list[str],
    *,
    payload: dict | None = None,
) -> tuple[str, object]:
    errors = []
    for path in paths:
        try:
            return path, await client.post(path, json=payload or {})
        except (NotFoundError, ForbiddenError, BadRequestError, ConflictError) as e:
            errors.append(f"{path}: {e}")
            continue
    raise NotFoundError("No candidate endpoint worked. Tried:\n" + "\n".join(errors))


def _format_alias(alias: dict) -> str:
    address = _first_present(alias, "email", "alias", "address", "value") or "(unknown alias)"
    enabled = _first_present(alias, "enabled", "active", "is_enabled")
    program = _first_present(alias, "program", "program_title", "program_slug")
    created = _first_present(alias, "created_at", "createdAt", "creation_date")
    parts = [str(address)]
    if enabled is not None:
        parts.append(f"enabled: {_compact(enabled)}")
    if program:
        parts.append(f"program: {_compact(program)}")
    if created:
        parts.append(f"created: {created}")
    return " | ".join(parts)


def _format_credential_item(item: dict, include_secrets: bool) -> str:
    title = _first_present(item, "title", "name", "label", "scope", "asset") or "credential"
    status = _first_present(item, "status", "state", "assignment_status")
    login = _first_present(item, "login", "username", "email", "identifier")
    password = _first_present(item, "password", "secret")
    pool_id = _first_present(item, "id", "uuid", "pool_id", "credential_pool_id")

    parts = [str(title)]
    if pool_id:
        parts.append(f"id: {pool_id}")
    if status:
        parts.append(f"status: {status}")
    if login:
        parts.append(f"login: {login}")
    if password:
        parts.append(f"password: {password if include_secrets else '(hidden)'}")
    return " | ".join(parts)


def _collect_named_lists(data: object, wanted: tuple[str, ...]) -> list[dict]:
    found: list[dict] = []

    def walk(value: object):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in wanted and isinstance(child, list):
                    found.extend(x for x in child if isinstance(x, dict))
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found


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
    Get full details for a specific program, including scope, reward ranges,
    guidelines, requirements, out-of-scope rules, and disabled vulnerability types.

    Args:
        slug: The program slug/identifier (e.g. 'acme-corp'). Use list_programs to find slugs.
    """
    try:
        client = _client()
        async with client:
            try:
                p = await client.get(f"/programs/{slug}")
                if not isinstance(p, dict):
                    raise NotFoundError("Unexpected response type — falling back to list")
            except (NotFoundError, ForbiddenError):
                # Private programs may return 403/404 on the detail endpoint.
                # Fall back to the program listing where they are always present.
                programs = await client.get_all_pages("/programs")
                matches = [x for x in programs if x.get("slug") == slug]
                if not matches:
                    return f"Program '{slug}' not found. Use list_programs to see available slugs."
                p = matches[0]
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR

    # --- Scopes (in-scope) ---
    scopes = p.get("scopes", [])
    scope_lines = "\n".join(
        f"  [{s.get('scope_type', '?')}] {s.get('scope', '?')}"
        + (f" — {s.get('asset_label', '')}" if s.get("asset_label") else "")
        for s in scopes
    ) or "  (none listed)"

    # --- Out-of-scope ---
    out_of_scope = p.get("out_of_scope", [])
    oos_lines = "\n".join(
        f"  [{s.get('scope_type', '?')}] {s.get('scope', '?')}"
        for s in out_of_scope
    ) or "  (none listed)"

    # --- Reward policy ---
    reward = p.get("reward_policy", {}) or {}
    if reward:
        reward_parts = []
        if reward.get("min_reward") is not None or reward.get("max_reward") is not None:
            reward_parts.append(
                f"range: {reward.get('min_reward', 'N/A')} – {reward.get('max_reward', 'N/A')}"
            )
        # Per-severity reward ranges
        for sev in ("critical", "high", "medium", "low", "informative"):
            key = f"{sev}_reward"
            if reward.get(key) is not None:
                reward_parts.append(f"{sev}: {reward[key]}")
        rewards_info = " | ".join(reward_parts) if reward_parts else "N/A"
    else:
        rewards_info = "N/A"

    # --- Disabled vulnerability types ---
    disabled_vuln_types = p.get("disabled_vulnerability_types", []) or []
    disabled_str = ", ".join(
        v.get("name", str(v)) if isinstance(v, dict) else str(v)
        for v in disabled_vuln_types
    ) or "none"

    # --- Guidelines / policy text ---
    guidelines = (p.get("guidelines") or "").strip()
    policy = (p.get("policy") or "").strip()

    # --- Languages ---
    langs = p.get("languages", []) or []
    lang_str = ", ".join(
        la.get("name", str(la)) if isinstance(la, dict) else str(la)
        for la in langs
    ) or "N/A"

    # --- PGP key ---
    pgp_key = (p.get("pgp_key") or "").strip()

    sections = [
        f"Title   : {p.get('title', slug)}",
        f"Slug    : {slug}",
        f"Status  : {p.get('status', 'N/A')}",
        f"Public  : {p.get('public', '?')}",
        f"Bounty  : {p.get('bounty', False)}",
        f"Rewards : {rewards_info}",
        f"Languages: {lang_str}",
        f"Disabled vuln types: {disabled_str}",
        "",
        "=== In-Scope Targets ===",
        scope_lines,
        "",
        "=== Out-of-Scope Targets ===",
        oos_lines,
    ]

    if guidelines:
        sections += ["", "=== Guidelines ===", guidelines]

    if policy:
        sections += ["", "=== Policy / Requirements ===", policy]

    if pgp_key:
        sections += ["", "=== PGP Key ===", pgp_key]

    return "\n".join(sections)


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
async def list_report_comments(report_id: int, raw: bool = False) -> str:
    """
    List comments/messages for a vulnerability report when your token has access.

    Args:
        report_id: The numeric report ID.
        raw: Return raw JSON instead of a readable summary.
    """
    try:
        client = _client()
        async with client:
            path, data = await _get_with_fallback(
                client,
                [
                    f"/reports/{report_id}/comments",
                    f"/reports/{report_id}/messages",
                    f"/reports/{report_id}/activities",
                ],
            )
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError as e:
        return f"Report comments for {report_id} were not found.\n{e}"
    except ForbiddenError:
        return f"Access forbidden for report {report_id} comments."

    if raw:
        return _as_json(data)

    comments = _items_from(data, ("comments", "messages", "activities"))
    if not comments:
        return f"No comments/messages found for report {report_id}. Endpoint used: {path}"

    lines = []
    for c in comments:
        if not isinstance(c, dict):
            continue
        author = c.get("author") or c.get("user") or {}
        if isinstance(author, dict):
            author_name = author.get("username") or author.get("name") or "?"
        else:
            author_name = str(author)
        created = _first_present(c, "created_at", "createdAt", "date") or "?"
        body = _first_present(c, "message", "body", "content", "text") or ""
        lines.append(f"[{created}] {author_name}: {body}")

    return f"{len(lines)} comment/message(s) for report {report_id}:\n" + "\n\n".join(lines)


@mcp.tool()
async def list_email_aliases(raw: bool = False) -> str:
    """
    List your YesWeHack email aliases.

    YesWeHack requires KYC verification for alias usage. The exact UI endpoint is
    not publicly documented, so this tool tries the known API shapes and reports
    the attempted endpoints if none work.

    Args:
        raw: Return raw JSON instead of a readable summary.
    """
    try:
        client = _client()
        async with client:
            path, data = await _get_with_fallback(
                client,
                [
                    "/user/email-aliases",
                    "/users/me/email-aliases",
                    "/me/email-aliases",
                    "/email-aliases",
                    "/email-alias",
                ],
            )
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError as e:
        return str(e)

    if raw:
        return _as_json(data)

    aliases = _items_from(data, ("aliases", "email_aliases", "emailAliases"))
    if not aliases and isinstance(data, dict):
        aliases = _collect_named_lists(data, ("aliases", "email_aliases", "emailAliases"))

    if not aliases:
        return f"No email aliases found. Endpoint used: {path}"

    lines = [_format_alias(a) for a in aliases if isinstance(a, dict)]
    return f"{len(lines)} email alias(es). Endpoint used: {path}\n" + "\n".join(lines)


@mcp.tool()
async def get_program_credentials(
    program_slug: str,
    include_secrets: bool = True,
    raw: bool = False,
) -> str:
    """
    Get credential pools and any assigned credentials for a specific program.

    Some programs expose credential pools only after you are invited/accepted and
    KYC-verified. If credentials require a request first, use
    request_program_credentials with the pool id shown by this tool.

    Args:
        program_slug: Program slug/identifier.
        include_secrets: Include passwords/secrets when the API returns them.
        raw: Return raw JSON instead of a readable summary.
    """
    try:
        client = _client()
        async with client:
            path, data = await _get_with_fallback(
                client,
                [
                    f"/programs/{program_slug}/credentials",
                    f"/programs/{program_slug}/credential-pools",
                    f"/programs/{program_slug}/credentials-pools",
                    f"/programs/{program_slug}/credentials/requests",
                ],
            )
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError as e:
        return f"No credentials endpoint was available for '{program_slug}'.\n{e}"

    if raw:
        return _as_json(data)

    credentials = _items_from(
        data,
        (
            "credentials",
            "credential_pools",
            "credentialPools",
            "pools",
            "requests",
        ),
    )
    if not credentials and isinstance(data, dict):
        credentials = _collect_named_lists(
            data,
            (
                "credentials",
                "credential_pools",
                "credentialPools",
                "pools",
                "requests",
            ),
        )

    if not credentials:
        return f"No credential pools or assigned credentials found for '{program_slug}'. Endpoint used: {path}"

    lines = [
        _format_credential_item(c, include_secrets=include_secrets)
        for c in credentials
        if isinstance(c, dict)
    ]
    return (
        f"{len(lines)} credential item(s) for '{program_slug}'. Endpoint used: {path}\n"
        + "\n".join(lines)
    )


@mcp.tool()
async def request_program_credentials(
    program_slug: str,
    pool_id: str = "",
    email: str = "",
    raw: bool = False,
) -> str:
    """
    Request credentials from a program credential pool.

    This performs a state-changing YesWeHack action. Use get_program_credentials
    first to find an available pool id. Some email-credential pools require an
    email address; pass either a YesWeHack alias or another allowed address.

    Args:
        program_slug: Program slug/identifier.
        pool_id: Optional credential pool id. If omitted, the generic program
                 credential request endpoint is attempted.
        email: Optional email address for email-based credential pools.
        raw: Return raw JSON instead of a readable summary.
    """
    payload = {}
    if email:
        payload["email"] = email

    if pool_id:
        paths = [
            f"/programs/{program_slug}/credentials/{pool_id}/request",
            f"/programs/{program_slug}/credential-pools/{pool_id}/request",
            f"/programs/{program_slug}/credentials-pools/{pool_id}/request",
            f"/programs/{program_slug}/credentials/{pool_id}",
        ]
    else:
        paths = [
            f"/programs/{program_slug}/credentials/request",
            f"/programs/{program_slug}/credentials",
        ]

    try:
        client = _client()
        async with client:
            path, data = await _post_with_fallback(client, paths, payload=payload)
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError as e:
        return f"Could not request credentials for '{program_slug}'.\n{e}"

    if raw:
        return _as_json(data)

    if data is None:
        return f"Credential request submitted for '{program_slug}'. Endpoint used: {path}"

    items = _items_from(data, ("credentials", "requests", "items"))
    if items:
        lines = [
            _format_credential_item(c, include_secrets=True)
            for c in items
            if isinstance(c, dict)
        ]
        return (
            f"Credential request submitted for '{program_slug}'. Endpoint used: {path}\n"
            + "\n".join(lines)
        )

    return (
        f"Credential request submitted for '{program_slug}'. Endpoint used: {path}\n"
        + _as_json(data)
    )


@mcp.tool()
async def yeswehack_api_get(path: str, params_json: str = "") -> str:
    """
    Read an authenticated YesWeHack API endpoint that is not wrapped yet.

    This is a read-only escape hatch for API coverage gaps. Path must be a
    relative API path such as /programs/example or /reports/123.

    Args:
        path: Relative API path beginning with /.
        params_json: Optional JSON object of query parameters.
    """
    if not path.startswith("/") or path.startswith("//") or "://" in path:
        return "path must be a relative API path beginning with '/'."

    try:
        params = _parse_params(params_json)
        client = _client()
        async with client:
            data = await client.get(path, params=params or None)
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError:
        return f"Endpoint not found: {path}"
    except ForbiddenError:
        return f"Access forbidden: {path}"

    return _as_json(data)


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
