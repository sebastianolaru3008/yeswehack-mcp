"""
YesWeHack MCP Server

Exposes YesWeHack API functionality to Claude via the Model Context Protocol.
Run with: uv run server.py
"""

import copy
import functools
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


def _tool_errors(fn):
    """Turn API errors that escape a tool into a message string.

    Apply directly under @mcp.tool(); functools.wraps keeps the signature and
    docstring FastMCP builds the tool schema from. Response bodies of
    unexpected statuses are not echoed.
    """

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except NotAuthenticatedError:
            return AUTH_ERROR
        except (ValueError, ForbiddenError, NotFoundError, BadRequestError, ConflictError) as e:
            return str(e)
        except httpx.HTTPStatusError as e:
            return f"HTTP {e.response.status_code} for {e.request.url.path}"
        except httpx.HTTPError as e:
            return f"Request failed: {type(e).__name__}"

    return wrapper


def _redacted(data: object, keys: frozenset[str]) -> object:
    """Deep copy of `data` with every non-null value of `keys` replaced by (hidden)."""
    data = copy.deepcopy(data)

    def walk(value: object):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in keys and child is not None:
                    value[key] = "(hidden)"
                else:
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return data


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
@_tool_errors
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
    except ForbiddenError:
        # /user is a web-session route: Personal Access Tokens get 403 here.
        return "Access forbidden: /user (needs a browser/API login token; Personal Access Tokens get 403)."

    lines = [
        f"Username : {user.get('username', 'N/A')}",
        f"Email    : {user.get('email', 'N/A')}",
        f"Rank     : {user.get('rank', 'N/A')}",
        f"Reputation: {user.get('reputation', 'N/A')}",
    ]
    return "\n".join(lines)


@mcp.tool()
@_tool_errors
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
@_tool_errors
async def list_email_aliases(raw: bool = False) -> str:
    """
    List your YesWeHack email aliases.

    Uses GET /user/email-aliases, a web-session route that is not part of the
    Personal Access Token API: it answers 403 for PATs and needs a browser/API JWT.

    Args:
        raw: Return raw JSON instead of a readable summary.
    """
    path = "/user/email-aliases"
    try:
        client = _client()
        async with client:
            data = await client.get(path)
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except ForbiddenError:
        # Web-session route: Personal Access Tokens get 403 here.
        return f"Access forbidden: {path} (needs a browser/API login token; Personal Access Tokens get 403)."

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
@_tool_errors
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


# ---- helpers ------------------------------------------------------------

def _public_client() -> httpx.AsyncClient:
    """Unauthenticated client for public endpoints (hacktivity)."""
    return httpx.AsyncClient(base_url="https://api.yeswehack.com", timeout=30.0)


def _workflow_state(report: dict) -> str:
    status = report.get("status")
    if isinstance(status, dict):
        return str(status.get("workflow_state") or "?")
    return _compact(status) if status is not None else "?"


def _cvss_summary(report: dict) -> str:
    cvss = report.get("cvss") or {}
    if not isinstance(cvss, dict) or not cvss:
        return "?"
    crit = cvss.get("criticity") or "?"
    score = cvss.get("score")
    return f"{crit}" + (f" ({score})" if score is not None else "")


def _username(obj: object) -> str:
    if isinstance(obj, dict):
        return str(obj.get("username") or obj.get("slug") or "?")
    return "?"


def _format_log(entry: dict) -> str:
    created = _first_present(entry, "created_at") or "?"
    author = _username(entry.get("author"))
    kind = entry.get("type") or "?"
    body = (entry.get("message") or "").strip()
    if kind == "comment":
        return f"[{created}] {author}: {body}"
    extra = []
    old_s, new_s = entry.get("old_status"), entry.get("status")
    if isinstance(old_s, dict) or isinstance(new_s, dict):
        extra.append(f"{_workflow_state({'status': old_s})} -> {_workflow_state({'status': new_s})}")
    old_c, new_c = entry.get("old_cvss"), entry.get("new_cvss")
    if isinstance(new_c, dict) and new_c:
        extra.append(f"cvss {_cvss_summary({'cvss': old_c})} -> {_cvss_summary({'cvss': new_c})}")
    if entry.get("bounty_reward_amount"):
        extra.append(f"reward {entry['bounty_reward_amount']}")
    line = f"[{created}] {author} ({kind}) {' | '.join(extra)}".rstrip()
    return f"{line}: {body}" if body else line


def _format_credential_item(item: dict, include_secrets: bool) -> str:
    pool = item.get("credential_pool") or {}
    title = _first_present(pool, "title", "slug") if isinstance(pool, dict) else None
    parts = [str(title or "credential")]
    if isinstance(pool, dict) and pool.get("slug"):
        parts.append(f"pool: {pool['slug']}")
    if item.get("id") is not None:
        parts.append(f"id: {item['id']}")
    status = _first_present(item, "status")
    if status:
        parts.append(f"status: {status}")
    login = _first_present(item, "login", "email")
    if login:
        parts.append(f"login: {login}")
    if item.get("password"):
        parts.append(f"password: {item['password'] if include_secrets else '(hidden)'}")
    return " | ".join(parts)


# ---- tools --------------------------------------------------------------


@mcp.tool()
@_tool_errors
async def get_program(slug: str) -> str:
    """
    Get full details for a specific program: scope, out-of-scope, reward grid,
    rules, qualifying / non-qualifying vulnerability types, languages.

    Args:
        slug: The program slug/identifier (e.g. 'acme-corp'). Use list_programs to find slugs.
    """
    try:
        client = _client()
        async with client:
            try:
                p = await client.get(f"/programs/{slug}")
                if not isinstance(p, dict):
                    raise NotFoundError("Unexpected response type")
            except (NotFoundError, ForbiddenError):
                # A PAT without access to the program gets 404 here; the listing
                # may still contain it.
                programs = await client.get_all_pages("/programs")
                matches = [x for x in programs if x.get("slug") == slug]
                if not matches:
                    return f"Program '{slug}' not found. Use list_programs to see available slugs."
                p = matches[0]
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR

    scope_lines = "\n".join(
        f"  [{s.get('scope_type_name') or s.get('scope_type') or '?'}] {s.get('scope', '?')}"
        + (f" (asset value: {s['asset_value']})" if s.get("asset_value") else "")
        for s in (p.get("scopes") or [])
        if isinstance(s, dict)
    ) or "  (none listed)"

    oos_lines = "\n".join(
        f"  {s.get('scope', '?') if isinstance(s, dict) else s}"
        for s in (p.get("out_of_scope") or [])
    ) or "  (none listed)"

    reward_parts = []
    if p.get("bounty_reward_min") is not None or p.get("bounty_reward_max") is not None:
        reward_parts.append(f"range: {p.get('bounty_reward_min', 'N/A')} - {p.get('bounty_reward_max', 'N/A')}")
    grid = p.get("reward_grid_default") or {}
    if isinstance(grid, dict):
        for sev in ("low", "medium", "high", "critical"):
            if grid.get(f"bounty_{sev}") is not None:
                reward_parts.append(f"{sev}: {grid[f'bounty_{sev}']}")
    rewards_info = " | ".join(reward_parts) if reward_parts else "N/A"

    def _names(values: object) -> str:
        if not isinstance(values, list) or not values:
            return "none"
        return ", ".join(v.get("name", str(v)) if isinstance(v, dict) else str(v) for v in values)

    sections = [
        f"Title   : {p.get('title', slug)}",
        f"Slug    : {slug}",
        f"Type    : {p.get('type', 'N/A')}",
        f"Status  : {p.get('status', 'N/A')}",
        f"Public  : {_compact(p.get('public'))}",
        f"Bounty  : {_compact(p.get('bounty'))}",
        f"Rewards : {rewards_info}",
        f"Languages: {_names(p.get('supported_languages'))}",
        f"Qualifying vulnerabilities: {_names(p.get('qualifying_vulnerability'))}",
        f"Non-qualifying vulnerabilities: {_names(p.get('non_qualifying_vulnerability'))}",
        "",
        "=== In-Scope Targets ===",
        scope_lines,
        "",
        "=== Out-of-Scope Targets ===",
        oos_lines,
    ]

    rules = (p.get("rules") or "").strip()
    if rules:
        sections += ["", "=== Rules ===", rules]

    account_access = (p.get("account_access") or "").strip()
    if account_access:
        sections += ["", "=== Account Access ===", account_access]

    return "\n".join(sections)


@mcp.tool()
@_tool_errors
async def list_reports(
    program_slug: str,
    status: str = "",
    page: int = 1,
    results_per_page: int = 50,
) -> str:
    """
    List vulnerability reports submitted to a program (one page).

    Args:
        program_slug: The program slug identifier.
        status: Optional workflow-state filter, comma-separated for several:
                new, under_review, more_info, accepted, resolved, wont_fix,
                informative, duplicate, out_of_scope, rtfs, not_applicable,
                invalid, spam, auto_close.
        page: Page number (default 1).
        results_per_page: Page size (default 50, API maximum 100).
    """
    params: dict = {"page": page, "resultsPerPage": results_per_page}
    statuses = [s.strip() for s in status.split(",") if s.strip()]
    if statuses:
        params["filter[status][]"] = statuses
    try:
        client = _client()
        async with client:
            data = await client.get(f"/programs/{program_slug}/reports", params=params)
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError:
        return f"Program '{program_slug}' not found."
    except ForbiddenError:
        return f"Access forbidden: reports of '{program_slug}'."
    except BadRequestError as e:
        return str(e)

    reports = _items_from(data)
    if not reports:
        label = f" with status '{status}'" if status else ""
        return f"No reports found for '{program_slug}'{label}."

    lines = []
    for r in reports:
        if not isinstance(r, dict):
            continue
        lines.append(
            f"[{r.get('id', '?')}] {r.get('local_id', '')} - {r.get('title', '(no title)')}"
            f" | {_workflow_state(r)} | cvss {_cvss_summary(r)}"
        )

    pagination = data.get("pagination", {}) if isinstance(data, dict) else {}
    header = f"{len(lines)} report(s) for '{program_slug}'"
    if pagination:
        header += f" (page {pagination.get('page', page)}/{pagination.get('nb_pages', '?')}, total {pagination.get('nb_results', '?')})"
    return header + ":\n" + "\n".join(lines)


@mcp.tool()
@_tool_errors
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
    except ForbiddenError:
        return f"Access forbidden: report {report_id}."

    program = r.get("program") or {}
    cvss = r.get("cvss") or {}
    bug_type = r.get("bug_type") or {}
    reward = r.get("reward")
    bounty = f"{reward} {r.get('currency') or ''}".strip() if reward not in (None, "") else "N/A"
    return "\n".join([
        f"ID       : {report_id}",
        f"Local ID : {r.get('local_id', 'N/A')}",
        f"Title    : {r.get('title', 'N/A')}",
        f"Status   : {_workflow_state(r)}",
        f"Severity : {cvss.get('criticity') or r.get('criticity') or 'N/A'}",
        f"CVSS     : {_compact(cvss.get('score'))} {cvss.get('vector') or ''}".rstrip(),
        f"Bug type : {bug_type.get('name', 'N/A')}",
        f"Scope    : {r.get('scope') or 'N/A'}",
        f"Program  : {program.get('title', 'N/A')} ({program.get('slug', 'N/A')})",
        f"Hunter   : {_username(r.get('hunter'))}",
        f"Bounty   : {bounty}",
        f"Tracking : {r.get('tracking_status') or 'N/A'}",
        f"Created  : {r.get('created_at', 'N/A')}",
        "",
        "Description:",
        r.get("description") or "(empty)",
    ])


@mcp.tool()
@_tool_errors
async def list_report_comments(report_id: int, include_history: bool = False, raw: bool = False) -> str:
    """
    List comments of a vulnerability report (from /reports/{id}/logs).

    Args:
        report_id: The numeric report ID.
        include_history: Also show non-comment log entries (status, CVSS, reward changes).
        raw: Return raw JSON instead of a readable summary.
    """
    try:
        client = _client()
        async with client:
            data = await client.get(f"/reports/{report_id}/logs")
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError:
        return f"Report {report_id} not found."
    except ForbiddenError:
        return f"Access forbidden for report {report_id} logs."

    if raw:
        return _as_json(_redacted(data, frozenset({"tracker_token", "claim_email"})))

    entries = [e for e in _items_from(data) if isinstance(e, dict)]
    if not include_history:
        entries = [e for e in entries if e.get("type") == "comment"]
    if not entries:
        what = "log entries" if include_history else "comments"
        return f"No {what} found for report {report_id}."

    lines = [_format_log(e) for e in entries]
    noun = "log entry(ies)" if include_history else "comment(s)"
    return f"{len(lines)} {noun} for report {report_id}:\n" + "\n\n".join(lines)


@mcp.tool()
@_tool_errors
async def get_program_credentials(
    program_slug: str,
    include_secrets: bool = False,
    raw: bool = False,
) -> str:
    """
    List the credentials assigned to you and your pending credential requests
    for a program (hunter view, /programs/{slug}/hunter/credentials).

    Args:
        program_slug: Program slug/identifier.
        include_secrets: Print passwords. Off by default; secrets then show as (hidden).
        raw: Return raw JSON instead of a readable summary (passwords stay
             (hidden) unless include_secrets is True).
    """
    try:
        client = _client()
        async with client:
            data = await client.get(f"/programs/{program_slug}/hunter/credentials")
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError:
        return f"Program '{program_slug}' not found."
    except ForbiddenError:
        return f"Access forbidden: credentials of '{program_slug}' (hunter role required)."

    if raw:
        return _as_json(data if include_secrets else _redacted(data, frozenset({"password"})))

    items = data.get("items") if isinstance(data, dict) else None
    items = items if isinstance(items, dict) else {}
    credentials = [c for c in (items.get("credentials") or []) if isinstance(c, dict)]
    requests = [q for q in (items.get("credential_requests") or []) if isinstance(q, dict)]

    if not credentials and not requests:
        return f"No credentials or pending requests for '{program_slug}'."

    out = [f"{len(credentials)} credential(s), {len(requests)} pending request(s) for '{program_slug}'"]
    for c in credentials:
        out.append("  " + _format_credential_item(c, include_secrets=include_secrets))
    for q in requests:
        pool = q.get("credential_pool") or {}
        name = _first_present(pool, "title", "slug") if isinstance(pool, dict) else "?"
        out.append(f"  request: {name} | created: {q.get('created_at', '?')}")
    return "\n".join(out)


@mcp.tool()
@_tool_errors
async def request_program_credentials(
    program_slug: str,
    pool_slug: str = "",
    pool_type: str = "classic",
    email: str = "",
    raw: bool = False,
) -> str:
    """
    Request credentials from a program credential pool
    (POST /programs/{slug}/hunter/ask-credentials/{pool_slug}/{type}).

    This performs a state-changing YesWeHack action.

    Args:
        program_slug: Program slug/identifier.
        pool_slug: Credential pool slug (required).
        pool_type: 'classic' (default), 'email' or 'email-alias'. Only 'email'
                   pools need `email`; it is sent as the request body {"emails": [email]}.
                   'classic' and 'email-alias' requests carry no body.
        email: Email address for 'email' pools (ignored for other pool types).
        raw: Return raw JSON instead of a readable summary.
    """
    if not pool_slug:
        return "pool_slug is required. Use get_program_credentials or the program rules to find pool slugs."
    if pool_type not in ("classic", "email", "email-alias"):
        return "pool_type must be 'classic', 'email' or 'email-alias'."
    if pool_type == "email" and not email:
        return "email is required for pool_type 'email'."

    path = f"/programs/{program_slug}/hunter/ask-credentials/{pool_slug}/{pool_type}"
    payload = {"emails": [email]} if pool_type == "email" else None

    try:
        client = _client()
        async with client:
            data = await client.post(path, json=payload)
    except ValueError as e:
        return str(e)
    except NotAuthenticatedError:
        return AUTH_ERROR
    except NotFoundError:
        return f"Program '{program_slug}' or pool '{pool_slug}' not found."
    except ForbiddenError:
        return f"Access forbidden: cannot request credentials for '{program_slug}'."
    except (BadRequestError, ConflictError) as e:
        return str(e)

    if raw:
        return _as_json(data)
    msg = f"Credential request submitted for pool '{pool_slug}' of '{program_slug}'."
    if data:
        msg += "\n" + _as_json(data)
    return msg


@mcp.tool()
async def get_hacktivity(page: int = 1) -> str:
    """
    Get the public YesWeHack hacktivity feed (/v2/hacktivity). No authentication required.
    Entries carry date, status, bug type and hunter only; the API returns 50 per page.

    Args:
        page: Page number (default 1).
    """
    try:
        async with _public_client() as http:
            resp = await http.get("/v2/hacktivity", params={"page": page})
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        return f"Error fetching hacktivity: {e}"
    except ValueError:
        return "Error fetching hacktivity: invalid JSON"

    items = _items_from(data)
    if not items:
        return f"No hacktivity entries found on page {page}."

    lines = []
    for item in items:
        if not isinstance(item, dict):
            continue
        bug = item.get("bug_type") or {}
        bug_name = bug.get("name", "?") if isinstance(bug, dict) else str(bug)
        lines.append(f"{item.get('date', '?')} | {_username(item.get('hunter'))} | {bug_name} | {item.get('status', '?')}")

    return f"Hacktivity page {page}:\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
