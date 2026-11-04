"""READ-ONLY live tests against the real YesWeHack API.

Run with `make test-live` (loads YWH_PAT from ./.env). Every call below goes
through a server tool that issues HTTP GET only. Never add calls to
`request_program_credentials`, `authenticate` or any write method here.

Assertions check structure, headers and labels only: no token, report body,
hunter name or credential value is printed, asserted or written to disk.
"""

import json
import os
import re

import pytest

import server

pytestmark = pytest.mark.live

if not os.environ.get("YWH_PAT", "").strip():
    pytest.skip("YWH_PAT not set", allow_module_level=True)
# load_token() prefers YWH_TOKEN over YWH_PAT, so a session JWT would silently
# drive the suite. Refuse instead of guessing which token is in use.
if os.environ.get("YWH_TOKEN", "").strip():
    pytest.skip("YWH_TOKEN set; live suite requires a PAT in YWH_PAT only", allow_module_level=True)


# Module-level cache so the file performs about a dozen GET requests in total.
_CACHE: dict[str, object] = {}


async def _programs_output() -> str:
    if "programs" not in _CACHE:
        _CACHE["programs"] = await server.list_programs(all_pages=False)
    return _CACHE["programs"]


async def _first_slug() -> str:
    if "slug" not in _CACHE:
        match = re.search(r"\(slug: ([^,]+), status:", await _programs_output())
        found = match is not None
        assert found, "list_programs returned no program line with a slug"
        _CACHE["slug"] = match.group(1)
    return _CACHE["slug"]


async def _accepted_reports_output() -> str:
    if "reports" not in _CACHE:
        _CACHE["reports"] = await server.list_reports(
            await _first_slug(), status="accepted,resolved", results_per_page=2
        )
    return _CACHE["reports"]


async def _first_report_id() -> int:
    if "report_id" not in _CACHE:
        match = re.search(r"^\[(\d+)\]", await _accepted_reports_output(), re.MULTILINE)
        if not match:
            pytest.skip("first program has no accepted/resolved report to inspect")
        _CACHE["report_id"] = int(match.group(1))
    return _CACHE["report_id"]


def _field(output: str, label: str) -> str:
    """Return the line starting with `label`, failing if it is absent."""
    for line in output.splitlines():
        if line.startswith(label):
            return line
    raise AssertionError(f"missing line {label!r}")


def _is_na(output: str, label: str) -> bool:
    line = _field(output, label)
    return line.rstrip().endswith("N/A")


# Every assert below checks a pre-bound bool or int with a fixed-text message.
# Pytest's assertion rewriting would otherwise echo the tool output (program,
# report, credential or profile text) into the failure report.


# (a)
async def test_list_programs_has_slug_line():
    out = await _programs_output()
    has_header = out.startswith("Found ")
    assert has_header, "missing 'Found N program(s)' header"
    has_slug_line = any("slug:" in line for line in out.splitlines()[1:])
    assert has_slug_line, "no program line with 'slug:'"


# (b)
async def test_get_program_details():
    out = await server.get_program(await _first_slug())
    starts_with_title = out.startswith("Title   :")
    assert starts_with_title, "no Title line"
    for label in ("Rewards :", "Languages:"):
        _field(out, label)
    has_scope_header = "=== In-Scope Targets ===" in out
    assert has_scope_header, "missing In-Scope header"
    for label in ("Status  :", "Public  :", "Bounty  :"):
        is_na = _is_na(out, label)
        assert not is_na, f"{label} is N/A"


# (c)
async def test_list_reports_status_filter_and_bad_status():
    out = await _accepted_reports_output()
    if out.startswith("No reports found"):
        pytest.skip("first program has no accepted/resolved reports")
    has_page = "(page 1/" in out.splitlines()[0]
    assert has_page, "header lacks '(page 1/'"
    n_reports = len(out.splitlines()) - 1
    assert n_reports <= 2, f"{n_reports} report lines"  # results_per_page=2 is honoured

    bad = await server.list_reports(await _first_slug(), status="bogus")
    has_400 = "400" in bad
    assert has_400, "status=bogus did not report HTTP 400"


# (d)
async def test_get_report_core_fields_filled():
    out = await server.get_report(await _first_report_id())
    for label in ("Status   :", "Severity :", "CVSS     :", "Bug type :"):
        is_na = _is_na(out, label)
        assert not is_na, f"{label} is N/A"


def _count_from_header(output: str, empty_prefix: str, suffix: str) -> int:
    first = output.splitlines()[0]
    if first.startswith(empty_prefix):
        return 0
    header_ok = first.endswith(suffix)
    assert header_ok, f"header does not end with {suffix!r}"
    return int(first.split()[0])


# (e)
async def test_list_report_comments_default_and_history():
    report_id = await _first_report_id()
    default = await server.list_report_comments(report_id)
    default_count = _count_from_header(
        default, "No comments found", f"comment(s) for report {report_id}:"
    )
    history = await server.list_report_comments(report_id, include_history=True)
    history_count = _count_from_header(
        history, "No log entries found", f"log entry(ies) for report {report_id}:"
    )
    assert history_count >= default_count, f"{history_count} < {default_count}"


# (f)
async def test_get_program_credentials_listing_or_forbidden():
    slug = await _first_slug()
    out = await server.get_program_credentials(slug)
    forbidden = out == f"Access forbidden: credentials of '{slug}' (hunter role required)."
    listing = re.match(r"\d+ credential\(s\), \d+ pending request\(s\) for ", out) is not None
    empty = out == f"No credentials or pending requests for '{slug}'."
    ok = forbidden or listing or empty
    assert ok, "unexpected credentials answer"


# (g)
async def test_api_get_report_count_by_status():
    out = await server.yeswehack_api_get(f"/programs/{await _first_slug()}/reports/count/status")
    data = json.loads(out)
    has_items_list = isinstance(data, dict) and isinstance(data.get("items"), list)
    assert has_items_list, "response has no 'items' list"


# (h)
async def test_hacktivity_without_token(monkeypatch):
    # get_hacktivity uses _public_client() and never loads a token; the delenv only documents intent.
    monkeypatch.delenv("YWH_PAT", raising=False)
    monkeypatch.delenv("YWH_TOKEN", raising=False)
    out = await server.get_hacktivity(page=1)
    has_header = out.startswith("Hacktivity page 1:")
    assert has_header, "missing 'Hacktivity page 1:' header"


# (i) /user and /user/email-aliases are web-session (JWT) routes. A PAT gets
# 403 (or 401, mapped to the "Not authenticated" message), so either answer
# proves the tool handles the refusal instead of raising.
@pytest.mark.parametrize("tool", ["get_current_user", "list_email_aliases"])
async def test_jwt_only_routes_refuse_pat_gracefully(tool):
    lowered = (await getattr(server, tool)()).lower()
    refused = "forbidden" in lowered or "403" in lowered or "not authenticated" in lowered
    assert refused, f"{tool} did not report a refusal"
