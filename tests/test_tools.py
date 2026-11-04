"""Behaviour of the MCP tools against the real YesWeHack API shapes."""

import json

import httpx
import pytest

import auth
import server
from client import YesWeHackClient


async def test_get_hacktivity_uses_v2_endpoint(api):
    out = await server.get_hacktivity()
    assert "/v2/hacktivity" in [r.url.path for r in api.requests]
    assert "janedoe" in out
    assert "SQL Injection" in out
    assert "Error" not in out


async def test_list_report_comments_reads_logs_endpoint(api):
    out = await server.list_report_comments(123)
    assert [r.url.path for r in api.requests] == ["/reports/123/logs"]
    assert "Thanks, we can reproduce." in out
    assert "triager1" in out


async def test_list_report_comments_only_counts_comment_logs(api):
    out = await server.list_report_comments(123)
    assert out.startswith("1 comment(s)")
    assert "manager1" not in out


async def test_list_report_comments_include_history_shows_status_updates(api):
    out = await server.list_report_comments(123, include_history=True)
    assert "under_review" in out and "accepted" in out
    assert "manager1" in out


async def test_list_reports_sends_filter_status_param(api):
    await server.list_reports("acme-corp", status="accepted")
    req = api.requests[-1]
    assert req.url.params.get_list("filter[status][]") == ["accepted"]
    assert "status" not in req.url.params


async def test_list_reports_status_filter_can_exclude_everything(api):
    out = await server.list_reports("acme-corp", status="new")
    assert out.startswith("No reports found")


async def test_list_reports_prints_workflow_state_and_cvss(api):
    out = await server.list_reports("acme-corp")
    assert "accepted" in out
    assert "H" in out and "7.5" in out
    assert "workflow_state" not in out


async def test_list_reports_invalid_status_returns_api_message(api):
    out = await server.list_reports("acme-corp", status="bogus")
    assert "Invalid report status" in out


async def test_get_report_shows_cvss_status_bug_type_and_scope(api):
    out = await server.get_report(123)
    assert "accepted" in out
    assert "CVSS:3.1/AV:N/AC:L" in out
    assert "7.5" in out
    assert "Cross-Site Scripting (XSS) - Stored" in out
    assert "https://www.example.com" in out
    header = out.split("Description:")[0]
    assert "Severity : H" in header
    assert "Status   : accepted" in header
    assert ": N/A" not in header


async def test_get_program_uses_real_field_names(api):
    out = await server.get_program("acme-corp")
    assert "Be nice. Report responsibly." in out  # rules
    assert "GB, FR" in out  # supported_languages
    assert "50" in out and "5000" in out  # bounty_reward_min/max
    assert "Clickjacking" in out  # non_qualifying_vulnerability
    assert "SQL injection" in out  # qualifying_vulnerability
    assert "[Web Application] https://www.example.com" in out  # scope_type_name
    assert "*.staging.example.com" in out  # out_of_scope strings
    assert "N/A" not in out


async def test_get_program_prints_reward_grid(api):
    out = await server.get_program("acme-corp")
    assert "low: 50" in out and "critical: 5000" in out


async def test_get_program_credentials_uses_hunter_endpoint(api):
    out = await server.get_program_credentials("acme-corp")
    assert [r.url.path for r in api.requests] == ["/programs/acme-corp/hunter/credentials"]
    assert "testuser" in out
    assert "Mail accounts" in out  # pending request shown


async def test_get_program_credentials_hides_secrets_by_default(api):
    out = await server.get_program_credentials("acme-corp")
    assert "s3cret" not in out
    out = await server.get_program_credentials("acme-corp", include_secrets=True)
    assert "s3cret" in out


async def test_request_program_credentials_posts_emails_list(api):
    out = await server.request_program_credentials(
        "acme-corp", pool_slug="mail-accounts", pool_type="email", email="hunter@example.com"
    )
    req = api.requests[-1]
    assert req.method == "POST"
    assert req.url.path == "/programs/acme-corp/hunter/ask-credentials/mail-accounts/email"
    assert json.loads(req.content) == {"emails": ["hunter@example.com"]}
    assert "submitted" in out


async def test_request_program_credentials_classic_has_no_body(api):
    await server.request_program_credentials("acme-corp", pool_slug="web-accounts")
    req = api.requests[-1]
    assert req.url.path == "/programs/acme-corp/hunter/ask-credentials/web-accounts/classic"
    assert req.content in (b"", b"{}")


async def test_request_program_credentials_requires_pool_slug(api):
    out = await server.request_program_credentials("acme-corp")
    assert "pool_slug" in out
    assert api.requests == []


async def test_api_login_returns_totp_required_without_code(api):
    with pytest.raises(auth.TotpRequired):
        await auth.api_login("user@example.com", "pw", transport=api.transport)


async def test_api_login_completes_totp_via_account_totp(api):
    out = await auth.api_login("user@example.com", "pw", "123456", transport=api.transport)
    paths = [(r.method, r.url.path) for r in api.requests]
    assert paths == [("POST", "/login"), ("POST", "/account/totp")]
    assert json.loads(api.requests[0].content) == {"email": "user@example.com", "password": "pw"}
    assert "Authenticated successfully" in out
    assert json.loads((auth.TOKEN_FILE).read_text())["token"].startswith("eyJ")


async def test_get_current_user_reports_403_for_pat_instead_of_raising(monkeypatch):
    # Live API: GET /user answers 403 for a Personal Access Token (JWT-only route).
    transport = httpx.MockTransport(lambda request: httpx.Response(403, json={"code": 403, "message": "Forbidden"}))
    monkeypatch.setattr(server, "_client", lambda: YesWeHackClient("pat-token", transport=transport))
    out = await server.get_current_user()
    assert out.startswith("Access forbidden: /user")


# ---- fix wave: shared helpers ---------------------------------------------


def _serve(monkeypatch, handler):
    """Route both the authenticated and the public client through `handler`."""
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(server, "_client", lambda: YesWeHackClient("pat-token", transport=transport))
    monkeypatch.setattr(
        server,
        "_public_client",
        lambda: httpx.AsyncClient(base_url="https://api.yeswehack.com", transport=transport),
    )


def _status(code: int):
    return lambda request: httpx.Response(code, json={"code": code, "message": "body-detail"})


def _json(payload):
    return lambda request: httpx.Response(200, json=payload)


# ---- 1: tools return strings for API errors instead of raising -------------


async def test_list_programs_400_returns_message(monkeypatch):
    _serve(monkeypatch, _status(400))
    out = await server.list_programs()
    assert "400" in out and "/programs" in out


async def test_list_programs_403_returns_message(monkeypatch):
    _serve(monkeypatch, _status(403))
    out = await server.list_programs()
    assert out == "Access forbidden: /programs"


async def test_get_program_double_404_returns_message(monkeypatch):
    _serve(monkeypatch, _status(404))
    out = await server.get_program("nope")
    assert out == "Resource not found: /programs"


async def test_get_current_user_404_returns_message(monkeypatch):
    _serve(monkeypatch, _status(404))
    out = await server.get_current_user()
    assert out == "Resource not found: /user"


async def test_api_get_405_returns_status_and_path(api):
    out = await server.yeswehack_api_get("/reports/123/comments")
    assert out == "HTTP 405 for /reports/123/comments"


async def test_get_report_500_returns_status_without_body(monkeypatch):
    _serve(monkeypatch, _status(500))
    out = await server.get_report(123)
    assert out == "HTTP 500 for /reports/123"


async def test_transport_error_returns_message(monkeypatch):
    def boom(request):
        raise httpx.ConnectError("connection refused", request=request)

    _serve(monkeypatch, boom)
    out = await server.list_report_comments(123)
    assert out == "Request failed: ConnectError"


def test_tool_schemas_survive_error_decorator():
    tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    assert len(tools) == 12
    props = tools["list_reports"].parameters["properties"]
    assert set(props) == {"program_slug", "status", "page", "results_per_page"}
    assert "workflow-state filter" in tools["list_reports"].description


# ---- 2: raw credentials respect include_secrets ----------------------------


async def test_get_program_credentials_raw_hides_passwords(api):
    out = await server.get_program_credentials("acme-corp", raw=True)
    assert "s3cret" not in out
    assert json.loads(out)["items"]["credentials"][0]["password"] == "(hidden)"


async def test_get_program_credentials_raw_with_secrets_shows_passwords(api):
    out = await server.get_program_credentials("acme-corp", raw=True, include_secrets=True)
    assert json.loads(out)["items"]["credentials"][0]["password"] == "s3cret"


# ---- 4: only 'email' pools send a body -------------------------------------


async def test_request_program_credentials_email_alias_has_no_body(api):
    out = await server.request_program_credentials("acme-corp", pool_slug="alias-accounts", pool_type="email-alias")
    assert "submitted" in out
    req = api.requests[-1]
    assert req.url.path == "/programs/acme-corp/hunter/ask-credentials/alias-accounts/email-alias"
    assert req.content in (b"", b"{}")


async def test_request_program_credentials_email_pool_requires_email(api):
    out = await server.request_program_credentials("acme-corp", pool_slug="mail-accounts", pool_type="email")
    assert out == "email is required for pool_type 'email'."
    assert api.requests == []


# ---- 5: token file permissions ---------------------------------------------


def test_token_file_is_private(monkeypatch, tmp_path):
    import stat

    cfg = tmp_path / "cfg"
    monkeypatch.setattr(auth, "CONFIG_DIR", cfg)
    monkeypatch.setattr(auth, "TOKEN_FILE", cfg / "token.json")
    monkeypatch.setattr(auth, "BROWSER_PROFILE_DIR", cfg / "browser-profile")
    auth.direct_token_auth("x")
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o700
    assert stat.S_IMODE(auth.TOKEN_FILE.stat().st_mode) == 0o600
    # An existing world-readable file is tightened on the next save.
    auth.TOKEN_FILE.chmod(0o644)
    auth.direct_token_auth("y")
    assert stat.S_IMODE(auth.TOKEN_FILE.stat().st_mode) == 0o600
    assert json.loads(auth.TOKEN_FILE.read_text())["token"] == "y"


# ---- 6: raw report logs hide tracker tokens and claim emails ---------------


async def test_list_report_comments_raw_hides_tracker_token_and_claim_email(monkeypatch):
    entry = {
        "id": 3,
        "type": "tracker-update",
        "tracker_token": "trk-0000",
        "claim_email": "claimer@example.com",
        "author": {"username": "manager1"},
        "created_at": "2026-01-05T00:00:00+00:00",
    }
    _serve(monkeypatch, _json({"items": [entry]}))
    out = await server.list_report_comments(123, raw=True)
    assert "trk-0000" not in out and "claimer@example.com" not in out
    logged = json.loads(out)["items"][0]
    assert logged["tracker_token"] == "(hidden)" and logged["claim_email"] == "(hidden)"


# ---- 7: email_alias is a boolean, never a login ----------------------------


async def test_credential_item_does_not_print_email_alias_flag_as_login(monkeypatch):
    item = {"id": 8, "login": None, "email": None, "email_alias": True, "status": "A",
            "credential_pool": {"slug": "alias-accounts", "title": "Alias accounts"}}
    _serve(monkeypatch, _json({"items": {"credentials": [item], "credential_requests": []}}))
    out = await server.get_program_credentials("acme-corp")
    assert "Alias accounts" in out
    assert "login:" not in out


# ---- 8: CVSS line shows N/A for a missing score ----------------------------


async def test_get_report_cvss_without_score_shows_na(monkeypatch):
    from conftest import REPORT_DETAIL

    report = {**REPORT_DETAIL, "cvss": {"criticity": "L", "score": None, "vector": "CVSS:3.1/AV:L"}}
    _serve(monkeypatch, _json(report))
    out = await server.get_report(123)
    assert "CVSS     : N/A CVSS:3.1/AV:L" in out.splitlines()


# ---- 9: list_email_aliases calls the route directly ------------------------


async def test_list_email_aliases_403_for_pat(monkeypatch):
    _serve(monkeypatch, _status(403))
    out = await server.list_email_aliases()
    assert out.startswith("Access forbidden: /user/email-aliases")


async def test_list_email_aliases_lists_items(monkeypatch):
    _serve(monkeypatch, _json({"items": [{"email": "alias@example.com", "enabled": True}]}))
    out = await server.list_email_aliases()
    assert out.startswith("1 email alias(es). Endpoint used: /user/email-aliases")
    assert "alias@example.com | enabled: yes" in out


# ---- 10: hacktivity with a non-JSON body -----------------------------------


async def test_get_hacktivity_invalid_json(monkeypatch):
    _serve(monkeypatch, lambda request: httpx.Response(200, text="<html>maintenance</html>"))
    out = await server.get_hacktivity()
    assert out == "Error fetching hacktivity: invalid JSON"


# ---- 11: ask-credentials answers 204 with no body --------------------------


async def test_request_program_credentials_empty_204_message(api):
    out = await server.request_program_credentials("acme-corp", pool_slug="web-accounts")
    assert out == "Credential request submitted for pool 'web-accounts' of 'acme-corp'."
