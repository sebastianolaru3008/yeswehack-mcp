"""Shared fixtures: a fake YesWeHack API served through httpx.MockTransport.

Response shapes follow the official OpenAPI spec (https://api.yeswehack.com/doc.json,
v25.24.0) and live responses observed on 2026-11-04.
"""

import json

import httpx
import pytest

import server
from client import YesWeHackClient

PROGRAM = {
    "title": "Acme Corp",
    "slug": "acme-corp",
    "type": "bug-bounty",
    "status": "V",
    "public": False,
    "bounty": True,
    "rules": "Be nice. Report responsibly.",
    "supported_languages": ["GB", "FR"],
    "bounty_reward_min": 50,
    "bounty_reward_max": 5000,
    "reward_grid_default": {
        "bounty_low": 50,
        "bounty_medium": 300,
        "bounty_high": 1000,
        "bounty_critical": 5000,
    },
    "qualifying_vulnerability": ["SQL injection", "XSS"],
    "non_qualifying_vulnerability": ["Clickjacking", "Missing SPF"],
    "scopes": [
        {
            "scope": "https://www.example.com",
            "scope_type": "web-application",
            "scope_type_name": "Web Application",
            "asset_value": "high",
            "report_count": 3,
        }
    ],
    "out_of_scope": ["*.staging.example.com"],
}

REPORT_ITEM = {
    "id": 123,
    "local_id": "#YWH-PGM1234-56",
    "title": "Stored XSS in profile",
    "status": {"workflow_state": "accepted"},
    "cvss": {"criticity": "H", "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L", "version": "v3.1"},
    "hunter": {"username": "janedoe"},
    "program": {"title": "Acme Corp", "slug": "acme-corp"},
    "reward": 1000,
    "currency": "EUR",
    "created_at": "2026-01-02T03:04:05+00:00",
}

REPORT_DETAIL = {
    **REPORT_ITEM,
    "scope": "https://www.example.com",
    "bug_type": {"name": "Cross-Site Scripting (XSS) - Stored", "slug": "xss-stored"},
    "description": "Payload in the display name is rendered unescaped.",
    "tracking_status": "T",
    "priority": None,
}

LOGS = [
    {
        "id": 1,
        "type": "comment",
        "message": "Thanks, we can reproduce.",
        "author": {"username": "triager1"},
        "created_at": "2026-01-03T00:00:00+00:00",
        "private": False,
    },
    {
        "id": 2,
        "type": "status-update",
        "status": {"workflow_state": "accepted"},
        "old_status": {"workflow_state": "under_review"},
        "message": "",
        "author": {"username": "manager1"},
        "created_at": "2026-01-04T00:00:00+00:00",
    },
]

HUNTER_CREDENTIALS = {
    "items": {
        "credentials": [
            {
                "id": 7,
                "login": "testuser",
                "email": None,
                "password": "s3cret",
                "status": "A",
                "credential_pool": {"slug": "web-accounts", "title": "Web accounts", "type": "classic"},
            }
        ],
        "credential_requests": [
            {"credential_pool": {"slug": "mail-accounts", "title": "Mail accounts"}, "created_at": "2026-01-05"}
        ],
    }
}

HACKTIVITY_V2 = {
    "items": [
        {
            "date": "2026-11-03",
            "status": "accepted",
            "bug_type": {"name": "SQL Injection", "slug": "sqli"},
            "hunter": {"username": "janedoe"},
        }
    ]
}


class FakeApi:
    """Routes requests like api.yeswehack.com and records them."""

    def __init__(self):
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        method = request.method
        params = request.url.params

        if path == "/hacktivity":
            return _err(404)
        if path == "/v2/hacktivity":
            return httpx.Response(200, json=HACKTIVITY_V2)
        if path == "/programs/acme-corp" and method == "GET":
            return httpx.Response(200, json=PROGRAM)
        if path == "/programs/acme-corp/reports" and method == "GET":
            statuses = params.get_list("filter[status][]")
            if "bogus" in statuses:
                return _err(400, "Invalid report status")
            items = [REPORT_ITEM]
            if statuses and REPORT_ITEM["status"]["workflow_state"] not in statuses:
                items = []
            return httpx.Response(
                200,
                json={
                    "pagination": {"page": 1, "nb_pages": 1, "results_per_page": 50, "nb_results": len(items)},
                    "items": items,
                },
            )
        if path == "/reports/123" and method == "GET":
            return httpx.Response(200, json=REPORT_DETAIL)
        if path == "/reports/123/logs" and method == "GET":
            return httpx.Response(200, json={"items": LOGS})
        if path == "/reports/123/comments" and method == "GET":
            return _err(405, "Method Not Allowed")
        if path == "/programs/acme-corp/hunter/credentials" and method == "GET":
            return httpx.Response(200, json=HUNTER_CREDENTIALS)
        if path == "/programs/acme-corp/credentials":
            return _err(404)
        if path.startswith("/programs/acme-corp/hunter/ask-credentials/") and method == "POST":
            return httpx.Response(204)  # spec: 204 No Content
        if path == "/login" and method == "POST":
            body = json.loads(request.content)
            if body.get("password") != "pw":
                return _err(401, "Bad credentials")
            return httpx.Response(200, json={"totp_token": "totp-abc"})
        if path == "/account/totp" and method == "POST":
            body = json.loads(request.content)
            if body == {"token": "totp-abc", "code": "123456"}:
                return httpx.Response(200, json={"token": _jwt()})
            return _err(401, "Invalid TOTP")
        return _err(404)


def _err(code: int, message: str = "Not Found") -> httpx.Response:
    return httpx.Response(code, json={"code": code, "message": message})


def _jwt() -> str:
    import base64

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{seg({'alg': 'none'})}.{seg({'exp': 4102444800})}.sig"


@pytest.fixture
def api(monkeypatch, tmp_path):
    fake = FakeApi()
    transport = httpx.MockTransport(fake)
    monkeypatch.setattr(server, "_client", lambda: YesWeHackClient("pat-token", transport=transport))
    monkeypatch.setattr(server, "_public_client", lambda: httpx.AsyncClient(base_url="https://api.yeswehack.com", transport=transport))
    monkeypatch.setattr("auth.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("auth.TOKEN_FILE", tmp_path / "token.json")
    monkeypatch.setattr("auth.BROWSER_PROFILE_DIR", tmp_path / "browser-profile")
    fake.transport = transport
    return fake
