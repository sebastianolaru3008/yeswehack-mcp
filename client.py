"""
YesWeHack API client — async httpx wrapper with auth injection and pagination.
"""

import httpx

BASE_URL = "https://api.yeswehack.com"


class NotAuthenticatedError(Exception):
    pass


class NotFoundError(Exception):
    pass


class ForbiddenError(Exception):
    pass


class BadRequestError(Exception):
    pass


class ConflictError(Exception):
    pass


class YesWeHackClient:
    def __init__(self, token: str):
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        # Browser/API-login sessions are JWTs and use Authorization: Bearer.
        # Official Personal Access Tokens use X-AUTH-TOKEN.
        if token.count(".") == 2 or token.startswith("eyJ"):
            headers = {"Authorization": f"Bearer {token}"}
        else:
            headers = {"X-AUTH-TOKEN": token}

        self._http = httpx.AsyncClient(
            base_url=BASE_URL,
            headers={**headers, "Accept": "application/json"},
            timeout=30.0,
        )

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json: dict | None = None,
    ) -> dict | list | None:
        resp = await self._http.request(method, path, params=params, json=json)
        if resp.status_code == 401:
            raise NotAuthenticatedError("Token expired or invalid.")
        if resp.status_code == 403:
            raise ForbiddenError(f"Access forbidden: {path}")
        if resp.status_code == 404:
            raise NotFoundError(f"Resource not found: {path}")
        if resp.status_code == 409:
            raise ConflictError(_error_message(resp, path))
        if resp.status_code == 400:
            raise BadRequestError(_error_message(resp, path))
        resp.raise_for_status()
        if not resp.content:
            return None
        return resp.json()

    async def get(self, path: str, params: dict | None = None) -> dict | list | None:
        return await self.request("GET", path, params=params)

    async def post(
        self,
        path: str,
        *,
        params: dict | None = None,
        json: dict | None = None,
    ) -> dict | list | None:
        return await self.request("POST", path, params=params, json=json)

    async def patch(
        self,
        path: str,
        *,
        params: dict | None = None,
        json: dict | None = None,
    ) -> dict | list | None:
        return await self.request("PATCH", path, params=params, json=json)

    async def delete(
        self,
        path: str,
        *,
        params: dict | None = None,
        json: dict | None = None,
    ) -> dict | list | None:
        return await self.request("DELETE", path, params=params, json=json)

    async def get_all_pages(self, path: str, extra_params: dict | None = None) -> list:
        results = []
        page = 1
        while True:
            params = {"page": page}
            if extra_params:
                params.update(extra_params)
            data = await self.get(path, params=params)
            items = data.get("items", [])
            if not items:
                break
            results.extend(items)
            nb_pages = data.get("pagination", {}).get("nb_pages", 1)
            if page >= nb_pages:
                break
            page += 1
        return results

    async def close(self):
        await self._http.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self._http.aclose()


def _error_message(resp: httpx.Response, path: str) -> str:
    try:
        data = resp.json()
    except ValueError:
        return f"HTTP {resp.status_code} for {path}: {resp.text}"

    if isinstance(data, dict):
        message = data.get("message") or data.get("detail") or data.get("error")
        if message:
            return f"HTTP {resp.status_code} for {path}: {message}"
    return f"HTTP {resp.status_code} for {path}: {data}"
