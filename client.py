"""
YesWeHack API client — async httpx wrapper with auth injection and pagination.
"""

import httpx

BASE_URL = "https://api.yeswehack.com"


class NotAuthenticatedError(Exception):
    pass


class NotFoundError(Exception):
    pass


class YesWeHackClient:
    def __init__(self, token: str):
        self._http = httpx.AsyncClient(
            base_url=BASE_URL,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )

    async def get(self, path: str, params: dict | None = None) -> dict:
        resp = await self._http.get(path, params=params)
        if resp.status_code == 401:
            raise NotAuthenticatedError("Token expired or invalid.")
        if resp.status_code == 404:
            raise NotFoundError(f"Resource not found: {path}")
        resp.raise_for_status()
        return resp.json()

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
