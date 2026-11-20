"""Lean async client for Elasticsearch and Kibana, with a separate user per agent role.

Permissions are enforced by Elastic (roles range_blue/range_red/range_orchestrator), not by
the prompt: Blue physically cannot read range-groundtruth.
"""
from __future__ import annotations

import ssl
from typing import Any

import httpx

from .config import ROLE_USERS, settings


class ElasticError(RuntimeError):
    def __init__(self, status: int, body: str, url: str):
        super().__init__(f"HTTP {status} {url}: {body[:800]}")
        self.status = status
        self.body = body


class Elastic:
    def __init__(self, role: str):
        user, pw_attr = ROLE_USERS[role]
        password = getattr(settings, pw_attr)
        if not password:
            raise SystemExit(f"Password for Elastic user {user} is missing (RANGE_*_PASSWORD in docker/.env)")
        self.role = role
        self.user = user
        ctx = ssl.create_default_context(cafile=settings.ca_cert)
        common = dict(auth=(user, password), verify=ctx, timeout=httpx.Timeout(60.0, connect=10.0))
        self._es = httpx.AsyncClient(base_url=settings.es_url, **common)
        self._kb = httpx.AsyncClient(
            base_url=settings.kibana_url,
            headers={"kbn-xsrf": "ai-range", "elastic-api-version": "2023-10-31"},
            **common,
        )

    async def close(self) -> None:
        await self._es.aclose()
        await self._kb.aclose()

    async def __aenter__(self) -> "Elastic":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    @staticmethod
    def _check(r: httpx.Response) -> Any:
        if r.status_code >= 400:
            raise ElasticError(r.status_code, r.text, str(r.url))
        if not r.content:
            return None
        ctype = r.headers.get("content-type", "")
        return r.json() if "json" in ctype else r.text

    async def es(self, method: str, path: str, json: Any = None, params: dict | None = None) -> Any:
        return self._check(await self._es.request(method, path, json=json, params=params))

    async def kibana(self, method: str, path: str, json: Any = None, params: dict | None = None,
                     headers: dict | None = None) -> Any:
        return self._check(await self._kb.request(method, path, json=json, params=params, headers=headers))

    async def index_doc(self, data_stream: str, doc: dict) -> None:
        """Append a document to a data stream (create only, matching create_doc privileges)."""
        await self.es("POST", f"/{data_stream}/_doc", json=doc)

    async def esql(self, query: str, params: list | None = None) -> dict:
        body: dict[str, Any] = {"query": query}
        if params:
            body["params"] = params
        return await self.es("POST", "/_query", json=body, params={"format": "json"})
