"""Lean async client for the SentinelOne management API (v2.1) and PowerQuery (SDL).

- Management API: `/web/api/v2.1/...`, header `Authorization: ApiToken <token>`.
- PowerQuery: `/sdl/v2/api/queries` on the same console (launch -> poll -> delete), header
  `Authorization: Bearer <token>`; polling needs the routing header `X-Dataset-Query-Forward-Tag`.

Permissions are enforced by the console (role of the service user). In addition, the client limits
everything to the range site (`S1_SITE_ID`), if set.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import re
from typing import Any
from urllib.parse import quote

import httpx

from .config import settings

API = "/web/api/v2.1"
SDL_QUERIES = "/sdl/v2/api/queries"
UAM_GRAPHQL = "/web/api/v2.1/unifiedalerts/graphql"
# Incidents (Unified Incident Management): separate endpoint, introspection blocked ->
# schema via GET <endpoint>/schema (can be saved to agents/schema/s1_uim_schema.graphql; git-ignored, not in the repo)
UIM_GRAPHQL = "/web/api/v2.1/unifiedincidents/graphql"

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types { ...FullType }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description isDeprecated deprecationReason
    args { ...InputValue }
    type { ...TypeRef }
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
}
"""


def type_ref(t: dict | None) -> str:
    """Introspection TypeRef -> GraphQL notation ([Alert!]!)."""
    if not t:
        return "?"
    if t["kind"] == "NON_NULL":
        return f"{type_ref(t.get('ofType'))}!"
    if t["kind"] == "LIST":
        return f"[{type_ref(t.get('ofType'))}]"
    return t.get("name") or "?"


def schema_to_sdl(schema: dict) -> str:
    """Introspection result -> compact SDL (without built-in __ types), for reading/grep."""
    out = []
    roots = {k: (schema.get(k) or {}).get("name") for k in ("queryType", "mutationType", "subscriptionType")}
    out.append("# Root: " + ", ".join(f"{k}={v}" for k, v in roots.items() if v))
    kw = {"OBJECT": "type", "INPUT_OBJECT": "input", "ENUM": "enum", "INTERFACE": "interface",
          "UNION": "union", "SCALAR": "scalar"}
    types = sorted((t for t in schema["types"] if not t["name"].startswith("__")),
                   key=lambda t: (t["name"] not in roots.values(), t["name"]))
    for t in types:
        if t.get("description"):
            out.append('"""' + t["description"].strip() + '"""')
        k = kw.get(t["kind"], t["kind"].lower())
        if t["kind"] == "SCALAR":
            out.append(f"scalar {t['name']}\n")
            continue
        if t["kind"] == "UNION":
            out.append(f"union {t['name']} = " + " | ".join(type_ref(p) for p in t.get("possibleTypes") or []) + "\n")
            continue
        impl = " implements " + " & ".join(type_ref(i) for i in t["interfaces"]) if t.get("interfaces") else ""
        out.append(f"{k} {t['name']}{impl} {{")
        if t["kind"] == "ENUM":
            out += [f"  {e['name']}" + (" @deprecated" if e.get("isDeprecated") else "") for e in t["enumValues"] or []]
        for f in (t.get("fields") or t.get("inputFields") or []):
            args = ", ".join(f"{a['name']}: {type_ref(a['type'])}"
                             + (f" = {a['defaultValue']}" if a.get("defaultValue") is not None else "")
                             for a in f.get("args") or [])
            desc = f"  # {f['description'].strip().splitlines()[0][:160]}" if f.get("description") else ""
            dep = " @deprecated" if f.get("isDeprecated") else ""
            out.append(f"  {f['name']}{f'({args})' if args else ''}: {type_ref(f['type'])}{dep}{desc}")
        out.append("}\n")
    return "\n".join(out)
PQ_TIMEOUT_S = 90


class S1Error(RuntimeError):
    def __init__(self, status: int, body: str, url: str):
        text = body
        if body.lstrip().startswith("<"):       # HTML error page (e.g. 503 during a console upgrade) -> text only
            text = " ".join(re.sub(r"<style.*?</style>|<[^>]+>", " ", body, flags=re.S).split())
        super().__init__(f"HTTP {status} {url.split('?')[0]}: {text[:800]}")
        self.status = status
        self.body = body


# --------------------------------------------------------------------------- time

_REL_RE = re.compile(r"^-?(?:now-)?(\d+)([smhd])$", re.IGNORECASE)
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def to_iso(value: str | None, default: str = "now-24h") -> str:
    """'now-24h', '-90m', '2h' or ISO -> ISO UTC (for createdAt__gte etc.)."""
    value = (value or default).strip()
    m = _REL_RE.match(value)
    if m:
        n, unit = int(m.group(1)), m.group(2).lower()
        delta = dt.timedelta(**{_UNITS[unit]: n})
        t = dt.datetime.now(dt.timezone.utc) - delta
    elif value.lower() == "now":
        t = dt.datetime.now(dt.timezone.utc)
    else:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_pq_time(value: str | None) -> str | None:
    """Time value for PowerQuery: relative values ('24h', 'now-2h', '-90m') stay relative, ISO -> epoch ms."""
    if not value:
        return None
    value = value.strip()
    m = _REL_RE.match(value)
    if m:
        return f"{m.group(1)}{m.group(2).lower()}"
    if value.isdigit():
        return value
    return str(int(dt.datetime.fromisoformat(to_iso(value).replace("Z", "+00:00")).timestamp() * 1000))


# --------------------------------------------------------------------------- PowerQuery helpers

def split_pipeline(query: str) -> tuple[str, str]:
    """Split the leading filter from the rest ('| …') - pipes inside quotes do not count."""
    quote_ch = None
    i = 0
    while i < len(query):
        c = query[i]
        if quote_ch:
            if c == "\\":
                i += 2
                continue
            if c == quote_ch:
                quote_ch = None
        elif c in ("'", '"'):
            quote_ch = c
        elif c == "|":
            return query[:i].strip(), query[i:].strip()
        i += 1
    return query.strip(), ""


def scope_query(query: str, site_id: str) -> str:
    """Prepend the range site as a mandatory filter (only the leading filter is extended)."""
    if not site_id:
        return query.strip()
    if not re.fullmatch(r"\d+", site_id):
        raise SystemExit(f"S1_SITE_ID {site_id!r} is not a numeric site ID")
    lead, rest = split_pipeline(query)
    scoped = f"site.id = '{site_id}'" + (f" and ({lead})" if lead else "")
    return f"{scoped} {rest}".strip()


# --------------------------------------------------------------------------- Client

class SentinelOne:
    def __init__(self, role: str = "blue"):
        token = settings.s1_token_for(role)
        if not settings.s1_url or not token:
            raise SystemExit("SentinelOne access missing: set S1_CONSOLE_URL and S1_API_TOKEN in docker/.env")
        self.role = role
        self.site_id = settings.s1_site_id
        self._token = token
        self._c = httpx.AsyncClient(base_url=settings.s1_url, timeout=httpx.Timeout(60.0, connect=10.0),
                                    headers={"Accept": "application/json"})

    async def close(self) -> None:
        await self._c.aclose()

    async def __aenter__(self) -> "SentinelOne":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    @staticmethod
    def _check(r: httpx.Response) -> Any:
        if r.status_code >= 400:
            raise S1Error(r.status_code, r.text, str(r.url))
        if not r.content:
            return None
        return r.json() if "json" in r.headers.get("content-type", "") else r.text

    # ------------------------------------------------------------- management API

    async def api(self, method: str, path: str, json: Any = None, params: dict | None = None) -> Any:
        """path relative to /web/api/v2.1 (e.g. '/threats'). Lists in params -> comma-separated."""
        if params:
            params = {k: ",".join(map(str, v)) if isinstance(v, (list, tuple, set)) else v
                      for k, v in params.items() if v not in (None, "", [])}
            params = {k: str(v).lower() if isinstance(v, bool) else v for k, v in params.items()}
        r = await self._c.request(method, f"{API}{path}", json=json, params=params,
                                  headers={"Authorization": f"ApiToken {self._token}"})
        return self._check(r)

    async def paged(self, path: str, params: dict | None = None, limit: int = 1000) -> list[dict]:
        """Cursor paging over GET lists (data + pagination.nextCursor)."""
        out: list[dict] = []
        params = dict(params or {})
        cursor = None
        while len(out) < limit:
            page = {**params, "limit": min(1000, limit - len(out))}
            if cursor:
                page["cursor"] = cursor
            r = await self.api("GET", path, params=page)
            data = r.get("data") or []
            if isinstance(data, dict):        # e.g. /sites returns {"sites": [...]}
                data = next((v for v in data.values() if isinstance(v, list)), [])
            out.extend(data)
            cursor = (r.get("pagination") or {}).get("nextCursor")
            if not cursor or not data:
                break
        return out

    # ------------------------------------------------------------- GraphQL (Unified Alert Management)

    async def graphql(self, query: str, variables: dict | None = None, path: str = UAM_GRAPHQL) -> dict:
        """GraphQL request; GraphQL errors (errors without data) -> S1Error."""
        r = await self._c.post(path, json={"query": query, "variables": variables or {}},
                               headers={"Authorization": f"ApiToken {self._token}"})
        res = self._check(r)
        if isinstance(res, dict) and res.get("errors") and not res.get("data"):
            raise S1Error(400, str(res["errors"])[:1500], path)
        return res

    async def token_details(self) -> dict:
        """createdAt/expiresAt of our own API token."""
        r = await self.api("POST", "/users/api-token-details", json={"data": {"apiToken": self._token}})
        return (r or {}).get("data") or {}

    def site_params(self) -> dict:
        """Site restriction for GET parameters and API filter objects."""
        return {"siteIds": [self.site_id]} if self.site_id else {}

    # ------------------------------------------------------------- PowerQuery

    async def powerquery(self, query: str, start: str | None = "24h", end: str | None = None, *,
                         scoped: bool = True, timeout_s: int = PQ_TIMEOUT_S) -> dict:
        """Run a PowerQuery and return the table: {columns: [...], values: [[...]], matchCount, ...}."""
        q = scope_query(query, self.site_id) if scoped else query.strip()
        body: dict[str, Any] = {"queryType": "PQ", "tenant": True, "queryPriority": "HIGH",
                                "pq": {"query": q, "resultType": "TABLE"}}
        if (s := to_pq_time(start)):
            body["startTime"] = s
        if (e := to_pq_time(end)):
            body["endTime"] = e
        bearer = {"Authorization": f"Bearer {self._token}"}
        r = await self._c.post(SDL_QUERIES, json=body, headers=bearer)
        res = self._check(r)
        tag = r.headers.get("X-Dataset-Query-Forward-Tag", "")
        qid = res.get("id")
        hdr = {**bearer, "X-Dataset-Query-Forward-Tag": tag}
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout_s
            while res.get("data") is None and not res.get("error"):
                if loop.time() > deadline:
                    raise S1Error(408, f"PowerQuery not finished after {timeout_s}s - narrow the time range/query", q)
                await asyncio.sleep(1)
                r = await self._c.get(f"{SDL_QUERIES}/{quote(qid, safe='')}", headers=hdr,
                                      params={"lastStepSeen": res.get("stepsCompleted") or 0})
                res = self._check(r)
        finally:
            if qid:
                try:
                    await self._c.delete(f"{SDL_QUERIES}/{quote(qid, safe='')}", headers=hdr)
                except Exception:  # noqa: BLE001 - cleanup is best effort (the query expires anyway)
                    pass
        if res.get("error"):
            err = res["error"]
            raise S1Error(400, f"{err.get('message')} {err.get('details') or ''}".strip(), q)
        data = res.get("data") or {}
        data["query"] = q
        return data

    # ------------------------------------------------------------- Agents

    async def find_agents(self, host: str) -> list[dict]:
        """Agents of the range site whose computerName (without domain) matches the short name."""
        short = host.strip().split(".")[0].lower()
        agents = await self.paged("/agents", {"computerName__contains": short, **self.site_params()}, limit=50)
        return [a for a in agents if str(a.get("computerName", "")).split(".")[0].lower() == short]
