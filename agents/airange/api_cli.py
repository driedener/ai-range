"""CLI `api`: generic access to SentinelOne and Elastic for the operator (not for the agents).

Uses the same clients as Blue/Engineer/scorer (sentinelone.py, elastic.py), so site scope, paging and the
PowerQuery flow exist only once. `{SITE}` in the path, parameters, JSON and variables is replaced with
S1_SITE_ID. Output: JSON on stdout; errors on stderr with exit code 1.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .config import ROLE_USERS, settings
from .elastic import Elastic, ElasticError
from .sentinelone import API, S1Error, SentinelOne

GQL = {
    "uam": "/web/api/v2.1/unifiedalerts/graphql",
    "uim": "/web/api/v2.1/unifiedincidents/graphql",
    "xspm-vuln": "/web/api/v2.1/xspm/findings/vulnerabilities/graphql",
    "xspm-misconf": "/web/api/v2.1/xspm/findings/misconfigurations/graphql",
}
ES_ROLES = ["orchestrator", "blue", "red"]


def add_parser(sub) -> None:
    import argparse  # noqa: PLC0415

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", help="write the result to a file (relative to agents/, e.g. reports/x.json)")
    common.add_argument("--compact", action="store_true", help="single-line JSON")
    common.add_argument("--fields", help="only these fields per record in data[]/rows[] (a,b.c)")
    p = sub.add_parser("api", help="SentinelOne/Elastic API directly (operator): s1, gql, pq, es, kb, esql")
    t = p.add_subparsers(dest="target", required=True)

    s = t.add_parser("s1", parents=[common], help="REST, path relative to /web/api/v2.1")
    s.add_argument("method")
    s.add_argument("path")
    s.add_argument("-p", "--param", action="append", default=[], help="key=value, repeatable (same key -> list)")
    s.add_argument("-j", "--json", help="body: JSON, @file or - (stdin)")
    s.add_argument("--all", action="store_true", help="GET with cursor paging across all pages")
    s.add_argument("--limit", type=int, default=10000)
    s.add_argument("--orch", action="store_true", help="scorer token (S1_ORCH_API_TOKEN) instead of S1_API_TOKEN")

    s = t.add_parser("gql", parents=[common], help="GraphQL: uam | uim | xspm-vuln | xspm-misconf | /path ($scope is set automatically)")
    s.add_argument("endpoint")
    s.add_argument("query", help="query, @file or -")
    s.add_argument("-v", "--vars", help="variables: JSON, @file or -")
    s.add_argument("--orch", action="store_true")

    s = t.add_parser("pq", parents=[common], help="PowerQuery (site.id filter added automatically)")
    s.add_argument("query", help="PowerQuery, @file or -")
    s.add_argument("--start", default="24h", help="24h, now-2h, -90m or ISO")
    s.add_argument("--end")
    s.add_argument("--unscoped", action="store_true", help="without the site.id filter")
    s.add_argument("--timeout", type=int, default=120)

    for name, hlp in (("es", "Elasticsearch REST"), ("kb", "Kibana REST")):
        s = t.add_parser(name, parents=[common], help=hlp)
        s.add_argument("method")
        s.add_argument("path")
        s.add_argument("-p", "--param", action="append", default=[])
        s.add_argument("-j", "--json")
        s.add_argument("-u", "--user", choices=ES_ROLES, default="orchestrator")

    s = t.add_parser("esql", parents=[common], help="ES|QL (result as row objects)")
    s.add_argument("query", help="ES|QL, @file or -")
    s.add_argument("-u", "--user", choices=ES_ROLES, default="orchestrator")


# --------------------------------------------------------------------------- helpers

def _subst(text: str) -> str:
    return text.replace("{SITE}", settings.s1_site_id or "{SITE}")


def _read(value: str | None) -> str | None:
    if value is None:
        return None
    if value == "-":
        return sys.stdin.read()
    if value.startswith("@"):
        return Path(value[1:]).read_text(encoding="utf-8")
    return value


def _json(value: str | None) -> Any:
    raw = _read(value)
    return json.loads(_subst(raw)) if raw else None


def _params(items: list[str]) -> dict:
    out: dict[str, Any] = {}
    for item in items:
        k, _, v = item.partition("=")
        v = _subst(v)
        if k in out:
            out[k] = (out[k] if isinstance(out[k], list) else [out[k]]) + [v]
        else:
            out[k] = v
    return out


def _s1_path(path: str) -> str:
    path = _subst(path)
    if path.startswith(API):
        path = path[len(API):]
    return path if path.startswith("/") else "/" + path


def _pick(obj: Any, fields: list[str]) -> Any:
    def one(d: Any) -> dict:
        out = {}
        for f in fields:
            cur = d
            for part in f.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            out[f] = cur
        return out
    if isinstance(obj, list):
        return [one(d) for d in obj]
    if isinstance(obj, dict):
        for key in ("data", "rows"):
            if isinstance(obj.get(key), list):
                return {**{k: v for k, v in obj.items() if k != key}, key: [one(d) for d in obj[key]]}
        if isinstance(obj.get("data"), dict):
            return {**obj, "data": one(obj["data"])}
        return one(obj)
    return obj


def _emit(obj: Any, a) -> None:
    if a.fields:
        obj = _pick(obj, [f.strip() for f in a.fields.split(",") if f.strip()])
    text = obj if isinstance(obj, str) else json.dumps(obj, indent=None if a.compact else 2,
                                                       ensure_ascii=False, default=str)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"-> agents/{a.out} ({len(text)} characters)")
    else:
        print(text)


# --------------------------------------------------------------------------- execution

async def _s1(a) -> Any:
    async with SentinelOne("orchestrator" if getattr(a, "orch", False) else "blue") as s1:
        if a.target == "s1":
            path, params = _s1_path(a.path), _params(a.param)
            if a.all:
                if a.method.upper() != "GET":
                    raise SystemExit("--all only with GET")
                data = await s1.paged(path, params, limit=a.limit)
                return {"total": len(data), "data": data}
            return await s1.api(a.method.upper(), path, json=_json(a.json), params=params)
        if a.target == "gql":
            query = _read(a.query)
            variables = _json(a.vars) or {}
            if "$scope" in query and "scope" not in variables and s1.site_id:
                variables["scope"] = {"scopeIds": [s1.site_id], "scopeType": "SITE"}
            return await s1.graphql(query, variables, path=GQL.get(a.endpoint, a.endpoint))
        data = await s1.powerquery(_read(a.query), a.start, a.end, scoped=not a.unscoped, timeout_s=a.timeout)
        cols = [c.get("name") for c in data.get("columns") or []]
        return {"query": data.get("query"), "matchCount": data.get("matchCount"), "columns": cols,
                "rows": [dict(zip(cols, v)) for v in data.get("values") or []]}


async def _elastic(a) -> Any:
    if a.user not in ROLE_USERS:
        raise SystemExit(f"Unknown Elastic user {a.user!r}")
    async with Elastic(a.user) as el:
        if a.target == "esql":
            r = await el.esql(_read(a.query))
            cols = [c["name"] for c in r.get("columns") or []]
            return {"columns": cols, "rows": [dict(zip(cols, v)) for v in r.get("values") or []]}
        path = _subst(a.path)
        path = path if path.startswith("/") else "/" + path
        call = el.kibana if a.target == "kb" else el.es
        return await call(a.method.upper(), path, json=_json(a.json), params=_params(a.param) or None)


async def cmd_api(a) -> None:
    try:
        res = await (_s1(a) if a.target in ("s1", "gql", "pq") else _elastic(a))
    except (S1Error, ElasticError) as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from None
    _emit(res, a)
