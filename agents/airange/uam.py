"""Unified Alert Management (UAM) via GraphQL - one alert view across all S1 sources
(EDR, STAR/custom rules, Identity, Cloud, third party).

Endpoint: /web/api/v2.1/unifiedalerts/graphql. Generate the schema with `airange s1-schema` (introspection)
into agents/schema/ (git-ignored, not in the repo). Filter field names (fieldId) come from
`alertColumnMetadata`, action IDs from `alertAvailableActions` (e.g. S1/alert/statusUpdate, S1/kill,
S1/incident/create).
"""
from __future__ import annotations

import datetime as dt
import re
from typing import Any

from .sentinelone import UIM_GRAPHQL, S1Error, SentinelOne

PAGE_SIZE = 100
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Elastic workflow status <-> UAM status
STATUS_TO_UAM = {"open": "NEW", "acknowledged": "IN_PROGRESS", "closed": "RESOLVED"}
UAM_TO_STATUS = {v: k for k, v in STATUS_TO_UAM.items()}
# Short forms for the verdict (full enum values are allowed too)
VERDICT_SHORT = {"true_positive": "TRUE_POSITIVE_UNDEFINED", "false_positive": "FALSE_POSITIVE_UNDEFINED",
                 "benign": "FALSE_POSITIVE_BENIGN", "suspicious": "TRUE_POSITIVE_BENIGN_BUT_SUSPICIOUS",
                 "undefined": "UNDEFINED"}
VERDICTS = [
    "UNDEFINED", "TRUE_POSITIVE_UNDEFINED", "TRUE_POSITIVE_MALWARE", "TRUE_POSITIVE_UNAUTHORIZED_ACCESS",
    "TRUE_POSITIVE_EXPLOITATION_TOOLS", "TRUE_POSITIVE_ADVANCED_PERSISTENT_THREAT", "TRUE_POSITIVE_DATA_EXFILTRATION",
    "TRUE_POSITIVE_INSIDER_THREAT", "TRUE_POSITIVE_PHISHING_ATTACK", "TRUE_POSITIVE_POLICY_VIOLATION",
    "TRUE_POSITIVE_RANSOMWARE", "TRUE_POSITIVE_DENIAL_OF_SERVICE", "TRUE_POSITIVE_PUA_ADWARE",
    "TRUE_POSITIVE_BENIGN", "TRUE_POSITIVE_BENIGN_BUT_SUSPICIOUS", "FALSE_POSITIVE_UNDEFINED", "FALSE_POSITIVE_BENIGN",
    "FALSE_POSITIVE_BENIGN_BUT_SUSPICIOUS", "FALSE_POSITIVE_USER_ERROR", "FALSE_POSITIVE_SYSTEM_ERROR",
]
MITIGATION_ACTIONS = {"kill": "S1/kill", "quarantine": "S1/quarantine", "remediate": "S1/remediate",
                      "rollback": "S1/rollback"}
ACTION_STATUS = "S1/alert/statusUpdate"
ACTION_VERDICT = "S1/alert/analystVerdictUpdate"
ACTION_NOTE = "S1/alert/addNote"
ACTION_INCIDENT_CREATE = "S1/incident/create"
ACTION_INCIDENT_ADD = "S1/incident/addToExisting"

ALERT_FIELDS = """
  id name description severity status analystVerdict classification confidenceLevel
  createdAt detectedAt updatedAt storylineId externalId noteExists labels result
  detectionSource { product vendor }
  analytics { name category uid typeValue }
  process { cmdLine parentName file { name path sha1 } }
  assets { name osType category primary }
  detectionTime { asset { ipV4 ipV4Addresses lastLoggedInUser domain }
                  attacker { ip host } targetUser { name domain } scope { siteId siteName } }
  incident { id name }
"""

ALERTS_QUERY = f"""
query Alerts($scope: ScopeSelectorInput, $filters: [FilterInput!], $first: Int, $after: String, $sort: SortInput) {{
  alerts(scope: $scope, filters: $filters, first: $first, after: $after, sort: $sort) {{
    totalCount
    pageInfo {{ hasNextPage endCursor }}
    edges {{ node {{ {ALERT_FIELDS} }} }}
  }}
}}"""

DETAIL_FIELDS = f"""
  {ALERT_FIELDS}
  process {{ cmdLine parentName username userDomain file {{ name path sha1 sha256 isSignatureValid certSubject }} }}
  indicators {{ type title message eventTime severity
               attacks {{ tactic {{ uid name }} technique {{ uid name }} }}
               observables {{ name type value }}
               eventSearchParams {{ filter }} }}
  observables {{ name type value }}
  relatedAlerts {{ id name }}
"""

TRIGGER_MUTATION = """
mutation Trigger($scope: ScopeSelectorInput, $filter: OrFilterSelectionInput, $actions: [TriggerActionInput!]) {
  alertTriggerActions(scope: $scope, filter: $filter, actions: $actions) {
    __typename
    ... on ActionsTriggered { actions { actionId success { id } failure { id errorMessage } skip { id skipMessage } } }
    ... on TriggerActionsError { errors { errorMessage } }
    ... on TriggerActionsScheduled { executionId }
  }
}"""


# --------------------------------------------------------------------------- filter helpers

def f_in(field: str, values: list[str]) -> dict:
    return {"fieldId": field, "stringIn": {"values": list(values)}}


def f_contains(field: str, value: str) -> dict:
    return {"fieldId": field, "match": {"operator": "contains", "values": [value]}}


def f_range(field: str, start: dt.datetime | None = None, end: dt.datetime | None = None) -> dict:
    rng: dict[str, Any] = {}
    if start:
        rng.update(start=int(start.timestamp() * 1000), startInclusive=True)
    if end:
        rng.update(end=int(end.timestamp() * 1000), endInclusive=True)
    return {"fieldId": field, "dateTimeRange": rng}


def ids_filter(ids: list[str]) -> dict:
    return {"or": [{"and": [f_in("id", ids)]}]}


def parse_ts(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


# --------------------------------------------------------------------------- client functions

class UAM:
    def __init__(self, s1: SentinelOne):
        self.s1 = s1

    @property
    def scope(self) -> dict | None:
        return {"scopeIds": [self.s1.site_id], "scopeType": "SITE"} if self.s1.site_id else None

    async def q(self, query: str, variables: dict | None = None) -> dict:
        scope = {"scope": self.scope} if self.scope and "$scope" in query else {}
        res = await self.s1.graphql(query, {**scope, **(variables or {})})
        if res.get("errors"):
            raise S1Error(400, str(res["errors"])[:1500], "unifiedalerts/graphql")
        return res["data"]

    async def alerts(self, filters: list[dict], limit: int = 200, sort_by: str = "detectedAt",
                     order: str = "DESC") -> tuple[list[dict], int]:
        out: list[dict] = []
        after, total = None, 0
        while len(out) < limit:
            data = (await self.q(ALERTS_QUERY, {"filters": filters, "first": min(PAGE_SIZE, limit - len(out)),
                                                "after": after, "sort": {"by": sort_by, "order": order}}))["alerts"]
            total = data["totalCount"]
            out += [e["node"] for e in data.get("edges") or [] if e and e.get("node")]
            if not data["pageInfo"]["hasNextPage"] or not data.get("edges"):
                break
            after = data["pageInfo"]["endCursor"]
        return out, total

    async def detail(self, alert_id: str) -> dict:
        data = await self.q(f"query($id: ID!, $scope: ScopeSelectorInput) {{ alert(id: $id, scope: $scope) "
                            f"{{ {DETAIL_FIELDS} }} }}", {"id": alert_id})
        return data["alert"]

    async def details(self, ids: list[str], chunk: int = 20) -> dict[str, dict]:
        """Several alerts with indicators (MITRE) - fetched in chunks using GraphQL aliases."""
        out: dict[str, dict] = {}
        for i in range(0, len(ids), chunk):
            part = ids[i:i + chunk]
            body = " ".join(f'a{n}: alert(id: "{aid}", scope: $scope) {{ id indicators {{ eventTime attacks '
                            f'{{ tactic {{ uid }} technique {{ uid }} }} }} }}' for n, aid in enumerate(part))
            data = await self.q(f"query($scope: ScopeSelectorInput) {{ {body} }}")
            out.update({v["id"]: v for v in data.values() if v})
        return out

    async def notes(self, alert_id: str) -> list[dict]:
        data = await self.s1.graphql("query($id: ID!) { alertNotes(alertId: $id) { data { createdAt text } } }",
                                     {"id": alert_id})
        return ((data.get("data") or {}).get("alertNotes") or {}).get("data") or []

    async def timeline(self, alert_id: str, n: int = 20) -> list[dict]:
        data = await self.s1.graphql("query($id: ID!, $n: Int) { alertTimeline(alertId: $id, first: $n) "
                                     "{ edges { node { createdAt eventText eventType } } } }", {"id": alert_id, "n": n})
        edges = (((data.get("data") or {}).get("alertTimeline") or {}).get("edges")) or []
        return [e["node"] for e in edges if e]

    async def add_note(self, alert_id: str, markdown: str) -> None:
        res = await self.s1.graphql(
            "mutation($id: ID!, $t: String!, $p: String) { addAlertNote(alertId: $id, text: $t, plainText: $p, "
            "type: MARKDOWN) { data { id } } }", {"id": alert_id, "t": markdown, "p": markdown})
        if res.get("errors"):
            raise S1Error(400, str(res["errors"])[:800], "addAlertNote")

    async def incidents(self, filters: list[dict], limit: int = 500) -> list[dict]:
        """Incidents (Unified Incident Management, separate endpoint) - id, name, status."""
        out: list[dict] = []
        after = None
        while len(out) < limit:
            res = await self.s1.graphql(
                "query($scope: ScopeSelectorInput, $f: [FilterInput], $first: Int, $after: String) { "
                "incidents(scope: $scope, filters: $f, first: $first, after: $after) { "
                "pageInfo { hasNextPage endCursor } edges { node { id name status } } } }",
                {"scope": self.scope, "f": filters, "first": min(PAGE_SIZE, limit - len(out)), "after": after},
                path=UIM_GRAPHQL)
            if res.get("errors"):
                raise S1Error(400, str(res["errors"])[:1500], "unifiedincidents/graphql")
            data = res["data"]["incidents"]
            out += [e["node"] for e in data.get("edges") or [] if e and e.get("node")]
            if not data["pageInfo"]["hasNextPage"] or not data.get("edges"):
                break
            after = data["pageInfo"]["endCursor"]
        return out

    async def incident_status(self, ids: list[str], status: str) -> list[str]:
        """Set the status of incidents (NEW | IN_PROGRESS | RESOLVED | CLOSED) -> changed IDs."""
        res = await self.s1.graphql(
            "mutation($scope: ScopeSelectorInput, $filter: OrFilterSelectionInput!, $status: Status!) { "
            "updateIncidentStatus(scope: $scope, filter: $filter, status: $status) { updatedIncidentIds } }",
            {"scope": self.scope, "filter": ids_filter(ids), "status": status}, path=UIM_GRAPHQL)
        if res.get("errors"):
            raise S1Error(400, str(res["errors"])[:1500], "updateIncidentStatus")
        return (res["data"]["updateIncidentStatus"] or {}).get("updatedIncidentIds") or []

    async def trigger(self, ids: list[str], actions: list[dict]) -> dict:
        """alertTriggerActions -> {action_id: {success, failure, skip}} or scheduled/errors."""
        data = (await self.q(TRIGGER_MUTATION, {"filter": ids_filter(ids), "actions": actions}))["alertTriggerActions"]
        kind = (data or {}).get("__typename")
        if kind == "TriggerActionsError":
            raise S1Error(400, "; ".join(e["errorMessage"] for e in data["errors"]), "alertTriggerActions")
        if kind == "TriggerActionsScheduled":
            return {"scheduled": data.get("executionId")}
        out = {}
        for a in (data or {}).get("actions") or []:
            r = {"success": len(a["success"])}
            if a["failure"]:
                r["failure"] = [f"{f['id']}: {f.get('errorMessage')}" for f in a["failure"]]
            if a["skip"]:
                r["skip"] = [f"{s['id']}: {s.get('skipMessage')}" for s in a["skip"]]
            out[a["actionId"]] = r
        return out


# --------------------------------------------------------------------------- normalization

def short_host(name: Any) -> str:
    return str(name or "").strip().lower().split(".")[0]


def alert_hosts(a: dict) -> list[str]:
    hosts = [short_host(x.get("name")) for x in sorted(a.get("assets") or [], key=lambda x: not x.get("primary"))]
    return [h for h in dict.fromkeys(hosts) if h]


def rule_name(a: dict) -> str:
    """Stable rule name: EDR names start with the process ('cmd.exe (CLI ef7e) - X detected') -> 'X detected'."""
    name = str(a.get("name") or (a.get("analytics") or {}).get("name") or "?")
    if (a.get("detectionSource") or {}).get("product") == "EDR" and " - " in name:
        return name.split(" - ", 1)[1]
    return name


def mitre_ids(detail: dict | None, a: dict | None = None) -> list[str]:
    """T-IDs from indicator attacks (uid is sometimes a name instead of an ID) and from name/description."""
    ids: set[str] = set()
    for ind in (detail or {}).get("indicators") or []:
        for att in ind.get("attacks") or []:
            for part in (att.get("technique"), att.get("tactic")):
                ids.update(TECH_RE.findall(str((part or {}).get("uid") or "")))
    if a:
        ids.update(TECH_RE.findall(f"{a.get('name') or ''} {a.get('description') or ''}"))
    return sorted(ids)


def summary(a: dict) -> dict:
    """Compact alert row for the Blue tools."""
    dt_ = a.get("detectionTime") or {}
    asset = dt_.get("asset") or {}
    proc = a.get("process") or {}
    out = {
        "id": a.get("id"),
        "@timestamp": a.get("createdAt"),
        "detected_at": a.get("detectedAt"),
        "name": a.get("name"),
        "source": (a.get("detectionSource") or {}).get("product"),
        "analytic": (a.get("analytics") or {}).get("name"),
        "severity": str(a.get("severity") or "").lower(),
        "confidence": a.get("confidenceLevel"),
        "classification": a.get("classification"),
        "status": UAM_TO_STATUS.get(a.get("status"), a.get("status")),
        "verdict": a.get("analystVerdict"),
        "result": a.get("result"),
        "host": ", ".join(alert_hosts(a)),
        "host_ip": ", ".join(asset.get("ipV4Addresses") or ([asset["ipV4"]] if asset.get("ipV4") else [])),
        "user": asset.get("lastLoggedInUser"),
        "target_user": (dt_.get("targetUser") or {}).get("name"),
        "attacker_ip": (dt_.get("attacker") or {}).get("ip"),
        "process": (proc.get("file") or {}).get("name"),
        "parent": proc.get("parentName"),
        "command_line": (proc.get("cmdLine") or "")[:400],
        "storyline": a.get("storylineId"),
        "incident": (a.get("incident") or {}).get("name"),
        "mitre": mitre_ids(None, a),
    }
    return {k: v for k, v in out.items() if v not in (None, [], "")}
