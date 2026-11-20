"""xSPM vulnerabilities (Singularity Vulnerability Management) via GraphQL.

Endpoint: /web/api/v2.1/xspm/findings/vulnerabilities/graphql. Introspection is blocked there; the schema
comes from GET <endpoint>/schema (SDL; can be saved to agents/schema/s1_xspm_vulnerabilities_schema.graphql,
which is git-ignored and not in the repo). Filter field names (fieldId) come from `vulnerabilityColumnMetadata`.

A finding is one CVE on one asset in one piece of software - so the same CVE shows up several times, per host
(and per package). Grouped views can only be sorted by count on the server side, not by risk score.
"""
from __future__ import annotations

from typing import Any

from .sentinelone import S1Error, SentinelOne

XSPM_VULN_GRAPHQL = "/web/api/v2.1/xspm/findings/vulnerabilities/graphql"
PAGE_SIZE = 100

# Short form -> status enum. RESOLVED/RISK_ACKED/SUPPRESSED are deliberately set only by a human (or the scanner).
STATUS_TO_XSPM = {"new": "NEW", "in_progress": "IN_PROGRESS", "risk_accepted": "RISK_ACKED", "resolved": "RESOLVED"}
XSPM_TO_STATUS = {v: k for k, v in STATUS_TO_XSPM.items()}
VERDICT_TO_XSPM = {"true_positive": "TRUE_POSITIVE", "false_positive": "FALSE_POSITIVE"}
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SORT_FIELDS = {"risk": "cveRiskScore", "epss": "cveEpssScore", "detected": "detectedAt", "severity": "severity"}
GROUP_FIELDS = {"host": "assetName", "software": "softwareName"}

VULN_FIELDS = """
  id name severity status analystVerdict detectedAt lastSeenAt
  asset { name type osType criticality }
  cve { id nvdBaseScore riskScore epssScore exploitMaturity exploitedInTheWild remediationLevel publishedDate }
  software { name version type fixVersion fixVersionAvailable }
"""

LIST_QUERY = f"""
query Vulns($scope: ScopeSelectorInput, $filters: [FilterInput!], $first: Int, $after: String, $sorts: [SortInput!]) {{
  vulnerabilities(scope: $scope, filters: $filters, first: $first, after: $after, sorts: $sorts, includeHidden: false) {{
    totalCount
    pageInfo {{ hasNextPage endCursor }}
    edges {{ node {{ {VULN_FIELDS} }} }}
  }}
}}"""

GROUPS_QUERY = """
query Groups($scope: ScopeSelectorInput, $filters: [FilterInput!], $by: String!, $first: Int, $summary: [String!]) {
  vulnerabilityGroups(scope: $scope, filters: $filters, groupByFieldId: $by, first: $first,
                      summaryFieldIds: $summary, includeHidden: false) {
    totalCount
    edges { node { value count fieldSummaries {
      __typename fieldId
      ... on ValueCountSummary { values { value count } }
      ... on DistinctCountSummary { distinctCount }
    } } }
  }
}"""

COUNTS_QUERY = """
query Counts($scope: ScopeSelectorInput, $filters: [FilterInput!], $fields: [String!]!) {
  vulnerabilitiesFiltersCount(scope: $scope, filters: $filters, fieldIds: $fields, includeHidden: false) {
    data { fieldId values { value count } }
  }
}"""

DETAIL_QUERY = """
query Detail($id: ID!, $scope: ScopeSelectorInput) {
  vulnerability(id: $id, scope: $scope) {
    id name severity status analystVerdict detectedAt lastSeenAt resolvedAt selfLink attackPathExists
    assignee { fullName }
    asset { name type category osType criticality riskFactors status }
    software { name version vendor type fixVersion fixVersionAvailable paths }
    cve { id description nvdBaseScore riskScore epssScore epssPercentile exploitMaturity exploitedInTheWild
          kevAvailable remediationLevel reportConfidence publishedDate nvdReferenceUrl
          riskIndicators { severity values }
          s1BaseValues { attackVector attackComplexity privilegesRequired userInteractions scope
                         confidentiality integrity availability }
          timeline { date key } }
  }
}"""

RELATED_QUERY = """
query Related($scope: ScopeSelectorInput, $filters: [FilterInput!], $first: Int) {
  vulnerabilityRelatedAssets(scope: $scope, filters: $filters, first: $first) {
    totalCount
    edges { node { vulnerabilityId asset { name } software { name version } } }
  }
}"""

NOTES_QUERY = """
query Notes($id: ID!, $n: Int) {
  vulnerabilityNotes(vulnerabilityId: $id, first: $n) { edges { node { createdAt text author { fullName } } } }
}"""

HISTORY_QUERY = """
query History($id: ID!, $n: Int) {
  vulnerabilityHistory(vulnerabilityId: $id, first: $n) { edges { node { createdAt eventType eventText } } }
}"""

STATUS_MUTATION = """
mutation Status($scope: ScopeSelectorInput, $filter: OrFilterSelectionInput, $update: StatusUpdateInput) {
  vulnerabilitiesStatusUpdateV2(scope: $scope, filter: $filter, statusUpdate: $update) { updatedFindingIds }
}"""

VERDICT_MUTATION = """
mutation Verdict($scope: ScopeSelectorInput, $filter: OrFilterSelectionInput, $verdict: AnalystVerdict) {
  vulnerabilitiesAnalystVerdictUpdateV2(scope: $scope, filter: $filter, analystVerdict: $verdict) { updatedFindingIds }
}"""

NOTE_MUTATION = """
mutation Note($scope: ScopeSelectorInput, $filter: OrFilterSelectionInput, $text: String!) {
  addVulnerabilityNoteV2(scope: $scope, filter: $filter, text: $text) { updatedFindingIds }
}"""


# --------------------------------------------------------------------------- filter helpers

def f_match(field: str, values: list[str], operator: str = "exactMatch") -> dict:
    """Full-text filter (case-insensitive); multiple values are OR-combined."""
    return {"fieldId": field, "match": {"operator": operator, "values": list(values)}}


def f_bool(field: str, value: bool) -> dict:
    return {"fieldId": field, "booleanEqual": {"value": bool(value)}}


def _edges(conn: dict | None) -> list[dict]:
    return [e["node"] for e in (conn or {}).get("edges") or [] if e and e.get("node")]


# --------------------------------------------------------------------------- client functions

class XSPM:
    def __init__(self, s1: SentinelOne):
        self.s1 = s1

    @property
    def scope(self) -> dict | None:
        return {"scopeIds": [self.s1.site_id], "scopeType": "SITE"} if self.s1.site_id else None

    async def q(self, query: str, variables: dict | None = None) -> dict:
        scope = {"scope": self.scope} if self.scope and "$scope" in query else {}
        res = await self.s1.graphql(query, {**scope, **(variables or {})}, path=XSPM_VULN_GRAPHQL)
        if res.get("errors"):
            raise S1Error(400, str(res["errors"])[:1500], "xspm/findings/vulnerabilities/graphql")
        return res["data"]

    async def vulnerabilities(self, filters: list[dict], limit: int = 100, sort_by: str = "cveRiskScore",
                              order: str = "DESC") -> tuple[list[dict], int]:
        out: list[dict] = []
        after, total = None, 0
        while len(out) < limit:
            data = (await self.q(LIST_QUERY, {"filters": filters, "first": min(PAGE_SIZE, limit - len(out)),
                                              "after": after, "sorts": [{"by": sort_by, "order": order}]}))
            data = data["vulnerabilities"]
            total = data["totalCount"]
            page = _edges(data)
            out += page
            if not data["pageInfo"]["hasNextPage"] or not page:
                break
            after = data["pageInfo"]["endCursor"]
        return out, total

    async def groups(self, filters: list[dict], group_by: str, limit: int = 50,
                     summary: list[str] | None = None) -> tuple[list[dict], int]:
        data = (await self.q(GROUPS_QUERY, {"filters": filters, "by": group_by, "first": limit,
                                            "summary": summary or []}))["vulnerabilityGroups"]
        return _edges(data), data["totalCount"]

    async def counts(self, filters: list[dict], fields: list[str]) -> dict[str, dict[str, int]]:
        data = (await self.q(COUNTS_QUERY, {"filters": filters, "fields": fields}))["vulnerabilitiesFiltersCount"]
        return {f["fieldId"]: {str(v["value"]): v["count"] for v in f["values"] if v["count"]}
                for f in data["data"]}

    async def detail(self, vuln_id: str) -> dict:
        return (await self.q(DETAIL_QUERY, {"id": vuln_id}))["vulnerability"]

    async def related(self, filters: list[dict], limit: int = 100) -> list[dict]:
        return _edges((await self.q(RELATED_QUERY, {"filters": filters, "first": limit}))["vulnerabilityRelatedAssets"])

    async def notes(self, vuln_id: str, n: int = 20) -> list[dict]:
        return _edges((await self.q(NOTES_QUERY, {"id": vuln_id, "n": n}))["vulnerabilityNotes"])

    async def history(self, vuln_id: str, n: int = 20) -> list[dict]:
        return _edges((await self.q(HISTORY_QUERY, {"id": vuln_id, "n": n}))["vulnerabilityHistory"])

    async def update(self, filters: list[dict], status: str | None = None, verdict: str | None = None,
                     note: str | None = None) -> dict[str, int]:
        """Status/verdict/note for all findings matching the (AND-combined) filters."""
        sel = {"filter": {"or": [{"and": filters}]}}
        out: dict[str, int] = {}
        if status:
            upd = {"status": status, **({"analystVerdict": verdict} if verdict else {})}
            res = await self.q(STATUS_MUTATION, {**sel, "update": upd})
            out["status_updated"] = len(res["vulnerabilitiesStatusUpdateV2"]["updatedFindingIds"])
            if verdict:
                out["verdict_updated"] = out["status_updated"]
        elif verdict:
            res = await self.q(VERDICT_MUTATION, {**sel, "verdict": verdict})
            out["verdict_updated"] = len(res["vulnerabilitiesAnalystVerdictUpdateV2"]["updatedFindingIds"])
        if note:
            res = await self.q(NOTE_MUTATION, {**sel, "text": note})
            out["notes_added"] = len(res["addVulnerabilityNoteV2"]["updatedFindingIds"])
        return out


# --------------------------------------------------------------------------- normalization

def short_host(name: Any) -> str:
    return str(name or "").strip().lower().split(".")[0]


def _num(v: Any) -> float | None:
    try:
        return round(float(v), 4) if v is not None else None
    except (TypeError, ValueError):
        return None


def first_line(text: Any, n: int = 200) -> str:
    """Finding names are often whole CVE descriptions (kernel commits) - the first line is enough."""
    line = str(text or "").strip().split("\n", 1)[0].strip()
    return line[:n] + ("…" if len(line) > n else "")


def summary(v: dict) -> dict:
    """Compact finding row for the Blue tools."""
    cve, sw, asset = v.get("cve") or {}, v.get("software") or {}, v.get("asset") or {}
    out = {
        "id": v.get("id"),
        "cve": cve.get("id"),
        "host": short_host(asset.get("name")),
        "severity": str(v.get("severity") or "").lower(),
        "risk_score": _num(cve.get("riskScore")),
        "cvss": _num(cve.get("nvdBaseScore")),
        "epss": _num(cve.get("epssScore")),
        "exploited_in_wild": cve.get("exploitedInTheWild") or None,
        "exploit_maturity": cve.get("exploitMaturity"),
        "software": f"{sw.get('name')} {sw.get('version') or ''}".strip() if sw.get("name") else None,
        "fix": sw.get("fixVersion") or ("available" if sw.get("fixVersionAvailable") else None),
        "status": XSPM_TO_STATUS.get(v.get("status"), v.get("status")),
        "verdict": v.get("analystVerdict"),
        "detected_at": v.get("detectedAt"),
        "title": first_line(v.get("name")),
    }
    return {k: val for k, val in out.items() if val not in (None, [], "")}


def by_cve(rows: list[dict]) -> list[dict]:
    """Group findings (already sorted) by CVE - the order of first occurrence is kept."""
    groups: dict[str, dict] = {}
    for v in rows:
        s = summary(v)
        g = groups.get(s.get("cve") or s["id"])
        if g is None:
            g = {k: s[k] for k in ("cve", "severity", "risk_score", "cvss", "epss", "exploited_in_wild",
                                   "exploit_maturity", "title") if k in s}
            g.update(findings=0, hosts=[], software=[], fix=[], status=[], verdict=[], example_id=s["id"])
            groups[s.get("cve") or s["id"]] = g
        g["findings"] += 1
        for key, val in (("hosts", s.get("host")), ("software", s.get("software")), ("fix", s.get("fix")),
                         ("status", s.get("status")), ("verdict", s.get("verdict"))):
            if val and val not in g[key]:
                g[key].append(val)
    out = []
    for g in groups.values():
        g["software"], g["fix"] = g["software"][:5], g["fix"][:3]
        out.append({k: v for k, v in g.items() if v not in (None, [], "")})
    return out


def group_row(node: dict) -> dict:
    """vulnerabilityGroups node -> {value, findings, <fieldId>: …}."""
    out: dict[str, Any] = {"value": node.get("value"), "findings": node.get("count")}
    for s in node.get("fieldSummaries") or []:
        if s.get("__typename") == "ValueCountSummary":
            out[s["fieldId"]] = {str(x["value"]).lower(): x["count"] for x in s.get("values") or []}
        elif s.get("__typename") == "DistinctCountSummary":
            out[f"{s['fieldId']}_distinct"] = s.get("distinctCount")
    return out
