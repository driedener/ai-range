---
name: range-api
description: Talk to the AI range's SentinelOne and Elastic APIs from the Claude session – via the agents container (`agents api …`, `agents vms …`), without reading Swagger/PDFs. Use when S1 agents, alerts (UAM), vulnerabilities (xSPM), PowerQuery, Ranger, Firewall Control, STAR rules, Elasticsearch/Kibana (ground truth, traces, scores) need to be queried/changed or the range VMs need to be started/stopped.
---

# Range APIs (SentinelOne + Elastic) via the agents container

Everything runs through the CLI in the Compose service `agents` (`agents/airange/api_cli.py`), using the same clients as
Blue/Engineer/Scorer. From Git Bash in the `docker/` directory:

```bash
cd docker
A() { MSYS_NO_PATHCONV=1 docker compose run --rm -T agents "$@" 2>&1 | grep -v "Container ai-range"; }
A check                                     # access (LLM, Elastic users, S1, Kali)
A vms status                                # VMs: start | stop [--timeout 180] | status
A api s1 GET /agents --all -p 'siteIds={SITE}' --fields computerName,networkStatus,isActive --compact
```

- `MSYS_NO_PATHCONV=1` is mandatory (otherwise Git Bash turns `/agents` into a Windows path), `-T` for no TTY.
- The container brings its credentials from `docker/.env`. **Never print secrets or write them into commands.**
- `{SITE}` in the path, `-p`, JSON and GraphQL variables is replaced by `S1_SITE_ID` (range site).
- Body: `-j '<json>'`, `-j @file.json` or `-j -` (stdin). Same for query/variables. File paths are
  container paths: `agents/` is `/app` (working directory), so e.g. `@reports/q.json` for `agents/reports/q.json`.
- Options after the target: `--compact`, `--out reports/x.json` (large results, ends up in `agents/reports/`),
  `--fields a,b.c` (fields per record from `data[]`/`rows[]` or from the object).
- Errors: message on stderr, exit 1. HTTP 503 with HTML = S1 console upgrade, wait.
- Elastic users: `-u orchestrator` (default, reads everything incl. ground truth), `blue`, `red`. The superuser `elastic`
  is deliberately not in the container – admin tasks via Kibana or Ansible (`tools` container).
- Look up deeper details only selectively via grep: `sources/sentinelone/api/swagger_2.1.json` (REST),
  `agents/schema/s1_uam_schema.graphql`, `agents/schema/s1_xspm_vulnerabilities_schema.graphql`.
  These files are local only (git-ignored): download the swagger from your console into
  `sources/sentinelone/api/`; generate the UAM schema with `agents s1-schema` (others: `s1-schema --path …` or `GET <endpoint>/schema`).
  The agent implementations (`agents/airange/*.py`, `tools/blue_s1*.py`, `tools/engineer_s1.py`) show working calls.

The tables below use the short form `s1 GET …`, `gql …`, `pq …`, `es …` – in full, `A api s1 GET …`.

## Write actions

The S1 console is a real tenant (NFR). Calls that change things (POST/PUT/DELETE, GraphQL mutations) only on
explicit request and always limited to the range site (`siteIds`/`filter.siteIds` = `{SITE}`).
Conventions: Blue firewall rules are named `ai-range blue: …`, Engineer STAR rules `ai-range: …`.
Cleanup after exercises: `A cleanup` (or the individual steps under *Cleanup*).

## SentinelOne – REST (`s1 METHOD PATH`, path relative to `/web/api/v2.1`)

Auth `Authorization: ApiToken <S1_API_TOKEN>` (role SOC, site scope). `--orch` = the scorer's viewer token.
Lists: `data[]` + `pagination.nextCursor`; `--all` paginates. Multiple values comma-separated (`-p ids=1 -p ids=2` → `ids=1,2`).
Filter suffixes: `__contains`, `__gte`, `__lte`, `__gt`, `__lt` (e.g. `createdAt__gte=2026-11-15T00:00:00Z`).

| Purpose | Call |
|---|---|
| Console version | `GET /system/info` |
| Agents (site) | `GET /agents --all -p siteIds={SITE}` · fields: `id computerName networkStatus isActive isDecommissioned agentVersion lastActiveDate externalIp networkInterfaces[].inet osName` |
| Count | `GET /agents/count -p siteIds={SITE}` |
| Isolate / release | `POST /agents/actions/disconnect` or `/connect` with `-j '{"filter":{"ids":["<agentId>"]}}'` |
| Remove agent (stale) | `POST /agents/actions/decommission -j '{"filter":{"ids":[…]}}'` |
| Threats (legacy) | `GET /threats -p siteIds={SITE} -p limit=50` |
| Sites | `GET /sites -p siteIds={SITE}` (list under `data.sites`) |
| Activities (audit) | `GET /activities -p siteIds={SITE} -p limit=50 -p sortOrder=desc` |
| Token expiry | `POST /users/api-token-details -j '{"data":{"apiToken":"…"}}'` (do not print the token) |
| Ranger settings | `GET /ranger/settings -p siteIds={SITE}` (`minAgentsInNetworkToScan` must be 1) |
| Ranger devices | `GET /ranger/table-view -p siteIds={SITE} -p period=last7d [-p localIp__contains=10.0.21.200] [-p managedStates=Unsecured] [-p deviceReviews=Isolated]` · fields `id localIp ipAddresses macAddress managedState deviceReview osType hostnames tcpPorts firstSeen lastSeen` – a device without an agent (e.g. Kali) has `managedState: "Unsecured"` (filter value is case-sensitive; `unmanaged` returns nothing) |
| Block / release device | `POST /ranger/device-review -j '{"data":{"deviceReview":"Isolated","reason":"Other","reasonDetails":"…"},"filter":{"ids":["<id>"],"siteIds":["{SITE}"]}}'` (release: `"Not Reviewed"`) |
| Firewall status | `GET /firewall-control/configuration -p siteIds={SITE}` |
| Enable firewall | `PUT /firewall-control/configuration -j '{"filter":{"siteIds":["{SITE}"]},"data":{"enabled":true,"reportBlocked":true,"inheritSettings":false}}'` |
| Firewall rules | `GET /firewall-control --all -p siteIds={SITE} [-p name__contains=ai-range]` |
| Create rule | `POST /firewall-control -j @rule.json` (structure see below) |
| Rule on/off · delete | `PUT /firewall-control/enable` `{"filter":{"siteIds":[…],"ids":[…]},"data":{"status":"Disabled"}}` · `DELETE /firewall-control` `{"filter":{"siteIds":[…],"ids":[…]}}` |
| STAR/custom rules | `GET /cloud-detection/rules -p siteIds={SITE} -p isLegacy=false -p includeScheduledRules=true [-p name__contains=ai-range]` · create `POST /cloud-detection/rules {"filter":{"siteIds":[…]},"data":{…}}` · change `PUT /cloud-detection/rules/<id>` · disable `PUT /cloud-detection/rules/disable {"filter":{"ids":[…]}}` |

Firewall rule (`data`): `{"name":"ai-range blue: …","description":"…","action":"Block","direction":"inbound","protocol":"any","osTypes":["windows","linux"],"status":"Enabled","application":{"type":"any","values":[]},"localHost":{"type":"any","values":[]},"remoteHosts":[{"type":"addresses","values":["10.0.21.200"]}],"localPort":{"type":"any","values":[]},"remotePort":{"type":"any","values":[]},"location":{"type":"all","values":[]}}` – CIDRs as `{"type":"cidr","values":["…/24"]}`.

## SentinelOne – GraphQL (`gql <endpoint> <query> [-v vars]`)

Endpoints: `uam` (Unified Alert Management), `uim` (incidents), `xspm-vuln`, `xspm-misconf`. If the query contains `$scope`, the script sets
`scope = {scopeIds:[SITE], scopeType: SITE}` automatically. Filters: `[FilterInput!]` with `fieldId` and exactly one operator:
`stringIn:{values:[…]}`, `match:{operator:"contains"|"exactMatch", values:[…]}`, `booleanEqual:{value:true}`,
`dateTimeRange:{start:<epoch-ms>, startInclusive:true, end:…}`.

```bash
# Latest alerts
A api gql uam 'query($scope: ScopeSelectorInput){ alerts(scope:$scope, first:20, sort:{by:"detectedAt", order:DESC}){ totalCount pageInfo{hasNextPage endCursor} edges{ node{ id name severity status analystVerdict detectedAt detectionSource{product} assets{name} process{cmdLine file{name}} detectionTime{attacker{ip}} } } } }'
# Filtered (variables, multiple filters = AND): status NEW, host contains WS01 (case-insensitive)
A api gql uam 'query($scope: ScopeSelectorInput, $f:[FilterInput!]){ alerts(scope:$scope, filters:$f, first:50){ totalCount edges{node{id name}} } }' \
  -v '{"f":[{"fieldId":"status","stringIn":{"values":["NEW"]}},{"fieldId":"assetName","match":{"operator":"contains","values":["WS01"]}}]}'
# Detail with MITRE
A api gql uam 'query($id: ID!, $scope: ScopeSelectorInput){ alert(id:$id, scope:$scope){ name description indicators{ title attacks{ technique{uid name} } } } }' -v '{"id":"<alertId>"}'
```

- Common filter `fieldId`s: `id`, `alertName`, `status` (`NEW | IN_PROGRESS | RESOLVED`), `severity` (`LOW…CRITICAL`), `analystVerdict`, `detectedAt`/`createdAt` (dateTimeRange), `assetName`, `detectionProduct` (`EDR`, `STAR`, `Identity`…), `analyticsName`, `processName`, `cmdLine`, `fileName`, `detectionAttackerIpAddress`, `detectionAssetIpV4`, `detectionTargetUserName`, `mitreTechniques`, `incidentId`, `storylineId`. Full list: `query($scope: ScopeSelectorInput){ alertColumnMetadata(scope:$scope){ fieldId filterTypes enumValues } }`. Actions per alert: `alertAvailableActions`.
- Actions on alerts: `mutation($scope: ScopeSelectorInput, $filter: OrFilterSelectionInput, $actions:[TriggerActionInput!]){ alertTriggerActions(scope:$scope, filter:$filter, actions:$actions){ __typename } }`
  with `filter = {"or":[{"and":[{"fieldId":"id","stringIn":{"values":[…]}}]}]}` and action IDs `S1/alert/statusUpdate`,
  `S1/alert/analystVerdictUpdate`, `S1/alert/addNote`, `S1/kill`, `S1/quarantine`, `S1/remediate`, `S1/rollback`, `S1/incident/create`.
- Note: `mutation($id: ID!, $t: String!){ addAlertNote(alertId:$id, text:$t, plainText:$t, type: MARKDOWN){ data{id} } }`.
- xSPM: `vulnerabilities(scope, filters, first, after, sorts:[{by:"cveRiskScore", order:DESC}], includeHidden:false)`, fields
  `id name severity status asset{name} cve{id riskScore epssScore exploitedInTheWild} software{name version fixVersion}`;
  groups `vulnerabilityGroups(groupByFieldId:"assetName"|"softwareName")`; status change `vulnerabilitiesStatusUpdateV2`.
  Introspection is blocked for xSPM – schema via `GET <endpoint>/schema` or the file under `agents/schema/`.
- Incidents (`uim`, schema `agents/schema/s1_uim_schema.graphql`, introspection blocked): alert mutations do
  not affect incidents. List `query($scope: ScopeSelectorInput, $f:[FilterInput]){ incidents(scope:$scope, filters:$f, first:100){ totalCount edges{node{id name status}} } }`
  (status `NEW | IN_PROGRESS | RESOLVED | CLOSED`); set status
  `mutation($scope: ScopeSelectorInput, $filter: OrFilterSelectionInput!){ updateIncidentStatus(scope:$scope, filter:$filter, status: RESOLVED){ updatedIncidentIds } }`
  with `filter = {"or":[{"and":[{"fieldId":"id","stringIn":{"values":[…]}}]}]}`. More: `updateIncidentAnalystVerdict`, `updateIncidentSeverity`, `addAlertsToIncident`.

## SentinelOne – PowerQuery (`pq "<query>" [--start 24h] [--end …]`)

Telemetry (Deep Visibility/SDL), read-only. The script prepends `site.id = '<SITE>' and (…)` (`--unscoped` without it).
Syntax: `<filter> | columns a,b | group n=count() by a | sort -n | limit 50`; strings in `'…'`, `contains` is case-insensitive.

- `event.type`: `'Process Creation'`, `'IP Connect'`, `'IP Listen'`, `'DNS Resolved'`, `'Login'`, `'File Creation'`,
  `'Registry Value Modified'`, `'Behavioral Indicators'`, `'Command Script'`, `'Task Register'`, `'Named Pipe Creation'`
- Fields: `endpoint.name` (upper case: `WS01`), `event.time`, `src.process.name/.cmdline/.user/.parent.name`, `tgt.process.name/.cmdline`,
  `tgt.file.path`, `src.ip.address`, `dst.ip.address`, `dst.port.number`, `event.dns.request`,
  `event.login.userName/.type/.loginIsSuccessful`, `indicator.name/.category`

```bash
A api pq "event.type = 'Login' and event.login.loginIsSuccessful = false | group fails=count() by src.ip.address, event.login.userName | sort -fails" --start 24h
```

## Elastic (`es` / `kb` / `esql`)

Stack from `docker/compose.yml` (`es01:9200`, `kibana:5601` in the Compose network; the container uses the CA from the
volume `ai-range_certs`). If the stack is not running: `cd docker && docker compose --env-file .env up -d`, and for an empty
stack afterwards `docker compose --env-file .env run --rm -T tools sh -c "cd ansible && ansible-playbook playbooks/elastic-config.yml"`
(users, roles, indices). Check with `A check`.

Users (`-u`): `orchestrator` (default, reads everything), `blue` (blue-agent, **no** access to `range-groundtruth`), `red`.

| Index / data stream | Content |
|---|---|
| `range-groundtruth` | Red steps (technique, time, host) – basis of the scoring |
| `range-agenttrace` | Tool calls of all agents |
| `range-scores` | Result per exercise (`run_id`) |
| `.alerts-security.alerts-default` | Elastic Security alerts (Elastic mode only) |
| `logs-*`, `metrics-*` | Telemetry (Elastic Agent/Defend; not in S1 mode) |

```bash
A api esql 'FROM range-scores | SORT @timestamp DESC | LIMIT 5'
A api es GET '/range-*/_count'
A api es POST /range-groundtruth/_search -j '{"size":5,"sort":[{"@timestamp":"desc"}]}'
A api kb GET /api/detection_engine/rules/_find -p per_page=20
A api kb POST /api/detection_engine/signals/search -j '{"size":10,"query":{"match_all":{}}}'
```

The client sets the Kibana headers (`kbn-xsrf`, `elastic-api-version: 2023-10-31`) itself.

## Cleanup after an S1 exercise (equivalent to `agents cleanup`)

1. Isolated agents: `s1 GET /agents --all -p siteIds={SITE} --fields id,computerName,networkStatus` → `POST /agents/actions/connect`.
2. Ranger blocks: `s1 GET /ranger/table-view -p siteIds={SITE} -p period=last7d -p deviceReviews=Isolated` → device-review `"Not Reviewed"`.
3. Blue rules: `s1 GET /firewall-control --all -p siteIds={SITE} -p name__contains=ai-range` → `DELETE /firewall-control`.
4. Open alerts (`status` NEW/IN_PROGRESS): `alertTriggerActions` with `S1/alert/statusUpdate` and `{"status":{"value":"RESOLVED"}}`.
5. Open incidents: `gql uim` → `updateIncidentStatus(status: RESOLVED)`.
