# SentinelOne

With `AIRANGE_EDR=sentinelone` (in `docker/.env`) SentinelOne replaces Elastic Defend and the Elastic detection
engine:

| Area | `elastic` (default) | `sentinelone` |
|---|---|---|
| Agent on the range hosts | Elastic Agent + Defend (Fleet) | SentinelOne agent (`ansible/roles/sentinelone_agent`) |
| Telemetry for Blue/Engineer | ES\|QL (`esql`) | PowerQuery (`powerquery`, `/sdl/v2/api/queries`) |
| Alerts | `.alerts-security*` | Unified Alert Management (GraphQL), all sources: EDR, STAR/custom rules, Identity, ... |
| Triage | Workflow status + tags | Status (NEW/IN_PROGRESS/RESOLVED) + analyst verdict + Markdown notes |
| Cases | Kibana cases | UAM incidents (`S1/incident/create` or `addToExisting`) + case text as alert note |
| Response | Isolate, kill/suspend (PID), process list | Isolate/release (REST, disconnect from network), alert mitigation (UAM: kill/quarantine/remediate/rollback), agent status |
| Engineer rules | Kibana detection rules (EQL/ES\|QL/KQL) | STAR rules (REST; `events` = S1QL 2.0 filter, `scheduled` = PowerQuery) |

Unchanged in the Elastic stack on the controller: ground truth (`range-groundtruth`), agent traces
(`range-agenttrace`) and scores (`range-scores`). The stack must keep running; in S1 mode `elastic-config.yml` no
longer creates Defend policies and prebuilt rules (`defend_enabled`/`rules_enabled` follow `AIRANGE_EDR`).

## APIs

| Purpose | Endpoint | Auth |
|---|---|---|
| Alerts, notes, incidents, mitigation | `POST /web/api/v2.1/unifiedalerts/graphql` (UAM) | `ApiToken <token>` |
| Incidents | `/web/api/v2.1/unifiedincidents/graphql` (UIM) | `ApiToken <token>` |
| Vulnerabilities | `/web/api/v2.1/xspm/findings/vulnerabilities/graphql` (xSPM) | `ApiToken <token>` |
| Telemetry | `/sdl/v2/api/queries` (launch -> poll -> delete, header `X-Dataset-Query-Forward-Tag`) | `Bearer <token>` |
| Agents (isolation, status), sites, STAR rules, Ranger, Firewall Control | `/web/api/v2.1/...` (REST) | `ApiToken <token>` |

### API specifications (local only)

The vendor API specifications are not part of the repository. They are reference material for development and
for the operator; the agents do not read them at runtime.

- **REST (Swagger 2.1):** download the Swagger/OpenAPI JSON from your console's API documentation and save it as
  `sources/sentinelone/api/swagger_2.1.json` (git-ignored).
- **UAM GraphQL schema:** `agents s1-schema` fetches it from the console by introspection into `agents/schema/`
  (git-ignored, created on demand). It writes only the UAM schema by default; other GraphQL APIs with
  introspection via `--path`. Re-run after console updates:

    ```sh
    docker compose --env-file .env run --rm agents s1-schema      # optional --path for other GraphQL APIs
    ```

- **xSPM and UIM schemas:** introspection is disabled on these endpoints. `GET <endpoint>/schema` returns the SDL;
  store it as `agents/schema/s1_xspm_vulnerabilities_schema.graphql` or `agents/schema/s1_uim_schema.graphql` if
  you need it.

Important details from schema and documentation:

- `alerts(filters: [FilterInput!])` = flat AND list; `alertTriggerActions(filter:)` = `{or: [{and: [FilterInput]}]}`.
- Filter field names (`fieldId`) come from `alertColumnMetadata`, among them `id`, `status`, `severity`,
  `createdAt`, `detectedAt` (date range in epoch ms), `assetName`, `alertName`, `detectionProduct`,
  `mitreTechniques`, `incidentId`.
- Action IDs from `alertAvailableActions`: `S1/alert/statusUpdate`, `S1/alert/analystVerdictUpdate`,
  `S1/alert/addNote`, `S1/incident/create`, `S1/incident/addToExisting`, `S1/kill`, `S1/quarantine`,
  `S1/remediate`, `S1/rollback`, `S1/disconnectFromNetwork`, ...
- Notes via the mutation `addAlertNote(alertId, text, type: MARKDOWN)`.

## Setup

1. Create a **site** for the range in the console (e.g. `ai-range`) and note the site ID.
2. Create a **service user** scoped to this site (Settings -> Users -> Service Users):
    - for Blue/Engineer/Ansible role **SOC** (or IR Team): edit unified alerts, disconnect/mitigate, manage STAR
      rules, Deep Visibility/PowerQuery.
    - optionally a second service user with role **Viewer** for the scorer (`S1_ORCH_API_TOKEN`).

    The site scope of the token is the actual permission boundary; `S1_SITE_ID` additionally filters in the code.
3. `docker/.env`:

    ```ini
    AIRANGE_EDR=sentinelone
    S1_CONSOLE_URL=https://<tenant>.sentinelone.net
    S1_API_TOKEN=<service user token>
    S1_SITE_ID=<site ID>
    # optional: S1_ORCH_API_TOKEN, S1_SITE_TOKEN (otherwise read from the site via API)
    ```

4. Put the **installers** into `sources/sentinelone/installer/` (git-ignored):
   `SentinelOneInstaller_windows_64bit_*.exe` and `SentinelAgent_linux_x86_64_*.deb`. The role takes the
   alphabetically last (= newest) file of each.
5. Roll out the agents (on fresh VMs or after uninstalling Elastic Agent; avoid running two EDRs side by side):

    ```sh
    docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/agents.yml"
    ```

    Windows: copy the installer via WinRM (~90 MB), `<exe> -t <site token> -q`, reboot on exit code 3010.
    Linux: `.deb` via `apt`, `sentinelctl management token set ...`, `sentinelctl control start`.
    Idempotent: hosts with an existing service (`SentinelAgent` or `sentinelone.service`) are skipped.
6. Check: `docker compose --env-file .env run --rm agents check` shows console version, token expiry, site,
   missing range hosts, open UAM alerts and a test PowerQuery.

### Identity (Singularity Identity / Ranger AD)

S1 detects many AD attacks (Kerberoasting, AS-REP roasting, password spraying, enumeration, ...) only with the
Identity component. It needs an AD connector (a Windows member server with the S1 agent, **not a DC**; the host
with service `identity_connector` in `range.yaml`, SQL01 in the example) and an AD read account:

1. Account `svc.s1identity` (OU ServiceAccounts, only Domain Users, password never expires) with its **own**
   password `S1_AD_PASSWORD` in `docker/.env`, deliberately not `RANGE_USER_PASSWORD`, which Red can spray:

    ```sh
    docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/ad.yml --tags s1_identity"
    ```

2. Connector and AD configuration via API (role `sentinelone_identity`, connector `s1id_connector_host` = the
   `identity_connector` host, features Singularity Identity + Ranger AD + **Ranger AD Protect**, **LDAPS** (636)
   and **WinRM over HTTPS** (5986) to the DC FQDN (e.g. `dc01.corp.internal`) with a certificate from the
   enterprise CA (e.g. `CORP-CA01-CA`), trusted by the domain hosts, daily refresh at 03:00 in the time zone `s1id_time_zone`, default `locale.timezone` from `range.yaml`):

    ```sh
    docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/s1-identity.yml"
    ```

    Flow: `enableWebsocketOnAgent` -> `addAdConnector` -> `addCompleteAdConfiguration`. Idempotent; if the
    existing configuration differs (encryption, DC, user, connector) it is overwritten with `update: true`.
    Undocumented API quirks: the password must be passed **Base64-encoded** (otherwise Kerberos `0x18` at the DC,
    and the API reports "Invalid Credentials"), `allowedScopes` as `{scopeId, scopeLevel}` (otherwise "Scope Input
    is null").

3. **Identity policies:** complete the Identity onboarding wizard once. Its default policies
   (`default_policy_account_site_*`) cannot be activated; use copies (`duplicatePolicy`) named `ai-range DC` and
   `ai-range Clients` instead. In `ai-range DC` enable ingestion, Compromised Credential Protection and Threat
   Detection in the console. This is not possible via API: `createPolicy`/`updatePolicy` require undocumented
   input objects per engine (`adDcConfig`, `ccpConfig` with `autoScanConfig`, `xdrIngestionConfig`, ...), and DC
   policies cannot be read through `getIdentityPolicyDetails` (server error). The playbook then activates both
   policies by name (`s1id_policy_names`). Check: `adConfigurations` -> `isPolicyActive: true`.

4. **Conditional Access** (`ai-range CA`, `tasks/conditional_access.yml`, runs with `s1-identity.yml`): one rule
   covering all AD attacks Singularity Identity knows (46, list taken from the default CA policy), action
   `s1id_ca_response_action` (default `BLOCK`: block AD traffic from the source at the DC for
   `s1id_ca_block_minutes`, raise an alert), with the IP of the identity connector as exception. The role creates
   the policy, corrects deviations and activates it; only one CA policy per site may be active, so another one is
   deactivated first. API quirks: `duplicatePolicy` on the default CA policy fails, `createPolicy` with
   `engineConfigurationInput: [{engineType: CONDITIONAL_ACCESS, caConfig: {...}}]` works; `updatePolicy` needs the
   IDs of `caConfig`, `advancedSettings` and the rule. Exceptions are `{type, subType, values, domains}` with `type`
   `IDENTITY` (USERS/GROUPS) or `NETWORK_ENTITY_SOURCE`/`_TARGET` (HOSTNAME/IP_ADDRESS/IP_ADDRESS_RANGE); the API
   rejects accounts and host names here because they are resolved through the Ranger AD inventory (the assessment
   fails, see below), so only IP exceptions are used.

5. **AD Secure EP** (client policy `ai-range Clients`): the mode `DETECT` or `DETECT_AND_PROTECT` (console:
   Protect) can only be set in the console; `createPolicy`/`updatePolicy` reject any AD Secure EP configuration
   with "No rules are configured for the AD Secure EP policy". `s1-identity.yml` compares the mode with
   `s1id_ep_action` and reports deviations. The same applies to the mode of the DC policy.

**Connector requirements** (S1 documentation "AD Connector with Windows Agent: requirements"):

- From the connector to the DCs: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, WinRM 5985 (or 5986 with HTTPS).
- Threat Detection and the assessment fetch the DCs' event logs via WinRM/RPC. For this `ad.yml --tags
  s1_identity` adds `svc.s1identity` to *Event Log Readers* and *Remote Management Users* (no admin rights) and
  enables the firewall group *Remote Event Log Management* (RPC, RPC-EPMAP, NP-In) on the DCs. Without it: WinRM
  "Access denied", remote event log "RPC server is unavailable", assessment `FAILED`.
- WinRM over HTTPS: `ad.yml --tags s1_identity` creates an HTTPS listener (5986) on the DCs with the DC
  certificate from the enterprise CA (Server Authentication, FQDN) plus a firewall rule. The CRL of the range CA
  is only distributed via LDAP; as SYSTEM/computer account (which is how the connector runs) the revocation check
  works, while tests from an Ansible WinRM session as local admin fail because of the double hop
  (`CRYPT_E_REVOCATION_OFFLINE`).
- Rebuilding: an AD configuration can only be deleted (`deleteAdConfiguration`, `input: [<id>]`) while no
  identity policy is active, so deactivate them first. The DC policy can only be re-activated after the AD learning
  phase ("AD Learning is IN_PROGRESS"); the playbook waits for it. `getCloudlinkConfigurations` is empty as long as
  no AD configuration exists; the cloudlink ID then comes from the response of `addAdConnector`.
- **ISPM / Ranger AD assessment is not pursued further** (as of 11/2026): the assessment fails with "Exception
  while fetching domain details from root dse ... subscriber 5668". On the DC, creating the configuration via API
  shows successful Kerberos logons (4768/4624), whereas starting the assessment and saving in the console show
  4771 `0x18` (wrong password) from the connector; S1 probably handles the (Base64) password inconsistently
  internally. Threat Detection (Singularity Identity) and Ranger AD Protect work independently of this.
- Recommended for the connector: 4 cores / 16 GB RAM. SQL01 in the example has 4 cores / 6 GB.
- No DC as connector. Trigger the assessment again: `POST /ranger-ad/trigger-assessment`
  (`{"filter": {"domainName": ["corp.internal"], "isFullScan": true, "scanSource": "AD"}}`).

The connector may be isolated; most identity functions keep running (but without a connection to the DCs there
is no event-log-based Threat Detection and no assessment).

### Log collection (Windows event logs)

The S1 agent additionally collects Windows event logs into the data lake (queryable with PowerQuery). One rule
per channel (role `sentinelone_logcollection`, scope range site, idempotent by name):

| Rule | Channel | Events |
|---|---|---|
| `ai-range Security` | Security | 1102, 4624/4625/4648, 4662, 4672, 4688, 4697/4698/4702, 4719, 4720-4726, 4728/4732/4756, 4738, 4740, 4767, 4768/4769/4771, 4776, 4781, 5136, 5140, 5145 |
| `ai-range Sysmon` | Microsoft-Windows-Sysmon/Operational | all |
| `ai-range PowerShell` | Microsoft-Windows-PowerShell/Operational | 4103, 4104 |
| `ai-range System` | System | 7045, 104 |

```sh
docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/s1-logcollection.yml"
```

Channels and IDs are in `roles/sentinelone_logcollection/defaults/main.yml` (`s1lc_rules`). The playbook does not
apply changed IDs to existing rules (it only creates/enables); delete the rule in the console and roll out again.

### Agent policy (detect / protect)

The role `sentinelone_policy` sets the agent policy for the site and every group that does not inherit (Default
Group). Protect needs an automatic action (`mitigation.quarantineThreat` = kill & quarantine); the API rejects
`mitigation.none`:

```sh
docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/s1-policy.yml"
# back to detect: ... -e s1pol_mitigation_mode=detect -e s1pol_mitigation_mode_suspicious=detect
```

With **Detect** exercises measure detection; with **Protect** S1 blocks known Red tools immediately and the
exercise mainly measures prevention.

### Network Discovery (Ranger) and Firewall Control

Required for the Blue tools `network_device` and `firewall`. Not automated by Ansible; enable both once for the
range site, for example with `agents api s1 PUT ...`:

- **Network Discovery:** `PUT /ranger/settings` (filter `siteIds`) with `enabled: true` and
  **`minAgentsInNetworkToScan: 1`**. The default of 100 is never reached in the range, and then no agent scans.
  `scanOnlyLocalSubnets: true` limits the scan to the range network. The device view is built periodically
  (`snapshotPeriod`, default 120 min), so new devices appear with a delay. Ranger runs on the Windows agents
  (`rangerStatus: Enabled`), not on the Linux agents. The active scans (ICMP, TCP ports, SMB, SNMP, ...) are visible
  in the telemetry and can trigger detections of their own.
- **Firewall Control:** `PUT /firewall-control/configuration` with `enabled: true`, `reportBlocked: true`,
  `inheritSettings: false`. Without rules this does not change any traffic. Blue creates its own rules with the
  prefix `ai-range blue:`; `agents cleanup` deletes them again.

## Tool behaviour

- **Site boundary:** UAM queries and actions run with `scope: {scopeType: SITE, scopeIds: [S1_SITE_ID]}`; every
  PowerQuery gets `site.id = '<S1_SITE_ID>'` as mandatory filter; REST calls run with `siteIds`. Isolation and
  mitigation only for range hosts from `range.yaml`.
- **IDs:** UAM alert IDs (UUIDs) for `get_alert`, `update_alerts`, `create_case`, `response_action mitigate`.
- **Status mapping:** open <-> NEW, acknowledged <-> IN_PROGRESS, closed <-> RESOLVED. Verdict short forms
  `true_positive`, `false_positive`, `benign`, `suspicious`, `undefined` or an exact enum value.
- **get_alert** returns a ready-made PowerQuery filter per indicator (`eventSearchParams.filter`), a starting point
  for hunting.
- **create_case:** creates an incident `[ai-range] <title>` or attaches to an existing one via `incident_id`, adds
  the case text as Markdown note to every alert and sets the alerts to IN_PROGRESS.
- **Response:** `isolate`/`release` = REST disconnect/connect (waits until `networkStatus` matches), `mitigate` =
  UAM action on the alert. Killing arbitrary PIDs is not possible with S1 (only via remote scripts, deliberately not
  enabled). `AIRANGE_BLUE_RESPONSE=off` -> recommendations only.
- **Network response:** `network_device isolate` sets the device review of a device without agent to "Isolated",
  `release` to "Not Reviewed". `firewall create_rule` creates rules for all range endpoints of one operating
  system; block rules only with concrete addresses in the range network, never the gateway, the DC or the
  controller.
- **Engineer:** new rules are named `ai-range: ...`, live in the range site, `queryLang 2.0`, `Permanent`,
  **without** auto-response (`networkQuarantine=false`, `treatAsThreat=UNDEFINED`). MITRE IDs are written as a line
  `MITRE ATT&CK: T...` in the description. Changing/disabling only for rules with this prefix. There is no preview
  API: `preview_rule` runs the rule logic as PowerQuery over the time window.

## Scorer

With `AIRANGE_EDR=sentinelone`, `score` fetches all UAM alerts of the site in the window (`createdAt`), loads
their indicators (MITRE) via GraphQL aliases and normalizes them to the same format as Elastic alerts
(`scorer.norm_s1`):

| Field | Source |
|---|---|
| Alert time (TTD) | `createdAt` (creation at the source) |
| Event time (step assignment) | `detectedAt` |
| Host / IPs | `assets[].name`, `detectionTime.asset.ipV4Addresses`, `detectionTime.attacker.ip` (-> source IP) |
| MITRE | `indicators[].attacks[].technique.uid` (real T-IDs only) + `T...` IDs from name/description |
| Rule (noise) | Alert name; for EDR without the process prefix (`cmd.exe (CLI ...) - X detected` -> `X detected`) |
| Engineer rule | Name starts with `ai-range:` |
| Triage | `status` + `updatedAt` |

Report and `range-scores` carry `platform: sentinelone`, so runs of both platforms can be compared.

## Tests

```sh
docker compose --env-file .env run --rm -T --entrypoint python agents tests/smoke_s1.py           # offline (default), no console
docker compose --env-file .env run --rm -T --entrypoint python agents tests/smoke_s1.py read      # live, read-only
```

The offline mode uses the fixture topology `agents/tests/range.test.yaml`, not your `range.yaml`. Further tests
are described in [Agents & scoring](agents.md#tests).

Verified live (read-only, against a console): PowerQuery, UAM `alerts`/`alert`/notes/timeline/
`alertAvailableActions`, STAR rule list, preview via PowerQuery, site and host guards.

## Open points

- **Write actions** (status/verdict/note, create incident, mitigation, isolation, create STAR rule) are built from
  the schema but have not been executed live yet. In particular the format of `createIncident.severity` is unclear
  (sent: `LOW|MEDIUM|HIGH|CRITICAL`).
- **MITRE on EDR alerts:** for "Agent Policy" alerts `technique.uid` often contains a name instead of a T-ID (e.g.
  "Inhibit System Recovery"); then there is no technique match in the scorer. A name -> ID mapping may help.
- Windows installer: switches `-t ... -q` and exit codes (`sentinelone_win_ok_rc`) for the version in use.
- **xSPM writes** (`update_vulnerabilities`: verdict, status, note) are built from the schema but not executed
  live. According to `vulnerabilityAvailableActions` the Blue service user may perform them (target status from
  NEW: IN_PROGRESS, RISK_ACKED, RESOLVED); whether NEW is accepted as a step back is open.
- Further GraphQL APIs: Asset Inventory (`/web/api/v2.1/graphql`) and xSPM misconfigurations
  (`/web/api/v2.1/xspm/findings/misconfigurations/graphql`) are not used.

## Vulnerabilities (xSPM)

Blue triages the findings from Singularity Vulnerability Management through
`/web/api/v2.1/xspm/findings/vulnerabilities/graphql` (`agents/airange/xspm.py`).

- One finding = one CVE on one asset in one piece of software. A range site easily has tens of thousands, almost
  all low/medium; `list_vulnerabilities` therefore groups by CVE (at most 500 findings per call, sorted by S1 risk
  score) and always returns the count per severity/status.
- All queries and changes are filtered by the range host names (`assetName`). Other assets in the same site are
  neither visible to nor changed by Blue.
- `update_vulnerabilities` sets verdict (TRUE_/FALSE_POSITIVE), status (only NEW/IN_PROGRESS) and note, by IDs or
  for one CVE on all range hosts (at most 200 findings per call). RESOLVED/RISK_ACKED remain reserved for humans.
- Grouped queries (`vulnerabilityGroups`) cannot be sorted by risk score; a `stringIn` filter on `assetName` causes
  a server error there, hence `match`/`exactMatch` (case-insensitive).
