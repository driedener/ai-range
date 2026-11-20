# Elastic

The Elastic configuration is code: playbook `ansible/playbooks/elastic-config.yml` -> role
`ansible/roles/elastic_fleet_config`. It runs in the `tools` container on `localhost` and talks only to the
Kibana and Elasticsearch APIs (`https://kibana:5601`, `https://es01:9200`, CA `/certs/ca/ca.crt`, user
`elastic`). Every step reads the current state first and writes only when it differs. The playbook is idempotent
and can be re-run at any time. `site.yml` includes it.

## Running

From `docker/` (the stack must be running and the Fleet Server enrolled):

```sh
docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/elastic-config.yml"
```

Single steps by tag (`--tags defend|rules|indices|ilm|security`), variables with `-e`, for example:

```sh
docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/elastic-config.yml --tags defend -e defend_mode=prevent"
```

The playbook needs no `ansible.cfg` and no inventory (implicit `localhost`, role by relative path).

## Required environment variables (tools container)

| Variable | Purpose |
|---|---|
| `ELASTIC_PASSWORD` | Admin access (`elastic`) for all API calls |
| `RANGE_BLUE_PASSWORD` | Password of user `blue-agent` |
| `RANGE_RED_PASSWORD` | Password of user `red-agent` |
| `RANGE_ORCH_PASSWORD` | Password of user `orchestrator` |

If one of the three `RANGE_*_PASSWORD` values is missing or shorter than 8 characters, the playbook aborts before
making any change. The variables must be set in `docker/.env` **and** passed through to the `tools` service under
`environment:` in `docker/compose.yml` (already the case for these four).

## What the playbook does

Order: preflight -> ILM -> indices -> roles/users -> Defend -> rules.

With `AIRANGE_EDR=sentinelone` the Defend and rules steps are skipped (`defend_enabled` / `rules_enabled` follow
`AIRANGE_EDR`); ground truth, traces and scores still live in Elasticsearch.

### Preflight

Checks environment variables and the CA, waits until Kibana reports `available`, reads the licence
(`GET _license`) and calls `POST /api/fleet/setup` (idempotent).

### 1. Elastic Defend (`tasks/defend.yml`, tag `defend`)

- Checks that the preconfigured agent policies `range-windows` and `range-linux` exist.
- Installs the `endpoint` package if missing (version from `GET /api/fleet/epm/packages/endpoint`).
- Creates one package policy `defend-<policy>` per agent policy (`POST /api/fleet/package_policies`). According to
  the documentation and the Kibana source (`fleet_integration.ts`), the **create** input is
  `type: ENDPOINT_INTEGRATION_CONFIG` with `config._config.value = {type: endpoint, endpointConfig: {preset: EDRComplete}}`.
  Kibana replaces it on creation with the actual input `type: endpoint` with `config.integration_config`,
  `config.artifact_manifest` and `config.policy`.
- Then sets `inputs[type=endpoint].config.policy.value.<os>.<protection>.mode` for `windows`/`linux` ×
  `malware`, `ransomware`, `memory_protection`, `behavior_protection` to `defend_mode`, via GET -> modify ->
  `PUT /api/fleet/package_policies/<id>` with `version` for optimistic locking. Protections that do not exist in
  the policy object (e.g. `ransomware` on Linux) or have `supported: false` (Basic licence) stay unchanged.

### 2. Prebuilt detection rules (`tasks/rules.yml`, tag `rules`)

- `GET /api/detection_engine/rules/prepackaged/_status`. If rules are missing or outdated, the
  `security_detection_engine` package is missing, or `rules_always_refresh: true` is set, it calls
  `PUT /api/detection_engine/rules/prepackaged` (installs/updates rules and timelines; takes minutes).
- Enables all **prebuilt** rules (`params.immutable:true`) matching
  `tags:("OS: Windows" OR "OS: Linux") AND tags:("Tactic: ..." OR ...) AND NOT params.type:machine_learning`
  via `POST /api/detection_engine/rules/_bulk_action` (`action: enable`, `query`). Before that, `_find` counts the
  affected rules that are still disabled; if there are none, nothing changes.
- KQL has no wildcards inside phrases (`"Tactic: *"` does not work), so the 14 MITRE tactics are listed in
  `rules_enable_tactic_tags`.

### 3. Range indices (`tasks/indices.yml`, tag `indices`)

Index templates (priority 500, 1 shard, `number_of_replicas: 0` because of the single node, ILM `range-14d`) and
pre-created data streams:

| Data stream | Contents | Important fields |
|---|---|---|
| `range-groundtruth` | Ground truth of the Red agent | `@timestamp`, `run.id`, `agent.name`, `source.ip`/`destination.ip` (ip), `host.name`, `threat.technique.id`/`.name`, `threat.tactic.name`, `process.command_line` (wildcard + `.text`), `event.outcome`, `message` |
| `range-agenttrace` | Tool calls / LLM traces of all agents | `run.id`, `agent.name`, `agent.role` (red\|blue\|engineer), `tool.name`, `tool.input` (flattened, send an **object**), `tool.input_raw` (text, if the input is not an object), `tool.output` (text, `index: false`), `llm.model`, `llm.tokens.{input,output,total,cache_read,cache_write}`, `event.duration`, `event.outcome`, `error.message` |

Writing: `POST range-groundtruth/_doc` or `range-agenttrace/_doc` (data streams need `@timestamp`; only
`create`/`_doc`, no updates). When a mapping changes, increment `range_template_version`; the playbook then
rewrites the template and marks the data streams for a lazy rollover.

### 4. Roles and users (`tasks/security.yml`, tag `security`)

Roles via `PUT /api/security/role/<name>` (Elasticsearch and Kibana part together), users via
`PUT /_security/user/<name>`.

| Role | ES indices | Kibana |
|---|---|---|
| `range_blue` | read: `logs-*`, `metrics-*`; read/write/maintenance: `.alerts-security*`, `.internal.alerts-security*`, `.siem-signals*`, `.preview.alerts-security*`, `.internal.preview.alerts-security*` (rule preview); read/write: `.lists*`, `.items*`; only `create_doc`: `range-agenttrace*` | Security (`siem*`) `minimal_all` + sub-features `range_blue_siem_subfeatures` (endpoint list read, response actions history read, host isolation all, process operations all), Cases all, Timeline/Notes all (if present), Actions read, Fleet + Integrations read |
| `range_red` | only `create_doc`/`auto_configure`: `range-groundtruth*`, `range-agenttrace*` | none |
| `range_orchestrator` | read/write/create_index: `range-*`; read: `logs-*`, `metrics-*`, alert indices | Security read, Cases read, Fleet + Integrations read |

Users: `blue-agent` -> `range_blue`, `red-agent` -> `range_red`, `orchestrator` -> `range_orchestrator`. The
playbook detects password drift with a login test (`GET /_security/_authenticate` with the password from the
environment) and resets the password on 401.

The Kibana feature IDs of the Security solution are versioned between 9.x minors (`siem` -> `siemV2` ->
`siemV3` -> ..., likewise `securitySolutionCases*`). The playbook reads `GET /api/features` and takes the highest
version. Additional features (e.g. Discover) can be added with
`range_blue_extra_kibana_features: {discover_v2: [read]}`. The response action sub-features of Elastic Defend
(`host_isolation_all`, `process_operations_all`, ...) are **not** included in `all` (`includeIn: none`), so
`range_blue` gets `minimal_all` plus the list `range_blue_siem_subfeatures` (empty list = plain `all` again).

#### Ground-truth isolation (design decision)

Elasticsearch index privileges have no negation, so any role with `logs-*` could also read
`logs-range.groundtruth-default`. Ground truth **and** agent traces therefore deliberately live **outside**
`logs-*`, under their own prefix `range-*`:

- `range_blue` gets `logs-*`/`metrics-*` and thus all telemetry (Fleet integrations, Defend, agent monitoring),
  but no pattern that matches `range-groundtruth*`. Backing indices (`.ds-range-*`) are excluded by the data
  stream privileges as well.
- The agent traces would reveal the Red agent's actions, so Blue may only append there (`create_doc`), not read.
- No Fleet/integration index template matches `range-*`, so there is no collision with the managed templates.
- Downside: `range-*` does not follow the `type-dataset-namespace` scheme, and the default Kibana data views
  (`logs-*`) do not show the data. Create a separate data view `range-*` for the orchestrator.

The alternative, giving Blue only `logs-*-range` (the namespace of the agent policies), was rejected as fragile:
every new namespace would either break the isolation or hide telemetry.

### 5. ILM (`tasks/ilm.yml`, tags `ilm`, `indices`)

- Policy `range-14d`: hot with rollover (`1d` / `10gb` primary shard), delete 14 days **after rollover**. Actual
  retention is therefore about 14-15 days.
- `logs_retention_days` (default `14`, `0` = off): creates the policy `range-logs-retention` and sets
  `index.lifecycle.name` in the component template **`logs@custom`**. Existing content is kept; only this setting
  is merged. All Fleet `logs-*` templates include `logs@custom` after their `@package` template, so the setting
  wins. The managed policy `logs` is **not** modified. The setting applies only to new backing indices; existing
  data streams pick it up at the next rollover (manually: `POST logs-<...>/_rollover`). For `metrics-*` use
  `metrics@custom` analogously (not automated).

## Variables (selection, see `defaults/main.yml`)

| Variable | Default | Meaning |
|---|---|---|
| `defend_mode` | `detect` | `detect` \| `prevent` \| `off` for malware/ransomware/memory/behavior |
| `defend_preset` | `EDRComplete` | Preset at creation (`DataCollection`, `NGAV`, `EDREssential`, `EDRComplete`) |
| `defend_agent_policies` | `[range-windows, range-linux]` | Target agent policies |
| `defend_policy_os` | `[windows, linux]` | Operating systems whose modes are set |
| `rules_enabled` | `true` (`false` with SentinelOne) | Rules step on/off |
| `rules_always_refresh` | `false` | Always reinstall/update the prebuilt package |
| `rules_enable_os_tags` | `OS: Windows`, `OS: Linux` | OR-combined |
| `rules_enable_tactic_tags` | all 14 MITRE tactics | OR-combined, AND with OS |
| `rules_enable_data_source_tags` | `[]` | Optional, e.g. `Data Source: Elastic Defend`, to skip rules for third-party sources that do not exist |
| `rules_exclude_ml` | `true` | Skip ML rules |
| `rules_enable_query_override` | `""` | Own KQL query instead of the tag filters |
| `range_groundtruth_stream` / `range_agenttrace_stream` | `range-groundtruth` / `range-agenttrace` | Data stream names |
| `range_retention_days` | `14` | Retention of `range-*` |
| `logs_retention_days` | `14` | Retention of `logs-*` via `logs@custom` (`0` = leave alone) |
| `range_users` | 3 users | User name, role, environment variable of the password |

Load: with the default filter several hundred rules are enabled. Many target data sources that do not exist in
the range (third-party EDR, cloud, ...). They run empty but cost rule executions. Use
`rules_enable_data_source_tags` to limit the selection to existing sources.

## Licence: Basic vs. Trial

| Feature | Basic | Trial / Platinum+ |
|---|---|---|
| Fleet, integrations, Defend telemetry (events) | yes | yes |
| Defend malware protection (detect/prevent) | yes | yes |
| Defend ransomware / memory / behavior protection | no (stays `off`, playbook skips) | yes |
| Defend response actions (isolate, kill process, ...) | no | yes (details per version in Elastic's subscription overview) |
| Prebuilt rules (query, EQL, threshold, new terms, ES\|QL, indicator match) | yes | yes |
| ML rules / anomaly detection | no (playbook skips them) | yes |
| Rule actions with external connectors (e-mail, Slack, webhook, ...) | no (index/server log only) | yes |
| Cases, Timeline | yes | yes |
| Native roles/users, feature privileges | yes | yes |

When the 30-day trial expires, the cluster falls back to Basic. Paid protections already set to
`detect`/`prevent` remain in the policy object but are no longer executed by the endpoint. A new playbook run on
Basic skips them (`supported: false`). Policy updates may fail for licence reasons until the paid protections are
set to `off` in the UI. Blue's response actions (isolation) need Trial or a paid licence.

## Checks after the first run

- Defend: did `POST /api/fleet/package_policies` accept the create input `ENDPOINT_INTEGRATION_CONFIG`/`_config`
  in your 9.x version? Does the response contain `inputs[0].config.policy.value.{windows,linux}`?
- Bulk enable: is the number of enabled rules plausible? Watch for errors in the debug output.
- Feature IDs (`siemV*`, `securitySolutionCasesV*`): check `GET /api/security/role/range_blue` in Kibana.
- Log in as `blue-agent`: `GET range-groundtruth/_search` must return `403`, `GET logs-*/_search` `200`.
