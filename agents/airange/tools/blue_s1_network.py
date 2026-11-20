"""Network response of the blue agent for SentinelOne:

- `network_device`: Ranger (Network Discovery) – list discovered, unmanaged devices and block them via
  device review "Isolated" or release them again. Managed range endpoints still go through
  `response_action` (agent isolation).
- `firewall`: Firewall Control of the range site – status/activation and own rules (prefix "ai-range blue:"):
  create, enable/disable, delete. Other rules are read-only.

Guardrails (in addition to the service user's permissions): only the range site, only addresses in the range network,
never gateway, DC or management IPs; every change needs a justification; response mode "off" ->
recommendation only. Everything created here survives a VM rollback -> `cleanup` removes it.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

from claude_agent_sdk import SdkMcpTool

from ..config import RANGE_HOSTS, settings
from ..runner import make_tool
from ..sentinelone import SentinelOne
from ..topology import TOPOLOGY
from ..uam import ACTION_STATUS, ACTION_VERDICT, UAM, f_in
from .blue import ToolError
from .blue_s1 import _recommend, safe

RULE_PREFIX = "ai-range blue: "
CLEANUP_VERDICT = "TRUE_POSITIVE_BENIGN"   # verdict for alerts the cleanup closes without one
DEVICE_ACTIONS = ["list", "isolate", "release"]
FW_ACTIONS = ["status", "enable", "create_rule", "set_status", "delete_rule"]
RELEASED_REVIEW = "Not Reviewed"
OPEN_STATUS = ["NEW", "IN_PROGRESS"]   # alerts and incidents alike


def protected_ips() -> set[str]:
    """Addresses Blue must never block: gateway(s), DC, management (controller)."""
    return set(settings.target_exclude) | set(settings.mgmt_ips) | {TOPOLOGY.dc.ip}


def check_remote(value: str) -> str:
    """IP or CIDR in the range network, without protected addresses."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ToolError(f"{value!r}: not an IP address/CIDR") from exc
    if not net.subnet_of(ipaddress.ip_network(settings.target_cidr)):
        raise ToolError(f"{value}: is outside the range network {settings.target_cidr}")
    hit = [ip for ip in protected_ips() if ipaddress.ip_address(ip) in net]
    if hit:
        raise ToolError(f"{value}: contains protected addresses {sorted(hit)} (gateway/DC/management) – refused")
    return str(net) if net.num_addresses > 1 else str(net.network_address)


# --------------------------------------------------------------------------- Ranger

def _device_row(d: dict) -> dict:
    keys = ("id", "localIp", "macAddress", "hostnames", "hostname", "managedState", "deviceReview", "osName",
            "osType", "manufacturer", "deviceType", "deviceFunction", "firstSeen", "lastSeen", "tcpPorts",
            "networkName", "agentId")
    return {k: d[k] for k in keys if d.get(k) not in (None, "", [])}


def _device_ips(d: dict) -> list[str]:
    raw = d.get("localIp") or d.get("localIps") or []
    vals = raw if isinstance(raw, list) else [raw]
    return [str(v).strip() for v in vals if v]


def build_device_tool(s1: SentinelOne) -> SdkMcpTool:
    async def devices(extra: dict | None = None, limit: int = 200) -> list[dict]:
        params = {**s1.site_params(), "period": "last7d", **(extra or {})}
        return await s1.paged("/ranger/table-view", params, limit=limit)

    async def resolve(args: dict) -> dict:
        if args.get("device_id"):
            found = await devices({"ids": [str(args["device_id"])]}, limit=5)
        elif args.get("ip"):
            ip = check_remote(args["ip"])
            found = [d for d in await devices({"localIp": ip}, limit=20) if ip in _device_ips(d)]
        else:
            raise ToolError("specify device_id or ip (from action=list)")
        if not found:
            raise ToolError("Device not found in the Network Discovery of the range site (action=list)")
        if len(found) > 1:
            raise ToolError(f"ambiguous ({len(found)} devices) – use device_id from action=list")
        d = found[0]
        ips = _device_ips(d)
        if not ips:
            raise ToolError("Device without a known IP – refused")
        for ip in ips:
            check_remote(ip)
            if ip in RANGE_HOSTS:
                raise ToolError(f"{ip} is the managed range host {RANGE_HOSTS[ip]} – use response_action "
                                "(isolate) for it")
        return d

    @safe
    async def network_device(args: dict) -> dict:
        action = args.get("action")
        if action not in DEVICE_ACTIONS:
            raise ToolError(f"action must be one of {DEVICE_ACTIONS}")
        if action == "list":
            extra: dict[str, Any] = {}
            if args.get("ip"):
                extra["localIp__contains"] = [str(args["ip"]).strip()]
            if args.get("unmanaged_only", True):
                # Ranger value for devices without an agent is "Unsecured" (case-sensitive; "unmanaged" returns nothing)
                extra["managedStates"] = ["Unsecured"]
            rows = [d for d in await devices(extra) if any(
                ipaddress.ip_address(ip) in ipaddress.ip_network(settings.target_cidr)
                for ip in _device_ips(d) if _is_ip(ip))]
            return {"total": len(rows), "devices": [_device_row(d) for d in rows[:100]],
                    "note": "isolate blocks a device network-wide via the managed agents (Ranger)."}
        reason = (args.get("reason") or "").strip()
        if not reason:
            raise ToolError("reason is mandatory (justification)")
        d = await resolve(args)
        label = f"{', '.join(_device_ips(d))} ({d.get('macAddress') or d.get('id')})"
        if settings.blue_response_mode != "auto":
            return _recommend(f"network_device/{action}", label, reason)
        review = "Isolated" if action == "isolate" else RELEASED_REVIEW
        r = await s1.api("POST", "/ranger/device-review", json={
            "data": {"deviceReview": review, "reason": "Other", "reasonDetails": f"[ai-range blue] {reason}"[:500]},
            "filter": {"ids": [d["id"]], **s1.site_params()}})
        after = (await devices({"ids": [d["id"]]}, limit=1) or [d])[0]
        return {"executed": True, "action": action, "device": _device_row(after),
                "affected": (r or {}).get("data", {}).get("affected") if isinstance(r, dict) else None,
                "reason": reason}

    return make_tool("network_device", (
        "Ranger/Network Discovery: devices in the range network that SentinelOne has discovered (also without an agent, e.g. a "
        "foreign attacker device). list (default only unmanaged devices; ip filters), isolate (device review "
        "'Isolated': the managed agents block the device), release (lift the block). For managed range hosts "
        f"use response_action. Gateway, {TOPOLOGY.dc.name} and management are protected. reason is mandatory for "
        "isolate/release; in response mode 'off' recommendation only."), {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": DEVICE_ACTIONS},
            "device_id": {"type": "string", "description": "ID from action=list"},
            "ip": {"type": "string", "description": "IP of the device (alternative to device_id; filter for list)"},
            "unmanaged_only": {"type": "boolean", "description": "list: only devices without an agent (default true)"},
            "reason": {"type": "string"},
        },
        "required": ["action"],
    }, network_device)


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- Firewall Control

def _rule_row(r: dict) -> dict:
    keys = ("id", "name", "action", "direction", "status", "protocol", "osTypes", "remoteHosts", "remoteHost",
            "remotePort", "localPort", "application", "order", "scope", "description", "createdAt")
    return {k: r[k] for k in keys if r.get(k) not in (None, "", [])}


def build_firewall_tool(s1: SentinelOne) -> SdkMcpTool:
    site = s1.site_params()

    async def rules(extra: dict | None = None) -> list[dict]:
        return await s1.paged("/firewall-control", {**site, **(extra or {})}, limit=500)

    async def own(ids: list[str]) -> list[dict]:
        if not ids or not all(str(i).isdigit() for i in ids):
            raise ToolError("rule_ids: numeric rule IDs from action=status")
        found = await rules({"ids": [str(i) for i in ids]})
        foreign = [r.get("name") for r in found if not str(r.get("name", "")).startswith(RULE_PREFIX)]
        if foreign:
            raise ToolError(f"Only own rules ({RULE_PREFIX}…) can be changed – refused for {foreign}")
        if len(found) != len(set(ids)):
            raise ToolError("Not all rule IDs found in the range site")
        return found

    def ports(value: Any, name: str) -> dict:
        if not value:
            return {"type": "any", "values": []}
        vals = [int(p) for p in (value if isinstance(value, list) else [value])]
        if any(not 1 <= p <= 65535 for p in vals):
            raise ToolError(f"{name}: ports 1–65535")
        return {"type": "ports", "values": vals}

    @safe
    async def firewall(args: dict) -> dict:
        action = args.get("action")
        if action not in FW_ACTIONS:
            raise ToolError(f"action must be one of {FW_ACTIONS}")
        if action == "status":
            conf = await s1.api("GET", "/firewall-control/configuration", params=site)
            allr = await rules()
            return {"configuration": (conf or {}).get("data"), "rules_total": len(allr),
                    "own_rules": [_rule_row(r) for r in allr if str(r.get("name", "")).startswith(RULE_PREFIX)],
                    "other_rules": [_rule_row(r) for r in allr if not str(r.get("name", "")).startswith(RULE_PREFIX)][:30]}
        reason = (args.get("reason") or "").strip()
        if not reason:
            raise ToolError("reason is mandatory (justification)")

        if action == "enable":
            if settings.blue_response_mode != "auto":
                return _recommend("firewall/enable", "Range-Site", reason)
            r = await s1.api("PUT", "/firewall-control/configuration",
                             json={"filter": site, "data": {"enabled": True, "reportBlocked": True,
                                                            "inheritSettings": False}})
            return {"executed": True, "action": "enable", "configuration": (r or {}).get("data"), "reason": reason}

        if action == "create_rule":
            fw_action = args.get("rule_action")
            if fw_action not in ("Allow", "Block"):
                raise ToolError("rule_action: Allow or Block")
            direction = args.get("direction") or "inbound"
            if direction not in ("inbound", "outbound", "any"):
                raise ToolError("direction: inbound | outbound | any")
            remotes = args.get("remote_hosts") or []
            if fw_action == "Block" and not remotes:
                raise ToolError("Block rules need remote_hosts (IPs/CIDRs in the range network) – 'any' is not allowed")
            checked = [check_remote(h) for h in remotes]
            protocol = (args.get("protocol") or "any").lower()
            if protocol not in ("any", "tcp", "udp", "icmp"):
                raise ToolError("protocol: any | tcp | udp | icmp")
            os_types = args.get("os_types") or ["windows", "linux"]
            if any(o not in ("windows", "linux") for o in os_types):
                raise ToolError("os_types: windows and/or linux")
            name = (args.get("name") or "").strip()
            if not name:
                raise ToolError("name is mandatory")
            data = {
                "name": (RULE_PREFIX + name)[:100], "description": f"[ai-range blue] {reason}"[:500],
                "action": fw_action, "direction": direction, "protocol": protocol, "osTypes": os_types,
                "status": "Enabled", "application": {"type": "any", "values": []},
                "localHost": {"type": "any", "values": []},
                "remoteHosts": ([{"type": "addresses", "values": [h for h in checked if "/" not in h]}]
                                if any("/" not in h for h in checked) else [])
                               + [{"type": "cidr", "values": [h]} for h in checked if "/" in h]
                               or [{"type": "any", "values": []}],
                "localPort": ports(args.get("local_ports"), "local_ports"),
                "remotePort": ports(args.get("remote_ports"), "remote_ports"),
                "location": {"type": "all", "values": []},
            }
            if settings.blue_response_mode != "auto":
                return _recommend("firewall/create_rule", "Range-Site", reason, f"{fw_action} {direction} {checked}")
            r = await s1.api("POST", "/firewall-control", json={"filter": site, "data": data})
            return {"executed": True, "action": "create_rule", "rule": _rule_row((r or {}).get("data") or data),
                    "note": "Rules only take effect if Firewall Control is active for the site (action=status).",
                    "reason": reason}

        found = await own(list(args.get("rule_ids") or []))
        ids = [r["id"] for r in found]
        if settings.blue_response_mode != "auto":
            return _recommend(f"firewall/{action}", ", ".join(r["name"] for r in found), reason)
        if action == "set_status":
            status = args.get("status")
            if status not in ("Enabled", "Disabled"):
                raise ToolError("status: Enabled | Disabled")
            r = await s1.api("PUT", "/firewall-control/enable", json={"filter": {**site, "ids": ids},
                                                                        "data": {"status": status}})
        else:
            r = await s1.api("DELETE", "/firewall-control", json={"filter": {**site, "ids": ids}})
        return {"executed": True, "action": action, "rules": [r_["name"] for r_ in found],
                "affected": (r or {}).get("data", {}).get("affected") if isinstance(r, dict) else None,
                "reason": reason}

    return make_tool("firewall", (
        "SentinelOne Firewall Control of the range endpoints (base configuration of the host firewalls). status "
        "(configuration + rules), enable (turn on Firewall Control for the site), create_rule (own rule: "
        "rule_action Allow|Block, direction, protocol, remote_hosts, remote_ports/local_ports, os_types), set_status "
        "(own rules Enabled/Disabled), delete_rule. Rules apply to all range endpoints of the selected "
        f"operating systems. Block rules only with concrete addresses/CIDRs in the range network – never gateway, {TOPOLOGY.dc.name} or "
        "management. Only own rules (prefix 'ai-range blue:') can be changed. reason is mandatory for changes; "
        "in response mode 'off' recommendation only."), {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": FW_ACTIONS},
            "name": {"type": "string", "description": "create_rule: rule name (prefix is added)"},
            "rule_action": {"type": "string", "enum": ["Allow", "Block"]},
            "direction": {"type": "string", "enum": ["inbound", "outbound", "any"], "description": "Default inbound"},
            "protocol": {"type": "string", "enum": ["any", "tcp", "udp", "icmp"], "description": "Default any"},
            "remote_hosts": {"type": "array", "items": {"type": "string"},
                             "description": "IPs/CIDRs in the range network (mandatory for Block)"},
            "remote_ports": {"type": "array", "items": {"type": "integer"}},
            "local_ports": {"type": "array", "items": {"type": "integer"}},
            "os_types": {"type": "array", "items": {"type": "string", "enum": ["windows", "linux"]},
                         "description": "Default both"},
            "rule_ids": {"type": "array", "items": {"type": "string"}, "description": "set_status/delete_rule"},
            "status": {"type": "string", "enum": ["Enabled", "Disabled"]},
            "reason": {"type": "string"},
        },
        "required": ["action"],
    }, firewall)


# --------------------------------------------------------------------------- Cleanup (CLI `cleanup`)

async def cleanup(s1: SentinelOne, dry_run: bool = False) -> dict:
    """Removes what Blue left behind in the console: agent isolations, Ranger blocks, own firewall rules.
    Also sets all open alerts and incidents of the range site to RESOLVED, so that the next triage
    does not run into leftovers from earlier exercises."""
    site = s1.site_params()
    out: dict[str, Any] = {}
    uam = UAM(s1)
    alerts, _ = await uam.alerts([f_in("status", OPEN_STATUS)], limit=5000)
    out["alerts_open"] = [f"{n}× {name}" for name, n in Counter(a.get("name") or "?" for a in alerts).most_common()]
    incidents = await uam.incidents([f_in("status", OPEN_STATUS)])
    out["incidents_open"] = [i.get("name") or i["id"] for i in incidents]
    agents = [a for a in await s1.paged("/agents", site, limit=500) if a.get("networkStatus") != "connected"]
    out["agents_isolated"] = [a.get("computerName") for a in agents]
    devices = await s1.paged("/ranger/table-view", {**site, "period": "last7d", "deviceReviews": ["Isolated"]},
                             limit=500)
    out["devices_isolated"] = [", ".join(_device_ips(d)) or d.get("id") for d in devices]
    rules = [r for r in await s1.paged("/firewall-control", {**site, "name__contains": RULE_PREFIX.strip()}, limit=500)
             if str(r.get("name", "")).startswith(RULE_PREFIX)]
    out["firewall_rules"] = [r.get("name") for r in rules]
    if dry_run:
        return out
    if agents:
        await s1.api("POST", "/agents/actions/connect", json={"filter": {"ids": [a["id"] for a in agents]}})
    if devices:
        await s1.api("POST", "/ranger/device-review", json={
            "data": {"deviceReview": RELEASED_REVIEW, "reason": "Other", "reasonDetails": "[ai-range] cleanup"},
            "filter": {"ids": [d["id"] for d in devices], **site}})
    if rules:
        await s1.api("DELETE", "/firewall-control", json={"filter": {**site, "ids": [r["id"] for r in rules]}})
    # The console rejects RESOLVED ("Invalid argument") for alerts without an analyst verdict. Alerts that still
    # have none get CLEANUP_VERDICT first (authorized test activity); verdicts set by Blue are left untouched.
    ids = [a["id"] for a in alerts]
    no_verdict = {a["id"] for a in alerts if (a.get("analystVerdict") or "UNDEFINED") == "UNDEFINED"}
    failed: list[str] = []
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        unset = [x for x in chunk if x in no_verdict]
        if unset:
            await uam.trigger(unset, [{"id": ACTION_VERDICT, "payload": {"analystVerdict": {"value": CLEANUP_VERDICT}}}])
        res = await uam.trigger(chunk, [{"id": ACTION_STATUS, "payload": {"status": {"value": "RESOLVED"}}}])
        failed += (res.get(ACTION_STATUS) or {}).get("failure", [])
    if failed:
        out["alerts_not_resolved"] = failed
    if incidents:
        await uam.incident_status([i["id"] for i in incidents], "RESOLVED")
    return out
