"""Red agent tools: run commands on the attacker VM (role attacker in range.yaml) – with scope guard and ground truth.

Every attack step goes through `kali_exec`. The tool
  1. checks the scope (only the range network without gateway/Kali, no firewall manipulation),
  2. runs the command via SSH on the attacker VM,
  3. writes a ground truth entry (ATT&CK technique, target, command, result) to range-groundtruth.
The ground truth therefore comes from the tool and not from the model's self-reporting.
Second line of defense: nftables on the attacker VM (Ansible role kali) blocks everything except range network + internet.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import shlex
from typing import Any

import asyncssh

from ..config import RANGE_HOSTS, RANGE_IPS, settings
from ..elastic import Elastic
from ..runner import make_tool, text_result
from ..topology import TOPOLOGY
from ..trace import now_iso, write_groundtruth

TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![\d.])")
# Commands the agent could use to defeat the network guard on Kali
FORBIDDEN = re.compile(
    r"\b(nft|iptables|ip6tables|iptables-restore|ufw|firewall-cmd)\b|/etc/nftables|"
    r"systemctl\s+(stop|disable|mask)\s+nftables|\bip\s+route\b|\bip\s+addr\b|\bip\s+link\b",
    re.IGNORECASE,
)
WORKDIR = "/home/range/work"
MAX_OUTPUT = 15000


class ScopeError(ValueError):
    pass


def resolve_target(target: str) -> tuple[str, str | None]:
    """Target (IP, hostname or FQDN) -> (ip, hostname). Raises ScopeError outside the range."""
    t = target.strip().lower()
    if not t:
        raise ScopeError("empty target")
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        net = None
    if net is not None:
        if net.num_addresses > 1:
            if not net.subnet_of(ipaddress.ip_network(settings.target_cidr)):
                raise ScopeError(f"Network {t} is outside of {settings.target_cidr}")
            return str(net), None
        ip = str(net.network_address)
        if not settings.in_scope(ip):
            raise ScopeError(f"{ip} is not in scope ({settings.target_cidr}, excluding {', '.join(settings.target_exclude)} and Kali)")
        return ip, RANGE_HOSTS.get(ip)
    short = t.split(".")[0]
    if t in (settings.domain, ) or t.endswith("." + settings.domain) or t == short:
        if t == settings.domain:          # the domain itself -> DC
            short = TOPOLOGY.dc.host
        if short in RANGE_IPS:
            return RANGE_IPS[short], short
    raise ScopeError(f"Unknown target '{target}'. Allowed: IPs in {settings.target_cidr} or range hosts "
                     f"({', '.join(sorted(RANGE_IPS))}, optionally with .{settings.domain})")


def check_command(command: str) -> list[str]:
    """Checks the command text. Returns the IPs found in it; raises ScopeError on violations."""
    if FORBIDDEN.search(command):
        raise ScopeError("Command modifies firewall/routing of the attacker VM – not allowed.")
    found: list[str] = []
    for m in IPV4_RE.finditer(command):
        ip, prefix = m.group(1), m.group(2)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or ip in ("0.0.0.0", "255.255.255.255"):
            continue
        if prefix:
            resolve_target(f"{ip}/{prefix}")
        elif not settings.in_scope(ip) and ip != settings.kali_host:
            raise ScopeError(f"IP {ip} in the command is not in scope ({settings.target_cidr}).")
        found.append(ip)
    return found


class KaliSession:
    """A reused SSH connection to the attacker VM."""

    def __init__(self) -> None:
        self._conn: asyncssh.SSHClientConnection | None = None
        self._lock = asyncio.Lock()

    async def conn(self) -> asyncssh.SSHClientConnection:
        async with self._lock:
            if self._conn is None or self._conn.is_closed():
                self._conn = await asyncssh.connect(
                    settings.kali_host, username=settings.kali_user, password=settings.kali_password,
                    known_hosts=None, connect_timeout=15,
                )
                await self._conn.run(f"mkdir -p {WORKDIR}", check=False)
            return self._conn

    async def run(self, command: str, timeout: int) -> tuple[int | None, str, bool]:
        conn = await self.conn()
        # Scenario credentials as env ($DOMAIN_USER/$DOMAIN_PASS …) – not in the command text
        wrapped = (f"cd {WORKDIR} && set -a && . {WORKDIR}/.scenario_env 2>/dev/null; set +a; "
                   f"bash -lc {shlex.quote(command)}")
        try:
            res = await asyncio.wait_for(conn.run(wrapped, check=False), timeout=timeout)
            out = (res.stdout or "") + (("\n[stderr]\n" + res.stderr) if res.stderr else "")
            return res.exit_status, out, False
        except asyncio.TimeoutError:
            return None, "", True

    async def write_file(self, path: str, content: str) -> None:
        conn = await self.conn()
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(path, "w") as fh:
                await fh.write(content)

    async def set_scenario_env(self, env: dict[str, str]) -> None:
        """Writes the scenario variables (0600) – empty = delete."""
        lines = "".join(f"{k}={shlex.quote(v)}\n" for k, v in env.items())
        conn = await self.conn()
        await conn.run(f"umask 077 && printf %s {shlex.quote(lines)} > {WORKDIR}/.scenario_env", check=True)

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()


def _tail(text: str) -> str:
    if len(text) <= MAX_OUTPUT:
        return text
    return f"…[{len(text) - MAX_OUTPUT} characters truncated at the start]\n" + text[-MAX_OUTPUT:]


def build_red_tools(es: Elastic, kali: KaliSession, run_id: str, agent_name: str) -> list:
    async def kali_exec(args: dict[str, Any]) -> dict[str, Any]:
        command = args["command"]
        technique_id = args["technique_id"].strip().upper()
        if not TECHNIQUE_RE.match(technique_id):
            return text_result(f"technique_id '{technique_id}' invalid (format T1234 or T1234.001)", True)
        if args["tactic"] not in TACTICS:
            return text_result(f"tactic must be one of {TACTICS}", True)
        timeout = max(10, min(int(args.get("timeout_s") or 300), 1800))
        try:
            resolved = [resolve_target(t) for t in args["targets"]]
            cmd_ips = check_command(command)
        except ScopeError as exc:
            return text_result(f"SCOPE VIOLATION – not executed: {exc}", True)

        target_ips = list(dict.fromkeys([ip for ip, _ in resolved] + [ip for ip in cmd_ips if ip != settings.kali_host]))
        target_hosts = list(dict.fromkeys(
            [h for _, h in resolved if h] + [RANGE_HOSTS[ip] for ip in target_ips if ip in RANGE_HOSTS]
        ))

        started = now_iso()
        exit_code, output, timed_out = await kali.run(command, timeout)
        outcome = "success" if exit_code == 0 else "failure"
        status = "Timeout" if timed_out else f"Exit code {exit_code}"
        try:
            await write_groundtruth(
                es, run_id, agent_name,
                technique_id=technique_id, technique_name=args["technique_name"], tactic=args["tactic"],
                command=command, target_hosts=target_hosts, target_ips=target_ips,
                source_ip=settings.kali_host, outcome=outcome, message=args.get("purpose", ""),
                started=started, extra={"exit_code": exit_code, "timed_out": timed_out},
            )
            gt_note = ""
        except Exception as exc:  # noqa: BLE001
            gt_note = f"\n[WARNING: ground truth not written: {exc}]"
        return text_result(f"[{status}]\n{_tail(output)}{gt_note}", is_error=False)

    async def kali_write_file(args: dict[str, Any]) -> dict[str, Any]:
        name = args["filename"].strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name):
            return text_result("filename: only letters, digits, . _ - (no paths)", True)
        await kali.write_file(f"{WORKDIR}/{name}", args["content"])
        return text_result(f"written: {WORKDIR}/{name} ({len(args['content'])} characters)")

    exec_schema = {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": f"Shell command (bash) on {TOPOLOGY.attacker.name}. Working directory "
                        f"{WORKDIR}. sudo available without password. Non-interactive; limit long runs."},
            "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1,
                        "description": f"Target(s) of this step: IPs, network {settings.target_cidr} or hostnames "
                                       f"({TOPOLOGY.dc.host}, {TOPOLOGY.example()}, …, FQDN also works). For ground truth and scope check."},
            "technique_id": {"type": "string", "description": "MITRE ATT&CK technique ID, e.g. T1046 or T1558.003"},
            "technique_name": {"type": "string", "description": "Name of the technique, e.g. 'Kerberoasting'"},
            "tactic": {"type": "string", "enum": TACTICS},
            "purpose": {"type": "string", "description": "One sentence: what should this step achieve?"},
            "timeout_s": {"type": "integer", "minimum": 10, "maximum": 1800, "default": 300},
        },
        "required": ["command", "targets", "technique_id", "technique_name", "tactic", "purpose"],
    }
    write_schema = {
        "type": "object",
        "properties": {
            "filename": {"type": "string", "description": f"File name in {WORKDIR} (without path)"},
            "content": {"type": "string"},
        },
        "required": ["filename", "content"],
    }
    return [
        make_tool("kali_exec",
                  f"Runs ONE attack step as a shell command on the attacker VM {TOPOLOGY.attacker.name} and logs "
                  f"it as ground truth (ATT&CK technique mandatory). Only targets in {settings.target_cidr} are allowed; "
                  "violations are rejected. Returns stdout/stderr (truncated) and the exit code.",
                  exec_schema, kali_exec),
        make_tool("kali_write_file",
                  f"Creates a text file (e.g. user list, script) in the working directory {WORKDIR} on {TOPOLOGY.attacker.name}. "
                  "Not an attack step, no ground truth.",
                  write_schema, kali_write_file),
    ]
