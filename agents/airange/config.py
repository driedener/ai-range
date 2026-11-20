"""Settings from the environment (docker/.env -> compose -> container)."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

from .topology import TOPOLOGY


def _env(name: str, default: str | None = None, required: bool = False) -> str:
    val = os.environ.get(name, default)
    if required and not val:
        raise SystemExit(f"Environment variable {name} is missing (docker/.env)")
    return val or ""


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    es_url: str = field(default_factory=lambda: _env("AIRANGE_ES_URL", "https://es01:9200"))
    kibana_url: str = field(default_factory=lambda: _env("AIRANGE_KIBANA_URL", "https://kibana:5601"))
    ca_cert: str = field(default_factory=lambda: _env("AIRANGE_CA_CERT", "/certs/ca/ca.crt"))

    # Elastic user per role (created by ansible/roles/elastic_fleet_config)
    blue_password: str = field(default_factory=lambda: _env("RANGE_BLUE_PASSWORD"))
    red_password: str = field(default_factory=lambda: _env("RANGE_RED_PASSWORD"))
    orch_password: str = field(default_factory=lambda: _env("RANGE_ORCH_PASSWORD"))

    # Kali (the Red agent runs commands there over SSH)
    # Kali = the VM with role attacker in range.yaml (env override only for special cases)
    kali_host: str = field(default_factory=lambda: _env("AIRANGE_KALI_HOST", TOPOLOGY.attacker.ip))
    kali_user: str = field(default_factory=lambda: _env("AIRANGE_KALI_USER", "range"))
    kali_password: str = field(default_factory=lambda: _env("RANGE_ADMIN_PASSWORD"))

    # Scope: Red may only attack this network, never these addresses (gateway, Kali itself) - from range.yaml
    target_cidr: str = field(default_factory=lambda: _env("AIRANGE_TARGET_CIDR", TOPOLOGY.cidr))
    target_exclude: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            x.strip() for x in _env("AIRANGE_TARGET_EXCLUDE", TOPOLOGY.gateway).split(",") if x.strip()
        )
    )
    domain: str = field(default_factory=lambda: _env("AIRANGE_DOMAIN", TOPOLOGY.domain))
    # Management host(s): alerts from there never count as detections, Blue must never block them
    mgmt_ips: tuple[str, ...] = field(default_factory=lambda: tuple(
        x.strip() for x in _env("AIRANGE_MGMT_IPS", TOPOLOGY.controller_ip).split(",") if x.strip()))

    # Models / cost cap (USD per agent run)
    model: str = field(default_factory=lambda: _env("AIRANGE_MODEL", "claude-opus-5-5"))
    red_model: str = field(default_factory=lambda: _env("AIRANGE_RED_MODEL", ""))
    # Optional per-role models; empty = AIRANGE_MODEL
    blue_model: str = field(default_factory=lambda: _env("AIRANGE_BLUE_MODEL", ""))
    engineer_model: str = field(default_factory=lambda: _env("AIRANGE_ENGINEER_MODEL", ""))
    max_budget_usd: float = field(default_factory=lambda: _float("AIRANGE_MAX_BUDGET_USD", 5.0))
    # Red needs far more turns for a complete attack path than Blue/Engineer
    red_max_budget_usd: float = field(default_factory=lambda: _float("AIRANGE_RED_MAX_BUDGET_USD", 10.0))

    # Blue response: off = recommend only, auto = run isolate/kill itself
    blue_response_mode: str = field(default_factory=lambda: _env("AIRANGE_BLUE_RESPONSE", "auto"))

    # Exercise flow: sequential = Red -> wait -> Blue; parallel = Blue monitors live while Red attacks
    exercise_mode: str = field(default_factory=lambda: _env("AIRANGE_EXERCISE_MODE", "sequential").strip().lower())

    # Proxmox (snapshots/rollback of the range)
    pve_endpoint: str = field(default_factory=lambda: _env("PROXMOX_VE_ENDPOINT"))
    pve_token: str = field(default_factory=lambda: _env("PROXMOX_VE_API_TOKEN"))

    # Security platform for Blue/Engineer/scorer: elastic | sentinelone.
    # Ground truth, agent traces and scores live in Elasticsearch (range-*) either way.
    edr: str = field(default_factory=lambda: _env("AIRANGE_EDR", "elastic").strip().lower())

    # SentinelOne (only with AIRANGE_EDR=sentinelone)
    s1_url: str = field(default_factory=lambda: _env("S1_CONSOLE_URL").rstrip("/"))
    # Service user token for Blue/Engineer (role e.g. "SOC"), optional separate token for the scorer (Viewer)
    s1_api_token: str = field(default_factory=lambda: _env("S1_API_TOKEN"))
    s1_orch_api_token: str = field(default_factory=lambda: _env("S1_ORCH_API_TOKEN"))
    # Range site - limits queries, response actions and new STAR rules to this site
    s1_site_id: str = field(default_factory=lambda: _env("S1_SITE_ID"))

    def model_for(self, role: str) -> str:
        return getattr(self, f"{role}_model", "") or self.model

    def budget_for(self, role: str) -> float:
        return getattr(self, f"{role}_max_budget_usd", None) or self.max_budget_usd

    def s1_token_for(self, role: str) -> str:
        if role == "orchestrator":
            return self.s1_orch_api_token or self.s1_api_token
        return self.s1_api_token

    @property
    def use_s1(self) -> bool:
        if self.edr not in ("elastic", "sentinelone"):
            raise SystemExit(f"AIRANGE_EDR={self.edr!r} - allowed: elastic | sentinelone")
        return self.edr == "sentinelone"

    def in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return addr in ipaddress.ip_network(self.target_cidr) and ip not in self.target_exclude and ip != self.kali_host


settings = Settings()

# Range hosts without the attacker (IP -> lower-case short name, like host.name in Elastic) - from range.yaml
RANGE_HOSTS = {v.ip: v.host for v in TOPOLOGY.targets}
RANGE_IPS = {v: k for k, v in RANGE_HOSTS.items()}     # hostname -> ip

# Elastic user per agent role
ROLE_USERS = {
    "red": ("red-agent", "red_password"),
    "blue": ("blue-agent", "blue_password"),
    "engineer": ("blue-agent", "blue_password"),
    "orchestrator": ("orchestrator", "orch_password"),
}
