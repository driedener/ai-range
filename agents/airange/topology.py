"""Range topology from range.yaml (repo root, /range.yaml in the container).

Provides names, network and roles for the scope guard, prompts, tool descriptions and snapshots, so no
host names or IPs are hard-coded. range.yaml is validated by scripts/configure.py; here it is only read.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_CANDIDATES = [
    os.environ.get("AIRANGE_RANGE_FILE", ""),
    "/range.yaml",
    str(Path(__file__).resolve().parents[2] / "range.yaml"),   # local checkout
]


@dataclass(frozen=True)
class VM:
    name: str          # as in range.yaml (e.g. DC01)
    ip: str
    role: str          # dc | server | client | linux_server | attacker
    os: str            # windows | linux
    vm_id: int
    services: tuple[str, ...] = ()

    @property
    def host(self) -> str:
        """Lower-case short name, as hosts appear in alerts/events (host.name)."""
        return self.name.lower()


@dataclass(frozen=True)
class Topology:
    organization: str
    domain: str
    netbios: str
    cidr: str
    gateway: str
    controller_name: str
    controller_ip: str
    vms: tuple[VM, ...] = field(default_factory=tuple)

    # ------------------------------------------------------------------ queries
    def by_role(self, *roles: str) -> list[VM]:
        return [v for v in self.vms if v.role in roles]

    def by_service(self, service: str) -> list[VM]:
        return [v for v in self.vms if service in v.services]

    @property
    def dc(self) -> VM:
        return self.by_role("dc")[0]

    @property
    def attacker(self) -> VM:
        return self.by_role("attacker")[0]

    @property
    def targets(self) -> list[VM]:
        """All range hosts except the attacker."""
        return [v for v in self.vms if v.role != "attacker"]

    def example(self, role: str = "client") -> str:
        """Example host name for tool descriptions."""
        vms = self.by_role(role) or self.targets
        return vms[0].host if vms else "host01"

    def endpoints_text(self) -> str:
        """'DC01, CA01 (Server), WS01, WS02 (Clients), lnx-web01 (Linux)' for prompts."""
        parts = []
        for roles, label in ((("dc", "server"), "Server"), (("client",), "Clients"), (("linux_server",), "Linux")):
            names = [v.name for v in self.by_role(*roles)]
            if names:
                parts.append(f"{', '.join(names)} ({label})")
        return ", ".join(parts)

    def placeholders(self) -> dict[str, str]:
        """${RANGE_*} placeholders for scenarios."""
        def first(service: str) -> VM | None:
            vms = self.by_service(service)
            return vms[0] if vms else None
        out = {"RANGE_DOMAIN": self.domain, "RANGE_NETBIOS": self.netbios, "RANGE_CIDR": self.cidr,
               "RANGE_DC": self.dc.name, "RANGE_DC_IP": self.dc.ip, "RANGE_ATTACKER": self.attacker.name,
               "RANGE_ATTACKER_IP": self.attacker.ip, "RANGE_ORGANIZATION": self.organization}
        for svc in ("fileserver", "ca", "web", "sql"):
            vm = first(svc)
            if vm:
                out[f"RANGE_{svc.upper()}"] = vm.name
                out[f"RANGE_{svc.upper()}_IP"] = vm.ip
        # first client; Linux web server = Linux server with "web" in its name, DB server = the other one
        # (same as vuln_local_admin / vuln_linux in ansible/roles)
        linux = self.by_role("linux_server")
        web = next((v for v in linux if "web" in v.host), linux[0] if linux else None)
        db = next((v for v in linux if v is not web), web)
        for key, vm in (("CLIENT", (self.by_role("client") or [None])[0]), ("LINUX_WEB", web), ("LINUX_DB", db)):
            if vm:
                out[f"RANGE_{key}"] = vm.name
                out[f"RANGE_{key}_IP"] = vm.ip
        return out


def load_topology() -> Topology:
    path = next((p for p in _CANDIDATES if p and Path(p).is_file()), None)
    if not path:
        raise SystemExit("range.yaml not found (/range.yaml in the container or the repo root; AIRANGE_RANGE_FILE)")
    cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    templates = cfg["proxmox"]["templates"]
    base = int(cfg["network"].get("vm_id_base", 0))
    vms = tuple(
        VM(name=name, ip=str(v["ip"]), role=v["role"], os=templates[v["template"]]["os"],
           vm_id=int(v.get("vm_id") or base + int(str(v["ip"]).split(".")[-1])),
           services=tuple(v.get("services") or ()))
        for name, v in cfg["vms"].items())
    net = ipaddress.ip_network(str(cfg["network"]["cidr"]))
    return Topology(organization=cfg.get("organization", "Range Corp"), domain=cfg["domain"],
                    netbios=cfg["netbios"], cidr=str(net), gateway=str(cfg["network"]["gateway"]),
                    controller_name=cfg["controller"]["name"], controller_ip=str(cfg["controller"]["ip"]), vms=vms)


TOPOLOGY = load_topology()
