"""Snapshots/rollback of the range VMs (all VMs from range.yaml, by VMID) via the Proxmox API.

Deliberately NOT an agent tool - only for the operator (CLI), to reset the range after an exercise.
"""
from __future__ import annotations

import asyncio
import re

import httpx

from .config import settings
from .topology import TOPOLOGY

RANGE_VMIDS = {v.vm_id for v in TOPOLOGY.vms}


class Proxmox:
    def __init__(self) -> None:
        if not settings.pve_endpoint or not settings.pve_token:
            raise SystemExit("PROXMOX_VE_ENDPOINT/PROXMOX_VE_API_TOKEN missing")
        self._c = httpx.AsyncClient(
            base_url=settings.pve_endpoint.rstrip("/") + "/api2/json",
            headers={"Authorization": f"PVEAPIToken={settings.pve_token}"},
            verify=False, timeout=60,  # Proxmox with a self-signed certificate (PROXMOX_VE_INSECURE)
        )

    async def __aenter__(self) -> "Proxmox":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._c.aclose()

    async def _req(self, method: str, path: str, **kw):
        r = await self._c.request(method, path, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"Proxmox {method} {path}: {r.status_code} {r.text[:300]}")
        return r.json().get("data")

    async def range_vms(self) -> list[dict]:
        vms = await self._req("GET", "/cluster/resources", params={"type": "vm"})
        return sorted((v for v in vms if v["vmid"] in RANGE_VMIDS and not v.get("template")),
                      key=lambda v: v["vmid"])

    async def _wait(self, node: str, upid: str, timeout: int = 900) -> str:
        for _ in range(timeout // 2):
            st = await self._req("GET", f"/nodes/{node}/tasks/{upid}/status")
            if st.get("status") == "stopped":
                return st.get("exitstatus", "?")
            await asyncio.sleep(2)
        return "timeout"

    async def snapshot(self, name: str, description: str = "") -> None:
        _check_name(name)
        vms = await self.range_vms()

        async def one(v: dict) -> str:
            upid = await self._req("POST", f"/nodes/{v['node']}/qemu/{v['vmid']}/snapshot",
                                   data={"snapname": name, "description": description, "vmstate": 0})
            return f"{v['name']}: {await self._wait(v['node'], upid)}"

        for line in await asyncio.gather(*(one(v) for v in vms)):
            print(line)

    async def rollback(self, name: str) -> None:
        _check_name(name)
        vms = await self.range_vms()

        async def one(v: dict) -> str:
            upid = await self._req("POST", f"/nodes/{v['node']}/qemu/{v['vmid']}/snapshot/{name}/rollback",
                                   data={"start": 1})
            return f"{v['name']}: {await self._wait(v['node'], upid)}"

        for line in await asyncio.gather(*(one(v) for v in vms)):
            print(line)

    async def delete(self, name: str) -> None:
        _check_name(name)
        vms = await self.range_vms()

        async def one(v: dict) -> str:
            upid = await self._req("DELETE", f"/nodes/{v['node']}/qemu/{v['vmid']}/snapshot/{name}")
            return f"{v['name']}: {await self._wait(v['node'], upid)}"

        for line in await asyncio.gather(*(one(v) for v in vms)):
            print(line)

    async def power(self, action: str, timeout: int = 180) -> None:
        """start: start stopped VMs; shutdown: shut down cleanly, hard power-off after timeout."""
        want = "stopped" if action == "start" else "running"
        vms = [v for v in await self.range_vms() if v["status"] == want]
        data = {"timeout": timeout, "forceStop": 1} if action == "shutdown" else None

        async def one(v: dict) -> str:
            upid = await self._req("POST", f"/nodes/{v['node']}/qemu/{v['vmid']}/status/{action}", data=data)
            return f"{v['name']}: {await self._wait(v['node'], upid, timeout=timeout + 120)}"

        for line in await asyncio.gather(*(one(v) for v in vms)):
            print(line)
        if not vms:
            print(f"no VM in state {want}")

    async def list_snapshots(self) -> None:
        for v in await self.range_vms():
            snaps = await self._req("GET", f"/nodes/{v['node']}/qemu/{v['vmid']}/snapshot")
            names = [s["name"] for s in snaps if s["name"] != "current"]
            print(f"{v['vmid']} {v['name']:10} {v['status']:8} {', '.join(names) or '-'}")


def _check_name(name: str) -> None:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,39}", name):
        raise SystemExit("Snapshot name: a letter first, then letters/digits/_/- (max. 40)")
