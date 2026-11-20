#!/usr/bin/env python3
"""Runs a command in a VM via the qemu-guest-agent (as root/SYSTEM).

Usage:
  python guestexec.py <node> <vmid> '<shell-command>'         # Linux: sh -c
  python guestexec.py --windows <node> <vmid> '<powershell>'  # Windows: powershell -Command
Env: PROXMOX_VE_ENDPOINT, PROXMOX_VE_API_TOKEN
Exit code = exit code of the command in the VM.
"""
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request

CTX = ssl._create_unverified_context()


def api(method, path, payload=None):
    base = os.environ["PROXMOX_VE_ENDPOINT"].rstrip("/") + "/api2/json"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Authorization", "PVEAPIToken=" + os.environ["PROXMOX_VE_API_TOKEN"])
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
        return json.load(r)["data"]


def main():
    args = sys.argv[1:]
    windows = args and args[0] == "--windows"
    if windows:
        args = args[1:]
    node, vmid, cmd = args[0], args[1], args[2]
    command = (["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd] if windows
               else ["sh", "-c", cmd])
    base = f"/nodes/{node}/qemu/{vmid}/agent"
    pid = api("POST", f"{base}/exec", {"command": command})["pid"]
    deadline = time.time() + float(os.environ.get("GUESTEXEC_TIMEOUT", "300"))
    while time.time() < deadline:
        st = api("GET", f"{base}/exec-status?" + urllib.parse.urlencode({"pid": pid}))
        if st.get("exited"):
            sys.stdout.write(st.get("out-data", ""))
            sys.stderr.write(st.get("err-data", ""))
            sys.exit(st.get("exitcode", 0))
        time.sleep(1)
    sys.exit("Timeout while waiting for the command")


if __name__ == "__main__":
    main()
