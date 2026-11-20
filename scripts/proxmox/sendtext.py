#!/usr/bin/env python3
"""Types text into a Proxmox VM console (API sendkey, US layout).

Usage:
  python sendtext.py <node> <vmid> "<text>"      # \n in the text = Enter
Env: PROXMOX_VE_ENDPOINT, PROXMOX_VE_API_TOKEN
"""
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request

SPECIAL = {
    " ": "spc", "\n": "ret", "\t": "tab", "-": "minus", "=": "equal", "[": "bracket_left",
    "]": "bracket_right", "\\": "backslash", ";": "semicolon", "'": "apostrophe", "`": "grave_accent",
    ",": "comma", ".": "dot", "/": "slash",
}
SHIFTED = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8", "(": "9", ")": "0",
    "_": "minus", "+": "equal", "{": "bracket_left", "}": "bracket_right", "|": "backslash",
    ":": "semicolon", '"': "apostrophe", "~": "grave_accent", "<": "comma", ">": "dot", "?": "slash",
}


def keyname(ch):
    if ch.isascii() and ch.isalpha():
        return ("shift-" + ch.lower()) if ch.isupper() else ch
    if ch.isdigit():
        return ch
    if ch in SPECIAL:
        return SPECIAL[ch]
    if ch in SHIFTED:
        return "shift-" + SPECIAL.get(SHIFTED[ch], SHIFTED[ch])
    raise ValueError(f"Character not supported: {ch!r}")


def main():
    node, vmid, text = sys.argv[1], sys.argv[2], sys.argv[3].replace("\\n", "\n")
    base = os.environ["PROXMOX_VE_ENDPOINT"].rstrip("/") + f"/api2/json/nodes/{node}/qemu/{vmid}/sendkey"
    ctx = ssl._create_unverified_context()
    for ch in text:
        req = urllib.request.Request(base, data=urllib.parse.urlencode({"key": keyname(ch)}).encode(),
                                     method="PUT")
        req.add_header("Authorization", "PVEAPIToken=" + os.environ["PROXMOX_VE_API_TOKEN"])
        urllib.request.urlopen(req, context=ctx, timeout=10).read()
        time.sleep(0.02)


if __name__ == "__main__":
    main()
