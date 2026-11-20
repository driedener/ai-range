#!/usr/bin/env python3
"""Screenshot of a Proxmox VM console via the API (vncproxy + vncwebsocket).

Usage:
  python screenshot.py <node> <vmid> <out.png>

Env: PROXMOX_VE_ENDPOINT (https://host:8006/), PROXMOX_VE_API_TOKEN (user@realm!id=secret)
Requires: websocket-client, pycryptodome
"""
import os
import ssl
import struct
import sys
import urllib.parse
import urllib.request
import json
import zlib

import websocket  # websocket-client
from Crypto.Cipher import DES


def api(method, path, data=None):
    base = os.environ["PROXMOX_VE_ENDPOINT"].rstrip("/") + "/api2/json"
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(base + path, data=body, method=method)
    req.add_header("Authorization", "PVEAPIToken=" + os.environ["PROXMOX_VE_API_TOKEN"])
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
        return json.load(r)["data"]


class WSStream:
    """Byte stream over WebSocket binary frames."""

    def __init__(self, ws):
        self.ws, self.buf = ws, b""

    def read(self, n):
        while len(self.buf) < n:
            frame = self.ws.recv()
            self.buf += frame if isinstance(frame, bytes) else frame.encode()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def write(self, data):
        self.ws.send(data, opcode=websocket.ABNF.OPCODE_BINARY)


def vnc_des_response(password, challenge):
    key = (password.encode()[:8]).ljust(8, b"\0")
    # VNC reverses the bit order of each key byte
    key = bytes(int(f"{b:08b}"[::-1], 2) for b in key)
    return DES.new(key, DES.MODE_ECB).encrypt(challenge)


def png(width, height, rgb):
    raw = b"".join(b"\0" + rgb[y * width * 3:(y + 1) * width * 3] for y in range(height))

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6))
            + chunk(b"IEND", b""))


def main():
    node, vmid, out = sys.argv[1], sys.argv[2], sys.argv[3]
    proxy = api("POST", f"/nodes/{node}/qemu/{vmid}/vncproxy", {"websocket": 1})
    host = urllib.parse.urlparse(os.environ["PROXMOX_VE_ENDPOINT"]).netloc
    url = (f"wss://{host}/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket"
           f"?port={proxy['port']}&vncticket={urllib.parse.quote(proxy['ticket'], safe='')}")
    ws = websocket.create_connection(
        url, sslopt={"cert_reqs": ssl.CERT_NONE}, subprotocols=["binary"],
        header=["Authorization: PVEAPIToken=" + os.environ["PROXMOX_VE_API_TOKEN"]], timeout=20)
    s = WSStream(ws)

    s.read(12)                      # "RFB 003.008\n"
    s.write(b"RFB 003.008\n")
    ntypes = s.read(1)[0]
    types = s.read(ntypes)
    if 2 in types:
        s.write(b"\x02")
        challenge = s.read(16)
        s.write(vnc_des_response(proxy["ticket"], challenge))
    elif 1 in types:
        s.write(b"\x01")
    else:
        sys.exit(f"No supported VNC security type: {list(types)}")
    if struct.unpack(">I", s.read(4))[0] != 0:
        sys.exit("VNC authentication failed")

    s.write(b"\x01")                # ClientInit, shared
    width, height = struct.unpack(">HH", s.read(4))
    s.read(16)                      # server pixel format
    s.read(struct.unpack(">I", s.read(4))[0])  # Name

    # 32bpp, little endian, true colour, R<<16 G<<8 B
    s.write(struct.pack(">BxxxBBBBHHHBBBxxx", 0, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
    s.write(struct.pack(">BxHi", 2, 1, 0))           # SetEncodings: Raw
    s.write(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height))

    fb = bytearray(width * height * 3)
    while True:
        mtype = s.read(1)[0]
        if mtype == 0:
            break
        if mtype == 2:              # Bell
            continue
        if mtype == 3:              # ServerCutText
            s.read(3)
            s.read(struct.unpack(">I", s.read(4))[0])
            continue
        if mtype == 1:              # SetColourMapEntries
            s.read(3)
            s.read(struct.unpack(">H", s.read(2))[0] * 6)
            continue
        sys.exit(f"Unexpected message {mtype}")
    s.read(1)
    nrects = struct.unpack(">H", s.read(2))[0]
    for _ in range(nrects):
        x, y, w, h, enc = struct.unpack(">HHHHi", s.read(12))
        if enc == -223:             # DesktopSize
            continue
        if enc != 0:
            sys.exit(f"Unexpected encoding {enc}")
        data = s.read(w * h * 4)
        for row in range(h):
            for col in range(w):
                i = (row * w + col) * 4
                b, g, r = data[i], data[i + 1], data[i + 2]
                j = ((y + row) * width + (x + col)) * 3
                fb[j:j + 3] = bytes((r, g, b))
    ws.close()
    with open(out, "wb") as f:
        f.write(png(width, height, bytes(fb)))
    print(f"{out}: {width}x{height}")


if __name__ == "__main__":
    main()
