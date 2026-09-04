#!/usr/bin/env python3
"""Carry an SSH session over a WebSocket, for ssh's ProxyCommand.

    ssh -o ProxyCommand="python3 bridge-proxy.py wss://host/ssh" ...

stdin and stdout are the SSH transport. This script moves those bytes over a
WebSocket to the host's bridge and moves the answers back. It reads nothing
in the stream and changes nothing in it.

Why this exists: a sandbox whose only egress is HTTP over TLS cannot open a
raw connection to port 22, and often cannot open one to 443 either, because
the gateway inspects the first bytes and resets anything that is not a TLS
handshake. This makes the session look like the HTTPS it already allows.

It is not a security boundary. TLS here protects the transport, and the
gateway may well be terminating it; what actually protects the session is the
SSH host key that ssh pins and the certificate the host's CA issued. Both are
end to end and neither is affected by which pipe the bytes travel down.

Standard library only: this runs wherever redeem.sh runs.
"""

import base64
import hashlib
import os
import select
import socket
import ssl
import sys
from urllib.parse import urlparse

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CHUNK = 65536


def die(msg):
    sys.stderr.write("bridge-proxy: %s\n" % msg)
    sys.exit(1)


def connect(host, port):
    """A TCP socket to host:port, through an HTTP CONNECT proxy when set."""
    proxy = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "")
    # NO_PROXY, exact matches only. Anything subtler is left alone: guessing
    # wrong here sends the session somewhere it should not go.
    no_proxy = (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "")
    if host in [h.strip() for h in no_proxy.split(",") if h.strip()]:
        proxy = ""
    if not proxy:
        return socket.create_connection((host, port), timeout=30)

    p = urlparse(proxy if "://" in proxy else "http://" + proxy)
    sock = socket.create_connection((p.hostname, p.port or 8080), timeout=30)
    req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)
    if p.username:
        auth = base64.b64encode(
            ("%s:%s" % (p.username, p.password or "")).encode()
        ).decode()
        req += "Proxy-Authorization: Basic %s\r\n" % auth
    sock.sendall((req + "\r\n").encode())

    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(1)
        if not chunk:
            die("proxy closed the connection during CONNECT")
        resp += chunk
    status = resp.split(b"\r\n")[0].decode("latin-1")
    if " 200 " not in status:
        die("proxy refused a tunnel to %s:%d (%s)" % (host, port, status))
    return sock


def handshake(sock, host, path):
    """Upgrade to a WebSocket. Returns leftover bytes read past the headers."""
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(
        (
            "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (path, host, key)
        ).encode()
    )
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(1)
        if not chunk:
            die("the host closed the connection during the WebSocket handshake")
        resp += chunk
    head, _, rest = resp.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    if "101" not in lines[0]:
        die("the bridge did not accept the upgrade (%s)" % lines[0])
    # Proves the peer is a WebSocket endpoint and not something that answered
    # 101 by accident.
    want = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    got = ""
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "sec-websocket-accept":
            got = value.strip()
    if got != want:
        die("the bridge's handshake did not verify")
    return rest


def frame(payload):
    """A masked binary frame. A client must mask; a server must not."""
    out = bytearray([0x82])
    n = len(payload)
    if n < 126:
        out.append(0x80 | n)
    elif n < 65536:
        out.append(0x80 | 126)
        out += n.to_bytes(2, "big")
    else:
        out.append(0x80 | 127)
        out += n.to_bytes(8, "big")
    mask = os.urandom(4)
    out += mask
    out += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(out)


class Reader:
    """Reassembles WebSocket frames from a stream."""

    def __init__(self, sock, buffered=b""):
        self.sock = sock
        self.buf = bytearray(buffered)

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(CHUNK)
            if not chunk:
                return False
            self.buf += chunk
        return True

    def next(self):
        """The next message's payload, or None when the peer is done."""
        while True:
            if not self._need(2):
                return None
            b0, b1 = self.buf[0], self.buf[1]
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            n = b1 & 0x7F
            offset = 2
            if n == 126:
                if not self._need(4):
                    return None
                n = int.from_bytes(self.buf[2:4], "big")
                offset = 4
            elif n == 127:
                if not self._need(10):
                    return None
                n = int.from_bytes(self.buf[2:10], "big")
                offset = 10
            if masked:
                if not self._need(offset + 4):
                    return None
                mask = bytes(self.buf[offset:offset + 4])
                offset += 4
            if not self._need(offset + n):
                return None
            payload = bytes(self.buf[offset:offset + n])
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            del self.buf[:offset + n]

            if opcode in (0x1, 0x2, 0x0):
                return payload
            if opcode == 0x8:  # close
                return None
            if opcode == 0x9:  # ping: answer, keep going
                pong = bytearray([0x8A, 0x80 | len(payload)])
                mask = os.urandom(4)
                pong += mask
                pong += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                self.sock.sendall(bytes(pong))
            # pong and anything unknown: ignore and read the next frame.


def main():
    # --probe answers one question — is a bridge reachable from here — using
    # this same handshake, so what is tested is what will be used. It opens no
    # session and spends nothing.
    probe = False
    args = sys.argv[1:]
    if args and args[0] == "--probe":
        probe, args = True, args[1:]
    if len(args) != 1:
        die("usage: bridge-proxy.py [--probe] wss://host[:port]/path")
    url = urlparse(args[0])
    if url.scheme != "wss":
        die("only wss:// is supported; got %r" % url.scheme)
    host, port = url.hostname, url.port or 443
    path = url.path or "/"
    if url.query:
        path += "?" + url.query

    sock = connect(host, port)

    if os.environ.get("GRANTD_BRIDGE_INSECURE_TLS") == "1":
        sys.stderr.write(
            "bridge-proxy: WARNING: TLS certificate checking is off "
            "(GRANTD_BRIDGE_INSECURE_TLS=1). The SSH host key is still "
            "pinned, so the session is still verified; only the transport is "
            "unauthenticated.\n"
        )
        ctx = ssl._create_unverified_context()
    else:
        ctx = ssl.create_default_context()
    sock = ctx.wrap_socket(sock, server_hostname=host)

    leftover = handshake(sock, url.netloc, path)
    if probe:
        sock.close()
        return
    reader = Reader(sock, leftover)

    stdin, stdout = sys.stdin.buffer.raw, sys.stdout.buffer.raw
    sock.setblocking(False)
    while True:
        try:
            ready, _, _ = select.select([stdin, sock], [], [])
        except (OSError, ValueError):
            return
        if stdin in ready:
            data = stdin.read(CHUNK)
            if not data:
                return
            sock.setblocking(True)
            sock.sendall(frame(data))
            sock.setblocking(False)
        if sock in ready:
            sock.setblocking(True)
            try:
                payload = reader.next()
            except (ssl.SSLWantReadError, BlockingIOError):
                sock.setblocking(False)
                continue
            if payload is None:
                return
            if payload:
                stdout.write(payload)
                stdout.flush()
            sock.setblocking(False)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        pass
