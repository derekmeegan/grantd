"""Stands in for nginx: a stub sshd, and TLS in front of the real bridge."""
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

REPO, WORK = sys.argv[1], sys.argv[2]
BANNER = b"SSH-2.0-stub\r\n"
# Deliberately not text: a transport that mangles high bytes or newlines
# produces a session that negotiates and then fails.
PAYLOAD = b"\x00\x01\x02binary\xff\xfe not text\r\n\x1b[0m trailing"


def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except Exception:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def stub_sshd():
    ln = socket.socket()
    ln.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ln.bind(("127.0.0.1", 0))
    ln.listen(8)

    def loop():
        while True:
            try:
                c, _ = ln.accept()
            except OSError:
                return

            def handle(c):
                try:
                    c.sendall(BANNER)
                    while True:
                        d = c.recv(65536)
                        if not d:
                            return
                        c.sendall(d)
                except Exception:
                    pass
                finally:
                    c.close()

            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return ln.getsockname()[1]


def tls_front(backend_port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(WORK, "cert.pem"), os.path.join(WORK, "key.pem"))
    ln = socket.socket()
    ln.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ln.bind(("127.0.0.1", 0))
    ln.listen(8)

    def loop():
        while True:
            try:
                raw, _ = ln.accept()
            except OSError:
                return

            def handle(raw):
                try:
                    c = ctx.wrap_socket(raw, server_side=True)
                    b = socket.create_connection(("127.0.0.1", backend_port))
                    threading.Thread(target=pipe, args=(c, b), daemon=True).start()
                    pipe(b, c)
                except Exception:
                    pass

            threading.Thread(target=handle, args=(raw,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return ln.getsockname()[1]


def fail(msg):
    print("  \033[31mFAIL\033[0m %s" % msg)
    sys.exit(1)


sshd_port = stub_sshd()
# The target is compiled in so that no request can move it; the test build is
# the one place it is set to anything else.
subprocess.run(
    ["go", "build", "-ldflags", "-X main.target=127.0.0.1:%d" % sshd_port,
     "-o", os.path.join(WORK, "grantd-bridge"), "./cmd/grantd-bridge"],
    cwd=os.path.join(REPO, "go"), check=True,
)

bridge_port = 18022
proc = subprocess.Popen(
    [os.path.join(WORK, "grantd-bridge"), "--listen", "127.0.0.1:%d" % bridge_port],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
try:
    time.sleep(0.8)
    front = tls_front(bridge_port)
    shim = os.path.join(REPO, "install", "bridge-proxy.py")
    env = dict(os.environ, GRANTD_BRIDGE_INSECURE_TLS="1")

    # 1. The shim's own probe agrees a bridge is there.
    if subprocess.run([sys.executable, shim, "--probe", "wss://localhost:%d/ssh" % front],
                      env=env, capture_output=True).returncode != 0:
        fail("the shim's --probe did not find the bridge")

    # 2. A session carries bytes both ways, unaltered.
    #
    # Once with Python's default buffered stdio and once with
    # PYTHONUNBUFFERED=1, which containers and CI commonly set. The shim reads
    # the raw file objects under sys.stdin/stdout, and those are shaped
    # differently in the two modes: a regression here showed up only in the
    # sandbox that most needs the bridge.
    for unbuffered in ("", "1"):
        session_env = dict(env)
        if unbuffered:
            session_env["PYTHONUNBUFFERED"] = unbuffered
        else:
            session_env.pop("PYTHONUNBUFFERED", None)
        p = subprocess.Popen([sys.executable, shim, "wss://localhost:%d/ssh" % front],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=session_env)
        p.stdin.write(PAYLOAD)
        p.stdin.flush()
        want = len(BANNER) + len(PAYLOAD)
        out = b""
        deadline = time.time() + 20
        import select
        while len(out) < want and time.time() < deadline:
            r, _, _ = select.select([p.stdout], [], [], 0.5)
            if r:
                chunk = os.read(p.stdout.fileno(), 65536)
                if not chunk:
                    break
                out += chunk
        p.kill()

        if out[:len(BANNER)] != BANNER:
            fail("banner = %r, want %r (PYTHONUNBUFFERED=%r)"
                 % (out[:len(BANNER)], BANNER, unbuffered))
        if out[len(BANNER):] != PAYLOAD:
            fail("the transport was not byte-exact:\n    got  %r\n    want %r"
                 % (out[len(BANNER):], PAYLOAD))

    # 3. Only wss. A visitor must not be talked into an unencrypted transport.
    r = subprocess.run([sys.executable, shim, "ws://localhost:%d/ssh" % front],
                       env=env, capture_output=True)
    if r.returncode == 0 or b"only wss" not in r.stderr:
        fail("the shim accepted a ws:// URL")
finally:
    proc.kill()

print("ok   the bridge carries an ssh transport byte for byte")
