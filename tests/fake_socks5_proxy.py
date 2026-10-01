#!/usr/bin/env python3
"""Fake SOCKS5 proxy for the HTTP-CONNECT -> SOCKS5 conversion test.

The shim must swallow the client's 'CONNECT example.com:443' request and
perform a real SOCKS5 handshake on the wire instead:
    <- 05 01 00            (greeting: no-auth)
    -> 05 00               (chosen: no-auth)
    <- 05 01 00 03 len host port
    -> 05 00 00 01 7f 00 00 01 01 bb   (success, 10 bytes starting 05 00 00)
The shim then rewrites the client's next recv() into an HTTP-style reply.
"""
import socket, sys

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(1)
srv.settimeout(5)


def expect(conn, n):
    d = b""
    while len(d) < n:
        c = conn.recv(n - len(d))
        if not c:
            break
        d += c
    return d


conn, _ = srv.accept()
try:
    greet = expect(conn, 3)
    conn.sendall(b"\x05\x00")
    req = expect(conn, 5)
    host_len = req[4]
    rest = expect(conn, host_len + 2)
    host = rest[:host_len].decode()
    port = int.from_bytes(rest[host_len:], "big")
    conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")

    checks = [
        ("greeting is SOCKS5 no-auth", greet == b"\x05\x01\x00"),
        ("request is SOCKS5 CONNECT/domain", req[:4] == b"\x05\x01\x00\x03"),
        ("target host", host == "example.com"),
        ("target port", port == 443),
    ]
    ok = True
    for name, passed in checks:
        print(f"  [{'ok' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
except Exception as e:
    print(f"FAIL: {e}")
    sys.exit(1)
