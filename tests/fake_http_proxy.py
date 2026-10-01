#!/usr/bin/env python3
"""Fake HTTP proxy for the auth-header injection test.

Asserts the client's first packet got a length-preserving
'Proxy-Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3M=' injection:
the request line must stay intact and the User-Agent line must be
replaced by the auth header plus an 'X:' filler header.

usage: fake_http_proxy.py PORT EXPECTED_TOTAL_LENGTH
"""
import socket, sys

PORT = int(sys.argv[1])
EXPECTED_LEN = int(sys.argv[2])


def handle(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    lines = data.decode("latin1").split("\r\n")
    checks = [
        ("length preserved", len(data) == EXPECTED_LEN),
        ("request line intact", lines[0] == "POST /drop HTTP/1.1"),
        ("auth header present",
         "Proxy-Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3M=" in lines),
        ("filler header present", any(l.startswith("X: ") for l in lines)),
        ("user-agent replaced", not any(l.startswith("User-Agent:") for l in lines)),
    ]
    ok = all(c for _, c in checks)
    for name, c in checks:
        print(f"  [{'ok' if c else 'FAIL'}] {name}")
    conn.sendall(b"HTTP/1.1 200 AUTH-OK\r\nContent-Length: 2\r\n\r\nhi")
    conn.close()
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(1)
srv.settimeout(5)
conn, _ = srv.accept()
handle(conn)
