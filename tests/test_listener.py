#!/usr/bin/env python3
"""UDP test listener: groups datagrams per source socket and asserts the
Direct-mode injection pattern: [optional packet, 0x00, 0x01, <74 bytes>].

usage: test_listener.py PORT EXPECT_PACKET(0|1)
"""
import socket, sys

port = int(sys.argv[1])
expect_packet = sys.argv[2] == "1"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
s.settimeout(3.0)

flows = {}  # src port -> [sizes]
try:
    while True:
        data, addr = s.recvfrom(65536)
        flows.setdefault(addr[1], []).append(len(data))
except socket.timeout:
    pass

seq = [5, 1, 1, 74] if expect_packet else [1, 1, 74]
ok = True
if len(flows) != 2:
    print(f"FAIL: expected 2 distinct UDP sockets, got {len(flows)}: {flows}")
    sys.exit(1)
for src, sizes in flows.items():
    expected = seq if sizes and 74 in sizes and sizes[0] != 10 else [10, 74]
    # the socket whose first datagram is 10 bytes must have NO probes
    if sizes[0] == 10:
        expected = [10, 74]
    if sizes != expected:
        print(f"FAIL: src {src}: got {sizes}, expected {expected}")
        ok = False
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
