#!/usr/bin/env bash
# Runs the full shim test suite against local fake proxies.
set -uo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0

note() { echo; echo "===== $* ====="; }

# check <name> <file1> <file2>... -- <pattern> [pattern...]
check() {
    local name="$1"; shift
    local files=()
    while [[ "$1" != "--" ]]; do files+=("$1"); shift; done
    shift
    local ok=1 p f cat_files=""
    for p in "$@"; do
        local found=0
        for f in "${files[@]}"; do
            grep -q "$p" "$f" && { found=1; break; }
        done
        [[ "$found" == 1 ]] || ok=0
    done
    for f in "${files[@]}"; do cat_files="$cat_files $f"; done
    if [[ "$ok" == 1 ]]; then
        echo "[PASS] $name"
    else
        echo "[FAIL] $name (patterns: $*)"
        for f in "${files[@]}"; do
            echo "  --- $f:"
            sed 's/^/    | /' "$f"
        done
        FAILURES=$((FAILURES + 1))
    fi
}

mkdir -p build
gcc -O2 -Wall -o build/test_sender tests/test_sender.c
gcc -O2 -Wall -Wextra -fPIC -shared -o build/libdrover.so src/drover_linux.c -ldl -lpthread

note "test 1/4: Direct mode, UDP injection, no packet file"
printf '[drover]\nproxy = \n' > "$TMP/direct.ini"
python3 tests/test_listener.py 15731 0 > "$TMP/t1_server.out" 2>&1 & LP=$!
sleep 0.4
DROVER_CONFIG="$TMP/direct.ini" DROVER_DEBUG=1 LD_PRELOAD=build/libdrover.so \
    build/test_sender udp 15731 > "$TMP/t1_client.out" 2>&1
wait $LP
check "udp direct (no packet)" "$TMP/t1_server.out" "$TMP/t1_client.out" -- "PASS" "injected Direct-mode probes"

note "test 2/4: Direct mode, UDP injection with drover-packet.bin"
printf 'PKT01' > "$TMP/packet.bin"
python3 tests/test_listener.py 15732 1 > "$TMP/t2_server.out" 2>&1 & LP=$!
sleep 0.4
DROVER_CONFIG="$TMP/direct.ini" DROVER_PACKET="$TMP/packet.bin" DROVER_DEBUG=1 \
    LD_PRELOAD=build/libdrover.so build/test_sender udp 15732 > "$TMP/t2_client.out" 2>&1
wait $LP
check "udp direct (with packet)" "$TMP/t2_server.out" "$TMP/t2_client.out" -- "PASS" "sent drover-packet.bin (5 bytes)"

note "test 3/4: HTTP proxy auth header injection"
printf '[drover]\nproxy = http://testuser:testpass@127.0.0.1:15733\n' > "$TMP/http.ini"
REQLEN="$(python3 -c 'req = ("POST /drop HTTP/1.1\r\nHost: target.example\r\nUser-Agent: " + "0123456789" * 4 + "0123456" + "\r\n\r\n"); print(len(req))')"
python3 tests/fake_http_proxy.py 15733 "$REQLEN" > "$TMP/t3_server.out" 2>&1 & SP=$!
sleep 0.4
DROVER_CONFIG="$TMP/http.ini" LD_PRELOAD=build/libdrover.so \
    build/test_sender httpauth 15733 > "$TMP/t3_client.out" 2>&1
wait $SP
check "http proxy auth" "$TMP/t3_server.out" "$TMP/t3_client.out" -- "PASS" "server said: HTTP/1.1 200 AUTH-OK"

note "test 4/4: HTTP CONNECT -> SOCKS5 conversion + fake reply"
printf '[drover]\nproxy = socks5://127.0.0.1:15734\n' > "$TMP/socks.ini"
python3 tests/fake_socks5_proxy.py 15734 > "$TMP/t4_server.out" 2>&1 & SP=$!
sleep 0.4
DROVER_CONFIG="$TMP/socks.ini" LD_PRELOAD=build/libdrover.so \
    build/test_sender socks5 15734 > "$TMP/t4_client.out" 2>&1
wait $SP
check "http connect -> socks5" "$TMP/t4_server.out" "$TMP/t4_client.out" -- "PASS" "proxy said: HTTP/1.1 200 Connection Established"

echo
if [[ "$FAILURES" == 0 ]]; then
    echo "ALL TESTS PASSED"
else
    echo "$FAILURES TEST(S) FAILED"
fi
exit "$FAILURES"
