#!/usr/bin/env bash
# Discord Drover Linux — installer (CLI equivalent of the Windows drover.exe)
# https://github.com/hdrover/discord-drover (Windows original)
#
# Usage:
#   ./install.sh                      # interactive install
#   ./install.sh direct               # Direct mode (no proxy, UDP manipulation only)
#   ./install.sh proxy http://127.0.0.1:1080
#   ./install.sh proxy socks5://10.0.0.1:1080
#   ./install.sh proxy http://user:pass@proxy.example.com:8080 --with-packet
#   ./install.sh uninstall
#   ./install.sh status
#
# Options:
#   --with-packet       also fetch the optional drover-packet.bin from the
#                       upstream project (sent before each new voice connection)
#   --desktop-file F    base .desktop to override (default: auto-detect discord.desktop)
#   --no-desktop        do not create the launcher override

set -euo pipefail

LIB_DIR="$HOME/.local/lib"
LIB_PATH="$LIB_DIR/libdrover.so"
DATA_DIR="$HOME/.local/share/drover"
CONFIG="$DATA_DIR/drover.ini"
PACKET="$DATA_DIR/drover-packet.bin"
DESKTOP_OVERRIDE="$HOME/.local/share/applications/discord.desktop"
UPSTREAM_PACKET_URL="https://raw.githubusercontent.com/hdrover/discord-drover/master/dist/drover-packet.bin"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROXY=""
MODE="install"
WITH_PACKET=0
NO_DESKTOP=0
DESKTOP_BASE=""

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "[*] $*"; }

normalize_desktop() {
    # trim + basic validation of a proxy URL (same formats as the original)
    local url="$1"
    [[ "$url" =~ ^(https?|socks5)://[^@]*@?[^:]+:[0-9]{1,5}$ ]] || \
    [[ "$url" =~ ^[^@]*@?[^:]+:[0-9]{1,5}$ ]] || die "cannot parse proxy '$url' (want http://host:port, socks5://host:port or http://user:pass@host:port)"
    echo "$url"
}

chrome_proxy_arg() {
    # --proxy-server value; scheme defaults to http, https->http, and the
    # login:password part is stripped (like the original FormatToChromeProxy)
    local url="$1" scheme rest
    if [[ "$url" == *"://"* ]]; then
        scheme="${url%%://*}"; rest="${url#*://}"
    else
        scheme="http"; rest="$url"
    fi
    [[ "$scheme" == "https" || -z "$scheme" ]] && scheme="http"
    rest="${rest##*@}"
    echo "${scheme}://${rest}"
}

build_lib() {
    command -v gcc >/dev/null || die "gcc not found (install base-devel)"
    info "building $LIB_PATH"
    mkdir -p "$LIB_DIR"
    gcc -O2 -Wall -Wextra -fPIC -shared -o "$LIB_PATH" "$REPO_DIR/src/drover_linux.c" -ldl -lpthread
}

write_config() {
    local proxy="${1:-}"
    mkdir -p "$DATA_DIR"
    # same file format as the original's SaveOptions
    printf '[drover]\nproxy = %s\n' "$proxy" > "$CONFIG"
    info "wrote $CONFIG"
}

fetch_packet() {
    info "fetching optional drover-packet.bin from upstream"
    command -v curl >/dev/null || die "curl not found"
    curl -fsSL -o "$PACKET" "$UPSTREAM_PACKET_URL" || die "download failed from $UPSTREAM_PACKET_URL"
    info "installed $PACKET ($(wc -c < "$PACKET") bytes)"
}

find_base_desktop() {
    if [[ -n "$DESKTOP_BASE" ]]; then
        [[ -f "$DESKTOP_BASE" ]] || die "desktop file not found: $DESKTOP_BASE"
        echo "$DESKTOP_BASE"
        return
    fi
    for f in /usr/share/applications/discord.desktop \
             /usr/share/applications/discord_canary.desktop \
             /usr/share/applications/discord-canary.desktop \
             /usr/share/applications/discord_ptb.desktop; do
        [[ -f "$f" ]] && { echo "$f"; return; }
    done
    die "no Discord .desktop found in /usr/share/applications (use --desktop-file)"
}

write_desktop() {
    local base proxy_flag exec_line
    base="$(find_base_desktop)"
    proxy_flag=""
    [[ -n "$PROXY" ]] && proxy_flag="--proxy-server=$(chrome_proxy_arg "$PROXY")"

    mkdir -p "$(dirname "$DESKTOP_OVERRIDE")"
    exec_line="env LD_PRELOAD=$LIB_PATH${proxy_flag:+ $proxy_flag} $(grep -m1 '^Exec=' "$base" | cut -d= -f2-)"
    sed -e "s|^Exec=.*|Exec=$exec_line|" "$base" > "$DESKTOP_OVERRIDE"
    command -v update-desktop-database >/dev/null && update-desktop-database "$(dirname "$DESKTOP_OVERRIDE")" 2>/dev/null || true
    info "wrote launcher override $DESKTOP_OVERRIDE"
    info "  Exec: $exec_line"
}

do_install() {
    build_lib
    write_config "$PROXY"
    [[ "$WITH_PACKET" == 1 ]] && fetch_packet
    if [[ "$NO_DESKTOP" == 1 ]]; then
        info "skipping desktop override (--no-desktop)"
        info "launch manually with:  LD_PRELOAD=$LIB_PATH discord"
    else
        write_desktop
    fi
    echo
    info "done. Fully quit Discord (tray icon -> Quit) and start it again."
    [[ -n "$PROXY" ]] && info "TCP goes through $PROXY; UDP voice manipulation is always active."
    info "verify:  grep drover /proc/\$(pgrep -f '/Discord' | head -1)/maps"
}

do_uninstall() {
    rm -f "$LIB_PATH" "$DESKTOP_OVERRIDE"
    rm -f "$CONFIG"
    if [[ "${1:-}" == "--purge" ]]; then
        rm -rf "$DATA_DIR"
        info "removed $DATA_DIR (including drover-packet.bin if present)"
    else
        info "kept $DATA_DIR (packet file); remove manually if desired"
    fi
    command -v update-desktop-database >/dev/null && update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
    info "uninstalled. Note: a running Discord must be restarted to drop the shim."
}

do_status() {
    echo "lib:      $([[ -f $LIB_PATH ]] && echo present || echo MISSING) ($LIB_PATH)"
    echo "config:   $CONFIG"
    [[ -f $CONFIG ]] && grep -H '^proxy' "$CONFIG" || true
    echo "packet:   $([[ -f $PACKET ]] && echo enabled || echo disabled) ($PACKET)"
    echo "launcher: $([[ -f $DESKTOP_OVERRIDE ]] && grep -h '^Exec=' $DESKTOP_OVERRIDE || echo MISSING)"
    local pid
    pid="$(pgrep -f '/Discord' | head -1 || true)"
    if [[ -n "$pid" ]]; then
        if grep -q drover "/proc/$pid/maps" 2>/dev/null; then
            echo "running Discord (pid $pid): shim LOADED"
        else
            echo "running Discord (pid $pid): shim NOT loaded (restart Discord)"
        fi
    else
        echo "Discord: not running"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        direct)    MODE="install"; PROXY=""; shift ;;
        proxy)     MODE="install"; [[ $# -ge 2 ]] || die "proxy needs a URL"; PROXY="$(normalize_desktop "$2")"; shift 2 ;;
        install)   MODE="install"; shift ;;
        uninstall) MODE="uninstall"; shift ;;
        status)    MODE="status"; shift ;;
        --with-packet) WITH_PACKET=1; shift ;;
        --no-desktop)  NO_DESKTOP=1; shift ;;
        --desktop-file) [[ $# -ge 2 ]] || die "--desktop-file needs a path"; DESKTOP_BASE="$2"; shift 2 ;;
        --purge) PURGE=1; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$MODE" in
    install)   do_install ;;
    uninstall) do_uninstall "${PURGE:+--purge}" ;;
    status)    do_status ;;
esac
