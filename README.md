# Discord Drover Linux (Proxy Settings for Discord)

A Linux port of [hdrover/discord-drover](https://github.com/hdrover/discord-drover) for the
**native Linux Discord client**. It forces Discord to use a specified proxy server
(HTTP or SOCKS5) for TCP connections (chat, updates) and slightly modifies Discord's
outgoing UDP traffic, which helps bypass some local restrictions on voice chats.

The original is a Windows `version.dll` that hooks the Winsock API from inside the
Discord process. The Linux client has no DLL search-order hijacking, so this port
implements the identical logic in C as an `LD_PRELOAD` shim: the same packet
detection, the same injections, the same delays, the same config file.

> This is an independent reimplementation of the upstream project's behavior —
> not affiliated with it. The optional `drover-packet.bin` is **not** distributed
> here; `install.sh --with-packet` fetches it from the upstream repository.

## Installation

Clone and use the included installer (the CLI equivalent of the Windows `drover.exe`):

### Automatic Installation

```bash
git clone https://github.com/Mohaymen009/discord-drover-linux.git
cd discord-drover-linux

# Direct mode: no proxy, only the UDP manipulation that bypasses
# voice chat restrictions (e.g. regions where Discord works but voice is blocked)
./install.sh direct

# Or with a proxy for TCP connections:
./install.sh proxy http://127.0.0.1:1080
./install.sh proxy socks5://10.0.0.1:1080
./install.sh proxy http://user:pass@proxy.example.com:8080 --with-packet
```

Then **fully quit Discord** (tray icon → Quit) and start it again from your
application launcher. The installer creates a user-level override of Discord's
`.desktop` entry that loads the shim and passes `--proxy-server=...` to Discord.

Requirements: `gcc` (base-devel), `python3` only for the test suite.

### Other commands

```bash
./install.sh status        # what is installed, and whether a running Discord has the shim loaded
./install.sh uninstall     # remove shim, config and launcher override
./install.sh uninstall --purge   # also remove ~/.local/share/drover (packet file etc.)
```

### Manual Installation

If you prefer manual setup:

```bash
gcc -O2 -fPIC -shared -o ~/.local/lib/libdrover.so src/drover_linux.c -ldl -lpthread
mkdir -p ~/.local/share/drover
printf '[drover]\nproxy = http://127.0.0.1:1080\n' > ~/.local/share/drover/drover.ini
LD_PRELOAD=~/.local/lib/libdrover.so discord
```

Leave `proxy` empty for Direct mode.

### Example `drover.ini` Configuration

```ini
[drover]
; Proxy can use http or socks5 protocols
proxy = http://127.0.0.1:1080
```

- **proxy**: Defines the main proxy server to use for Discord (HTTP or SOCKS5).
  If left empty, no proxy will be used, but UDP manipulation will still occur to
  bypass voice chat restrictions (same as Direct mode).

## Features

- Forces Discord to use a specified proxy for TCP connections.
- Slight interference with UDP traffic for bypassing voice chat restrictions.
  In Direct mode, no proxy is used, only UDP manipulation is performed.
- Supports HTTP proxies with authentication (login and password).
- Supports SOCKS5 proxies (Discord's `CONNECT` requests are transparently
  converted to the SOCKS5 protocol on the wire).
- No root and no system-level modifications: everything lives in `~/.local`,
  and the shim is loaded only into Discord via `LD_PRELOAD`.
- Survives Discord and package updates (unlike the Windows version, nothing is
  installed inside Discord's own folders).

## How it works

The shim is a shared library loaded into Discord's process, replacing a handful
of libc socket calls. It tracks every socket like the original `TSocketManager`
(first-send flags, 30-second garbage collection, `close()` purging for fd reuse):

| Windows original | This port |
|---|---|
| `MyWSASendTo`: first send on a UDP socket of a **74-byte** packet → send optional `drover-packet.bin`, a `0x00` byte, a `0x01` byte, `Sleep(50)`, then the real packet | `sendto()` **and `sendmsg()`** hooks (Linux Discord sends the voice handshake through `sendmsg` with iovecs — verified on Discord 1.0.160 where hooking `sendto` alone never fires) |
| `MyWSASend` + `AddHttpProxyAuthorizationHeader`: Basic proxy auth injected over the `User-Agent` header line, padded to the same length so request framing is untouched | `send()`/`write()` hooks, same length-preserving injection |
| `MySend` + `ConvertHttpToSocks5`: eats Discord's HTTP `CONNECT`, performs a real SOCKS5 handshake instead | `send()`/`write()` hooks, same inline handshake |
| `MyRecv`: fakes `HTTP/1.1 200 Connection Established` after the SOCKS5 reply | `recv()` hook, same behavior (including the upstream caveat that real server data may mix with the SOCKS5 response) |
| `GetCommandLineW` hook appending `--proxy-server=...` | `install.sh` writes `--proxy-server=...` into a user-level `.desktop` override (Linux-native, more reliable); the shim also sets `http_proxy`/`https_proxy` (and `all_proxy` for SOCKS5) for manual terminal launches |
| `GetEnvironmentVariableW` hook for `http_proxy`/`https_proxy` | `setenv()` at load time |
| `CreateProcessW` hook re-copying files into `app-*` dirs after Discord updates | not needed: the shim lives outside Discord's files, so updates can't remove it |

## Optional `drover-packet.bin`

If a `drover-packet.bin` file is present, its contents are sent at the start of
each new outgoing UDP connection, before the built-in UDP manipulation. This
can help bypass voice chat restrictions on networks where the built-in
manipulation alone is not enough.

```bash
./install.sh proxy ... --with-packet   # fetch from upstream and enable
# or manually:
curl -fsSL -o ~/.local/share/drover/drover-packet.bin \
  https://raw.githubusercontent.com/hdrover/discord-drover/master/dist/drover-packet.bin
```

The file is re-read before every new connection, so its contents can be edited
or replaced while Discord is running — there is no need to restart Discord;
starting a new voice connection is enough. Remove the file (or `mv` it elsewhere)
to disable. You can also point the shim at a custom path with the
`DROVER_PACKET` environment variable (set it to an empty string to force-disable).

## Configuration files and environment

| Path / variable | Purpose |
|---|---|
| `~/.local/share/drover/drover.ini` | proxy config (same `[drover] proxy = ...` format as upstream) |
| `~/.local/lib/libdrover.so` | the shim |
| `~/.local/share/applications/discord.desktop` | launcher override created by `install.sh` |
| `DROVER_CONFIG` | alternative path for `drover.ini` |
| `DROVER_PACKET` | alternative path for the packet file; empty = disabled |
| `DROVER_DEBUG=1` | verbose logging to stderr |

## Verify / troubleshoot

```bash
./install.sh status
# is the shim inside the running Discord?
grep drover /proc/$(pgrep -f '/Discord' | head -1)/maps
# debug output on a manual launch:
DROVER_DEBUG=1 LD_PRELOAD=~/.local/lib/libdrover.so discord
```

Self-test suite (fake proxies verify every hook — UDP injection, packet file,
auth-header injection, CONNECT→SOCKS5 conversion):

```bash
make test
```

## Known limitations

- SOCKS5 authentication is not supported (same as the Windows original; its
  handshake only offers the no-auth method). HTTP proxy auth **is** supported.
- Chromium may show a login dialog if the proxy rejects the injected
  credentials — same as upstream.
- Only contiguous sends (`send`/`write`) are intercepted for TCP; `sendmsg`
  iovecs are passed through. Chromium's network stack uses `send()`, so this
  matches how Discord behaves in practice.
- The `.desktop` override targets the packaged Discord (`/usr/share/applications/discord.desktop`);
  use `./install.sh proxy ... --desktop-file /path/to/other.desktop` for
  Canary/PTB-style packages. Flatpak/Snap Discord is not supported (sandboxed
  environment).

## Uninstall

```bash
./install.sh uninstall          # or: uninstall --purge
```

or manually: remove `~/.local/lib/libdrover.so`,
`~/.local/share/applications/discord.desktop` and `~/.local/share/drover/`,
then restart Discord.

## License

MIT — see [LICENSE](LICENSE). Upstream project: [hdrover/discord-drover](https://github.com/hdrover/discord-drover).
