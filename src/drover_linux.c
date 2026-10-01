/*
 * drover_linux.c — Linux LD_PRELOAD port of Discord Drover
 * (https://github.com/hdrover/discord-drover)
 *
 * Forces the native Linux Discord client (Electron) to use a specified
 * HTTP or SOCKS5 proxy for TCP connections, and performs the same UDP
 * traffic manipulation as the Windows original ("Direct mode").
 *
 * Mapping from the Windows original (Delphi, drover.dpr):
 *
 *   Windows hook                  Linux equivalent
 *   ----------------------------  ------------------------------------------
 *   socket/WSASocket tracking     getsockopt(SO_TYPE/SO_PROTOCOL) per fd,
 *                                 plus close() hook to purge entries
 *   MyWSASendTo (UDP, first send, sendto() hook
 *   74-byte packet -> optional    (identical: optional drover-packet.bin,
 *   drover-packet.bin + 0x00 +     1-byte 0x00, 1-byte 0x01, 50 ms delay)
 *   0x01 + Sleep(50))
 *   MyWSASend auth-header         send()/write() hooks: length-preserving
 *   injection (Basic proxy auth,  "Proxy-Authorization: Basic ..." injection
 *   User-Agent length matching)   over the User-Agent header line
 *   MySend HTTP->SOCKS5           send()/write() hooks: CONNECT interception,
 *   conversion (CONNECT eaten,    inline SOCKS5 handshake via real
 *   inline SOCKS5 handshake)      send/recv/select
 *   MyRecv fake "HTTP/1.1 200     recv() hook: SOCKS5 success reply
 *   Connection Established"       replaced with an HTTP-CONNECT-style reply
 *   GetCommandLineW ->            --proxy-server=... flag written by
 *   --proxy-server injection      install.sh into the Discord .desktop file
 *   GetEnvironmentVariableW ->    setenv("http_proxy"/"https_proxy") in the
 *   http_proxy/https_proxy        constructor (belt & suspenders for manual
 *                                 terminal launches)
 *   CreateProcessW self-heal      not needed: LD_PRELOAD lives outside
 *   copy into app-* dirs          Discord's files, survives updates
 *
 * Socket table entries are garbage-collected after 30 seconds and purged on
 * close(), so fd reuse is handled (mirrors TSocketManager.CollectGarbage).
 *
 * Limitations vs the Windows original (documented in README):
 *   - single contiguous send buffer per call (sendmsg iovecs not rewritten)
 *   - SOCKS5 authentication is not supported (same as the original)
 *
 * Build:  gcc -O2 -fPIC -shared -o libdrover.so src/drover_linux.c -ldl -lpthread
 * Usage:  LD_PRELOAD=/path/to/libdrover.so discord
 *
 * Environment:
 *   DROVER_CONFIG  path to drover.ini (default $HOME/.local/share/drover/drover.ini)
 *   DROVER_PACKET  path to the optional extra UDP payload; empty string
 *                  disables. Default $HOME/.local/share/drover/drover-packet.bin
 *                  (only used when the file exists; re-read before every new
 *                  connection, like the original)
 *   DROVER_DEBUG   set to a non-empty value for logging to stderr
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_PROTOCOL
#define SO_PROTOCOL 38
#endif

/* ------------------------------------------------------------------ */
/* real function pointers                                             */
/* ------------------------------------------------------------------ */

typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int,
                             const struct sockaddr *, socklen_t);
typedef ssize_t (*write_fn)(int, const void *, size_t);
typedef int (*close_fn)(int);

static send_fn real_send;
static recv_fn real_recv;
static sendto_fn real_sendto;
static write_fn real_write;
static close_fn real_close;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_table_len; /* read unlocked as a fast-path check */
static __thread int t_in_hook;

#define HOOK_ENTER()                                                           \
    do {                                                                       \
        if (t_in_hook)                                                         \
            goto passthrough;                                                  \
        t_in_hook = 1;                                                         \
    } while (0)
#define HOOK_LEAVE() (t_in_hook = 0)

/* ------------------------------------------------------------------ */
/* logging                                                            */
/* ------------------------------------------------------------------ */

static void drover_log(const char *fmt, ...)
{
    const char *dbg = getenv("DROVER_DEBUG");
    char buf[512];
    va_list ap;
    int n;
    if (!dbg || !*dbg)
        return;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n > 0) {
        buf[n] = '\n';
        write(2, "[drover] ", 9);
        write(2, buf, (size_t)n + 1);
    }
}

/* ------------------------------------------------------------------ */
/* proxy options (mirrors Options.pas)                                */
/* ------------------------------------------------------------------ */

struct proxy_cfg {
    int specified;
    char prot[16]; /* normalized scheme: http / socks5 / other */
    char login[256];
    char password[256];
    char host[256];
    int port;
    int is_http;
    int is_socks5;
    int is_auth;
};

static struct proxy_cfg g_proxy;
static char g_http_env_url[1024]; /* FormatToHttpEnv result */
static char g_chrome_proxy[1100]; /* FormatToChromeProxy result */

static void parse_proxy(const char *url) /* TProxyValue.ParseFromString */
{
    struct proxy_cfg p;
    char work[1024];
    const char *s = url, *at, *colon, *scheme_sep;
    size_t n;

    memset(&p, 0, sizeof(p));

    while (*s == ' ' || *s == '\t')
        s++;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' ||
                     s[n - 1] == '\n'))
        n--;
    if (n == 0 || n >= sizeof(work))
        goto done;
    memcpy(work, s, n);
    work[n] = '\0';

    p.specified = 1;

    /* optional scheme:// */
    scheme_sep = strstr(work, "://");
    if (scheme_sep) {
        size_t pl = (size_t)(scheme_sep - work);
        if (pl >= sizeof(p.prot))
            pl = sizeof(p.prot) - 1;
        memcpy(p.prot, work, pl);
        p.prot[pl] = '\0';
        for (char *q = p.prot; *q; q++)
            if (*q >= 'A' && *q <= 'Z')
                *q += 32;
        if (p.prot[0] == '\0' || strcmp(p.prot, "https") == 0)
            strcpy(p.prot, "http"); /* same normalization as the original */
        memmove(work, scheme_sep + 3, strlen(scheme_sep + 3) + 1);
    } else {
        strcpy(p.prot, "http");
    }

    /* optional login:password@ (last '@' wins) */
    at = strrchr(work, '@');
    if (at) {
        const char *c = memchr(work, ':', (size_t)(at - work));
        size_t ll, pl;
        if (!c || c > at)
            goto done;
        ll = (size_t)(c - work);
        pl = (size_t)(at - c - 1);
        if (ll >= sizeof(p.login) || pl >= sizeof(p.password))
            goto done;
        memcpy(p.login, work, ll);
        p.login[ll] = '\0';
        memcpy(p.password, c + 1, pl);
        p.password[pl] = '\0';
        memmove(work, at + 1, strlen(at + 1) + 1);
    }

    /* host:port (port = digits after the LAST colon, like the original's
     * greedy (.+):(\d+) regex) */
    colon = strrchr(work, ':');
    if (!colon || !*++colon)
        goto done;
    {
        char *end;
        long v = strtol(colon, &end, 10);
        if (*end != '\0' || v <= 0 || v > 65535)
            goto done;
        p.port = (int)v;
    }
    if ((size_t)(colon - 1 - work) >= sizeof(p.host) || colon - 1 == work)
        goto done;
    memcpy(p.host, work, (size_t)(colon - 1 - work));
    p.host[colon - 1 - work] = '\0';

    p.is_http = (strcmp(p.prot, "http") == 0);
    p.is_socks5 = (strcmp(p.prot, "socks5") == 0);
    p.is_auth = (p.login[0] != '\0' && p.password[0] != '\0');

done:
    g_proxy = p;

    if (g_proxy.specified) {
        snprintf(g_http_env_url, sizeof(g_http_env_url), "http://%s%s%s@%s:%d",
                 g_proxy.is_auth ? g_proxy.login : "",
                 g_proxy.is_auth ? ":" : "",
                 g_proxy.is_auth ? g_proxy.password : "", g_proxy.host,
                 g_proxy.port);
        snprintf(g_chrome_proxy, sizeof(g_chrome_proxy), "%s://%s:%d",
                 g_proxy.prot, g_proxy.host, g_proxy.port);
    }
}

/* minimal ini reader: [drover] proxy = ... */
static void load_config(void) /* LoadOptions */
{
    const char *env = getenv("DROVER_CONFIG");
    char path[4096], line[2048];
    FILE *f;
    int in_section = 0;

    if (env && *env) {
        snprintf(path, sizeof(path), "%s", env);
    } else {
        const char *home = getenv("HOME");
        if (!home || !*home)
            return;
        snprintf(path, sizeof(path), "%s/.local/share/drover/drover.ini", home);
    }

    f = fopen(path, "r");
    if (!f)
        return;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == ';' || *p == '#')
            continue;
        if (*p == '[') {
            char *close_br = strchr(p, ']');
            if (close_br) {
                *close_br = '\0';
                in_section = (strcmp(p + 1, "drover") == 0);
            }
            continue;
        }
        if (in_section && strncmp(p, "proxy", 5) == 0) {
            char *eq = p + 5;
            while (*eq == ' ' || *eq == '\t')
                eq++;
            if (*eq != '=')
                continue;
            eq++;
            while (*eq == ' ' || *eq == '\t')
                eq++;
            parse_proxy(eq); /* trims trailing whitespace itself */
            break;
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* optional extra UDP payload (drover-packet.bin)                     */
/* ------------------------------------------------------------------ */

/* returns path or NULL when disabled; like the original, the file is
 * re-read before every new connection */
static const char *packet_path(void)
{
    static char path_buf[4096];
    const char *env = getenv("DROVER_PACKET");
    if (env)
        return *env ? env : NULL;
    {
        const char *home = getenv("HOME");
        if (!home || !*home)
            return NULL;
        snprintf(path_buf, sizeof(path_buf),
                 "%s/.local/share/drover/drover-packet.bin", home);
    }
    return path_buf;
}

static ssize_t read_packet_file(unsigned char *out, size_t out_cap)
{
    const char *p = packet_path();
    FILE *f;
    size_t n;
    if (!p)
        return 0;
    f = fopen(p, "rb");
    if (!f)
        return 0;
    n = fread(out, 1, out_cap, f);
    fclose(f);
    return (ssize_t)n;
}

/* ------------------------------------------------------------------ */
/* socket table (mirrors TSocketManager)                              */
/* ------------------------------------------------------------------ */

#define GC_AGE_SECONDS 30
#define DISCORD_HANDSHAKE_LEN 74

enum { SOCK_KIND_OTHER = 0, SOCK_KIND_TCP, SOCK_KIND_UDP };

struct entry {
    int fd;
    int kind;
    int first_send_done;
    int fake_socks_http; /* SetFakeHttpProxyFlag */
    time_t created;
};

static struct entry *g_table;
static size_t g_table_cap;

static void collect_garbage_locked(void)
{
    time_t cutoff = time(NULL) - GC_AGE_SECONDS;
    size_t i, out = 0;
    for (i = 0; i < (size_t)g_table_len; i++) {
        if (g_table[i].created >= cutoff)
            g_table[out++] = g_table[i];
    }
    g_table_len = (int)out;
}

static int classify_fd(int fd)
{
    int type = 0, proto = 0;
    socklen_t slen = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &slen) != 0)
        return SOCK_KIND_OTHER; /* ENOTSOCK: file, pipe, ... */
    if (type == SOCK_STREAM)
        return SOCK_KIND_TCP;
    if (type != SOCK_DGRAM)
        return SOCK_KIND_OTHER;
    slen = sizeof(proto);
    if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &proto, &slen) == 0 &&
        proto != IPPROTO_UDP)
        return SOCK_KIND_OTHER;
    return SOCK_KIND_UDP;
}

/* find-or-create entry for fd; returns NULL on OOM */
static struct entry *entry_locked(int fd)
{
    size_t i;
    for (i = 0; i < (size_t)g_table_len; i++)
        if (g_table[i].fd == fd)
            return &g_table[i];
    if (g_table_len == 0 && (size_t)g_table_cap < 64) {
        g_table = realloc(NULL, 64 * sizeof(*g_table));
        if (!g_table)
            return NULL;
        g_table_cap = 64;
    } else if ((size_t)g_table_len == g_table_cap) {
        size_t ncap = g_table_cap * 2;
        struct entry *nt = realloc(g_table, ncap * sizeof(*nt));
        if (!nt)
            return NULL;
        g_table = nt;
        g_table_cap = ncap;
    }
    memset(&g_table[g_table_len], 0, sizeof(g_table[g_table_len]));
    g_table[g_table_len].fd = fd;
    g_table[g_table_len].kind = classify_fd(fd);
    g_table[g_table_len].created = time(NULL);
    return &g_table[g_table_len++];
}

/* IsFirstSend: consumes the first-send flag; also reports socket kind */
static int consume_first_send(int fd, int *kind)
{
    struct entry *e;
    int first = 0;
    pthread_mutex_lock(&g_lock);
    collect_garbage_locked();
    e = entry_locked(fd);
    if (e) {
        first = !e->first_send_done;
        e->first_send_done = 1;
        if (kind)
            *kind = e->kind;
    }
    pthread_mutex_unlock(&g_lock);
    return first;
}

static void set_fake_flag(int fd)
{
    pthread_mutex_lock(&g_lock);
    {
        size_t i;
        for (i = 0; i < (size_t)g_table_len; i++)
            if (g_table[i].fd == fd)
                g_table[i].fake_socks_http = 1;
    }
    pthread_mutex_unlock(&g_lock);
}

/* ResetFakeHttpProxyFlag: consumes the fake flag; returns 1 if it was set */
static int consume_fake_flag(int fd)
{
    int had = 0;
    pthread_mutex_lock(&g_lock);
    {
        size_t i;
        for (i = 0; i < (size_t)g_table_len; i++) {
            if (g_table[i].fd == fd) {
                had = g_table[i].fake_socks_http;
                g_table[i].fake_socks_http = 0;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_lock);
    return had;
}

static void purge_fd(int fd)
{
    if (g_table_len <= 0)
        return;
    pthread_mutex_lock(&g_lock);
    {
        size_t i;
        for (i = 0; i < (size_t)g_table_len; i++) {
            if (g_table[i].fd == fd) {
                g_table[i] = g_table[g_table_len - 1];
                g_table_len--;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_lock);
}

/* ------------------------------------------------------------------ */
/* base64 (for Basic proxy auth)                                      */
/* ------------------------------------------------------------------ */

static size_t base64_encode(const char *in, size_t in_len, char *out)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0, i;
    for (i = 0; i + 2 < in_len; i += 3) {
        uint32_t v = ((uint8_t)in[i] << 16) | ((uint8_t)in[i + 1] << 8) |
                     (uint8_t)in[i + 2];
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];
        out[o++] = tbl[v & 63];
    }
    if (i < in_len) {
        uint32_t v = (uint8_t)in[i] << 16;
        int rem = (int)(in_len - i);
        if (rem == 2)
            v |= (uint8_t)in[i + 1] << 8;
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = (rem == 2) ? tbl[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

/* ------------------------------------------------------------------ */
/* MyWSASendTo: UDP Direct-mode manipulation                          */
/* ------------------------------------------------------------------ */

static void inject_before_handshake(int fd, const struct sockaddr *dest,
                                    socklen_t dlen)
{
    unsigned char pkt[65536];
    ssize_t pkt_len = read_packet_file(pkt, sizeof(pkt));
    unsigned char probe;

    if (pkt_len > 0) {
        real_sendto(fd, pkt, (size_t)pkt_len, 0, dest, dlen);
        drover_log("sent drover-packet.bin (%zd bytes)", pkt_len);
    }
    probe = 0x00;
    real_sendto(fd, &probe, 1, 0, dest, dlen);
    probe = 0x01;
    real_sendto(fd, &probe, 1, 0, dest, dlen);
    {
        struct timespec ts = {0, 50 * 1000 * 1000}; /* Sleep(50) */
        nanosleep(&ts, NULL);
    }
    drover_log("injected Direct-mode probes before 74-byte handshake");
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    int kind = SOCK_KIND_OTHER;

    HOOK_ENTER();
    if (consume_first_send(sockfd, &kind) && kind == SOCK_KIND_UDP &&
        len == DISCORD_HANDSHAKE_LEN)
        inject_before_handshake(sockfd, dest_addr, addrlen);
    HOOK_LEAVE();

passthrough:
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

/* ------------------------------------------------------------------ */
/* AddHttpProxyAuthorizationHeader: Basic auth, length-preserving     */
/* ------------------------------------------------------------------ */

/* rewrites buf (up to ua_len bytes at ua_pos) with a Proxy-Authorization
 * header padded to exactly the User-Agent line length, then forwards it.
 * returns real_send() result, or -2 to signal "not handled, send original" */
static ssize_t send_with_auth_header(int fd, const void *buf, size_t len,
                                     int flags, size_t ua_pos, size_t ua_len)
{
    const char *prefix = "Proxy-Authorization: Basic ";
    const size_t prefix_len = 27;
    char creds[512 + 3], b64[1024], *injected, *copy;
    size_t creds_len, b64_len, ilen, filler_len, crlf_pos;
    ssize_t rv;

    creds_len = (size_t)snprintf(creds, sizeof(creds), "%s:%s", g_proxy.login,
                                 g_proxy.password);
    if (creds_len > 512)
        return -2;
    b64_len = base64_encode(creds, creds_len, b64);
    ilen = prefix_len + b64_len;

    filler_len = ua_len - ilen;
    if (filler_len < 6)
        return -1;

    injected = malloc(ilen + filler_len);
    copy = malloc(len);
    if (!injected || !copy) {
        free(injected);
        free(copy);
        return -2;
    }
    memcpy(injected, prefix, prefix_len);
    memcpy(injected + prefix_len, b64, b64_len);
    /* filler "\r\nX: " + X*(filler_len-5) -> total filler_len bytes,
     * exactly like the original */
    crlf_pos = ilen;
    memcpy(injected + crlf_pos, "\r\nX: ", 5);
    memset(injected + ilen + 5, 'X', filler_len - 5);
    if (ilen + filler_len != ua_len) { /* paranoia; math guarantees equal */
        free(injected);
        free(copy);
        return -2;
    }

    memcpy(copy, buf, len);
    memcpy(copy + ua_pos, injected, ua_len);
    rv = real_send(fd, copy, len, flags);
    free(injected);
    free(copy);
    return rv;
}

/* ------------------------------------------------------------------ */
/* ConvertHttpToSocks5                                                */
/* ------------------------------------------------------------------ */

/* Parses "CONNECT host:port", performs a real SOCKS5 handshake on fd and
 * swallows the CONNECT bytes. Returns 1 if handled. */
static int convert_http_to_socks5(int fd, const char *buf, size_t len,
                                  int flags)
{
    static const unsigned char greet[3] = {0x05, 0x01, 0x00};
    char host[256];
    unsigned char req[2 + 2 + 1 + 256 + 2], reply[2];
    unsigned long port;
    size_t host_len, req_len;
    size_t p = 8, q;
    fd_set rfds;
    struct timeval tv;
    ssize_t r;

    if (len < p || memcmp(buf, "CONNECT ", 8) != 0)
        return 0;

    /* host = [a-z\d.-]+ up to ':' (case-insensitive, same charset as the
     * original regex) */
    q = 0;
    while (p < len && q + 1 < sizeof(host)) {
        char c = buf[p];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '-';
        if (!ok)
            break;
        host[q++] = c;
        p++;
    }
    host[q] = '\0';
    host_len = q;
    if (host_len == 0 || p >= len || buf[p] != ':')
        return 0;
    p++;

    if (p >= len || buf[p] < '0' || buf[p] > '9')
        return 0;
    port = 0;
    while (p < len && buf[p] >= '0' && buf[p] <= '9') {
        port = port * 10 + (unsigned long)(buf[p] - '0');
        if (port > 65535)
            return 0;
        p++;
    }
    if (port == 0)
        return 0;

    /* --- SOCKS5: method negotiation (no auth, like the original) --- */
    if (real_send(fd, greet, sizeof(greet), flags) != (ssize_t)sizeof(greet))
        return 0;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    {
        int sr;
        do {
            sr = select(fd + 1, &rfds, NULL, NULL, &tv);
        } while (sr < 0 && errno == EINTR); /* retry; the original does not */
        if (sr < 1 || !FD_ISSET(fd, &rfds))
            return 0;
    }
    r = real_recv(fd, reply, 2, 0);
    if (r != 2 || reply[0] != 0x05 || reply[1] != 0x00)
        return 0;

    /* --- SOCKS5: CONNECT request (domain name, like the original) --- */
    req_len = 0;
    req[req_len++] = 0x05;
    req[req_len++] = 0x01;
    req[req_len++] = 0x00;
    req[req_len++] = 0x03;
    req[req_len++] = (unsigned char)host_len;
    memcpy(req + req_len, host, host_len);
    req_len += host_len;
    req[req_len++] = (unsigned char)((port >> 8) & 0xff); /* Hi */
    req[req_len++] = (unsigned char)(port & 0xff);        /* Lo */
    if (real_send(fd, req, req_len, flags) != (ssize_t)req_len)
        return 0;

    set_fake_flag(fd);
    return 1;
}

/* ------------------------------------------------------------------ */
/* send()/write(): TCP proxy handling on first send                   */
/* ------------------------------------------------------------------ */

static ssize_t tcp_first_send_hook(int fd, const void *buf, size_t len,
                                   int is_write, int flags)
{
    int kind = SOCK_KIND_OTHER;

    if (len == 0)
        return -2; /* nothing to decide on */

    if (!consume_first_send(fd, &kind) || kind != SOCK_KIND_TCP)
        return -2;

    /* ConvertHttpToSocks5 (takes priority, exactly like MySend) */
    if (g_proxy.is_socks5 &&
        convert_http_to_socks5(fd, buf, len, flags))
        return (ssize_t)len; /* pretend the CONNECT was sent */

    /* AddHttpProxyAuthorizationHeader (http proxy with auth); on internal
     * failure fall through and send the original buffer, like the original */
    if (g_proxy.is_http && g_proxy.is_auth && len <= 65536) {
        const char *b = buf;
        char *ua = memmem(b, len, "User-Agent:", 11);
        if (ua && !memmem(b, len, "\r\nProxy-Authorization: ", 23)) {
            char *crlf = memmem(ua, len - (size_t)(ua - b), "\r\n", 2);
            if (crlf) {
                ssize_t rv = send_with_auth_header(fd, buf, len, flags,
                                                   (size_t)(ua - b),
                                                   (size_t)(crlf - ua));
                return (rv >= 0) ? rv : -2;
            }
        }
    }
    (void)is_write;
    return -2;
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    ssize_t injected;
    HOOK_ENTER();
    if (g_proxy.specified) {
        injected = tcp_first_send_hook(fd, buf, len, 0, flags);
        if (injected != -2) {
            HOOK_LEAVE();
            return injected;
        }
    }
    HOOK_LEAVE();
passthrough:
    return real_send(fd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t len)
{
    ssize_t injected;
    HOOK_ENTER();
    if (g_proxy.specified && fd >= 3 && len > 0) {
        injected = tcp_first_send_hook(fd, buf, len, 1, 0);
        if (injected != -2) {
            HOOK_LEAVE();
            return injected;
        }
    }
    HOOK_LEAVE();
passthrough:
    return real_write(fd, buf, len);
}

/* ------------------------------------------------------------------ */
/* MyRecv: fake HTTP 200 after the SOCKS5 handshake                   */
/* ------------------------------------------------------------------ */

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    ssize_t r = real_recv(fd, buf, len, flags);

    if (r > 0 && consume_fake_flag(fd)) {
        static const char ok[] =
            "HTTP/1.1 200 Connection Established\r\n\r\n";
        size_t ok_len = sizeof(ok) - 1; /* 39 */
        /* Potential issue (kept from the original): real server data may
         * mix with the SOCKS5 response */
        if (r >= 10 && len >= ok_len &&
            memcmp(buf, "\x05\x00\x00", 3) == 0) {
            memcpy(buf, ok, ok_len);
            return (ssize_t)ok_len;
        }
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* close(): purge table entry so fd reuse is handled                  */
/* ------------------------------------------------------------------ */

int close(int fd)
{
    if (fd >= 0 && g_table_len > 0 && !t_in_hook) {
        t_in_hook = 1;
        purge_fd(fd);
        t_in_hook = 0;
    }
    return real_close(fd);
}

/* ------------------------------------------------------------------ */
/* init                                                               */
/* ------------------------------------------------------------------ */

static void resolve_all(void)
{
#define RESOLVE(field, name)                                                   \
    do {                                                                       \
        if (!field) {                                                          \
            field = (typeof(field))dlsym(RTLD_NEXT, name);                     \
            if (!field) {                                                      \
                const char *m = "[drover] FATAL: dlsym(" name ")\n";          \
                write(2, m, strlen(m));                                       \
                abort();                                                       \
            }                                                                 \
        }                                                                     \
    } while (0)
    RESOLVE(real_send, "send");
    RESOLVE(real_recv, "recv");
    RESOLVE(real_sendto, "sendto");
    RESOLVE(real_write, "write");
    RESOLVE(real_close, "close");
#undef RESOLVE
}

__attribute__((constructor)) static void drover_init(void)
{
    resolve_all();
    load_config();

    if (g_proxy.specified) {
        /* GetEnvironmentVariableW hook equivalent: make Chromium's env-based
         * proxy detection see the proxy too (the --proxy-server flag written
         * by install.sh takes precedence anyway) */
        setenv("http_proxy", g_http_env_url, 1);
        setenv("https_proxy", g_http_env_url, 1);
        if (g_proxy.is_socks5) {
            char socks_env[1100];
            snprintf(socks_env, sizeof(socks_env), "socks5://%s:%d",
                     g_proxy.host, g_proxy.port);
            setenv("all_proxy", socks_env, 1);
            setenv("socks_proxy", socks_env, 1);
        }
        drover_log("proxy %s (env %s)", g_chrome_proxy, g_http_env_url);
    } else {
        drover_log("Direct mode (no proxy configured)");
    }
    drover_log("loaded via LD_PRELOAD, pid=%d", (int)getpid());
}
