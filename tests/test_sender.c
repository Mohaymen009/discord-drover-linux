/* Test client for libdrover.so — see tests/run_tests.sh
 *
 *   test_sender udp       PORT   UDP: three sockets (74-first, 10-first, TCP-fake)
 *   test_sender httpauth  PORT   TCP: POST with User-Agent (expects auth injection)
 *   test_sender socks5    PORT   TCP: CONNECT example.com:443 (expects SOCKS5 conversion)
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static struct sockaddr_in mkdst(int port)
{
    struct sockaddr_in d = {0};
    d.sin_family = AF_INET;
    d.sin_port = htons((uint16_t)port);
    d.sin_addr.s_addr = inet_addr("127.0.0.1");
    return d;
}

static int udp_tests(int port)
{
    struct sockaddr_in dst = mkdst(port);

    /* case 1: 74-byte first packet on a fresh UDP socket -> probes injected */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    char pkt74[74];
    memset(pkt74, 'A', sizeof(pkt74));
    if (sendto(fd, pkt74, sizeof(pkt74), 0, (struct sockaddr *)&dst, sizeof(dst)) != 74)
        return 1;
    close(fd);
    sleep(1);

    /* case 2: first packet NOT 74 bytes -> no injection ever for this socket */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    char pkt10[10];
    memset(pkt10, 'B', sizeof(pkt10));
    char pkt74b[74];
    memset(pkt74b, 'C', sizeof(pkt74b));
    sendto(fd, pkt10, sizeof(pkt10), 0, (struct sockaddr *)&dst, sizeof(dst));
    sendto(fd, pkt74b, sizeof(pkt74b), 0, (struct sockaddr *)&dst, sizeof(dst));
    close(fd);
    return 0;
}

static int httpauth_test(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in dst = mkdst(port);
    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
        perror("connect");
        return 1;
    }
    /* long User-Agent line (58 chars incl. name) so the length-preserving
     * injection has room (needs >= 57) */
    const char *req =
        "POST /drop HTTP/1.1\r\n"
        "Host: target.example\r\n"
        "User-Agent: 01234567890123456789012345678901234567890123456\r\n"
        "\r\n";
    ssize_t n = send(fd, req, strlen(req), 0);
    printf("send returned %zd (original %zu)\n", n, strlen(req));
    char resp[256] = {0};
    ssize_t r = recv(fd, resp, sizeof(resp) - 1, 0);
    if (r > 0)
        printf("server said: %.*s\n", (int)r, resp);
    close(fd);
    return (n == (ssize_t)strlen(req) && r > 0) ? 0 : 1;
}

static int socks5_test(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in dst = mkdst(port);
    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
        perror("connect");
        return 1;
    }
    const char *req = "CONNECT example.com:443 HTTP/1.1\r\n\r\n";
    ssize_t n = send(fd, req, strlen(req), 0);
    printf("send returned %zd (original %zu)\n", n, strlen(req));
    char resp[256] = {0};
    ssize_t r = recv(fd, resp, sizeof(resp) - 1, 0);
    if (r > 0)
        printf("proxy said: %.*s\n", (int)r, resp);
    close(fd);
    /* the shim must pretend the whole CONNECT was sent, and recv() must
     * have been rewritten to an HTTP-style reply */
    return (n == (ssize_t)strlen(req) && r > 0 &&
            memcmp(resp, "HTTP/1.1 200 Connection Established", 35) == 0)
               ? 0
               : 1;
}

int main(int argc, char **argv)
{
    int port;
    if (argc < 3) {
        fprintf(stderr, "usage: %s udp|httpauth|socks5 PORT\n", argv[0]);
        return 2;
    }
    port = atoi(argv[2]);
    if (strcmp(argv[1], "udp") == 0)
        return udp_tests(port);
    if (strcmp(argv[1], "httpauth") == 0)
        return httpauth_test(port);
    if (strcmp(argv[1], "socks5") == 0)
        return socks5_test(port);
    return 2;
}
