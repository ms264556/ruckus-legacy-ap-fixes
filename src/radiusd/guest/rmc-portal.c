// SPDX-License-Identifier: MIT
/*
 * rmc-portal.c - "rmc-radiusd portal": a guest portal served by an SCG 2.6 AP itself, for guests signing in with a
 * guest pass (or accepting terms) without the controller.
 *
 * The 2.6 WISPr hotspot (br_dnat) sends an unauthorised station's TCP 80 to <dnat address>:8090 and lets it reach that
 * address only on 9997 and 9998; wispr_http adds "client_mac: aa:bb:cc:dd:ee:ff" and "uip: a.b.c.d" headers to the
 * redirected request. With the controller pointing the hotspot at the AP's own address:
 *
 *   8090   any request is redirected to http://<address>:9997/login?t=<ticket>. The ticket carries the client's MAC
 *          (from client_mac, or the ARP table for the client's address), its address and an expiry, signed with
 *          HMAC-SHA256 under a key made at start, so a form post cannot name another device.
 *   9997   GET /login shows the form; POST /login checks the ticket (signature, expiry, the poster's address) and the
 *          pass (rmc-guest.c), then authorises the station with hostapd's control command
 *            AUTH mac <mac> proxy 0 u:<uuid> s:<session seconds> uk:<uuid>
 *          sent to each socket in /var/run/hostapd until one answers OK. s: is the pass's remaining time, between 60
 *          and 864000 (hostapd's limits). The pass is recorded (bindings file) only once hostapd has said OK.
 *          With --terms there is no pass: the form is an accept button and the command is AUTH mac <mac> proxy 0 u:guest.
 *
 * Plain HTTP only, one process, at most MAX_CONN connections, each closed after one answer or CONN_TIMEOUT_MS.
 *
 * Usage: rmc-radiusd portal --passes <file> --bindings <file> --address <AP IP> [--terms] [--log <file>]
 *                           [-B] [-P <pidfile>]
 *   SIGHUP reloads the pass list (it is also reloaded when the file changes); SIGTERM or SIGINT exits.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "rmc-guest.h"

#define REDIRECT_PORT    8090
#define FORM_PORT        9997
#define HOSTAPD_DIR      "/var/run/hostapd"
#define MAX_CONN         16
#define CONN_TIMEOUT_MS  10000
#define REQ_MAX          4096
#define BODY_MAX         1024
#define TICKET_SECONDS   3600
#define HOSTAPD_WAIT_MS  1000
#define SESSION_MIN      60
#define SESSION_MAX      864000

struct conn {
    int fd;
    int form;                      /* accepted on the form port */
    struct in_addr peer;
    int64_t deadline_ms;
    size_t len;
    char buf[REQ_MAX + 1];
};

static struct {
    struct gp_ctx g;
    int terms;
    const char *address;
    const char *hostapd_dir;
    int ports[2];
    int listen_fd[2];
    uint8_t key[32];
    struct conn conns[MAX_CONN];
} P;

/* ---- small helpers ----------------------------------------------------------------------------------------------- */

static int listen_on(int port)
{
    struct sockaddr_in a;
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0), one = 1;

    if (s < 0)
        return -1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 16) != 0) {
        close(s);
        return -1;
    }
    return s;
}

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = digits[b[i] >> 4];
        out[2 * i + 1] = digits[b[i] & 15];
    }
    out[2 * n] = 0;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* The value of name in an application/x-www-form-urlencoded string, decoded into out; -1 when absent. */
static int form_value(const char *s, const char *name, char *out, size_t outlen)
{
    size_t nl = strlen(name), n = 0;

    while (s && *s) {
        if (!strncmp(s, name, nl) && s[nl] == '=') {
            for (s += nl + 1; *s && *s != '&' && n + 1 < outlen; s++) {
                if (*s == '+')
                    out[n++] = ' ';
                else if (*s == '%' && hexval(s[1]) >= 0 && hexval(s[2]) >= 0) {
                    out[n++] = (char)(hexval(s[1]) << 4 | hexval(s[2]));
                    s += 2;
                } else
                    out[n++] = *s;
            }
            out[n] = 0;
            return 0;
        }
        s = strchr(s, '&');
        if (s)
            s++;
    }
    return -1;
}

/* A request header's value (case-insensitive name), trimmed, into out; -1 when absent. */
static int header(const char *req, const char *name, char *out, size_t outlen)
{
    size_t nl = strlen(name), n;
    const char *line = strchr(req, '\n');

    while (line && line[1] && line[1] != '\r' && line[1] != '\n') {
        line++;
        if (!strncasecmp(line, name, nl) && line[nl] == ':') {
            const char *v = line + nl + 1, *e;

            while (*v == ' ' || *v == '\t')
                v++;
            for (e = v; *e && *e != '\r' && *e != '\n'; e++)
                ;
            n = (size_t)(e - v) < outlen - 1 ? (size_t)(e - v) : outlen - 1;
            memcpy(out, v, n);
            out[n] = 0;
            return 0;
        }
        line = strchr(line, '\n');
    }
    return -1;
}

/* The MAC the ARP table has for addr (when the guest is on one of the AP's own subnets). */
static int arp_mac(struct in_addr addr, uint8_t mac[6])
{
    FILE *f = fopen("/proc/net/arp", "r");
    char line[256], *field[4], *p;
    int found = -1;

    if (!f)
        return -1;
    /* "IP address  HW type  Flags  HW address  Mask  Device" */
    while (fgets(line, sizeof(line), f)) {
        struct in_addr a;
        int n = 0;

        for (p = line; *p && n < 4; ) {
            while (*p == ' ' || *p == '\t')
                p++;
            if (!*p || *p == '\n')
                break;
            field[n++] = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n')
                p++;
            if (*p)
                *p++ = 0;
        }
        if (n == 4 && inet_aton(field[0], &a) && a.s_addr == addr.s_addr && gp_parse_mac(field[3], mac) == 0
            && memcmp(mac, "\0\0\0\0\0\0", 6)) {
            found = 0;
            break;
        }
    }
    fclose(f);
    return found;
}

/* ---- tickets ------------------------------------------------------------------------------------------------------- */

/* <mac 12 hex>-<address 8 hex>-<expiry>-<first 16 bytes of the HMAC, hex> */
static void make_ticket(const uint8_t mac[6], struct in_addr addr, char *out, size_t outlen)
{
    char body[64], m[13], sig[65];
    uint8_t h[32];
    uint32_t a = ntohl(addr.s_addr);

    hex(mac, 6, m);
    snprintf(body, sizeof(body), "%s-%08x-%lld", m, (unsigned)a, (long long)(gp_now() + TICKET_SECONDS));
    gp_hmac_sha256(P.key, sizeof(P.key), (const uint8_t *)body, strlen(body), h);
    hex(h, 16, sig);
    snprintf(out, outlen, "%.63s-%.32s", body, sig);
}

static int check_ticket(const char *t, struct in_addr peer, uint8_t mac[6])
{
    char body[64], sig[65], *end;
    const char *dash = strrchr(t, '-');
    uint8_t h[32];
    unsigned long a;
    long long exp;
    size_t n;
    int i, diff = 0;

    if (!dash || (n = (size_t)(dash - t)) >= sizeof(body) || strlen(dash + 1) != 32)
        return -1;
    memcpy(body, t, n);
    body[n] = 0;
    gp_hmac_sha256(P.key, sizeof(P.key), (const uint8_t *)body, n, h);
    hex(h, 16, sig);
    for (i = 0; i < 32; i++)
        diff |= sig[i] ^ dash[1 + i];
    /* signed by this process, so the layout is make_ticket's */
    if (diff || n < 23 || body[12] != '-' || body[21] != '-' || gp_parse_mac(body, mac))
        return -1;
    a = strtoul(body + 13, &end, 16);
    if (end != body + 21)
        return -1;
    exp = strtoll(body + 22, &end, 10);
    if (*end || a != ntohl(peer.s_addr) || exp < gp_now())
        return -1;
    return 0;
}

/* ---- hostapd ----------------------------------------------------------------------------------------------------- */

/* Sends cmd to every control socket in the hostapd folder until one answers OK; 0 on OK. */
static int hostapd_auth(const char *cmd)
{
    DIR *dir = opendir(P.hostapd_dir);
    struct dirent *e;
    struct sockaddr_un local, to;
    int s = -1, ok = -1;

    if (!dir) {
        gp_log("cannot open %s: %s", P.hostapd_dir, strerror(errno));
        return -1;
    }
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    snprintf(local.sun_path, sizeof(local.sun_path), "/tmp/rmc-portal-%d", (int)getpid());
    unlink(local.sun_path);
    s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0 || bind(s, (struct sockaddr *)&local, sizeof(local)) != 0) {
        gp_log("cannot bind %s: %s", local.sun_path, strerror(errno));
        goto out;
    }
    while (ok != 0 && (e = readdir(dir))) {
        char reply[256];
        struct pollfd pfd = { s, POLLIN, 0 };
        ssize_t n;

        if (e->d_name[0] == '.')
            continue;
        memset(&to, 0, sizeof(to));
        to.sun_family = AF_UNIX;
        if ((size_t)snprintf(to.sun_path, sizeof(to.sun_path), "%s/%s", P.hostapd_dir, e->d_name)
            >= sizeof(to.sun_path))
            continue;
        if (sendto(s, cmd, strlen(cmd), MSG_NOSIGNAL, (struct sockaddr *)&to, sizeof(to)) < 0)
            continue;
        while (poll(&pfd, 1, HOSTAPD_WAIT_MS) == 1) {
            struct sockaddr_un from;
            socklen_t flen = sizeof(from);

            n = recvfrom(s, reply, sizeof(reply) - 1, 0, (struct sockaddr *)&from, &flen);
            if (n < 0)
                break;
            reply[n] = 0;
            if (strcmp(from.sun_path, to.sun_path))
                continue;          /* a late answer from an interface tried before */
            if (!strncmp(reply, "OK", 2))
                ok = 0;
            else
                gp_log("%s answered %.40s", e->d_name, reply);
            break;
        }
    }
out:
    if (s >= 0)
        close(s);
    unlink(local.sun_path);
    closedir(dir);
    return ok;
}

/* ---- pages ------------------------------------------------------------------------------------------------------- */

static void respond(struct conn *c, const char *status, const char *extra, const char *body)
{
    char head[512];
    size_t blen = strlen(body);
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\n"
                     "Cache-Control: no-store\r\nConnection: close\r\n%s\r\n", status, blen, extra ? extra : "");

    if (send(c->fd, head, (size_t)n, MSG_NOSIGNAL) == n && blen)
        send(c->fd, body, blen, MSG_NOSIGNAL);
}

static const char PAGE_HEAD[] =
    "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,"
    "initial-scale=1\"><title>Guest access</title><style>body{font-family:sans-serif;max-width:24em;margin:3em auto;"
    "padding:0 1em}input,button{font-size:1.2em;padding:.4em;width:100%;box-sizing:border-box;margin:.3em 0}"
    ".e{color:#b00020}</style></head><body><h1>Guest access</h1>";

static void form_page(struct conn *c, const char *ticket, const char *error)
{
    char body[2048];

    snprintf(body, sizeof(body),
             "%s%s%s%s<form method=\"post\" action=\"/login\"><input type=\"hidden\" name=\"t\" value=\"%s\">%s"
             "</form></body></html>",
             PAGE_HEAD, error ? "<p class=\"e\">" : "", error ? error : "", error ? "</p>" : "", ticket,
             P.terms ? "<p>By connecting you accept the terms of use of this network.</p>"
                       "<button type=\"submit\" name=\"accept\" value=\"1\">Accept and connect</button>"
                     : "<label for=\"code\">Guest pass</label><input id=\"code\" name=\"code\" inputmode=\"numeric\""
                       " autocomplete=\"off\" maxlength=\"20\" autofocus><button type=\"submit\">Connect</button>");
    respond(c, "200 OK", NULL, body);
}

static void message_page(struct conn *c, const char *status, const char *text)
{
    char body[1024];

    snprintf(body, sizeof(body), "%s<p>%s</p></body></html>", PAGE_HEAD, text);
    respond(c, status, NULL, body);
}

static const char *pass_message(int code)
{
    switch (code) {
    case GP_DEVICES: return "This guest pass is already in use on as many devices as it allows.";
    case GP_EXPIRED: return "This guest pass has expired.";
    case GP_REVOKED: return "This guest pass has been disabled.";
    case GP_BUSY:    return "Too many sign-in attempts. Please wait a minute and try again.";
    default:         return "That guest pass is not valid.";
    }
}

/* ---- requests ---------------------------------------------------------------------------------------------------- */

static void redirect(struct conn *c)
{
    char v[64], ticket[128], loc[256];
    uint8_t mac[6];

    if ((header(c->buf, "client_mac", v, sizeof(v)) != 0 || gp_parse_mac(v, mac) != 0) && arp_mac(c->peer, mac) != 0) {
        message_page(c, "200 OK", "This device could not be identified. Please reconnect to the network.");
        return;
    }
    make_ticket(mac, c->peer, ticket, sizeof(ticket));
    snprintf(loc, sizeof(loc), "Location: http://%s:%d/login?t=%s\r\n", P.address, P.ports[1], ticket);
    respond(c, "302 Found", loc, "");
}

static void login(struct conn *c, const char *body)
{
    char ticket[128], code[64], m[18], cmd[160];
    uint8_t mac[6];
    struct gp_decision d;

    if (form_value(body, "t", ticket, sizeof(ticket)) != 0 || check_ticket(ticket, c->peer, mac) != 0) {
        message_page(c, "200 OK", "This sign-in page has expired. Please open any web page to start again.");
        return;
    }
    gp_format_mac(mac, m);
    if (P.terms) {
        snprintf(cmd, sizeof(cmd), "AUTH mac %s proxy 0 u:guest", m);
        if (hostapd_auth(cmd) != 0) {
            gp_log("%s accepted the terms but no hostapd authorised it", m);
            form_page(c, ticket, "Connecting failed. Please try again.");
            return;
        }
        gp_log("%s accepted the terms", m);
        message_page(c, "200 OK", "You are connected.");
        return;
    }
    if (form_value(body, "code", code, sizeof(code)) != 0)
        code[0] = 0;
    gp_reload(&P.g, 0);
    gp_check(&P.g, code, strlen(code), mac, &d);
    if (d.code == GP_OK) {
        int64_t s = d.expiry - gp_now();

        if (s < SESSION_MIN)
            s = SESSION_MIN;
        if (s > SESSION_MAX)
            s = SESSION_MAX;
        snprintf(cmd, sizeof(cmd), "AUTH mac %s proxy 0 u:%s s:%lld uk:%s", m, d.pass->uuid, (long long)s,
                 d.pass->uuid);
        if (hostapd_auth(cmd) != 0) {
            gp_log("%s: pass %s accepted but no hostapd authorised it", m, d.pass->uuid);
            form_page(c, ticket, "Connecting failed. Please try again.");
            return;
        }
        gp_commit(&P.g, mac, &d);
        gp_log("%s signed in with pass %s%s", m, d.pass->uuid,
               d.bind == GP_BIND_FIRST ? " (first use)" : d.bind == GP_BIND_DEVICE ? " (new device)" : "");
        message_page(c, "200 OK", "You are connected.");
        return;
    }
    gp_log("%s refused with %d%s%s", m, d.code, d.pass ? " pass " : "", d.pass ? d.pass->uuid : "");
    form_page(c, ticket, pass_message(d.code));
}

/* Handles a complete request; 1 when it is not complete yet. */
static int handle(struct conn *c)
{
    char *end = strstr(c->buf, "\r\n\r\n"), *body, method[8], target[512], len_text[16];
    size_t hlen, clen = 0, i, j;

    if (!end)
        return c->len >= REQ_MAX ? (message_page(c, "431 Request Header Fields Too Large", "Request too large."), 0)
                                 : 1;
    hlen = (size_t)(end - c->buf) + 4;
    /* "<method> <target> HTTP/1.x" */
    for (i = 0; i < sizeof(method) - 1 && c->buf[i] > ' '; i++)
        method[i] = c->buf[i];
    method[i] = 0;
    for (j = 0; c->buf[i] == ' ' && j < sizeof(target) - 1 && c->buf[i + 1 + j] > ' '; j++)
        target[j] = c->buf[i + 1 + j];
    target[j] = 0;
    if (!i || !j) {
        message_page(c, "400 Bad Request", "Bad request.");
        return 0;
    }
    if (!c->form) {
        redirect(c);
        return 0;
    }
    if (!strcmp(method, "POST")) {
        if (header(c->buf, "content-length", len_text, sizeof(len_text)) == 0)
            clen = (size_t)strtoul(len_text, NULL, 10);
        if (clen > BODY_MAX) {
            message_page(c, "413 Payload Too Large", "Request too large.");
            return 0;
        }
        if (c->len < hlen + clen)
            return 1;
        body = c->buf + hlen;
        body[clen] = 0;
        if (!strcmp(target, "/login") || !strncmp(target, "/login?", 7))
            login(c, body);
        else
            message_page(c, "404 Not Found", "Not found.");
        return 0;
    }
    if (!strcmp(method, "GET") && (!strncmp(target, "/login?", 7) || !strcmp(target, "/login") || !strcmp(target, "/"))) {
        char ticket[128];
        uint8_t mac[6];
        const char *q = strchr(target, '?');

        if (q && form_value(q + 1, "t", ticket, sizeof(ticket)) == 0 && check_ticket(ticket, c->peer, mac) == 0)
            form_page(c, ticket, NULL);
        else
            message_page(c, "200 OK", "Please open any web page to sign in.");
        return 0;
    }
    message_page(c, "404 Not Found", "Not found.");
    return 0;
}

static void close_conn(struct conn *c)
{
    close(c->fd);
    c->fd = -1;
}

static void accept_on(int which)
{
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int fd, i;

    while ((fd = accept(P.listen_fd[which], (struct sockaddr *)&a, &alen)) >= 0) {
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        for (i = 0; i < MAX_CONN && P.conns[i].fd >= 0; i++)
            ;
        if (i == MAX_CONN) {
            close(fd);
            continue;
        }
        P.conns[i].fd = fd;
        P.conns[i].form = which == 1;
        P.conns[i].peer = a.sin_addr;
        P.conns[i].len = 0;
        P.conns[i].buf[0] = 0;
        P.conns[i].deadline_ms = gp_mono_ms() + CONN_TIMEOUT_MS;
        alen = sizeof(a);
    }
}

static void read_conn(struct conn *c)
{
    ssize_t n = recv(c->fd, c->buf + c->len, REQ_MAX - c->len, 0);

    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EINTR))
            close_conn(c);
        return;
    }
    c->len += (size_t)n;
    c->buf[c->len] = 0;
    if (memchr(c->buf, 0, c->len)) {
        message_page(c, "400 Bad Request", "Bad request.");
        close_conn(c);
        return;
    }
    if (handle(c) == 0 || c->len >= REQ_MAX)
        close_conn(c);
}

static void usage(void)
{
    fprintf(stderr, "usage: rmc-radiusd portal --passes <file> --bindings <file> --address <AP IP> [--terms]"
                    " [--log <file>] [-B] [-P <pidfile>]\n");
}

int rmc_portal_main(int argc, char *argv[])
{
    const char *passes = NULL, *bindings = NULL, *log = NULL, *pidfile = NULL, *env;
    struct pollfd pfd[2 + MAX_CONN];
    int map[2 + MAX_CONN];
    int i, daemon = 0;
    int64_t next_tick = 0;
    struct in_addr check;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;

        if (!strcmp(a, "-B")) { daemon = 1; continue; }
        if (!strcmp(a, "--terms")) { P.terms = 1; continue; }
        if (!v) { usage(); return 2; }
        if (!strcmp(a, "--passes")) passes = v;
        else if (!strcmp(a, "--bindings")) bindings = v;
        else if (!strcmp(a, "--address")) P.address = v;
        else if (!strcmp(a, "--log")) log = v;
        else if (!strcmp(a, "-P")) pidfile = v;
        else { usage(); return 2; }
        i++;
    }
    if (!P.address || !inet_aton(P.address, &check) || (!P.terms && (!passes || !bindings))) {
        usage();
        return 2;
    }

    /* Tests run on spare ports and a stand-in hostapd. */
    P.ports[0] = REDIRECT_PORT;
    P.ports[1] = FORM_PORT;
    env = getenv("RMC_PORTAL_PORTS");
    if (env) {
        char *end;

        P.ports[0] = (int)strtol(env, &end, 10);
        P.ports[1] = *end == ',' ? (int)strtol(end + 1, &end, 10) : 0;
        if (*end || P.ports[0] <= 0 || P.ports[1] <= 0) {
            usage();
            return 2;
        }
    }
    env = getenv("RMC_PORTAL_HOSTAPD");
    P.hostapd_dir = env && *env ? env : HOSTAPD_DIR;

    if (log && gp_log_open(log) != 0) {
        fprintf(stderr, "cannot open %s\n", log);
        return 1;
    }
    for (i = 0; i < 2; i++) {
        P.listen_fd[i] = listen_on(P.ports[i]);
        if (P.listen_fd[i] < 0) {
            gp_log("cannot listen on port %d: %s", P.ports[i], strerror(errno));
            return 1;
        }
    }
    for (i = 0; i < MAX_CONN; i++)
        P.conns[i].fd = -1;
    gp_random(P.key, sizeof(P.key));
    if (daemon && gp_daemonize(pidfile) != 0) {
        gp_log("cannot detach or write %s", pidfile ? pidfile : "the pid file");
        return 1;
    }
    gp_signals();
    gp_init(&P.g, passes, bindings);
    gp_reload(&P.g, 1);
    gp_log("started (%s, ports %d and %d)", P.terms ? "terms" : "guest passes", P.ports[0], P.ports[1]);

    while (!gp_stop) {
        int64_t now = gp_mono_ms();
        int n = 0;

        if (now >= next_tick) {
            gp_reload(&P.g, gp_hup);
            gp_hup = 0;
            next_tick = now + 1000;
        }
        for (i = 0; i < 2; i++) {
            pfd[n].fd = P.listen_fd[i];
            pfd[n].events = POLLIN;
            map[n++] = -1 - i;
        }
        for (i = 0; i < MAX_CONN; i++) {
            if (P.conns[i].fd < 0)
                continue;
            if (now >= P.conns[i].deadline_ms) {
                close_conn(&P.conns[i]);
                continue;
            }
            pfd[n].fd = P.conns[i].fd;
            pfd[n].events = POLLIN;
            map[n++] = i;
        }
        if (poll(pfd, (nfds_t)n, 250) <= 0)
            continue;
        for (i = 0; i < n; i++) {
            if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            if (map[i] < 0)
                accept_on(-1 - map[i]);
            else if (P.conns[map[i]].fd >= 0)
                read_conn(&P.conns[map[i]]);
        }
    }
    for (i = 0; i < MAX_CONN; i++)
        if (P.conns[i].fd >= 0)
            close(P.conns[i].fd);
    gp_log("stopped");
    return 0;
}
