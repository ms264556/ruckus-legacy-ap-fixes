// SPDX-License-Identifier: MIT
/*
 * rmc-urlfilter - a stand-in for the SmartZone 3.6 AP's uf_agent on images that ship avpd but no uf_agent
 * (3.6.2 for the H500/C500 and the ZF7372 family).
 *
 * avpd asks librsm's rsm_urlfilter_get_category for a host's web category; librsm sends a datagram to
 * /tmp/urlfilter_evt.sock and waits for the reply on its own socket. The stock uf_agent answers from its cache and,
 * on a miss, answers all zeros at once and asks BrightCloud in the background (avpd asks again on a later packet of
 * the flow). This daemon does the same, but asks the controller instead: GET /rmc-category?host=<host> through the
 * AP's SSH tunnel (127.0.0.1:8082), which answers "<id>[,<id>...]" (empty: uncategorized).
 *
 * Wire format, from the 3.6.2 R610 uf_agent (urlfilter event handler 0xaa98, cache answer 0xa6d0), native byte order:
 *   request, 0xb8 bytes: u32 type (2 = lookup) at 0x00, 0x70 bytes of avpd's flow context at 0x04, host at 0x78.
 *   reply,   0x94 bytes: u32 type (1) at 0x00, u32 reputation at 0x04, u32 category[5] at 0x08, u32 index of the
 *            last category at 0x1c, u32 confidence at 0x20, the request's flow context at 0x24.
 * A miss is answered with a zeroed reply, as the stock agent does.
 *
 * Usage: rmc-urlfilter [-f] [-v] [-s socket] [-p pidfile] [-a host:port]
 *   -f  stay in the foreground   -v  log every request (hex) and answer to syslog
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define REQ_LEN      0xb8
#define REQ_TYPE     0x00
#define REQ_CONTEXT  0x04
#define CONTEXT_LEN  0x70
#define REQ_HOST     0x78
#define HOST_LEN     (REQ_LEN - REQ_HOST)
#define REPLY_LEN    0x94
#define MAX_CATS     5
#define CONFIDENCE   99
#define REPUTATION   81          /* BrightCloud "trustworthy"; reputation blocking is never on */
#define CACHE_SLOTS  4096
#define TTL_HIT      3600
#define TTL_ERROR    30          /* a failed fetch is retried after this */
#define QUEUE_LEN    64

struct entry {
    char host[HOST_LEN];
    time_t expires;
    int state;                   /* 0 empty, 1 pending, 2 answered */
    uint32_t cats[MAX_CATS];
    int ncats;
};

static struct entry cache[CACHE_SLOTS];
static char queue[QUEUE_LEN][HOST_LEN];
static int q_head, q_tail;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;
static int verbose;
static const char *sock_path = "/tmp/urlfilter_evt.sock";
static const char *pid_path = "/var/run/uf_agent.pid";
static char api_host[64] = "127.0.0.1";
static int api_port = 8082;

static uint32_t hash(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

/* The host as the controller matches it: lower case, no port, no trailing dot, no leading "www.". */
static void normalize(const char *in, size_t len, char *out)
{
    size_t n = 0;
    for (size_t i = 0; i < len && in[i] && in[i] != ':' && in[i] != '/' && n < HOST_LEN - 1; i++) {
        char c = in[i];
        out[n++] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    out[n] = 0;
    while (n > 0 && out[n - 1] == '.') out[--n] = 0;
    if (strncmp(out, "www.", 4) == 0) memmove(out, out + 4, n - 3);
}

/* The slot for host: its own, or the one it may take (open addressing, 8 probes, else the first probe). */
static struct entry *slot(const char *host)
{
    uint32_t h = hash(host);
    struct entry *free_slot = NULL;
    time_t now = time(NULL);
    for (int i = 0; i < 8; i++) {
        struct entry *e = &cache[(h + i) % CACHE_SLOTS];
        if (e->state && strcmp(e->host, host) == 0) return e;
        if (!free_slot && (!e->state || e->expires < now)) free_slot = e;
    }
    return free_slot ? free_slot : &cache[h % CACHE_SLOTS];
}

static void put32(unsigned char *p, uint32_t v) { memcpy(p, &v, 4); }   /* native order, as the AP's own agent */

static void hexdump(const char *what, const unsigned char *b, int n)
{
    char line[3 * 32 + 1];
    for (int off = 0; off < n; off += 32) {
        int m = n - off < 32 ? n - off : 32, k = 0;
        for (int i = 0; i < m; i++) k += snprintf(line + k, sizeof line - k, "%02x ", b[off + i]);
        syslog(LOG_INFO, "%s %03x: %s", what, off, line);
    }
}

/* One lookup through the tunnel. Returns the number of categories (0..5), or -1 on failure. */
static int fetch(const char *host, uint32_t *cats)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)api_port) };
    inet_pton(AF_INET, api_host, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(fd); return -1; }
    char req[256], resp[1024];
    int n = snprintf(req, sizeof req, "GET /rmc-category?host=%s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", host);
    if (write(fd, req, (size_t)n) != n) { close(fd); return -1; }
    int got = 0, r;
    while (got < (int)sizeof resp - 1 && (r = (int)read(fd, resp + got, sizeof resp - 1 - got)) > 0) got += r;
    close(fd);
    resp[got] = 0;
    if (strncmp(resp, "HTTP/1.", 7) != 0 || strncmp(resp + 9, "200", 3) != 0) return -1;
    char *body = strstr(resp, "\r\n\r\n");
    if (!body) return -1;
    body += 4;
    int count = 0;
    while (*body && count < MAX_CATS) {
        long id = strtol(body, &body, 10);
        if (id > 0) cats[count++] = (uint32_t)id;
        while (*body && (*body < '0' || *body > '9')) body++;
    }
    return count;
}

static void *worker(void *arg)
{
    (void)arg;
    for (;;) {
        char host[HOST_LEN];
        pthread_mutex_lock(&lock);
        while (q_head == q_tail) pthread_cond_wait(&wake, &lock);
        memcpy(host, queue[q_head], HOST_LEN);
        q_head = (q_head + 1) % QUEUE_LEN;
        pthread_mutex_unlock(&lock);

        uint32_t cats[MAX_CATS] = { 0 };
        int n = fetch(host, cats);
        pthread_mutex_lock(&lock);
        struct entry *e = slot(host);
        strcpy(e->host, host);
        e->state = n < 0 ? 1 : 2;      /* a failure stays pending until it expires, so it is retried after TTL_ERROR */
        e->ncats = n < 0 ? 0 : n;
        memcpy(e->cats, cats, sizeof cats);
        e->expires = time(NULL) + (n < 0 ? TTL_ERROR : TTL_HIT);
        pthread_mutex_unlock(&lock);
        if (verbose || n < 0) syslog(n < 0 ? LOG_WARNING : LOG_INFO, "lookup %s: %s%d", host, n < 0 ? "failed " : "categories ", n);
    }
    return NULL;
}

/* Fills reply for host; returns 1 on a cache answer, 0 on a miss (the host is queued unless already pending). */
static int answer(const char *host, const unsigned char *req, unsigned char *reply)
{
    memset(reply, 0, REPLY_LEN);
    pthread_mutex_lock(&lock);
    struct entry *e = slot(host);
    time_t now = time(NULL);
    int fresh = e->state && strcmp(e->host, host) == 0 && e->expires >= now;
    if (fresh && e->state == 2) {
        put32(reply + 0x00, 1);
        put32(reply + 0x04, REPUTATION);
        for (int i = 0; i < e->ncats; i++) put32(reply + 0x08 + 4 * i, e->cats[i]);
        put32(reply + 0x1c, (uint32_t)(e->ncats > 0 ? e->ncats - 1 : 0));
        put32(reply + 0x20, e->ncats > 0 ? CONFIDENCE : 0);
        memcpy(reply + 0x24, req + REQ_CONTEXT, CONTEXT_LEN);
        pthread_mutex_unlock(&lock);
        return 1;
    }
    if (!fresh && (q_tail + 1) % QUEUE_LEN != q_head) {
        strcpy(e->host, host);
        e->state = 1;
        e->expires = now + TTL_ERROR;
        memcpy(queue[q_tail], host, HOST_LEN);
        q_tail = (q_tail + 1) % QUEUE_LEN;
        pthread_cond_signal(&wake);
    }
    pthread_mutex_unlock(&lock);
    return 0;
}

static void on_term(int sig) { (void)sig; unlink(pid_path); unlink(sock_path); _exit(0); }

/* -q: one lookup against the running agent, from a socket of our own, as librsm's client does. */
static int query(const char *host)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_un me = { .sun_family = AF_UNIX }, agent = { .sun_family = AF_UNIX };
    snprintf(me.sun_path, sizeof me.sun_path, "/tmp/rmc-urlfilter-q.%d", (int)getpid());
    strncpy(agent.sun_path, sock_path, sizeof agent.sun_path - 1);
    unlink(me.sun_path);
    if (bind(fd, (struct sockaddr *)&me, sizeof me) < 0) { perror("bind"); return 1; }
    unsigned char req[REQ_LEN] = { 0 }, reply[REPLY_LEN];
    uint32_t type = 2;
    memcpy(req + REQ_TYPE, &type, 4);
    for (int i = 0; i < CONTEXT_LEN; i++) req[REQ_CONTEXT + i] = (unsigned char)i;
    strncpy((char *)req + REQ_HOST, host, HOST_LEN - 1);
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int rc = 1;
    if (sendto(fd, req, REQ_LEN, 0, (struct sockaddr *)&agent, sizeof agent) < 0) perror("sendto");
    else {
        int n = (int)recv(fd, reply, sizeof reply, 0);
        if (n < 0) perror("recv");
        else {
            uint32_t v[9];
            memcpy(v, reply, sizeof v);
            int context_ok = n >= REPLY_LEN && memcmp(reply + 0x24, req + REQ_CONTEXT, CONTEXT_LEN) == 0;
            printf("%d bytes: type %u reputation %u categories %u %u %u %u %u last %u confidence %u context %s\n",
                   n, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], context_ok ? "echoed" : "absent");
            rc = 0;
        }
    }
    close(fd);
    unlink(me.sun_path);
    return rc;
}

int main(int argc, char **argv)
{
    int foreground = 0, opt;
    const char *query_host = NULL;
    while ((opt = getopt(argc, argv, "fvs:p:a:q:")) != -1) {
        switch (opt) {
        case 'q': query_host = optarg; break;
        case 'f': foreground = 1; break;
        case 'v': verbose = 1; break;
        case 's': sock_path = optarg; break;
        case 'p': pid_path = optarg; break;
        case 'a': {
            char *colon = strrchr(optarg, ':');
            if (!colon || colon - optarg >= (long)sizeof api_host) { fprintf(stderr, "-a host:port\n"); return 2; }
            memcpy(api_host, optarg, (size_t)(colon - optarg));
            api_host[colon - optarg] = 0;
            api_port = atoi(colon + 1);
            break;
        }
        default:
            fprintf(stderr, "usage: %s [-f] [-v] [-s socket] [-p pidfile] [-a host:port] | -q host [-s socket]\n", argv[0]);
            return 2;
        }
    }
    if (query_host) return query(query_host);
    openlog("rmc-urlfilter", LOG_PID, LOG_DAEMON);

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, sock_path, sizeof addr.sun_path - 1);
    unlink(sock_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    chmod(sock_path, 0666);

    if (!foreground && daemon(0, 0) < 0) { perror("daemon"); return 1; }
    FILE *pf = fopen(pid_path, "w");
    if (pf) { fprintf(pf, "%d\n", (int)getpid()); fclose(pf); }
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    signal(SIGPIPE, SIG_IGN);

    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0) { syslog(LOG_ERR, "no worker thread"); return 1; }
    syslog(LOG_INFO, "listening on %s, asking %s:%d", sock_path, api_host, api_port);

    for (;;) {
        unsigned char req[512], reply[REPLY_LEN];
        struct sockaddr_un from;
        socklen_t fromlen = sizeof from;
        int n = (int)recvfrom(fd, req, sizeof req, 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0) { if (errno != EINTR) syslog(LOG_ERR, "recvfrom: %s", strerror(errno)); continue; }
        if (verbose) { syslog(LOG_INFO, "request %d bytes from %s", n, fromlen > sizeof(sa_family_t) ? from.sun_path : "?"); hexdump("req", req, n); }
        uint32_t type;
        if (n < REQ_LEN) continue;
        memcpy(&type, req + REQ_TYPE, 4);
        if (type != 2) continue;
        char host[HOST_LEN];
        normalize((const char *)req + REQ_HOST, HOST_LEN, host);
        int hit = host[0] ? answer(host, req, reply) : (memset(reply, 0, REPLY_LEN), 0);
        if (verbose) syslog(LOG_INFO, "%s %s", host, hit ? "answered from cache" : "miss: zero reply, lookup queued");
        if (sendto(fd, reply, REPLY_LEN, 0, (struct sockaddr *)&from, fromlen) < 0)
            syslog(LOG_WARNING, "sendto %s: %s", from.sun_path, strerror(errno));
    }
}
