// SPDX-License-Identifier: MIT
/*
 * rmc-urlfilter - a stand-in for the SmartZone 3.6 AP's uf_agent on images that ship avpd but no uf_agent
 * (3.6.2 for the H500/C500 and the ZF7372 family).
 *
 * avpd asks librsm's rsm_urlfilter_get_category for a host's web category; librsm sends a datagram to
 * /tmp/urlfilter_evt.sock and waits for the reply on its own socket. The stock uf_agent answers from its cache and,
 * on a miss, answers all zeros at once and asks BrightCloud in the background (avpd asks again on a later packet of
 * the flow). This daemon asks the controller instead, and on a miss waits up to MISS_WAIT_MS for it (librsm waits
 * 100 ms) so the first flow to a host is decided too; a slower answer is a zeroed reply and is cached for the retry: GET /rmc-category?host=<host> through the
 * AP's SSH tunnel (127.0.0.1:8082), which answers "<id>[,<id>...]" (empty: uncategorized).
 *
 * Wire format, native byte order. 3.6.2 R610 uf_agent (urlfilter event handler 0xaa98, cache answer 0xa6d0):
 *   request, 0xb8 bytes: u32 type (2 = lookup) at 0x00, 0x70 bytes of avpd's flow context at 0x04, host at 0x78.
 *   reply,   0x94 bytes: u32 type (1) at 0x00, u32 reputation at 0x04, u32 category[5] at 0x08, u32 index of the
 *            last category at 0x1c, u32 confidence at 0x20, the request's flow context at 0x24.
 * 7.2.0 uf_agent (handler 0x12da0, cache answer 0x1298c): the same with a 0x7c-byte context, so a 0xc4-byte request
 * (host at 0x84), and a 0xe0-byte reply that ends with the host (0x40 bytes at 0xa0). Both put the host in the last
 * 0x40 bytes and the context from 0x04 to 0x44 bytes before the end. librsm takes only a reply of exactly the length
 * it expects (rsm_urlfilter_get_category): 3.6.2 sends 0xb8 and wants 0x94; 5.1.1 sends 0xb8 but wants 0xd4 (the
 * host appended, as on 7.x); 6.1.2 and 7.2.0 send 0xc4 and want 0xe0. So the host is appended except to a 0xb8-byte
 * request on 3.x, whose major version comes from /etc/version. 5.x and later leave the context zeroed (see fill).
 * A miss not answered in time gets a zeroed reply, as the stock agent's misses do.
 *
 * With the controller's filter file (rmc-filter.h) the answer comes from the AP itself, at once and with no
 * controller: a second thread fetches GET /rmc-filter?have=<content id> every hour and keeps the file in
 * FILTER_DIR (/writable, so it survives a reboot) or, without the room, in FILTER_DIR_TMP. When the controller has not
 * been reached for AWOL_AFTER and the file is older than REBUILD_EVERY, the thread rebuilds it from the lists named in
 * it, downloaded with curl.
 *
 * Usage: rmc-urlfilter [-f] [-v] [-s socket] [-p pidfile] [-a host:port] [-d filter dir]
 *        rmc-urlfilter -q host [-x] [-s socket]               one lookup against the running agent (-x: 7.x request)
 *        rmc-urlfilter -B sources [-c ca.pem] -o file [-w dir] build a filter ("<bit> <url or /path>" lines)
 *        rmc-urlfilter -L file host...                        look hosts up in a filter
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
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "rmc-filter.h"

#define REQ_LEN      0xb8
#define REQ_TYPE     0x00
#define REQ_CONTEXT  0x04
#define REQ_HOST     0x78
#define HOST_LEN     (REQ_LEN - REQ_HOST)
#define REPLY_LEN    0x94        /* the 3.6 reply */
#define HOST_FIELD   0x40        /* the host: the last bytes of a request, of a 7.x reply */
#define REQ_MAX      0x140
#define MAX_CATS     5
#define CONFIDENCE   99
#define REPUTATION   81          /* BrightCloud "trustworthy"; reputation blocking is never on */
#define CACHE_SLOTS  4096
#define TTL_HIT      3600
#define TTL_ERROR    30          /* a failed fetch is retried after this */
#define QUEUE_LEN    64
#define MISS_WAIT_MS 80          /* librsm waits 100 ms for a reply (select in rsm_urlfilter_get_category) */
#define FILTER_DIR     "/writable/rmc-content-filter"
#define FILTER_DIR_TMP "/tmp/rmc-content-filter"
#define FETCH_EVERY    3600      /* asks the controller for a newer filter */
#define STAMP_EVERY    (6 * 3600) /* the contact stamp is touched at most this often (flash) */
#define AWOL_AFTER     (2 * 86400) /* no controller for this long: the AP rebuilds the filter itself */
#define REBUILD_EVERY  86400     /* ...at most this often */
#define FILTER_MAX     (64L * 1024 * 1024)
#define CLOCK_SANE     1700000000L /* before this, the AP has no time yet and the age rules are skipped */

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
static pthread_cond_t answered = PTHREAD_COND_INITIALIZER;
static int verbose;
static const char *sock_path = "/tmp/urlfilter_evt.sock";
static const char *pid_path = "/var/run/uf_agent.pid";
static char api_host[64] = "127.0.0.1";
static int api_port = 8082;
static struct rmc_filter filter;   /* the loaded filter, read and swapped under lock */
static const char *filter_dir_override;
static const uint8_t default_web_ids[RMC_FILTER_CATS] = { 56, 27, 11, 14, 44 };  /* ContentCategories.WebCategoryId */

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
        pthread_cond_broadcast(&answered);
        pthread_mutex_unlock(&lock);
        if (verbose || n < 0) syslog(n < 0 ? LOG_WARNING : LOG_INFO, "lookup %s: %s%d", host, n < 0 ? "failed " : "categories ", n);
    }
    return NULL;
}

/* The cached answer for host, or NULL; called with lock held. */
static struct entry *cached(const char *host)
{
    struct entry *e = slot(host);
    return e->state == 2 && strcmp(e->host, host) == 0 && e->expires >= time(NULL) ? e : NULL;
}

static int fw_major;              /* the AP firmware's major version (/etc/version), 0 when unknown */

/* The reply to a request of n bytes: the context, then the host except on 3.x (and when the version is unknown). */
static int reply_len(int n) { return n == REQ_LEN && fw_major <= 3 ? REPLY_LEN : 0x24 + (n - 0x48) + HOST_FIELD; }

static void read_fw_major(void)
{
    FILE *f = fopen("/etc/version", "r");
    if (!f) return;
    if (fscanf(f, "%d", &fw_major) != 1) fw_major = 0;
    fclose(f);
}

static void fill(const struct entry *e, const unsigned char *req, int n, unsigned char *reply)
{
    put32(reply + 0x00, 1);
    put32(reply + 0x04, REPUTATION);
    for (int i = 0; i < e->ncats; i++) put32(reply + 0x08 + 4 * i, e->cats[i]);
    put32(reply + 0x1c, (uint32_t)(e->ncats > 0 ? e->ncats - 1 : 0));
    put32(reply + 0x20, e->ncats > 0 ? CONFIDENCE : 0);
    int context = n - 0x48;
    /* 3.6 takes the flow context back (proven on the H500). 5.x and 7.x agents answer with it zeroed and send it only
     * in the later push of a cloud answer; an echoed context crashed 5.2.2's rkscli (its context holds the caller's
     * pointers), so it stays zero there. */
    if (fw_major <= 3) memcpy(reply + 0x24, req + REQ_CONTEXT, (size_t)context);
    if (reply_len(n) > 0x24 + context) {
        memcpy(reply + 0x24 + context, req + n - HOST_FIELD, HOST_FIELD);
        reply[0x24 + context + HOST_FIELD - 1] = 0;
    }
}

/*
 * Fills reply for host; returns 3 when the filter file answered, 1 on a cache answer, 2 when the controller answered
 * within MISS_WAIT_MS, 0 on a miss (a zeroed reply; the host stays queued and avpd's retry finds it cached).
 */
static int answer(const char *host, const unsigned char *req, int n, unsigned char *reply)
{
    memset(reply, 0, (size_t)reply_len(n));
    pthread_mutex_lock(&lock);
    if (filter.base) {
        unsigned mask = rmc_filter_lookup(&filter, host);
        struct entry local = { .ncats = 0 };
        for (int bit = 0; bit < RMC_FILTER_CATS; bit++)
            if (mask & (1u << bit) && filter.web_id[bit]) local.cats[local.ncats++] = filter.web_id[bit];
        fill(&local, req, n, reply);
        pthread_mutex_unlock(&lock);
        return 3;
    }
    struct entry *e = cached(host);
    if (e) { fill(e, req, n, reply); pthread_mutex_unlock(&lock); return 1; }
    e = slot(host);
    time_t now = time(NULL);
    int pending = e->state == 1 && strcmp(e->host, host) == 0 && e->expires >= now;
    if (!pending && (q_tail + 1) % QUEUE_LEN != q_head) {
        strcpy(e->host, host);
        e->state = 1;
        e->expires = now + TTL_ERROR;
        memcpy(queue[q_tail], host, HOST_LEN);
        q_tail = (q_tail + 1) % QUEUE_LEN;
        pthread_cond_signal(&wake);
    }
    /* Wait a little for the worker, within librsm's 100 ms, so the first flow to a host is decided too. */
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += MISS_WAIT_MS * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }
    while (!(e = cached(host)))
        if (pthread_cond_timedwait(&answered, &lock, &deadline) == ETIMEDOUT) break;
    if (e) fill(e, req, n, reply);
    pthread_mutex_unlock(&lock);
    return e ? 2 : 0;
}

/* ---- the filter file -------------------------------------------------------------------------------------------- */

static char filter_home[256];      /* the folder the loaded filter came from; its contact stamp lives there too */

static void path_in(char *out, size_t n, const char *dir, const char *name) { snprintf(out, n, "%s/%s", dir, name); }

static time_t mtime_of(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? st.st_mtime : 0;
}

static void touch(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) close(fd);
    utimes(path, NULL);
}

/* Where a filter of need bytes is kept: /writable when it has the room (and some to spare), else /tmp. */
static const char *store_dir(size_t need)
{
    if (filter_dir_override) { mkdir(filter_dir_override, 0755); return filter_dir_override; }
    struct statvfs vfs;
    if ((mkdir(FILTER_DIR, 0755) == 0 || errno == EEXIST) && statvfs(FILTER_DIR, &vfs) == 0
        && (unsigned long long)vfs.f_bavail * vfs.f_frsize >= need + 512ULL * 1024) return FILTER_DIR;
    mkdir(FILTER_DIR_TMP, 0755);
    return FILTER_DIR_TMP;
}

/* Makes the filter at path (in dir) the one lookups use, as dir/filter.bin. */
static int install_filter(const char *path, const char *dir)
{
    struct rmc_filter fresh;
    if (rmc_filter_open(&fresh, path) != 0) { syslog(LOG_WARNING, "filter %s is not usable", path); unlink(path); return -1; }
    char final[300];
    path_in(final, sizeof final, dir, "filter.bin");
    if (rename(path, final) != 0) { syslog(LOG_WARNING, "rename %s: %s", path, strerror(errno)); rmc_filter_close(&fresh); unlink(path); return -1; }
    if (!filter_dir_override) {
        char other[300];
        path_in(other, sizeof other, strcmp(dir, FILTER_DIR) == 0 ? FILTER_DIR_TMP : FILTER_DIR, "filter.bin");
        unlink(other);
    }
    pthread_mutex_lock(&lock);
    struct rmc_filter old = filter;
    filter = fresh;
    snprintf(filter_home, sizeof filter_home, "%s", dir);
    pthread_mutex_unlock(&lock);
    rmc_filter_close(&old);
    syslog(LOG_INFO, "filter: %u names, built %lld by the %s, kept in %s", fresh.names, (long long)fresh.built_at,
           fresh.origin ? "AP" : "controller", dir);
    return 0;
}

static void drop_filter(void)
{
    pthread_mutex_lock(&lock);
    struct rmc_filter old = filter;
    memset(&filter, 0, sizeof filter);
    pthread_mutex_unlock(&lock);
    if (old.base) syslog(LOG_INFO, "filter dropped: the controller blocks nothing");
    rmc_filter_close(&old);
    char path[300];
    const char *dirs[] = { filter_dir_override ? filter_dir_override : FILTER_DIR, FILTER_DIR_TMP };
    for (int i = 0; i < 2; i++) { path_in(path, sizeof path, dirs[i], "filter.bin"); unlink(path); }
}

/* At start-up: the filter kept from before, so lookups work before (or without) the controller. */
static void load_kept_filter(void)
{
    const char *dirs[] = { filter_dir_override ? filter_dir_override : FILTER_DIR, FILTER_DIR_TMP };
    for (int i = 0; i < 2; i++) {
        char path[300];
        path_in(path, sizeof path, dirs[i], "filter.bin");
        struct rmc_filter f;
        if (rmc_filter_open(&f, path) != 0) continue;
        pthread_mutex_lock(&lock);
        filter = f;
        snprintf(filter_home, sizeof filter_home, "%s", dirs[i]);
        pthread_mutex_unlock(&lock);
        syslog(LOG_INFO, "filter from %s: %u names, built %lld", path, f.names, (long long)f.built_at);
        return;
    }
}

/* GET path through the tunnel into out_path: the HTTP status (the body is kept only for 200), -1 when unreachable. */
static int http_get_file(const char *path, const char *out_path)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { 30, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)api_port) };
    inet_pton(AF_INET, api_host, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(fd); return -1; }
    char req[300], buf[16384];
    int n = snprintf(req, sizeof req, "GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", path);
    if (write(fd, req, (size_t)n) != n) { close(fd); return -1; }
    int got = 0, r = 0;
    char *body = NULL;
    while (!body && got < (int)sizeof buf - 1 && (r = (int)read(fd, buf + got, sizeof buf - 1 - got)) > 0) {
        got += r;
        buf[got] = 0;
        body = strstr(buf, "\r\n\r\n");
    }
    if (!body || strncmp(buf, "HTTP/1.", 7) != 0) { close(fd); return -1; }
    int status = atoi(buf + 9);
    if (status != 200) { close(fd); return status; }
    body += 4;
    FILE *out = fopen(out_path, "wb");
    if (!out) { close(fd); return -1; }
    long total = got - (body - buf);
    int ok = fwrite(body, 1, (size_t)total, out) == (size_t)total;
    while (ok && (r = (int)read(fd, buf, sizeof buf)) > 0) {
        total += r;
        ok = total <= FILTER_MAX && fwrite(buf, 1, (size_t)r, out) == (size_t)r;
    }
    if (r < 0) ok = 0;
    close(fd);
    if (fclose(out) != 0) ok = 0;
    if (!ok) { unlink(out_path); return -1; }
    return 200;
}

/* The AP's own build from the lists the current filter names (the controller has been away too long). */
static void self_build(void)
{
    char *sources = NULL;
    size_t len = 0, ca_len = 0, size = 0;
    uint8_t ids[RMC_FILTER_CATS];
    pthread_mutex_lock(&lock);
    if (filter.base && filter.sources_len && (sources = malloc(filter.sources_len + filter.ca_len))) {
        len = filter.sources_len;
        ca_len = filter.ca_len;
        size = filter.size;
        memcpy(sources, filter.sources, len + ca_len);   /* the CA block follows the sources */
        memcpy(ids, filter.web_id, sizeof ids);
    }
    pthread_mutex_unlock(&lock);
    if (!sources) return;
    const char *dir = store_dir(size);
    char out[300], err[256];
    path_in(out, sizeof out, dir, "filter.new");
    mkdir(FILTER_DIR_TMP, 0755);
    syslog(LOG_INFO, "filter: no controller for over %d h, rebuilding from the lists", AWOL_AFTER / 3600);
    int rc = rmc_filter_build(sources, len, sources + len, ca_len, ids, FILTER_DIR_TMP "/build", out, (int64_t)time(NULL), 1, err, sizeof err);
    rmdir(FILTER_DIR_TMP "/build");
    free(sources);
    if (rc == 0) install_filter(out, dir);
    else syslog(LOG_WARNING, "filter rebuild failed: %s", err);
}

/* One round: ask the controller for a newer filter; without one for too long, rebuild it here. */
static void filter_round(void)
{
    uint64_t have = 0;
    size_t size = 0;
    int64_t built_at = 0;
    char home[256];
    pthread_mutex_lock(&lock);
    if (filter.base) { have = filter.content_id; size = filter.size; built_at = filter.built_at; }
    snprintf(home, sizeof home, "%s", filter_home);
    pthread_mutex_unlock(&lock);

    const char *dir = store_dir(size ? size : 2 * 1024 * 1024);
    char query[64], fresh[300], stamp[300];
    snprintf(query, sizeof query, "/rmc-filter?have=%016llx", (unsigned long long)have);
    path_in(fresh, sizeof fresh, dir, "filter.new");
    int status = http_get_file(query, fresh);
    time_t now = time(NULL);
    if (status == 200 || status == 304 || status == 404) {
        if (status == 200 && install_filter(fresh, dir) == 0) snprintf(home, sizeof home, "%s", dir);
        if (status == 404) drop_filter();
        path_in(stamp, sizeof stamp, home[0] ? home : dir, "contact");
        if (status != 304 || now - mtime_of(stamp) >= STAMP_EVERY) touch(stamp);
        return;
    }
    if (!home[0] || now < CLOCK_SANE) return;
    path_in(stamp, sizeof stamp, home, "contact");
    time_t contact = mtime_of(stamp);
    if (!contact) { path_in(stamp, sizeof stamp, home, "filter.bin"); contact = mtime_of(stamp); }
    if (now - contact > AWOL_AFTER && now - built_at > REBUILD_EVERY) self_build();
}

static void *filter_worker(void *arg)
{
    (void)arg;
    sleep(5);
    for (;;) {
        filter_round();
        sleep(FETCH_EVERY);
    }
    return NULL;
}

/* -B: builds a filter from a sources file (and curl's roots from a PEM file), as the AP does when the controller is away. */
static int build_cmd(const char *sources_path, const char *ca_path, const char *out_path, const char *workdir)
{
    static char sources[65536], ca[262144];
    size_t len = 0, ca_len = 0;
    FILE *in = fopen(sources_path, "rb");
    if (!in) { perror(sources_path); return 1; }
    len = fread(sources, 1, sizeof sources, in);
    fclose(in);
    if (ca_path) {
        if (!(in = fopen(ca_path, "rb"))) { perror(ca_path); return 1; }
        ca_len = fread(ca, 1, sizeof ca, in);
        fclose(in);
    }
    char err[256];
    if (rmc_filter_build(sources, len, ca, ca_len, default_web_ids, workdir, out_path, (int64_t)time(NULL), 1, err, sizeof err) != 0) {
        fprintf(stderr, "build failed: %s\n", err);
        return 1;
    }
    struct rmc_filter f;
    if (rmc_filter_open(&f, out_path) != 0) { fprintf(stderr, "%s: not a filter\n", out_path); return 1; }
    printf("%s: %u names, %u entries, %zu bytes\n", out_path, f.names, f.length, f.size);
    rmc_filter_close(&f);
    return 0;
}

/* -L: looks hosts up in a filter as the agent does, "<host> <mask>" per host; "-" reads hosts from stdin. */
static int lookup_cmd(const char *path, char **hosts, int count)
{
    struct rmc_filter f;
    if (rmc_filter_open(&f, path) != 0) { fprintf(stderr, "%s: not a filter\n", path); return 1; }
    char line[512], host[HOST_LEN];
    for (int i = 0; i < count; i++) {
        if (strcmp(hosts[i], "-") == 0) {
            while (fgets(line, sizeof line, stdin)) {
                line[strcspn(line, "\r\n")] = 0;
                normalize(line, strlen(line), host);
                printf("%s %u\n", line, host[0] ? rmc_filter_lookup(&f, host) : 0);
            }
            continue;
        }
        normalize(hosts[i], strlen(hosts[i]), host);
        printf("%s %u\n", hosts[i], host[0] ? rmc_filter_lookup(&f, host) : 0);
    }
    rmc_filter_close(&f);
    return 0;
}

static void on_term(int sig) { (void)sig; unlink(pid_path); unlink(sock_path); _exit(0); }

/* -q: one lookup against the running agent, from a socket of our own, as librsm's client does. */
static int query(const char *host, int req_len)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_un me = { .sun_family = AF_UNIX }, agent = { .sun_family = AF_UNIX };
    snprintf(me.sun_path, sizeof me.sun_path, "/tmp/rmc-urlfilter-q.%d", (int)getpid());
    strncpy(agent.sun_path, sock_path, sizeof agent.sun_path - 1);
    unlink(me.sun_path);
    if (bind(fd, (struct sockaddr *)&me, sizeof me) < 0) { perror("bind"); return 1; }
    unsigned char req[REQ_MAX] = { 0 }, reply[REQ_MAX + 0x40];
    uint32_t type = 2;
    int context = req_len - 0x48;
    memcpy(req + REQ_TYPE, &type, 4);
    for (int i = 0; i < context; i++) req[REQ_CONTEXT + i] = (unsigned char)i;
    strncpy((char *)req + req_len - HOST_FIELD, host, HOST_FIELD - 1);
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int rc = 1;
    if (sendto(fd, req, (size_t)req_len, 0, (struct sockaddr *)&agent, sizeof agent) < 0) perror("sendto");
    else {
        int n = (int)recv(fd, reply, sizeof reply, 0);
        if (n < 0) perror("recv");
        else {
            uint32_t v[9];
            memcpy(v, reply, sizeof v);
            int context_ok = n >= reply_len(req_len) && memcmp(reply + 0x24, req + REQ_CONTEXT, (size_t)context) == 0;
            printf("%d bytes: type %u reputation %u categories %u %u %u %u %u last %u confidence %u context %s\n",
                   n, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], context_ok ? "echoed" : "absent");
            if (verbose)
                for (int off = 0; off < n; off += 16) {
                    printf("%03x:", off);
                    for (int i = off; i < n && i < off + 16; i++) printf(" %02x", reply[i]);
                    printf("\n");
                }
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
    int query_len = REQ_LEN;
    const char *query_host = NULL, *build_sources = NULL, *build_out = NULL, *build_work = "/tmp/rmc-filter-build", *lookup_file = NULL, *build_ca = NULL;
    while ((opt = getopt(argc, argv, "fvs:p:a:q:d:B:c:o:w:L:x")) != -1) {
        switch (opt) {
        case 'q': query_host = optarg; break;
        case 'x': query_len = 0xc4; break;
        case 'd': filter_dir_override = optarg; break;
        case 'B': build_sources = optarg; break;
        case 'o': build_out = optarg; break;
        case 'c': build_ca = optarg; break;
        case 'w': build_work = optarg; break;
        case 'L': lookup_file = optarg; break;
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
            fprintf(stderr, "usage: %s [-f] [-v] [-s socket] [-p pidfile] [-a host:port] [-d dir] | -q host [-x] [-s socket] | -B sources [-c ca.pem] -o file [-w workdir] | -L file host...\n", argv[0]);
            return 2;
        }
    }
    read_fw_major();
    if (query_host) return query(query_host, query_len);
    if (build_sources) {
        if (!build_out) { fprintf(stderr, "-B needs -o file\n"); return 2; }
        return build_cmd(build_sources, build_ca, build_out, build_work);
    }
    if (lookup_file) return lookup_cmd(lookup_file, argv + optind, argc - optind);
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

    load_kept_filter();
    pthread_t t, ft;
    if (pthread_create(&t, NULL, worker, NULL) != 0) { syslog(LOG_ERR, "no worker thread"); return 1; }
    if (pthread_create(&ft, NULL, filter_worker, NULL) != 0) { syslog(LOG_ERR, "no filter thread"); return 1; }
    syslog(LOG_INFO, "listening on %s, asking %s:%d, firmware %d.x", sock_path, api_host, api_port, fw_major);

    for (;;) {
        unsigned char req[512], reply[512];
        struct sockaddr_un from;
        socklen_t fromlen = sizeof from;
        int n = (int)recvfrom(fd, req, sizeof req, 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0) { if (errno != EINTR) syslog(LOG_ERR, "recvfrom: %s", strerror(errno)); continue; }
        if (verbose) { syslog(LOG_INFO, "request %d bytes from %s", n, fromlen > sizeof(sa_family_t) ? from.sun_path : "?"); hexdump("req", req, n); }
        uint32_t type;
        if (n < REQ_LEN || n > REQ_MAX) { if (verbose) syslog(LOG_INFO, "ignored a %d-byte request", n); continue; }
        memcpy(&type, req + REQ_TYPE, 4);
        if (type != 2) continue;
        char host[HOST_LEN];
        normalize((const char *)req + n - HOST_FIELD, HOST_FIELD, host);
        int hit = host[0] ? answer(host, req, n, reply) : (memset(reply, 0, (size_t)reply_len(n)), 0);
        if (verbose) syslog(LOG_INFO, "%s %s", host, hit == 3 ? "answered from the filter" : hit == 1 ? "answered from cache" : hit == 2 ? "answered after a lookup" : "miss: zero reply, lookup queued");
        if (sendto(fd, reply, (size_t)reply_len(n), 0, (struct sockaddr *)&from, fromlen) < 0)
            syslog(LOG_WARNING, "sendto %s: %s", from.sun_path, strerror(errno));
    }
}
