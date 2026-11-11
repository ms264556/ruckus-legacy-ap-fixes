// SPDX-License-Identifier: MIT
/*
 * rmc-guest.c - the guest-pass roles of rmc-radiusd: the parts both roles share, and the dispatch from hostapd's main.
 *
 *   rmc-radiusd guestd ...   the idm relay for SmartZone 3.6.2 to 7.x firmware (rmc-guestd.c)
 *   rmc-radiusd portal ...   the guest portal for SCG 2.6 firmware (rmc-portal.c)
 *
 * Any other first argument runs hostapd's RADIUS server as before.
 *
 * Pass list (written by the controller, replaced whole), one record per line, fields separated by one space:
 *
 *   rmc-guests 1 <generated unix seconds> <salt, 32 hex>
 *   <sha256 hex of salt bytes + normalised code> <uuid> <state> <redeem-by> <first-used> <duration s> <max devices>
 *       <macs> <name>
 *
 * state 1 is usable, 0 revoked; redeem-by and first-used are unix seconds or "-"; macs are comma-separated
 * aa:bb:cc:dd:ee:ff or "-"; name is percent-encoded or "-". A malformed record is skipped; a file without a valid
 * header refuses every pass.
 *
 * Bindings file (appended here, read and emptied by the controller): "<unix seconds> <uuid> <mac> <first|device>" for
 * every pass accepted without the controller. A pass's first use sets first-used ("first"), a new device on a used
 * pass takes a slot ("device"). The lines still in the file are applied to every newly loaded pass list, so a pass
 * first used offline keeps its expiry until the controller has read them and sends a list that includes them.
 *
 * The checks mirror the controller's GuestVoucherService: 30 attempts a minute for the AP as a token bucket (more are
 * refused with 401), then 10 attempts per device MAC per 300 s (more are answered as an invalid pass for the rest of
 * the window), then the code (spaces, tabs and dashes dropped, exactly ten digits), revocation, expiry and the device
 * limit. Every pass is refused while the clock reads earlier than the list's generated time, since an AP that booted
 * without NTP may think it is 1970 and every pass would look unexpired.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>

#include "rmc-guest.h"

#define MAX_PASS_FILE    (8u << 20)
#define MAX_BINDINGS     (1u << 20)
#define LOG_LIMIT        (64 * 1024)
#define MAC_ATTEMPTS     10
#define MAC_WINDOW       300
#define AP_PER_MINUTE    30

volatile int gp_stop, gp_hup;

static int log_fd = 2;
static const char *log_path;
static const char *log_role = "guest";

/* ---- logging, time, small helpers ------------------------------------------------------------------------------- */

int gp_log_open(const char *path)
{
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);

    if (fd < 0)
        return -1;
    if (log_fd > 2)
        close(log_fd);
    log_fd = fd;
    log_path = path;
    return 0;
}

/* The log lives on flash: past LOG_LIMIT it moves to <file>.old (replacing the previous one) and starts again. */
static void log_rotate(void)
{
    struct stat st;
    char old[512];

    if (!log_path || fstat(log_fd, &st) != 0 || st.st_size < LOG_LIMIT)
        return;
    if ((size_t)snprintf(old, sizeof(old), "%s.old", log_path) >= sizeof(old))
        return;
    rename(log_path, old);
    gp_log_open(log_path);
}

void gp_log(const char *fmt, ...)
{
    char line[512];
    time_t t = time(NULL);
    struct tm tm;
    va_list ap;
    int n;

    gmtime_r(&t, &tm);
    n = snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d %s: ", tm.tm_year + 1900, tm.tm_mon + 1,
                 tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, log_role);
    va_start(ap, fmt);
    vsnprintf(line + n, sizeof(line) - (size_t)n - 1, fmt, ap);
    va_end(ap);
    if (log_fd < 0) {
        syslog(LOG_INFO, "%s", line + n);
        return;
    }
    n = (int)strlen(line);
    line[n++] = '\n';
    log_rotate();
    if (write(log_fd, line, (size_t)n) < 0) {
        /* nowhere else to say it */
    }
}

int64_t gp_now(void)
{
    return (int64_t)time(NULL);
}

int64_t gp_mono_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
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

static int parse_hex(const char *s, size_t len, uint8_t *out, size_t outlen)
{
    size_t i;

    if (len != 2 * outlen)
        return -1;
    for (i = 0; i < outlen; i++) {
        int h = hexval(s[2 * i]), l = hexval(s[2 * i + 1]);

        if (h < 0 || l < 0)
            return -1;
        out[i] = (uint8_t)(h << 4 | l);
    }
    return 0;
}

/* aa:bb:cc:dd:ee:ff, aa-bb-..., or twelve hex digits, either case. */
int gp_parse_mac(const char *s, uint8_t mac[6])
{
    int i, h, l;

    for (i = 0; i < 6; i++) {
        if (i > 0 && (*s == ':' || *s == '-'))
            s++;
        h = hexval(s[0]);
        l = h < 0 ? -1 : hexval(s[1]);
        if (l < 0)
            return -1;
        mac[i] = (uint8_t)(h << 4 | l);
        s += 2;
    }
    return 0;
}

void gp_format_mac(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* GuestVoucherService.NormalizeCode: spaces, tabs and dashes dropped; anything else, or not ten digits, is no code. */
int gp_normalize_code(const char *typed, size_t len, char out[11])
{
    size_t i, n = 0;

    if (len > 64)
        return -1;
    for (i = 0; i < len; i++) {
        char c = typed[i];

        if (c == ' ' || c == '-' || c == '\t')
            continue;
        if (c < '0' || c > '9' || n == 10)
            return -1;
        out[n++] = c;
    }
    out[n] = 0;
    return n == 10 ? 0 : -1;
}

void gp_random(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    ssize_t got = fd >= 0 ? read(fd, buf, len) : -1;

    if (fd >= 0)
        close(fd);
    if (got != (ssize_t)len) {
        struct timeval tv;
        size_t i;

        gettimeofday(&tv, NULL);
        srand((unsigned)(tv.tv_sec ^ tv.tv_usec ^ getpid()));
        for (i = 0; i < len; i++)
            buf[i] ^= (uint8_t)rand();
    }
}

/* ---- the pass list ---------------------------------------------------------------------------------------------- */

static char *read_file(const char *path, size_t limit, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    char *buf;
    size_t got = 0;

    if (fd < 0)
        return NULL;
    if (fstat(fd, &st) != 0 || st.st_size < 0 || (size_t)st.st_size > limit) {
        close(fd);
        return NULL;
    }
    buf = malloc((size_t)st.st_size + 1);
    while (buf && got < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);

        if (n <= 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    if (buf)
        buf[got] = 0;
    *len = got;
    return buf;
}

/* Splits s in place at single spaces into at most max fields; returns the count. */
static int split(char *s, char **f, int max)
{
    int n = 0;

    while (*s && n < max) {
        f[n++] = s;
        while (*s && *s != ' ')
            s++;
        if (!*s)
            break;
        *s++ = 0;
    }
    return *s ? -1 : n;
}

static int parse_i64(const char *s, int64_t *v, int dash_ok)
{
    int64_t r = 0;

    if (dash_ok && s[0] == '-' && !s[1]) {
        *v = -1;
        return 0;
    }
    if (!*s)
        return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || r > (INT64_MAX - 9) / 10)
            return -1;
        r = r * 10 + (*s - '0');
    }
    *v = r;
    return 0;
}

static void percent_decode(const char *s, char *out, size_t outlen)
{
    size_t n = 0;

    if (s[0] == '-' && !s[1]) {
        out[0] = 0;
        return;
    }
    while (*s && n + 1 < outlen) {
        if (s[0] == '%' && hexval(s[1]) >= 0 && hexval(s[2]) >= 0) {
            out[n++] = (char)(hexval(s[1]) << 4 | hexval(s[2]));
            s += 3;
        } else {
            out[n++] = *s++;
        }
    }
    out[n] = 0;
}

static int has_mac(const struct gp_pass *p, const uint8_t mac[6])
{
    int i;

    for (i = 0; i < p->nmacs; i++)
        if (!memcmp(p->macs[i], mac, 6))
            return 1;
    return 0;
}

static void add_mac(struct gp_pass *p, const uint8_t mac[6])
{
    if (!has_mac(p, mac) && p->nmacs < GP_MAX_MACS)
        memcpy(p->macs[p->nmacs++], mac, 6);
}

static int parse_record(char *line, struct gp_pass *p)
{
    char *f[9], *m;
    int64_t v;

    memset(p, 0, sizeof(*p));
    if (split(line, f, 9) != 9)
        return -1;
    if (parse_hex(f[0], strlen(f[0]), p->hash, 32) || strlen(f[1]) != 36)
        return -1;
    memcpy(p->uuid, f[1], 37);
    if ((f[2][0] != '0' && f[2][0] != '1') || f[2][1])
        return -1;
    p->usable = f[2][0] == '1';
    if (parse_i64(f[3], &p->redeem_by, 1) || parse_i64(f[4], &p->first_used, 1)
        || parse_i64(f[5], &p->duration, 0) || parse_i64(f[6], &v, 0) || v > 255)
        return -1;
    p->max_devices = (uint8_t)v;
    if (strcmp(f[7], "-")) {
        for (m = f[7]; *m; ) {
            uint8_t mac[6];

            if (gp_parse_mac(m, mac))
                return -1;
            add_mac(p, mac);
            m += 17;
            if (*m == ',')
                m++;
            else if (*m)
                return -1;
        }
    }
    percent_decode(f[8], p->name, sizeof(p->name));
    return 0;
}

static struct gp_pass *find_uuid(struct gp_list *l, const char *uuid)
{
    size_t i;

    for (i = 0; i < l->count; i++)
        if (!strcmp(l->passes[i].uuid, uuid))
            return &l->passes[i];
    return NULL;
}

/* The bindings file's lines, applied to the list just loaded. */
static void apply_bindings(struct gp_ctx *g)
{
    size_t len;
    char *buf = read_file(g->bindings_path, MAX_BINDINGS, &len), *line, *next;

    if (!buf)
        return;
    for (line = buf; line && *line; line = next) {
        char *f[4];
        int64_t t;
        uint8_t mac[6];
        struct gp_pass *p;

        next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        if (split(line, f, 4) != 4 || parse_i64(f[0], &t, 0) || gp_parse_mac(f[2], mac) || f[2][17]
            || !(p = find_uuid(&g->list, f[1])))
            continue;
        if (!strcmp(f[3], "first") && p->first_used < 0)
            p->first_used = t;
        add_mac(p, mac);
    }
    free(buf);
}

void gp_init(struct gp_ctx *g, const char *passes, const char *bindings)
{
    memset(g, 0, sizeof(*g));
    g->passes_path = passes;
    g->bindings_path = bindings;
    g->bucket_milli = AP_PER_MINUTE * 1000;
    g->bucket_at_ms = gp_mono_ms();
}

void gp_reload(struct gp_ctx *g, int force)
{
    struct stat st;
    struct gp_list l;
    size_t len, cap = 0;
    char *buf, *line, *next, *f[4];
    int64_t v;

    if (!g->passes_path)
        return;
    if (stat(g->passes_path, &st) != 0) {
        if (g->list.loaded || force)
            gp_log("no pass list at %s; every pass is refused", g->passes_path);
        free(g->list.passes);
        memset(&g->list, 0, sizeof(g->list));
        g->passes_mtime = 0;
        g->passes_ino = 0;
        return;
    }
    if (!force && st.st_mtime == g->passes_mtime && st.st_size == g->passes_size && st.st_ino == g->passes_ino)
        return;
    g->passes_mtime = st.st_mtime;
    g->passes_size = st.st_size;
    g->passes_ino = st.st_ino;

    memset(&l, 0, sizeof(l));
    buf = read_file(g->passes_path, MAX_PASS_FILE, &len);
    if (!buf) {
        gp_log("cannot read %s; every pass is refused", g->passes_path);
        goto replace;
    }
    next = strchr(buf, '\n');
    if (next)
        *next++ = 0;
    if (split(buf, f, 4) != 4 || strcmp(f[0], "rmc-guests") || strcmp(f[1], "1") || parse_i64(f[2], &v, 0)
        || parse_hex(f[3], strlen(f[3]), l.salt, 16)) {
        gp_log("%s has no valid header; every pass is refused", g->passes_path);
        goto replace;
    }
    l.loaded = 1;
    l.generated = v;
    for (line = next; line && *line; line = next) {
        next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        if (l.count == cap) {
            struct gp_pass *grown;

            cap = cap ? cap * 2 : 16;
            grown = realloc(l.passes, cap * sizeof(*grown));
            if (!grown) {
                gp_log("out of memory reading %s", g->passes_path);
                break;
            }
            l.passes = grown;
        }
        if (parse_record(line, &l.passes[l.count]) == 0)
            l.count++;
        else
            gp_log("%s: skipped a malformed record", g->passes_path);
    }

replace:
    free(buf);
    free(g->list.passes);
    g->list = l;
    apply_bindings(g);
    gp_log("loaded %zu passes from %s", l.count, g->passes_path);
}

/* ---- checks ------------------------------------------------------------------------------------------------------ */

static int take_ap_token(struct gp_ctx *g)
{
    int64_t now = gp_mono_ms(), cap = AP_PER_MINUTE * 1000;

    g->bucket_milli += (now - g->bucket_at_ms) * AP_PER_MINUTE / 60;
    if (g->bucket_milli > cap)
        g->bucket_milli = cap;
    g->bucket_at_ms = now;
    if (g->bucket_milli < 1000)
        return 0;
    g->bucket_milli -= 1000;
    return 1;
}

static int count_mac_attempt(struct gp_ctx *g, const uint8_t mac[6], int64_t now)
{
    const size_t n = sizeof(g->attempts) / sizeof(g->attempts[0]);
    size_t i, slot = n, spare = 0;

    /* The device's own entry; otherwise an unused one, or the one whose window started first. */
    for (i = 0; i < n && slot == n; i++) {
        if (g->attempts[i].used && !memcmp(g->attempts[i].mac, mac, 6))
            slot = i;
        else if (!g->attempts[i].used)
            spare = i;
        else if (g->attempts[spare].used && g->attempts[i].start < g->attempts[spare].start)
            spare = i;
    }
    if (slot == n) {
        slot = spare;
        memcpy(g->attempts[slot].mac, mac, 6);
        g->attempts[slot].used = 1;
        g->attempts[slot].count = 0;
        g->attempts[slot].start = now;
    }
    if (now - g->attempts[slot].start >= MAC_WINDOW || now < g->attempts[slot].start) {
        g->attempts[slot].start = now;
        g->attempts[slot].count = 0;
    }
    return ++g->attempts[slot].count <= MAC_ATTEMPTS;
}

void gp_check(struct gp_ctx *g, const char *typed, size_t typed_len, const uint8_t mac[6], struct gp_decision *d)
{
    int64_t now = gp_now();
    char code[11];
    uint8_t hash[32];
    struct gp_pass *p = NULL;
    size_t i;
    int known;

    memset(d, 0, sizeof(*d));
    d->code = GP_INVALID;
    if (!take_ap_token(g)) {
        d->code = GP_BUSY;
        return;
    }
    if (!count_mac_attempt(g, mac, now))
        return;
    if (!g->list.loaded)
        return;
    if (now < g->list.generated) {
        gp_log("the clock reads before the pass list was made; refusing");
        return;
    }
    if (gp_normalize_code(typed, typed_len, code))
        return;
    gp_sha256(g->list.salt, sizeof(g->list.salt), (const uint8_t *)code, 10, hash);
    for (i = 0; i < g->list.count; i++) {
        if (!memcmp(g->list.passes[i].hash, hash, 32)) {
            p = &g->list.passes[i];
            break;
        }
    }
    if (!p)
        return;
    d->pass = p;
    if (!p->usable) {
        d->code = GP_REVOKED;
        return;
    }
    if (p->first_used < 0 ? (p->redeem_by >= 0 && now >= p->redeem_by) : now >= p->first_used + p->duration) {
        d->code = GP_EXPIRED;
        return;
    }
    known = has_mac(p, mac);
    if (!known && p->max_devices && p->nmacs >= p->max_devices) {
        d->code = GP_DEVICES;
        return;
    }
    if (!known && p->nmacs >= GP_MAX_MACS) {
        d->code = GP_DEVICES;
        return;
    }
    d->code = GP_OK;
    d->bind = p->first_used < 0 ? GP_BIND_FIRST : known ? GP_BIND_NONE : GP_BIND_DEVICE;
    d->expiry = (p->first_used < 0 ? now : p->first_used) + p->duration;
}

void gp_commit(struct gp_ctx *g, const uint8_t mac[6], const struct gp_decision *d)
{
    char line[96], m[18];
    int64_t now = gp_now();
    int fd, n;

    if (d->code != GP_OK || !d->pass || d->bind == GP_BIND_NONE)
        return;
    if (d->bind == GP_BIND_FIRST && d->pass->first_used < 0)
        d->pass->first_used = now;
    add_mac(d->pass, mac);
    gp_format_mac(mac, m);
    n = snprintf(line, sizeof(line), "%lld %s %s %s\n", (long long)now, d->pass->uuid, m,
                 d->bind == GP_BIND_FIRST ? "first" : "device");
    fd = open(g->bindings_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, line, (size_t)n) != n)
        gp_log("cannot append to %s: %s", g->bindings_path, strerror(errno));
    if (fd >= 0)
        close(fd);
}

/* ---- process plumbing ------------------------------------------------------------------------------------------- */

static void on_signal(int sig)
{
    if (sig == SIGHUP)
        gp_hup = 1;
    else
        gp_stop = 1;
}

void gp_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/* hostapd's -B and -P: detach from the shell that started it, and write the pid. Without --log, logs go to syslog. */
int gp_daemonize(const char *pidfile)
{
    pid_t pid = fork();
    int fd;

    if (pid < 0)
        return -1;
    if (pid > 0)
        _exit(0);
    setsid();
    if (chdir("/") != 0) {
        /* stays where it was */
    }
    fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2)
            close(fd);
    }
    if (log_fd == 2) {
        log_fd = -1;
        openlog(log_role, LOG_PID, LOG_DAEMON);
    }
    if (pidfile) {
        FILE *f = fopen(pidfile, "w");

        if (!f)
            return -1;
        fprintf(f, "%d\n", (int)getpid());
        fclose(f);
    }
    return 0;
}

int rmc_guest_main(int argc, char *argv[])
{
    if (argc > 1 && !strcmp(argv[1], "guestd")) {
        log_role = "guestd";
        return rmc_guestd_main(argc - 1, argv + 1);
    }
    if (argc > 1 && !strcmp(argv[1], "portal")) {
        log_role = "portal";
        return rmc_portal_main(argc - 1, argv + 1);
    }
    return -1;
}
