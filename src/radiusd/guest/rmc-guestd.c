// SPDX-License-Identifier: MIT
/*
 * rmc-guestd.c - "rmc-radiusd guestd": a relay in front of idm on SmartZone 3.6.2 to 7.x APs that answers guest-pass
 * checks itself while the controller is unreachable.
 *
 * authd sends each guest pass a guest types to idm's AF_UNIX datagram socket /var/run/idm; idm asks the controller
 * (PUT /portalintf through the tunnel's 127.0.0.1:9081) and replies to the sender's address. With the controller
 * down idm drops the request and authd gives up after 30 s. This role takes idm's socket name:
 *
 *   takeover   hard-links idm's socket to /var/run/idm.real, binds its own at /var/run/idm.rmc and renames that
 *              over /var/run/idm. idm keeps its socket (now reached as idm.real). When idm restarts it unlinks and
 *              rebinds /var/run/idm; the inode changes and the takeover runs again. On exit idm.real is renamed back.
 *   relay      every datagram is passed to idm.real unchanged, with any SCM_RIGHTS descriptors, from a socket bound at
 *              /var/run/idm.rmc<n>, one for each original sender, so idm's reply comes back to the right relay
 *              socket and goes on to that sender from /var/run/idm.
 *   answers    a guest-pass request (id 5) is answered here from the controller's pass list (rmc-guest.c) when the
 *              status file says the controller is disconnected, when 127.0.0.1:9081 refuses a connection, when idm
 *              is not there, or when the relayed request has no reply within RELAY_TIMEOUT_MS. A real reply that
 *              arrives later for a request already answered is dropped, and so is a repeated request (same MAC and
 *              sequence number) while the first is outstanding.
 *
 * Messages, native byte order (authd and idm run on the same CPU), 32-bit fields:
 *   request id 5, 0x2ec bytes: 0x00 module (3), 0x04 id, 0x08 authd's sequence number, 0x0c length (0x2dc), 0x10 client
 *     MAC, 0x18 WLAN id, 0x1c the pass as typed (0x11 bytes up to 5.2.2, 0x96 from 6.1.2).
 *   reply id 6, 0x964 bytes: 0x00 module, 0x04 id, 0x08 the request's sequence number, 0x0c length (0x954), 0x10 client
 *     MAC, 0x18 result code, 0x1c user status (1 enabled), 0x20 expiry (absolute unix seconds), 0x24 WLAN id,
 *     0x28 device limit (0 none, at most 10), 0x2c session seconds, 0x30 MAC count, 0x34 ten 6-byte MACs, 0x70 the
 *     pass echoed, then the voucher uuid (0x25 bytes) and guest name (0x21 bytes short, 0x4b long) at 0x81 and 0xa6
 *     (short layout) or 0x106 and 0x12b (long).
 * authd (6.1.2 0x11b38) takes a 206 only with user status 1, an expiry in the future, the pass echoed exactly, and
 * the client's MAC first in the list when the limit is 1, or anywhere in it for 2 to 10.
 *
 * Usage: rmc-radiusd guestd --passes <file> --bindings <file> --layout short|long --status run:<path>|int:<path>
 *                           [--log <file>] [-B] [-P <pidfile>]
 *   --status run:<path>  connected while the file reads RUN (3.6.2 wsgclientState)
 *   --status int:<path>  connected while the file holds a non-zero number (.cubic_status, .cia_status)
 *   A status file that cannot be read counts as connected; the other checks still apply.
 *   SIGHUP reloads the pass list (it is also reloaded when the file changes); SIGTERM or SIGINT restores idm's socket
 *   name and exits.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "rmc-guest.h"

#define IDM_PATH          "/var/run/idm"
#define REQ_LEN           0x2ec
#define REPLY_LEN         0x964
#define ID_GUEST_REQ      5
#define ID_GUEST_REPLY    6
#define OFF_MODULE        0x00
#define OFF_ID            0x04
#define OFF_SEQ           0x08
#define OFF_LEN           0x0c
#define OFF_MAC           0x10
#define REQ_WLAN          0x18
#define REQ_PASS          0x1c
#define RSP_CODE          0x18
#define RSP_STATUS        0x1c
#define RSP_EXPIRY        0x20
#define RSP_WLAN          0x24
#define RSP_MAXDEV        0x28
#define RSP_SESSION       0x2c
#define RSP_NMACS         0x30
#define RSP_MACS          0x34
#define RSP_PASS          0x70

#define RELAY_TIMEOUT_MS  3000
#define ANSWERED_KEEP_MS  60000
#define MAX_SENDERS       8
#define MAX_PENDING       64
#define MAX_BATCH         32
#define MAX_DGRAM         0x10000
#define MAX_FDS           16

struct layout { size_t pass_len, uuid_off, name_off, name_len; };
static const struct layout SHORT_LAYOUT = { 0x11, 0x81, 0xa6, 0x21 };
static const struct layout LONG_LAYOUT = { 0x96, 0x106, 0x12b, 0x4b };

struct sender {
    int fd;                        /* relay socket, bound at path; -1 when the slot is free */
    struct sockaddr_un addr;       /* the original sender */
    socklen_t alen;
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    int64_t used_ms;
};

enum { P_FREE, P_PENDING, P_ANSWERED };

struct pending {
    int state;
    uint8_t mac[6];
    uint32_t seq;
    int64_t until_ms;              /* P_PENDING: the relay deadline; P_ANSWERED: when to forget it */
    struct sockaddr_un addr;
    socklen_t alen;
    uint8_t req[REQ_LEN];
};

static struct {
    struct gp_ctx g;
    const struct layout *layout;
    int status_run;                /* 1: run:<path>, 0: int:<path> */
    const char *status_path;
    char idm[96], real[112], tmp[112], lock[112];
    int probe_port;
    int main_fd;
    ino_t main_ino;
    int taken;
    struct sender senders[MAX_SENDERS];
    struct pending pending[MAX_PENDING];
    uint8_t buf[MAX_DGRAM];
} S;

static uint32_t get32(const uint8_t *p)
{
    uint32_t v;

    memcpy(&v, p, 4);
    return v;
}

static void put32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

static int unix_addr(struct sockaddr_un *a, const char *path)
{
    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(a->sun_path))
        return -1;
    strcpy(a->sun_path, path);
    return 0;
}

/* Whether a datagram socket is bound at path: connect() needs a listener and sends nothing. */
static int unix_live(const char *path)
{
    struct sockaddr_un a;
    int s, ok;

    if (unix_addr(&a, path))
        return 0;
    s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0)
        return 0;
    ok = connect(s, (struct sockaddr *)&a, sizeof(a)) == 0;
    close(s);
    return ok;
}

static int bound_socket(const char *path)
{
    struct sockaddr_un a;
    int s;

    if (unix_addr(&a, path))
        return -1;
    s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s < 0)
        return -1;
    unlink(path);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(s);
        return -1;
    }
    return s;
}

static void drain(int fd, int k);

/* ---- the controller's reachability ------------------------------------------------------------------------------ */

static int status_connected(void)
{
    char text[32];
    int fd = open(S.status_path, O_RDONLY | O_CLOEXEC);
    ssize_t n = fd >= 0 ? read(fd, text, sizeof(text) - 1) : -1;
    char *p, *end;
    long v;

    if (fd >= 0)
        close(fd);
    if (n < 0)
        return 1;
    text[n] = 0;
    for (p = text; *p == ' ' || *p == '\t'; p++)
        ;
    for (end = p + strlen(p); end > p && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' '); end--)
        ;
    *end = 0;
    if (S.status_run)
        return !strcmp(p, "RUN");
    v = strtol(p, &end, 10);
    return end == p ? 1 : v != 0;
}

/* Whether the tunnel's portal-interface port refuses a connection (the controller is not reachable through it). */
static int portal_refuses(void)
{
    struct sockaddr_in a;
    struct pollfd pfd;
    int s, err = 0;
    socklen_t elen = sizeof(err);

    s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s < 0)
        return 0;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)S.probe_port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
        close(s);
        return 0;
    }
    if (errno == EINPROGRESS) {
        pfd.fd = s;
        pfd.events = POLLOUT;
        if (poll(&pfd, 1, 200) == 1 && getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) == 0)
            errno = err;
        else
            errno = 0;
    }
    err = errno;
    close(s);
    return err == ECONNREFUSED;
}

/* ---- takeover ----------------------------------------------------------------------------------------------------- */

static void take_over(void)
{
    struct stat st, mine;
    int s;

    if (stat(S.idm, &st) != 0 || !S_ISSOCK(st.st_mode) || (S.taken && st.st_ino == S.main_ino))
        return;
    if (!unix_live(S.idm))
        return;
    unlink(S.real);
    if (link(S.idm, S.real) != 0) {
        gp_log("cannot link %s to %s: %s", S.idm, S.real, strerror(errno));
        return;
    }
    s = bound_socket(S.tmp);
    if (s < 0) {
        gp_log("cannot bind %s: %s", S.tmp, strerror(errno));
        unlink(S.real);
        return;
    }
    if (chmod(S.tmp, st.st_mode & 0777) != 0 || chown(S.tmp, st.st_uid, st.st_gid) != 0) {
        /* idm's own mode is what authd needs; root can send to it either way */
    }
    if (rename(S.tmp, S.idm) != 0 || stat(S.idm, &mine) != 0) {
        gp_log("cannot rename %s over %s: %s", S.tmp, S.idm, strerror(errno));
        close(s);
        unlink(S.tmp);
        unlink(S.real);
        return;
    }
    if (S.main_fd >= 0) {
        drain(S.main_fd, -1);
        close(S.main_fd);
    }
    S.main_fd = s;
    S.main_ino = mine.st_ino;
    gp_log("%s %s (idm is at %s)", S.taken ? "took over again" : "took over", S.idm, S.real);
    S.taken = 1;
}

/* At start: a relay that died without restoring idm's name leaves its dead socket at /var/run/idm and idm at idm.real. */
static void recover(void)
{
    struct stat a, b;

    if (lstat(S.real, &b) != 0)
        return;
    if (!unix_live(S.idm) && unix_live(S.real)) {
        if (rename(S.real, S.idm) == 0)
            gp_log("gave %s back to idm from an earlier run", S.idm);
    } else if (stat(S.idm, &a) != 0 || a.st_ino != b.st_ino) {
        unlink(S.real);
    }
}

static void restore(void)
{
    struct stat st, real;
    int i;

    if (S.taken && stat(S.idm, &st) == 0 && st.st_ino == S.main_ino && stat(S.real, &real) == 0) {
        if (rename(S.real, S.idm) == 0)
            gp_log("gave %s back to idm", S.idm);
        else
            gp_log("cannot rename %s back to %s: %s", S.real, S.idm, strerror(errno));
    } else {
        unlink(S.real);
    }
    if (S.main_fd >= 0)
        close(S.main_fd);
    for (i = 0; i < MAX_SENDERS; i++) {
        if (S.senders[i].fd >= 0) {
            close(S.senders[i].fd);
            unlink(S.senders[i].path);
        }
    }
    unlink(S.tmp);
}

/* ---- relaying ---------------------------------------------------------------------------------------------------- */

static int same_addr(const struct sockaddr_un *a, socklen_t alen, const struct sockaddr_un *b, socklen_t blen)
{
    return alen == blen && !memcmp(a, b, alen);
}

static int sender_for(const struct sockaddr_un *addr, socklen_t alen)
{
    int i, free_slot = -1, oldest = 0;
    struct sender *s;

    for (i = 0; i < MAX_SENDERS; i++) {
        s = &S.senders[i];
        if (s->fd >= 0 && same_addr(&s->addr, s->alen, addr, alen)) {
            s->used_ms = gp_mono_ms();
            return i;
        }
        if (s->fd < 0 && free_slot < 0)
            free_slot = i;
        if (s->fd >= 0 && s->used_ms < S.senders[oldest].used_ms)
            oldest = i;
    }
    i = free_slot >= 0 ? free_slot : oldest;
    s = &S.senders[i];
    if (s->fd >= 0)
        close(s->fd);
    snprintf(s->path, sizeof(s->path), "%s.rmc%d", S.idm, i);
    s->fd = bound_socket(s->path);
    if (s->fd < 0) {
        gp_log("cannot bind %s: %s", s->path, strerror(errno));
        return -1;
    }
    s->addr = *addr;
    s->alen = alen;
    s->used_ms = gp_mono_ms();
    return i;
}

static void close_fds(struct msghdr *m)
{
    struct cmsghdr *c;

    for (c = CMSG_FIRSTHDR(m); c; c = CMSG_NXTHDR(m, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            int *fds = (int *)CMSG_DATA(c);
            size_t i, n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);

            for (i = 0; i < n; i++)
                close(fds[i]);
        }
    }
}

/* Sends buf (with m's control data, if any) from socket fd to addr. */
static int send_to(int fd, const void *buf, size_t len, const struct sockaddr_un *addr, socklen_t alen,
                   struct msghdr *m)
{
    struct iovec iov = { (void *)buf, len };
    struct msghdr out;

    memset(&out, 0, sizeof(out));
    out.msg_name = (void *)addr;
    out.msg_namelen = alen;
    out.msg_iov = &iov;
    out.msg_iovlen = 1;
    if (m && m->msg_controllen) {
        out.msg_control = m->msg_control;
        out.msg_controllen = m->msg_controllen;
    }
    return sendmsg(fd, &out, MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
}

static int forward_to_idm(const uint8_t *buf, size_t len, const struct sockaddr_un *from, socklen_t flen,
                          struct msghdr *m)
{
    struct sockaddr_un real;
    int k;

    if (!S.taken || unix_addr(&real, S.real))
        return -1;
    k = sender_for(from, flen);
    if (k < 0)
        return -1;
    if (send_to(S.senders[k].fd, buf, len, &real, sizeof(real), m) != 0) {
        if (errno == ECONNREFUSED || errno == ENOENT)
            gp_log("idm is not answering at %s", S.real);
        else
            gp_log("cannot pass a message to idm: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static struct pending *find_pending(const uint8_t mac[6], uint32_t seq)
{
    int i;

    for (i = 0; i < MAX_PENDING; i++)
        if (S.pending[i].state != P_FREE && S.pending[i].seq == seq && !memcmp(S.pending[i].mac, mac, 6))
            return &S.pending[i];
    return NULL;
}

static struct pending *new_pending(void)
{
    int i, oldest = 0;

    for (i = 0; i < MAX_PENDING; i++) {
        if (S.pending[i].state == P_FREE)
            return &S.pending[i];
        if (S.pending[i].state == P_ANSWERED
            && (S.pending[oldest].state != P_ANSWERED || S.pending[i].until_ms < S.pending[oldest].until_ms))
            oldest = i;
    }
    return S.pending[oldest].state == P_ANSWERED ? &S.pending[oldest] : NULL;
}

/* ---- local answers ----------------------------------------------------------------------------------------------- */

static void answer(const uint8_t *req, const struct sockaddr_un *to, socklen_t tlen, const char *why)
{
    static uint8_t r[REPLY_LEN];
    const struct layout *L = S.layout;
    const uint8_t *mac = req + OFF_MAC;
    struct gp_decision d;
    char m[18];
    size_t typed = strnlen((const char *)req + REQ_PASS, L->pass_len);
    int64_t now;

    gp_reload(&S.g, 0);
    gp_check(&S.g, (const char *)req + REQ_PASS, typed, mac, &d);
    now = gp_now();
    memset(r, 0, sizeof(r));
    put32(r + OFF_MODULE, get32(req + OFF_MODULE));
    put32(r + OFF_ID, ID_GUEST_REPLY);
    put32(r + OFF_SEQ, get32(req + OFF_SEQ));
    put32(r + OFF_LEN, REPLY_LEN - 0x10);
    memcpy(r + OFF_MAC, mac, 6);
    put32(r + RSP_CODE, (uint32_t)d.code);
    put32(r + RSP_WLAN, get32(req + REQ_WLAN));
    if (d.code == GP_OK) {
        struct gp_pass *p = d.pass;
        uint32_t n = 1;
        int i;
        const char *name = p->name[0] ? p->name : "Guest";

        put32(r + RSP_STATUS, 1);
        put32(r + RSP_EXPIRY, (uint32_t)d.expiry);
        put32(r + RSP_MAXDEV, p->max_devices <= GP_MAX_MACS ? p->max_devices : 0);
        put32(r + RSP_SESSION, (uint32_t)(d.expiry > now ? d.expiry - now : 0));
        memcpy(r + RSP_MACS, mac, 6);
        for (i = 0; i < p->nmacs && n < GP_MAX_MACS; i++)
            if (memcmp(p->macs[i], mac, 6))
                memcpy(r + RSP_MACS + 6 * n++, p->macs[i], 6);
        put32(r + RSP_NMACS, n);
        memcpy(r + RSP_PASS, req + REQ_PASS, L->pass_len);
        memcpy(r + L->uuid_off, p->uuid, 36);
        memcpy(r + L->name_off, name, strnlen(name, L->name_len - 1));
    }
    gp_format_mac(mac, m);
    if (send_to(S.main_fd, r, sizeof(r), to, tlen, NULL) != 0) {
        gp_log("cannot answer %s: %s", m, strerror(errno));
        return;
    }
    gp_commit(&S.g, mac, &d);
    gp_log("answered %s seq %u with %d (%s)%s%s%s", m, (unsigned)get32(req + OFF_SEQ), d.code, why,
           d.pass ? " pass " : "", d.pass ? d.pass->uuid : "",
           d.bind == GP_BIND_FIRST ? " first use" : d.bind == GP_BIND_DEVICE ? " new device" : "");
}

/* ---- the event loop ---------------------------------------------------------------------------------------------- */

static void from_client(size_t len, struct sockaddr_un *from, socklen_t flen, struct msghdr *m)
{
    const uint8_t *b = S.buf;
    const char *why = NULL;
    struct pending *p;

    if (len >= REQ_PASS + S.layout->pass_len && get32(b + OFF_ID) == ID_GUEST_REQ
        && flen > offsetof(struct sockaddr_un, sun_path)) {
        uint32_t seq = get32(b + OFF_SEQ);

        if (find_pending(b + OFF_MAC, seq)) {
            close_fds(m);
            return;
        }
        if (!S.taken)
            why = "idm is not up";
        else if (!status_connected())
            why = "controller disconnected";
        else if (portal_refuses())
            why = "9081 refused";
        else if (forward_to_idm(b, len, from, flen, m) != 0)
            why = "idm unreachable";
        close_fds(m);
        p = new_pending();
        if (why) {
            uint8_t req[REQ_LEN];

            memset(req, 0, sizeof(req));
            memcpy(req, b, len < REQ_LEN ? len : REQ_LEN);
            answer(req, from, flen, why);
            if (p) {
                p->state = P_ANSWERED;
                memcpy(p->mac, b + OFF_MAC, 6);
                p->seq = seq;
                p->until_ms = gp_mono_ms() + ANSWERED_KEEP_MS;
            }
            return;
        }
        if (!p) {
            gp_log("too many guest passes waiting for idm; this one waits for idm alone");
            return;
        }
        p->state = P_PENDING;
        memcpy(p->mac, b + OFF_MAC, 6);
        p->seq = seq;
        p->until_ms = gp_mono_ms() + RELAY_TIMEOUT_MS;
        p->addr = *from;
        p->alen = flen;
        memset(p->req, 0, sizeof(p->req));
        memcpy(p->req, b, len < REQ_LEN ? len : REQ_LEN);
        return;
    }
    forward_to_idm(b, len, from, flen, m);
    close_fds(m);
}

static void from_idm(int k, size_t len, struct msghdr *m)
{
    struct sender *s = &S.senders[k];
    struct pending *p;

    if (len >= RSP_CODE && get32(S.buf + OFF_ID) == ID_GUEST_REPLY
        && (p = find_pending(S.buf + OFF_MAC, get32(S.buf + OFF_SEQ)))) {
        if (p->state == P_ANSWERED) {
            close_fds(m);
            return;
        }
        p->state = P_FREE;
    }
    if (s->alen > offsetof(struct sockaddr_un, sun_path) && S.main_fd >= 0
        && send_to(S.main_fd, S.buf, len, &s->addr, s->alen, m) != 0)
        gp_log("cannot pass idm's reply on: %s", strerror(errno));
    close_fds(m);
}

/* Reads up to MAX_BATCH datagrams from fd; k is the sender slot for a relay socket, -1 for the main socket. */
static void drain(int fd, int k)
{
    union { struct cmsghdr align; char buf[CMSG_SPACE(MAX_FDS * sizeof(int))]; } ctl;
    struct sockaddr_un from;
    struct iovec iov;
    struct msghdr m;
    ssize_t n;
    int i;

    for (i = 0; i < MAX_BATCH; i++) {
        memset(&m, 0, sizeof(m));
        memset(&from, 0, sizeof(from));
        iov.iov_base = S.buf;
        iov.iov_len = sizeof(S.buf);
        m.msg_name = &from;
        m.msg_namelen = sizeof(from);
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = ctl.buf;
        m.msg_controllen = sizeof(ctl.buf);
        n = recvmsg(fd, &m, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (n < 0)
            return;
        if (m.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
            gp_log("dropped a truncated message");
            close_fds(&m);
            continue;
        }
        if (k < 0)
            from_client((size_t)n, &from, m.msg_namelen, &m);
        else
            from_idm(k, (size_t)n, &m);
    }
}

static void expire_pending(void)
{
    int64_t now = gp_mono_ms();
    int i;

    for (i = 0; i < MAX_PENDING; i++) {
        struct pending *p = &S.pending[i];

        if (p->state == P_PENDING && now >= p->until_ms) {
            answer(p->req, &p->addr, p->alen, "no reply from idm");
            p->state = P_ANSWERED;
            p->until_ms = now + ANSWERED_KEEP_MS;
        } else if (p->state == P_ANSWERED && now >= p->until_ms) {
            p->state = P_FREE;
        }
    }
}

static void usage(void)
{
    fprintf(stderr, "usage: rmc-radiusd guestd --passes <file> --bindings <file> --layout short|long"
                    " --status run:<path>|int:<path> [--log <file>] [-B] [-P <pidfile>]\n");
}

int rmc_guestd_main(int argc, char *argv[])
{
    const char *passes = NULL, *bindings = NULL, *layout = NULL, *status = NULL, *log = NULL, *pidfile = NULL;
    const char *env;
    struct pollfd pfd[1 + MAX_SENDERS];
    int map[1 + MAX_SENDERS];
    int i, daemon = 0, lock_fd;
    int64_t next_tick = 0;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;

        if (!strcmp(a, "-B")) { daemon = 1; continue; }
        if (!v) { usage(); return 2; }
        if (!strcmp(a, "--passes")) passes = v;
        else if (!strcmp(a, "--bindings")) bindings = v;
        else if (!strcmp(a, "--layout")) layout = v;
        else if (!strcmp(a, "--status")) status = v;
        else if (!strcmp(a, "--log")) log = v;
        else if (!strcmp(a, "-P")) pidfile = v;
        else { usage(); return 2; }
        i++;
    }
    if (!passes || !bindings || !layout || !status) {
        usage();
        return 2;
    }
    if (!strcmp(layout, "short"))
        S.layout = &SHORT_LAYOUT;
    else if (!strcmp(layout, "long"))
        S.layout = &LONG_LAYOUT;
    else {
        usage();
        return 2;
    }
    if (!strncmp(status, "run:", 4))
        S.status_run = 1;
    else if (strncmp(status, "int:", 4)) {
        usage();
        return 2;
    }
    S.status_path = status + 4;

    /* Tests run against a stand-in idm elsewhere and a stand-in 9081. */
    env = getenv("RMC_GUESTD_IDM");
    snprintf(S.idm, sizeof(S.idm), "%s", env && *env ? env : IDM_PATH);
    env = getenv("RMC_GUESTD_PROBE_PORT");
    S.probe_port = env && *env ? atoi(env) : 9081;
    snprintf(S.real, sizeof(S.real), "%s.real", S.idm);
    snprintf(S.tmp, sizeof(S.tmp), "%s.rmc", S.idm);
    snprintf(S.lock, sizeof(S.lock), "%s.rmc.lock", S.idm);
    S.main_fd = -1;
    for (i = 0; i < MAX_SENDERS; i++)
        S.senders[i].fd = -1;

    if (log && gp_log_open(log) != 0) {
        fprintf(stderr, "cannot open %s\n", log);
        return 1;
    }
    lock_fd = open(S.lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        gp_log("another relay holds %s", S.lock);
        return 1;
    }
    if (daemon && gp_daemonize(pidfile) != 0) {
        gp_log("cannot detach or write %s", pidfile ? pidfile : "the pid file");
        return 1;
    }
    gp_signals();
    gp_init(&S.g, passes, bindings);
    gp_reload(&S.g, 1);
    recover();
    gp_log("started (%s layout, status %s)", layout, status);

    while (!gp_stop) {
        int64_t now = gp_mono_ms();
        int n = 0, timeout = 250;

        if (now >= next_tick) {
            take_over();
            gp_reload(&S.g, gp_hup);
            gp_hup = 0;
            next_tick = now + 1000;
        }
        if (S.main_fd >= 0) {
            pfd[n].fd = S.main_fd;
            pfd[n].events = POLLIN;
            map[n++] = -1;
        }
        for (i = 0; i < MAX_SENDERS; i++) {
            if (S.senders[i].fd >= 0) {
                pfd[n].fd = S.senders[i].fd;
                pfd[n].events = POLLIN;
                map[n++] = i;
            }
        }
        if (poll(pfd, (nfds_t)n, timeout) > 0) {
            for (i = 0; i < n; i++)
                if (pfd[i].revents & POLLIN)
                    drain(pfd[i].fd, map[i]);
        }
        expire_pending();
    }
    restore();
    unlink(S.lock);
    close(lock_fd);
    gp_log("stopped");
    return 0;
}
