// SPDX-License-Identifier: MIT
/*
 * rmc-guest.h - what the guest-pass roles of rmc-radiusd share: the controller's pass list, the bindings file, the
 * checks the controller applies to a typed pass, logging and the process plumbing. See rmc-guest.c.
 */
#ifndef RMC_GUEST_H
#define RMC_GUEST_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/* Highest device limit authd accepts in a reply (more is its error 0x67), and the MACs a reply carries. */
#define GP_MAX_MACS 10

/* Result codes, as the controller answers them and authd maps them (guest-portal.md 2.4). */
#define GP_OK       206
#define GP_INVALID  480
#define GP_DEVICES  485
#define GP_EXPIRED  490
#define GP_REVOKED  495
#define GP_BUSY     401

struct gp_pass {
    uint8_t hash[32];
    char uuid[37];
    uint8_t usable;
    uint8_t nmacs;
    uint8_t max_devices;           /* 0: no limit */
    int64_t redeem_by;             /* -1: none */
    int64_t first_used;            /* -1: unused */
    int64_t duration;
    uint8_t macs[GP_MAX_MACS][6];
    char name[76];                 /* decoded; "" for none */
};

struct gp_list {
    int loaded;                    /* a header was read */
    int64_t generated;
    uint8_t salt[16];
    struct gp_pass *passes;
    size_t count;
};

/* The outcome of one check: what to answer and, for GP_OK, what to record once the answer is out. */
enum gp_bind { GP_BIND_NONE, GP_BIND_FIRST, GP_BIND_DEVICE };

struct gp_decision {
    int code;
    struct gp_pass *pass;          /* the matched pass, or NULL */
    enum gp_bind bind;
    int64_t expiry;                /* absolute, for GP_OK */
};

struct gp_ctx {
    const char *passes_path;
    const char *bindings_path;
    struct gp_list list;
    time_t passes_mtime;
    off_t passes_size;
    ino_t passes_ino;
    /* brute-force state, see gp_check */
    struct { uint8_t mac[6]; uint8_t used; int64_t start; int count; } attempts[256];
    int64_t bucket_milli;
    int64_t bucket_at_ms;
};

/* common */
void gp_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int gp_log_open(const char *path);
int64_t gp_now(void);
int64_t gp_mono_ms(void);
int gp_parse_mac(const char *s, uint8_t mac[6]);
void gp_format_mac(const uint8_t mac[6], char out[18]);
int gp_normalize_code(const char *typed, size_t len, char out[11]);
void gp_sha256(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, uint8_t out[32]);
void gp_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *data, size_t len, uint8_t out[32]);
void gp_random(uint8_t *buf, size_t len);

void gp_init(struct gp_ctx *g, const char *passes, const char *bindings);
/* Reloads the pass list when asked to (force) or when the file changed; re-applies the bindings file. */
void gp_reload(struct gp_ctx *g, int force);
/* Checks a typed pass for a device; counts the attempt against the brute-force limits. */
void gp_check(struct gp_ctx *g, const char *typed, size_t typed_len, const uint8_t mac[6], struct gp_decision *d);
/* Records an accepted pass: updates the in-memory copy and appends to the bindings file. */
void gp_commit(struct gp_ctx *g, const uint8_t mac[6], const struct gp_decision *d);

/* process plumbing */
extern volatile int gp_stop, gp_hup;
void gp_signals(void);
int gp_daemonize(const char *pidfile);

int rmc_guestd_main(int argc, char *argv[]);
int rmc_portal_main(int argc, char *argv[]);
int rmc_guest_main(int argc, char *argv[]);

#endif
