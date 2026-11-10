// SPDX-License-Identifier: MIT
/*
 * rmc-filter - see rmc-filter.h. A 3-wise binary fuse filter whose 32-bit little-endian entries hold a 27-bit
 * fingerprint and a 5-bit category mask; a name's three entries XOR to its fingerprint and mask.
 *
 * The build streams: names are hashed as they are read and written to 16 bucket files by hash, each bucket is sorted
 * and merged on its own (a name on two lists gets both bits), the peeling order goes to a file and is read back in
 * reverse. Only the per-entry arrays stay in memory: a count, the XOR of hashes and of masks, and the peel queue.
 */
#include "rmc-filter.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define FP_BITS     27
#define FP_MASK     ((1u << FP_BITS) - 1)
#define MASK_BITS   5
#define ATTEMPTS    64
#define BUCKETS     16
#define NAME_REC    9           /* u64 name hash, u8 mask */
#define PEEL_REC    13          /* u64 hash, u32 entry, u8 mask */
#define LINE_MAX_   4096

static uint32_t rd32(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t rd64(const unsigned char *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }
static void wr32(unsigned char *p, uint32_t v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24); }
static void wr64(unsigned char *p, uint64_t v) { wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }

static uint64_t name_hash(const char *s, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 0x100000001b3ULL; }
    return h;
}

static uint64_t mix(uint64_t name, uint64_t seed)
{
    uint64_t k = name + seed;
    k ^= k >> 33; k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

static uint64_t seed_of(int attempt) { return 0x9e3779b97f4a7c15ULL * (uint64_t)(attempt + 1); }
static uint32_t fingerprint(uint64_t h) { return (uint32_t)(h ^ (h >> 32)) & FP_MASK; }

static void positions(uint64_t h, uint32_t seg_len, uint32_t seg_count_len, uint32_t p[3])
{
    uint32_t mask = seg_len - 1;
    p[0] = (uint32_t)(((h >> 32) * (uint64_t)seg_count_len) >> 32);
    p[1] = (p[0] + seg_len) ^ ((uint32_t)(h >> 18) & mask);
    p[2] = (p[0] + 2 * seg_len) ^ ((uint32_t)h & mask);
}

/* ContentFilterFile.Layout: integer only, so the controller and the AP agree. */
static void layout(uint32_t names, int attempt, uint32_t *seg_len, uint32_t *seg_count_len, uint32_t *length)
{
    uint32_t n = names < 2 ? 2 : names;
    int log2 = 31 - __builtin_clz(n);
    if (log2 < 1) log2 = 1;
    int exponent = log2 * 10 / 17 + 2;
    if (exponent < 4) exponent = 4;
    if (exponent > 18) exponent = 18;
    uint32_t sl = 1u << exponent;
    int64_t factor = 875 + 4983 / log2;
    if (factor < 1125) factor = 1125;
    int64_t capacity = (int64_t)names * factor / 1000;
    capacity += capacity * (attempt / 8) / 10;
    int64_t segments = (capacity + sl - 1) / sl - 2;
    if (segments < 1) segments = 1;
    *seg_len = sl;
    *seg_count_len = (uint32_t)(segments * sl);
    *length = (uint32_t)((segments + 2) * sl);
}

/* ---- reading ---------------------------------------------------------------------------------------------------- */

int rmc_filter_parse(const unsigned char *b, size_t n, struct rmc_filter *f)
{
    memset(f, 0, sizeof *f);
    if (n < RMC_FILTER_HEADER || memcmp(b, "RMCF", 4) != 0 || rd32(b + 4) != RMC_FILTER_VERSION) return -1;
    f->base = b;
    f->size = n;
    f->seed = rd64(b + 8);
    f->seg_len = rd32(b + 16);
    f->seg_count_len = rd32(b + 20);
    f->length = rd32(b + 24);
    f->names = rd32(b + 28);
    f->built_at = (int64_t)rd64(b + 32);
    memcpy(f->web_id, b + 40, RMC_FILTER_CATS);
    f->origin = b[45];
    f->content_id = rd64(b + 48);
    f->sources_len = rd32(b + 56);
    f->ca_len = rd32(b + 60);
    if (f->seg_len == 0 || (f->seg_len & (f->seg_len - 1)) != 0 || f->length > (1u << 28)) return -1;
    if ((uint64_t)f->seg_count_len + 2ULL * f->seg_len > f->length) return -1;
    if ((uint64_t)RMC_FILTER_HEADER + 4ULL * f->length + f->sources_len + f->ca_len != n) return -1;
    f->sources = (const char *)b + RMC_FILTER_HEADER + 4 * (size_t)f->length;
    f->ca = f->sources + f->sources_len;
    return 0;
}

int rmc_filter_open(struct rmc_filter *f, const char *path)
{
    memset(f, 0, sizeof *f);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < RMC_FILTER_HEADER) { close(fd); return -1; }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return -1;
    if (rmc_filter_parse(m, (size_t)st.st_size, f) != 0) { munmap(m, (size_t)st.st_size); memset(f, 0, sizeof *f); return -1; }
    return 0;
}

void rmc_filter_close(struct rmc_filter *f)
{
    if (f->base) munmap((void *)f->base, f->size);
    memset(f, 0, sizeof *f);
}

static unsigned probe(const struct rmc_filter *f, const char *name, size_t len)
{
    uint64_t h = mix(name_hash(name, len), f->seed);
    uint32_t p[3];
    positions(h, f->seg_len, f->seg_count_len, p);
    const unsigned char *e = f->base + RMC_FILTER_HEADER;
    uint32_t v = rd32(e + 4 * (size_t)p[0]) ^ rd32(e + 4 * (size_t)p[1]) ^ rd32(e + 4 * (size_t)p[2]);
    return v >> MASK_BITS == fingerprint(h) ? (v & ((1u << MASK_BITS) - 1)) : 0;
}

unsigned rmc_filter_lookup(const struct rmc_filter *f, const char *host)
{
    if (!f->base || f->length == 0) return 0;
    size_t len = strlen(host);
    if (len == 0 || len > RMC_HOST_MAX) return 0;
    for (size_t i = 0; i < len; i++) if ((unsigned char)host[i] >= 0x80) return 0;
    unsigned m = probe(f, host, len);
    if (!m && strncmp(host, "www.", 4) != 0) {
        char www[RMC_HOST_MAX + 5];
        memcpy(www, "www.", 4);
        memcpy(www + 4, host, len);
        m = probe(f, www, len + 4);
    }
    const char *rest = host;
    while (!m) {
        const char *dot = strchr(rest, '.');
        if (!dot || !strchr(dot + 1, '.')) break;
        rest = dot + 1;
        m = probe(f, rest, strlen(rest));
    }
    return m;
}

/* ---- list parsing (ContentListService.Parse) -------------------------------------------------------------------- */

static int is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'; }

static int ends_with(const char *s, size_t n, const char *suffix)
{
    size_t m = strlen(suffix);
    return n >= m && memcmp(s + n - m, suffix, m) == 0;
}

static int is_local(const char *s, size_t n)
{
    static const char *const names[] = { "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "0.0.0.0" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (strlen(names[i]) == n && memcmp(s, names[i], n) == 0) return 1;
    return ends_with(s, n, ".localdomain");
}

/* ContentListService.TryNormalizeHost, then the filter's ASCII-only rule. */
static int normalize(const char *s, size_t n, char *out)
{
    while (n && is_space(*s)) { s++; n--; }
    while (n && is_space(s[n - 1])) n--;
    for (size_t i = 0; i + 2 < n; i++)
        if (s[i] == ':' && s[i + 1] == '/' && s[i + 2] == '/') { s += i + 3; n -= i + 3; break; }
    for (size_t i = 0; i < n; i++)
        if (s[i] == '/' || s[i] == '?' || s[i] == '#') { n = i; break; }
    const char *first = memchr(s, ':', n);
    if (first) {
        const char *last = first;
        for (const char *p = first + 1; p < s + n; p++) if (*p == ':') last = p;
        if (last == first) n = (size_t)(first - s);
    }
    while (n && s[n - 1] == '.') n--;
    if (n == 0 || n > RMC_HOST_MAX || !memchr(s, '.', n)) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x80) return -1;
        out[i] = (char)(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    }
    out[n] = 0;
    return is_local(out, n) ? -1 : (int)n;
}

int rmc_list_line(const char *line, size_t len, char *out)
{
    const char *hash = memchr(line, '#', len);
    if (hash) len = (size_t)(hash - line);
    while (len && is_space(*line)) { line++; len--; }
    while (len && is_space(line[len - 1])) len--;
    if (!len) return -1;
    size_t space = 0;
    while (space < len && line[space] != ' ' && line[space] != '\t') space++;
    if (space == len) return normalize(line, len, out);   /* a domains-only list */
    if (!((space == 7 && memcmp(line, "0.0.0.0", 7) == 0) || (space == 9 && memcmp(line, "127.0.0.1", 9) == 0))) return -1;
    const char *name = line + space;
    size_t rest = len - space;
    while (rest && is_space(*name)) { name++; rest--; }
    size_t end = 0;
    while (end < rest && name[end] != ' ' && name[end] != '\t') end++;
    return normalize(name, end, out);
}

/* ---- building --------------------------------------------------------------------------------------------------- */

static void fail(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static void bucket_path(char *out, size_t n, const char *dir, char kind, int i) { snprintf(out, n, "%s/%c%02d", dir, kind, i); }

/* Characters a list URL may hold; it is passed to curl inside single quotes. */
static int url_ok(const char *u)
{
    if (strncmp(u, "https://", 8) != 0 && strncmp(u, "http://", 7) != 0) return 0;
    for (; *u; u++)
        if (!((*u >= 'a' && *u <= 'z') || (*u >= 'A' && *u <= 'Z') || (*u >= '0' && *u <= '9') || strchr(":/._~%?=&+-", *u))) return 0;
    return 1;
}

/* Reads one list and appends its names to the bucket files; the number of names, or -1. cafile: curl's roots, or NULL. */
static long read_list(const char *url, const char *cafile, unsigned bit, FILE *buckets[BUCKETS], char *err, size_t errlen)
{
    FILE *in;
    int piped = url[0] != '/';
    if (piped) {
        if (!url_ok(url)) { fail(err, errlen, "unusable list URL %s", url); return -1; }
        char cmd[1024];
        snprintf(cmd, sizeof cmd, "curl -sfL --max-time 600 --retry 2 %s%s%s'%s'", cafile ? "--cacert '" : "", cafile ? cafile : "",
                 cafile ? "' " : "", url);
        in = popen(cmd, "r");
    } else {
        in = fopen(url, "rb");
    }
    if (!in) { fail(err, errlen, "cannot read %s: %s", url, strerror(errno)); return -1; }

    static char buf[65536];
    static char line[LINE_MAX_];
    size_t line_len = 0;
    long names = 0;
    char name[RMC_HOST_MAX + 1];
    size_t got;
    int eof = 0;
    while (!eof) {
        got = fread(buf, 1, sizeof buf, in);
        if (got == 0) eof = 1;
        for (size_t i = 0; i <= got; i++) {
            int end_of_line = i == got ? eof : (buf[i] == '\n' || buf[i] == '\r' || buf[i] == '\f');
            if (i < got && !end_of_line) {
                if (line_len < sizeof line) line[line_len++] = buf[i];
                continue;
            }
            if (!end_of_line) break;
            int n = rmc_list_line(line, line_len, name);
            line_len = 0;
            if (n < 0) continue;
            uint64_t h = name_hash(name, (size_t)n);
            unsigned char rec[NAME_REC];
            wr64(rec, h);
            rec[8] = (unsigned char)(1u << bit);
            if (fwrite(rec, 1, NAME_REC, buckets[h >> 60]) != NAME_REC) { fail(err, errlen, "writing a bucket: %s", strerror(errno)); piped ? pclose(in) : fclose(in); return -1; }
            names++;
        }
    }
    int bad = ferror(in);
    int status = piped ? pclose(in) : fclose(in);
    if (bad || status != 0) { fail(err, errlen, "%s: download failed (status %d)", url, status); return -1; }
    if (names == 0) { fail(err, errlen, "%s: no host names", url); return -1; }
    return names;
}

struct name_rec { uint64_t h; unsigned char m; };

static int by_hash(const void *a, const void *b)
{
    uint64_t x = ((const struct name_rec *)a)->h, y = ((const struct name_rec *)b)->h;
    return x < y ? -1 : x > y;
}

/* Sorts each bucket and merges repeated names; the number of distinct names, or -1. */
static long dedupe(const char *dir, char *err, size_t errlen)
{
    long total = 0;
    char in_path[512], out_path[512];
    for (int b = 0; b < BUCKETS; b++) {
        bucket_path(in_path, sizeof in_path, dir, 'b', b);
        bucket_path(out_path, sizeof out_path, dir, 'u', b);
        FILE *in = fopen(in_path, "rb");
        if (!in) { fail(err, errlen, "%s: %s", in_path, strerror(errno)); return -1; }
        fseek(in, 0, SEEK_END);
        long bytes = ftell(in);
        fseek(in, 0, SEEK_SET);
        size_t count = (size_t)bytes / NAME_REC;
        struct name_rec *recs = count ? malloc(count * sizeof *recs) : NULL;
        if (count && !recs) { fclose(in); fail(err, errlen, "out of memory sorting %zu names", count); return -1; }
        unsigned char rec[NAME_REC];
        for (size_t i = 0; i < count && fread(rec, 1, NAME_REC, in) == NAME_REC; i++) { recs[i].h = rd64(rec); recs[i].m = rec[8]; }
        fclose(in);
        unlink(in_path);
        qsort(recs, count, sizeof *recs, by_hash);
        FILE *out = fopen(out_path, "wb");
        if (!out) { free(recs); fail(err, errlen, "%s: %s", out_path, strerror(errno)); return -1; }
        for (size_t i = 0; i < count;) {
            size_t j = i + 1;
            unsigned char m = recs[i].m;
            while (j < count && recs[j].h == recs[i].h) m |= recs[j++].m;
            wr64(rec, recs[i].h);
            rec[8] = m;
            fwrite(rec, 1, NAME_REC, out);
            total++;
            i = j;
        }
        free(recs);
        if (fclose(out) != 0) { fail(err, errlen, "%s: %s", out_path, strerror(errno)); return -1; }
    }
    return total;
}

/* One attempt at a seed: peels into the peel file. 1 when every name peeled, 0 to try the next seed, -1 on error. */
static int peel(const char *dir, uint32_t names, uint64_t seed, uint32_t seg_len, uint32_t seg_count_len, uint32_t length,
                const char *peel_path, char *err, size_t errlen)
{
    uint8_t *count = calloc(length, 1), *mask_xor = calloc(length, 1);
    uint64_t *hash_xor = calloc(length, sizeof *hash_xor);
    uint32_t *queue = malloc((size_t)length * sizeof *queue);
    FILE *out = NULL;
    int result = -1;
    if (!count || !mask_xor || !hash_xor || !queue) { fail(err, errlen, "out of memory for %u entries", length); goto done; }

    char path[512];
    unsigned char rec[PEEL_REC];
    for (int b = 0; b < BUCKETS; b++) {
        bucket_path(path, sizeof path, dir, 'u', b);
        FILE *in = fopen(path, "rb");
        if (!in) { fail(err, errlen, "%s: %s", path, strerror(errno)); goto done; }
        while (fread(rec, 1, NAME_REC, in) == NAME_REC) {
            uint64_t h = mix(rd64(rec), seed);
            uint32_t p[3];
            positions(h, seg_len, seg_count_len, p);
            for (int k = 0; k < 3; k++) {
                if (count[p[k]] == 255) { fclose(in); result = 0; goto done; }
                count[p[k]]++;
                hash_xor[p[k]] ^= h;
                mask_xor[p[k]] ^= rec[8];
            }
        }
        fclose(in);
    }

    out = fopen(peel_path, "wb");
    if (!out) { fail(err, errlen, "%s: %s", peel_path, strerror(errno)); goto done; }
    uint32_t queued = 0, peeled = 0;
    for (uint32_t i = 0; i < length; i++) if (count[i] == 1) queue[queued++] = i;
    while (queued > 0) {
        uint32_t s = queue[--queued];
        if (count[s] != 1) continue;
        uint64_t h = hash_xor[s];
        uint8_t m = mask_xor[s];
        wr64(rec, h);
        wr32(rec + 8, s);
        rec[12] = m;
        if (fwrite(rec, 1, PEEL_REC, out) != PEEL_REC) { fail(err, errlen, "writing the peel order: %s", strerror(errno)); goto done; }
        peeled++;
        uint32_t p[3];
        positions(h, seg_len, seg_count_len, p);
        for (int k = 0; k < 3; k++) {
            count[p[k]]--;
            hash_xor[p[k]] ^= h;
            mask_xor[p[k]] ^= m;
            if (count[p[k]] == 1) queue[queued++] = p[k];
        }
    }
    if (fclose(out) != 0) { out = NULL; fail(err, errlen, "%s: %s", peel_path, strerror(errno)); goto done; }
    out = NULL;
    result = peeled == names;
done:
    if (out) fclose(out);
    free(count); free(mask_xor); free(hash_xor); free(queue);
    return result;
}

/* Fills the entries from the peel order read back to front. */
static int assign(const char *peel_path, uint32_t names, uint32_t seg_len, uint32_t seg_count_len, uint32_t *entries, char *err, size_t errlen)
{
    enum { CHUNK = 4096 };
    static unsigned char buf[CHUNK * PEEL_REC];
    FILE *in = fopen(peel_path, "rb");
    if (!in) { fail(err, errlen, "%s: %s", peel_path, strerror(errno)); return -1; }
    uint32_t left = names;
    while (left > 0) {
        uint32_t take = left < CHUNK ? left : CHUNK;
        left -= take;
        if (fseek(in, (long)left * PEEL_REC, SEEK_SET) != 0 || fread(buf, PEEL_REC, take, in) != take) {
            fclose(in);
            fail(err, errlen, "reading the peel order back");
            return -1;
        }
        for (uint32_t i = take; i-- > 0;) {
            const unsigned char *r = buf + (size_t)i * PEEL_REC;
            uint64_t h = rd64(r);
            uint32_t s = rd32(r + 8), p[3];
            positions(h, seg_len, seg_count_len, p);
            uint32_t v = fingerprint(h) << MASK_BITS | r[12];
            for (int k = 0; k < 3; k++) if (p[k] != s) v ^= entries[p[k]];
            entries[s] = v;
        }
    }
    fclose(in);
    return 0;
}

static int write_file(const char *out_path, const uint32_t *entries, uint32_t length, uint32_t names, uint64_t seed, uint32_t seg_len,
                      uint32_t seg_count_len, const char *sources, size_t sources_len, const char *ca, size_t ca_len,
                      const uint8_t web_id[RMC_FILTER_CATS], int64_t now, uint8_t origin, char *err, size_t errlen)
{
    unsigned char le[4], header[RMC_FILTER_HEADER];
    uint64_t id = 0xcbf29ce484222325ULL;
    for (uint32_t i = 0; i < length; i++) {
        wr32(le, entries[i]);
        for (int k = 0; k < 4; k++) { id ^= le[k]; id *= 0x100000001b3ULL; }
    }
    for (size_t i = 0; i < sources_len; i++) { id ^= (unsigned char)sources[i]; id *= 0x100000001b3ULL; }
    for (size_t i = 0; i < ca_len; i++) { id ^= (unsigned char)ca[i]; id *= 0x100000001b3ULL; }
    memset(header, 0, sizeof header);
    memcpy(header, "RMCF", 4);
    wr32(header + 4, RMC_FILTER_VERSION);
    wr64(header + 8, seed);
    wr32(header + 16, seg_len);
    wr32(header + 20, seg_count_len);
    wr32(header + 24, length);
    wr32(header + 28, names);
    wr64(header + 32, (uint64_t)now);
    memcpy(header + 40, web_id, RMC_FILTER_CATS);
    header[45] = origin;
    wr64(header + 48, id);
    wr32(header + 56, (uint32_t)sources_len);
    wr32(header + 60, (uint32_t)ca_len);

    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.tmp", out_path);
    FILE *out = fopen(tmp, "wb");
    if (!out) { fail(err, errlen, "%s: %s", tmp, strerror(errno)); return -1; }
    int ok = fwrite(header, 1, sizeof header, out) == sizeof header;
    for (uint32_t i = 0; ok && i < length; i++) { wr32(le, entries[i]); ok = fwrite(le, 1, 4, out) == 4; }
    ok = ok && fwrite(sources, 1, sources_len, out) == sources_len;
    ok = ok && (ca_len == 0 || fwrite(ca, 1, ca_len, out) == ca_len);
    ok = ok && fflush(out) == 0 && fsync(fileno(out)) == 0;
    if (fclose(out) != 0) ok = 0;
    if (!ok || rename(tmp, out_path) != 0) { fail(err, errlen, "writing %s: %s", out_path, strerror(errno)); unlink(tmp); return -1; }
    return 0;
}

int rmc_filter_build(const char *sources, size_t sources_len, const char *ca, size_t ca_len, const uint8_t web_id[RMC_FILTER_CATS],
                     const char *workdir, const char *out_path, int64_t now, uint8_t origin, char *err, size_t errlen)
{
    char path[512], peel_path[512], ca_path[512];
    FILE *buckets[BUCKETS] = { 0 };
    uint32_t *entries = NULL;
    int result = -1;
    if (mkdir(workdir, 0755) != 0 && errno != EEXIST) { fail(err, errlen, "%s: %s", workdir, strerror(errno)); return -1; }
    snprintf(peel_path, sizeof peel_path, "%s/peel", workdir);
    snprintf(ca_path, sizeof ca_path, "%s/ca.pem", workdir);
    if (ca_len) {
        FILE *f = fopen(ca_path, "wb");
        int bad = !f || fwrite(ca, 1, ca_len, f) != ca_len;
        if (f && fclose(f) != 0) bad = 1;
        if (bad) { fail(err, errlen, "%s: %s", ca_path, strerror(errno)); unlink(ca_path); return -1; }
    }
    for (int b = 0; b < BUCKETS; b++) {
        bucket_path(path, sizeof path, workdir, 'b', b);
        if (!(buckets[b] = fopen(path, "wb"))) { fail(err, errlen, "%s: %s", path, strerror(errno)); goto done; }
    }

    /* Each "<bit> <url>" line of the sources. */
    int lists = 0;
    for (size_t at = 0; at < sources_len;) {
        size_t end = at;
        while (end < sources_len && sources[end] != '\n') end++;
        char line[1024];
        size_t n = end - at < sizeof line - 1 ? end - at : sizeof line - 1;
        memcpy(line, sources + at, n);
        line[n] = 0;
        at = end + 1;
        char *space = strchr(line, ' ');
        if (!space) continue;
        *space = 0;
        int bit = atoi(line);
        if (bit < 0 || bit >= RMC_FILTER_CATS) { fail(err, errlen, "bad source bit %d", bit); goto done; }
        if (read_list(space + 1, ca_len ? ca_path : NULL, (unsigned)bit, buckets, err, errlen) < 0) goto done;
        lists++;
    }
    for (int b = 0; b < BUCKETS; b++) {
        int bad = fclose(buckets[b]) != 0;
        buckets[b] = NULL;
        if (bad) { fail(err, errlen, "closing a bucket: %s", strerror(errno)); goto done; }
    }
    if (lists == 0) { fail(err, errlen, "no lists to build from"); goto done; }

    long distinct = dedupe(workdir, err, errlen);
    if (distinct <= 0) { if (distinct == 0) fail(err, errlen, "no host names"); goto done; }
    uint32_t names = (uint32_t)distinct;

    for (int attempt = 0; attempt < ATTEMPTS; attempt++) {
        uint64_t seed = seed_of(attempt);
        uint32_t seg_len, seg_count_len, length;
        layout(names, attempt, &seg_len, &seg_count_len, &length);
        int peeled = peel(workdir, names, seed, seg_len, seg_count_len, length, peel_path, err, errlen);
        if (peeled < 0) goto done;
        if (!peeled) continue;
        if (!(entries = calloc(length, sizeof *entries))) { fail(err, errlen, "out of memory for %u entries", length); goto done; }
        if (assign(peel_path, names, seg_len, seg_count_len, entries, err, errlen) != 0) goto done;
        result = write_file(out_path, entries, length, names, seed, seg_len, seg_count_len, sources, sources_len, ca, ca_len, web_id, now, origin, err, errlen);
        goto done;
    }
    fail(err, errlen, "no layout found for %u names in %d attempts", names, ATTEMPTS);
done:
    for (int b = 0; b < BUCKETS; b++) {
        if (buckets[b]) fclose(buckets[b]);
        bucket_path(path, sizeof path, workdir, 'b', b);
        unlink(path);
        bucket_path(path, sizeof path, workdir, 'u', b);
        unlink(path);
    }
    unlink(peel_path);
    unlink(ca_path);
    free(entries);
    return result;
}
