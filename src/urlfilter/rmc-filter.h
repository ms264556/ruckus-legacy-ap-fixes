// SPDX-License-Identifier: MIT
/*
 * rmc-filter - the controller's content-filter file on the AP: open and look names up in it, or build it from the
 * blocklists when the controller has been away. Format and algorithm: RuckusMiniController
 * Services/ContentFilter/ContentFilterFile.cs (docs/firmware/content-filtering.md §10); both builds of one set of
 * names are byte-identical apart from the header's time and origin.
 */
#ifndef RMC_FILTER_H
#define RMC_FILTER_H

#include <stddef.h>
#include <stdint.h>

#define RMC_FILTER_HEADER   64
#define RMC_FILTER_VERSION  1
#define RMC_FILTER_CATS     5
#define RMC_HOST_MAX        253

struct rmc_filter {
    const unsigned char *base;  /* the whole file (mmap) */
    size_t size;
    uint64_t seed;
    uint32_t seg_len, seg_count_len, length, names;
    int64_t built_at;
    uint8_t web_id[RMC_FILTER_CATS];
    uint8_t origin;             /* 0 controller, 1 built on the AP */
    uint64_t content_id;
    const char *sources;        /* "<bit> <url>\n" lines, not NUL-terminated */
    uint32_t sources_len;
    const char *ca;             /* PEM roots curl trusts for the list downloads, not NUL-terminated */
    uint32_t ca_len;
};

/* Checks a file image and fills f from it; 0 when it is a filter of this version. */
int rmc_filter_parse(const unsigned char *b, size_t n, struct rmc_filter *f);
/* Maps path and parses it; 0 on success. */
int rmc_filter_open(struct rmc_filter *f, const char *path);
void rmc_filter_close(struct rmc_filter *f);

/*
 * The category mask of a normalized host (lower case, no port, no trailing dot): the name, then "www." and the name,
 * then each parent domain down to (not including) the top-level domain. 0 when it is on no list.
 */
unsigned rmc_filter_lookup(const struct rmc_filter *f, const char *host);

/*
 * The controller's list parsing (ContentListService.Parse / TryNormalizeHost): the name on one line of a hosts file or
 * a domains-only list, normalized into out (RMC_HOST_MAX + 1 bytes). Its length, or -1 when the line names nothing
 * the filter stores (comments, other addresses, local names, non-ASCII).
 */
int rmc_list_line(const char *line, size_t len, char *out);

/*
 * Builds the filter from sources ("<bit> <url or /path>\n" lines; URLs are fetched with curl, trusting the PEM roots
 * in ca when there are any) into out_path, which carries the same sources and ca. workdir holds its temporary files
 * (about 13 bytes per name); memory is about 14 bytes per name. now is the header's time. 0 on success, else -1 with
 * a reason in err.
 */
int rmc_filter_build(const char *sources, size_t sources_len, const char *ca, size_t ca_len, const uint8_t web_id[RMC_FILTER_CATS],
                     const char *workdir, const char *out_path, int64_t now, uint8_t origin, char *err, size_t errlen);

#endif
