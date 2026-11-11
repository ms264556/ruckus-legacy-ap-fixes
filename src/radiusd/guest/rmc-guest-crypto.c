// SPDX-License-Identifier: MIT
/*
 * rmc-guest-crypto.c - SHA-256 and HMAC-SHA256 for the guest-pass roles, from the crypto hostapd already links
 * (crypto_wolfssl.c), so they add no code of their own.
 */
#include "utils/includes.h"
#include "utils/common.h"
#include "crypto/crypto.h"
#include "crypto/sha256.h"

#include "rmc-guest.h"

void gp_sha256(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, uint8_t out[32])
{
    const u8 *addr[2] = { a, b };
    size_t len[2] = { alen, blen };

    sha256_vector(2, addr, len, out);
}

void gp_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *data, size_t len, uint8_t out[32])
{
    hmac_sha256(key, klen, data, len, out);
}
