#!/usr/bin/env python3
"""Applies the rmc-radiusd changes to an unpacked hostapd 2.11 tree.

Each change replaces one exact block of upstream text, so a hostapd version whose text differs fails here instead of
building something unintended.

1. src/ap/eap_user_db.c: phase-2 names match the way the controller's EAP server matches them: any DOMAIN\\ prefix is
   dropped and ASCII case is ignored (user lines are written in lower case).
2. src/eap_server/eap_server_ttls.c: TTLS/PAP is checked against a stored NT hash (MD4 of the UTF-16LE password), so
   the users file needs no plaintext passwords. Trailing NULs (RFC 5281 11.2.5 padding) are dropped first.
3. src/radius/radius_server.c: the IPv4 socket binds 127.0.0.2 instead of every address. The AP's RADIUS client asks
   it there because SmartZone 2.x, 3.x and 5.1 firmware (librksradius) switch to TCP for exactly 127.0.0.1, and the
   reply has to come from the address the client sent to. Nothing off the AP can reach it.

Usage: apply-patches.py <hostapd source dir>
"""
import pathlib
import sys

root = pathlib.Path(sys.argv[1])


def replace(rel, old, new):
    path = root / rel
    text = path.read_text()
    if text.count(old) != 1:
        sys.exit(f"error: {rel}: expected exactly one match for the patched block")
    path.write_text(text.replace(old, new))


replace("src/ap/eap_user_db.c",
"""const struct hostapd_eap_user *
hostapd_get_eap_user(struct hostapd_data *hapd, const u8 *identity,
		     size_t identity_len, int phase2)
{""",
"""/* A phase-2 name without its DOMAIN\\ prefix, compared ignoring ASCII case. */
static int rmc_phase2_name_eq(const struct hostapd_eap_user *user,
			      const u8 *identity, size_t identity_len)
{
	size_t i;

	for (i = 0; i < identity_len; i++) {
		if (identity[i] == '\\\\') {
			identity += i + 1;
			identity_len -= i + 1;
			break;
		}
	}
	if (user->identity_len != identity_len)
		return 0;
	for (i = 0; i < identity_len; i++) {
		u8 a = user->identity[i], b = identity[i];

		if (a >= 'A' && a <= 'Z')
			a += 'a' - 'A';
		if (b >= 'A' && b <= 'Z')
			b += 'a' - 'A';
		if (a != b)
			return 0;
	}
	return 1;
}


const struct hostapd_eap_user *
hostapd_get_eap_user(struct hostapd_data *hapd, const u8 *identity,
		     size_t identity_len, int phase2)
{""")

replace("src/ap/eap_user_db.c",
"""		if (user->phase2 == !!phase2 &&
		    user->identity_len == identity_len &&
		    os_memcmp(user->identity, identity, identity_len) == 0)
			break;""",
"""		if (phase2 && user->phase2 && user->identity &&
		    rmc_phase2_name_eq(user, identity, identity_len))
			break;

		if (!phase2 && !user->phase2 &&
		    user->identity_len == identity_len &&
		    os_memcmp(user->identity, identity, identity_len) == 0)
			break;""")

replace("src/eap_server/eap_server_ttls.c",
"""	if (!sm->user || !sm->user->password || sm->user->password_hash ||
	    !(sm->user->ttls_auth & EAP_TTLS_AUTH_PAP)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/PAP: No plaintext user "
			   "password configured");
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (sm->user->password_len != user_password_len ||
	    os_memcmp_const(sm->user->password, user_password,
			    user_password_len) != 0) {""",
"""	if (!sm->user || !sm->user->password ||
	    !(sm->user->ttls_auth & EAP_TTLS_AUTH_PAP)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/PAP: No user password "
			   "configured");
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (sm->user->password_hash) {
		u8 hash[16];
		int ok;

		while (user_password_len > 0 &&
		       user_password[user_password_len - 1] == 0)
			user_password_len--;
		ok = sm->user->password_len == 16 &&
			rmc_nt_hash_utf8(user_password, user_password_len,
					 hash) == 0 &&
			os_memcmp_const(hash, sm->user->password, 16) == 0;
		forced_memzero(hash, sizeof(hash));
		if (!ok) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TTLS/PAP: Invalid user password");
			eap_ttls_state(data, FAILURE);
			return;
		}
	} else if (sm->user->password_len != user_password_len ||
	    os_memcmp_const(sm->user->password, user_password,
			    user_password_len) != 0) {""")

replace("src/eap_server/eap_server_ttls.c",
"""static void eap_ttls_process_phase2_pap(struct eap_sm *sm,""",
"""#include "crypto/crypto.h"

/*
 * NT hash of a UTF-8 password: MD4 of its UTF-16LE form. Malformed bytes become U+FFFD, as .NET's UTF-8 decoder
 * turns them, so the result matches the hash the controller stored.
 */
static int rmc_nt_hash_utf8(const u8 *pw, size_t len, u8 *hash)
{
	u8 buf[2 * 2 * 256];
	size_t i = 0, out = 0;
	const u8 *addr[1];
	size_t alen[1];
	int ret;

	while (i < len) {
		u32 cp = 0xfffd;
		size_t n = 1, k;
		u8 c = pw[i];

		if (c < 0x80) {
			cp = c;
		} else if (c >= 0xc2 && c <= 0xdf) {
			n = 2;
			cp = c & 0x1f;
		} else if (c >= 0xe0 && c <= 0xef) {
			n = 3;
			cp = c & 0x0f;
		} else if (c >= 0xf0 && c <= 0xf4) {
			n = 4;
			cp = c & 0x07;
		}
		if (n > 1) {
			if (i + n > len) {
				cp = 0xfffd;
				n = 1;
			} else {
				for (k = 1; k < n; k++) {
					if ((pw[i + k] & 0xc0) != 0x80)
						break;
					cp = (cp << 6) | (pw[i + k] & 0x3f);
				}
				if (k < n || (n == 3 && cp < 0x800) ||
				    (n == 4 && (cp < 0x10000 ||
						cp > 0x10ffff)) ||
				    (cp >= 0xd800 && cp <= 0xdfff)) {
					cp = 0xfffd;
					n = 1;
				}
			}
		}
		if (out + 4 > sizeof(buf))
			return -1;
		if (cp >= 0x10000) {
			u32 v = cp - 0x10000;
			u16 hi = 0xd800 | (v >> 10), lo = 0xdc00 | (v & 0x3ff);

			buf[out++] = hi & 0xff;
			buf[out++] = hi >> 8;
			buf[out++] = lo & 0xff;
			buf[out++] = lo >> 8;
		} else {
			buf[out++] = cp & 0xff;
			buf[out++] = cp >> 8;
		}
		i += n;
	}
	addr[0] = buf;
	alen[0] = out;
	ret = md4_vector(1, addr, alen, hash);
	forced_memzero(buf, sizeof(buf));
	return ret;
}


static void eap_ttls_process_phase2_pap(struct eap_sm *sm,""")

replace("src/radius/radius_server.c",
"""	os_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {""",
"""	os_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(0x7f000002); /* 127.0.0.2 only */
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {""")

print("patched", root)
