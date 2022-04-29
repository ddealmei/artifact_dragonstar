/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012-2016, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include "common.h"
#include "const_time.h"
#include "crypto.h"
#include "crypto_bignum_static.h"
#include "dragonfly.h"
#include "sha256.h"
#include "sae.h"
#include "wpabuf.h"


 /* IEEE 802.22 codes defined in hostapd */
#define WLAN_STATUS_SUCCESS 0
#define WLAN_STATUS_UNSPECIFIED_FAILURE 1
#define WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED 77
#define WLAN_EID_EXT_REJECTED_GROUPS 92
#define WLAN_EID_EXT_ANTI_CLOGGING_TOKEN 93
#define WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER 123
#define WLAN_EID_EXTENSION 255
#define WLAN_EID_EXT_PASSWORD_IDENTIFIER 33


/**
 * Initialize the structure with the right group. For now we simply support P-256
 * @param sae   - PUBLIC
 * @param group - PUBLIC
 * @return 0 on success, -1 on failure
 */
int sae_set_group(struct sae_data *sae, int group)
{
	struct sae_temporary_data *tmp;

#ifdef CONFIG_TESTING_OPTIONS
	/* Allow all groups for testing purposes in non-production builds. */
#else /* CONFIG_TESTING_OPTIONS */
	if (!dragonfly_suitable_group(group, 0)) {
		wpa_printf(DEBUG_flag, "SAE: Reject unsuitable group %d", group);
		return -1;
	}
#endif /* CONFIG_TESTING_OPTIONS */

	sae_clear_data(sae);
	tmp = sae->tmp = os_zalloc(sizeof(*tmp));
	if (tmp == NULL)
		return -1;

	/* First, check if this is an ECC group */
	tmp->ec = crypto_ec_init(group);
	if (tmp->ec) {
		wpa_printf(DEBUG_flag, "SAE: Selecting supported ECC group %d",
			   group);
		sae->group = group;
		tmp->prime_len = crypto_ec_prime_len(tmp->ec);
		tmp->prime = crypto_ec_get_prime_static(tmp->ec);
		tmp->order_len = crypto_ec_order_len(tmp->ec);
		tmp->order = crypto_ec_get_order_static(tmp->ec);
		return 0;
	}

	// /* Not an ECC group, check FFC */
	// tmp->dh = dh_groups_get(group);
	// if (tmp->dh) {
	// 	wpa_printf(DEBUG_flag, "SAE: Selecting supported FFC group %d",
	// 		   group);
	// 	sae->group = group;
	// 	tmp->prime_len = tmp->dh->prime_len;
	// 	if (tmp->prime_len > SAE_MAX_PRIME_LEN) {
	// 		sae_clear_data(sae);
	// 		return -1;
	// 	}

	// 	tmp->prime_buf = crypto_bignum_init_set(tmp->dh->prime,
	// 						tmp->prime_len);
	// 	if (tmp->prime_buf == NULL) {
	// 		sae_clear_data(sae);
	// 		return -1;
	// 	}
	// 	tmp->prime = tmp->prime_buf;

	// 	tmp->order_len = tmp->dh->order_len;
	// 	tmp->order_buf = crypto_bignum_init_set(tmp->dh->order,
	// 						tmp->dh->order_len);
	// 	if (tmp->order_buf == NULL) {
	// 		sae_clear_data(sae);
	// 		return -1;
	// 	}
	// 	tmp->order = tmp->order_buf;

	// 	return 0;
	// }

	// /* Unsupported group */
	// wpa_printf(DEBUG_flag,
	// 	   "SAE: Group %d not supported by the crypto library", group);
	return -1;
}


void sae_clear_temp_data(struct sae_data *sae)
{
	struct sae_temporary_data *tmp;
	if (sae == NULL || sae->tmp == NULL)
		return;
	tmp = sae->tmp;
	crypto_ec_deinit(tmp->ec);
	crypto_bignum_static_deinit(tmp->prime_buf, 0);
	crypto_bignum_static_deinit(tmp->order_buf, 0);
	crypto_bignum_static_deinit(tmp->sae_rand, 1);
	// crypto_bignum_deinit(tmp->pwe_ffc, 1);
	crypto_bignum_static_deinit(tmp->own_commit_scalar, 0);
	// crypto_bignum_deinit(tmp->own_commit_element_ffc, 0);
	// crypto_bignum_deinit(tmp->peer_commit_element_ffc, 0);
	crypto_ec_point_deinit(tmp->pwe_ecc, 1);
	crypto_ec_point_deinit(tmp->own_commit_element_ecc, 0);
	crypto_ec_point_deinit(tmp->peer_commit_element_ecc, 0);
	wpabuf_free(tmp->anti_clogging_token);
	wpabuf_free(tmp->own_rejected_groups);
	wpabuf_free(tmp->peer_rejected_groups);
	os_free(tmp->pw_id);
	bin_clear_free(tmp, sizeof(*tmp));
	sae->tmp = NULL;
}


void sae_clear_data(struct sae_data *sae)
{
	if (sae == NULL)
		return;
	sae_clear_temp_data(sae);
	crypto_bignum_static_deinit(sae->peer_commit_scalar, 0);
	crypto_bignum_static_deinit(sae->peer_commit_scalar_accepted, 0);
	os_memset(sae, 0, sizeof(*sae));
}


static void sae_pwd_seed_key(const u8 *addr1, const u8 *addr2, u8 *key)
{
	// wpa_printf(DEBUG_flag, "SAE: PWE derivation - addr1=" MACSTR
	// 	   " addr2=" MACSTR, MAC2STR(addr1), MAC2STR(addr2));
	if (os_memcmp(addr1, addr2, ETH_ALEN) > 0) {
		os_memcpy(key, addr1, ETH_ALEN);
		os_memcpy(key + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		os_memcpy(key, addr2, ETH_ALEN);
		os_memcpy(key + ETH_ALEN, addr1, ETH_ALEN);
	}
}


static int sae_test_pwd_seed_ecc(struct sae_data *sae, const u8 *pwd_seed,
				 const u8 *prime, const u8 *qr, const u8 *qnr,
				 u8 *pwd_value)
{
	struct crypto_bignum_static *y_sqr, *x_cand;
	int res;
	size_t bits;
	int cmp_prime;
	unsigned int in_range;

	hexdump("SAE: pwd-seed", pwd_seed, SHA256_MAC_LEN);

	/* pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p) */
	bits = crypto_ec_prime_len_bits(sae->tmp->ec);
	if (sha256_prf_bits(pwd_seed, SHA256_MAC_LEN, "SAE Hunting and Pecking",
			    prime, sae->tmp->prime_len, pwd_value, bits) < 0)
		return -1;
	if (bits % 8)
		buf_shift_right(pwd_value, sae->tmp->prime_len, 8 - bits % 8);
	hexdump("SAE: pwd-value",
			pwd_value, sae->tmp->prime_len);

	cmp_prime = const_time_memcmp(pwd_value, prime, sae->tmp->prime_len);
	/* Create a const_time mask for selection based on prf result
	 * being smaller than prime. */
	in_range = const_time_fill_msb((unsigned int) cmp_prime);
	/* The algorithm description would skip the next steps if
	 * cmp_prime >= 0 (return 0 here), but go through them regardless to
	 * minimize externally observable differences in behavior. */

	x_cand = crypto_bignum_static_init_set(pwd_value, sae->tmp->prime_len, sae->tmp->prime_len);
	if (!x_cand)
		return -1;
	y_sqr = crypto_ec_point_compute_y_sqr_static(sae->tmp->ec, x_cand);
	crypto_bignum_static_deinit(x_cand, 1);
	if (!y_sqr)
		return -1;

	res = dragonfly_is_quadratic_residue_blind(sae->tmp->ec, qr, qnr,
						   y_sqr);
	crypto_bignum_static_deinit(y_sqr, 1);
	if (res < 0)
		return res;
	return const_time_select_int(in_range, res, 0);
}


static int sae_derive_pwe_ecc(struct sae_data *sae, const u8 *addr1,
			      const u8 *addr2, const u8 *password,
			      size_t password_len)
{
	u8 counter, k;
	u8 addrs[2 * ETH_ALEN];
	const u8 *addr[2];
	size_t len[2];
	u8 *stub_password, *tmp_password;
	int pwd_seed_odd = 0;
	u8 prime[SAE_MAX_ECC_PRIME_LEN];
	size_t prime_len;
	struct crypto_bignum_static *x = NULL, *y = NULL, *qr = NULL, *qnr = NULL;
	u8 x_bin[SAE_MAX_ECC_PRIME_LEN];
	u8 x_cand_bin[SAE_MAX_ECC_PRIME_LEN];
	u8 qr_bin[SAE_MAX_ECC_PRIME_LEN];
	u8 qnr_bin[SAE_MAX_ECC_PRIME_LEN];
	u8 x_y[2 * SAE_MAX_ECC_PRIME_LEN];
	int res = -1;
	u8 found = 0; /* 0 (false) or 0xff (true) to be used as const_time_*
		       * mask */
	unsigned int is_eq;

	os_memset(x_bin, 0, sizeof(x_bin));

	stub_password = os_malloc(password_len);
	tmp_password = os_malloc(password_len);
	if (!stub_password || !tmp_password ||
	    memcpy(stub_password, password, password_len) < 0)
	    // random_get_bytes(stub_password, password_len) < 0)
		goto fail;

	prime_len = sae->tmp->prime_len;
	if (crypto_bignum_static_to_bin(sae->tmp->prime, prime, sizeof(prime),
				 prime_len) < 0)
		goto fail;

	/*
	 * Create a random quadratic residue (qr) and quadratic non-residue
	 * (qnr) modulo p for blinding purposes during the loop.
	 */
	if (dragonfly_get_random_qr_qnr(sae->tmp->prime, &qr, &qnr) < 0 ||
	    crypto_bignum_static_to_bin(qr, qr_bin, sizeof(qr_bin), prime_len) < 0 ||
	    crypto_bignum_static_to_bin(qnr, qnr_bin, sizeof(qnr_bin), prime_len) < 0)
		goto fail;

	// wpa_hexdump_ascii_key(DEBUG, "SAE: password",
	// 		      password, password_len);

	/*
	 * H(salt, ikm) = HMAC-SHA256(salt, ikm)
	 * base = password
	 * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
	 *              base || counter)
	 */
	sae_pwd_seed_key(addr1, addr2, addrs);

	addr[0] = tmp_password;
	len[0] = password_len;
	addr[1] = &counter;
	len[1] = sizeof(counter);

	/*
	 * Continue for at least k iterations to protect against side-channel
	 * attacks that attempt to determine the number of iterations required
	 * in the loop.
	 */
	k = dragonfly_min_pwe_loop_iter(sae->group);

	for (counter = 1; counter <= k || !found; counter++) {
		u8 pwd_seed[SHA256_MAC_LEN];

		if (counter > 200) {
			/* This should not happen in practice */
			wpa_printf(DEBUG_flag, "SAE: Failed to derive PWE");
			break;
		}

		wpa_printf(DEBUG_flag, "SAE: counter = %03u", counter);
		const_time_select_bin(found, stub_password, password,
				      password_len, tmp_password);
		if (hmac_sha256_vector(addrs, sizeof(addrs), 2,
				       addr, len, pwd_seed) < 0)
			break;

		res = sae_test_pwd_seed_ecc(sae, pwd_seed,
					    prime, qr_bin, qnr_bin, x_cand_bin);
		const_time_select_bin(found, x_bin, x_cand_bin, prime_len,
				      x_bin);
		pwd_seed_odd = const_time_select_u8(
			found, pwd_seed_odd,
			pwd_seed[SHA256_MAC_LEN - 1] & 0x01);
		os_memset(pwd_seed, 0, sizeof(pwd_seed));
		if (res < 0)
			goto fail;
		/* Need to minimize differences in handling res == 0 and 1 here
		 * to avoid differences in timing and instruction cache access,
		 * so use const_time_select_*() to make local copies of the
		 * values based on whether this loop iteration was the one that
		 * found the pwd-seed/x. */

		/* found is 0 or 0xff here and res is 0 or 1. Bitwise OR of them
		 * (with res converted to 0/0xff) handles this in constant time.
		 */
		found |= res * 0xff;
		wpa_printf(DEBUG_flag, "SAE: pwd-seed result %d found=0x%02x",
			   res, found);
	}

	if (!found) {
		wpa_printf(DEBUG_flag, "SAE: Could not generate PWE");
		res = -1;
		goto fail;
	}

	x = crypto_bignum_static_init_set(x_bin, prime_len, prime_len);
	hexdump("x bin: ", x_bin, 32);
	// crypto_bignum_print("x_big", x);
	if (!x) {
		res = -1;
		goto fail;
	}

	/* y = sqrt(x^3 + ax + b) mod p
	 * if LSB(save) == LSB(y): PWE = (x, y)
	 * else: PWE = (x, p - y)
	 *
	 * Calculate y and the two possible values for PWE and after that,
	 * use constant time selection to copy the correct alternative.
	 */
	y = crypto_ec_point_compute_y_sqr_static(sae->tmp->ec, x);
	if (!y ||
	    dragonfly_sqrt(sae->tmp->ec, y, y) < 0 ||
	    crypto_bignum_static_to_bin(y, x_y, SAE_MAX_ECC_PRIME_LEN,
				 prime_len) < 0 ||
	    crypto_bignum_static_sub(sae->tmp->prime, y, y) < 0 ||
	    crypto_bignum_static_to_bin(y, x_y + SAE_MAX_ECC_PRIME_LEN,
				 SAE_MAX_ECC_PRIME_LEN, prime_len) < 0) {
		wpa_printf(DEBUG_flag, "SAE: Could not solve y");
		goto fail;
	}

	is_eq = const_time_eq(pwd_seed_odd, x_y[prime_len - 1] & 0x01);
	const_time_select_bin(is_eq, x_y, x_y + SAE_MAX_ECC_PRIME_LEN,
			      prime_len, x_y + prime_len);
	os_memcpy(x_y, x_bin, prime_len);
	hexdump("SAE: PWE", x_y, 2 * prime_len);
	crypto_ec_point_deinit(sae->tmp->pwe_ecc, 1);
	sae->tmp->pwe_ecc = crypto_ec_point_from_bin(sae->tmp->ec, x_y);
	if (!sae->tmp->pwe_ecc) {
		wpa_printf(DEBUG_flag, "SAE: Could not generate PWE");
		res = -1;
	}

fail:
	forced_memzero(x_y, sizeof(x_y));
	crypto_bignum_static_deinit(qr, 0);
	crypto_bignum_static_deinit(qnr, 0);
	crypto_bignum_static_deinit(y, 1);
	os_free(stub_password);
	bin_clear_free(tmp_password, password_len);
	crypto_bignum_static_deinit(x, 1);
	os_memset(x_bin, 0, sizeof(x_bin));
	os_memset(x_cand_bin, 0, sizeof(x_cand_bin));

	return res;
}


static int hkdf_extract(size_t hash_len, const u8 *salt, size_t salt_len,
			size_t num_elem, const u8 *addr[], const size_t len[],
			u8 *prk)
{
	if (hash_len == 32)
		return hmac_sha256_vector(salt, salt_len, num_elem, addr, len,
					  prk);
#ifdef CONFIG_SHA384
	if (hash_len == 48)
		return hmac_sha384_vector(salt, salt_len, num_elem, addr, len,
					  prk);
#endif /* CONFIG_SHA384 */
#ifdef CONFIG_SHA512
	if (hash_len == 64)
		return hmac_sha512_vector(salt, salt_len, num_elem, addr, len,
					  prk);
#endif /* CONFIG_SHA512 */
	return -1;
}


static int hkdf_expand(size_t hash_len, const u8 *prk, size_t prk_len,
		       const char *info, u8 *okm, size_t okm_len)
{
	size_t info_len = os_strlen(info);

	if (hash_len == 32)
		return hmac_sha256_kdf(prk, prk_len, NULL,
				       (const u8 *) info, info_len,
				       okm, okm_len);
#ifdef CONFIG_SHA384
	if (hash_len == 48)
		return hmac_sha384_kdf(prk, prk_len, NULL,
				       (const u8 *) info, info_len,
				       okm, okm_len);
#endif /* CONFIG_SHA384 */
#ifdef CONFIG_SHA512
	if (hash_len == 64)
		return hmac_sha512_kdf(prk, prk_len, NULL,
				       (const u8 *) info, info_len,
				       okm, okm_len);
#endif /* CONFIG_SHA512 */
	return -1;
}


static int sswu_curve_param(int group, int *z)
{
	switch (group) {
	case 19:
		*z = -10;
		return 0;
	// case 20:
	// 	*z = -12;
	// 	return 0;
	// case 21:
	// 	*z = -4;
	// 	return 0;
	// case 25:
	// case 29:
	// 	*z = -5;
	// 	return 0;
	// case 26:
	// 	*z = 31;
	// 	return 0;
	// case 28:
	// 	*z = -2;
	// 	return 0;
	// case 30:
	// 	*z = 7;
	// 	return 0;
	}

	return -1;
}


static int debug_print_bignum(const char *title, const struct crypto_bignum_static *a,
			       size_t prime_len)
{
#ifdef DEBUG
	u8 *bin;

	bin = os_malloc(prime_len);
	if (bin && crypto_bignum_static_to_bin(a, bin, prime_len, prime_len) >= 0)
		hexdump(title, bin, prime_len);
	else
		wpa_printf(DEBUG_flag, "Could not print bignum (%s)", title);
	bin_clear_free(bin, prime_len);
#endif
	return 0;
}


static struct crypto_ec_point * sswu(struct crypto_ec *ec, int group,
				     const struct crypto_bignum_static *u)
{
	int z_int;
	const struct crypto_bignum_static *a, *b, *prime;
	struct crypto_bignum_static *u2, *t1, *t2, *z, *t, *zero, *one, *two, *three,
		*x1a, *x1b, *y = NULL;
	struct crypto_bignum_static *x1 = NULL, *x2, *gx1, *gx2, *v = NULL;
	unsigned int m_is_zero, is_qr, is_eq;
	size_t prime_len;
	u8 bin[SAE_MAX_ECC_PRIME_LEN];
	u8 bin1[SAE_MAX_ECC_PRIME_LEN];
	u8 bin2[SAE_MAX_ECC_PRIME_LEN];
	u8 x_y[2 * SAE_MAX_ECC_PRIME_LEN];
	struct crypto_ec_point *p = NULL;

	if (sswu_curve_param(group, &z_int) < 0)
		return NULL;

	prime = crypto_ec_get_prime_static(ec);
	prime_len = crypto_ec_prime_len(ec);
	a = crypto_ec_get_a_static(ec);
	b = crypto_ec_get_b_static(ec);

	u2 = crypto_bignum_static_init(prime_len);
	t1 = crypto_bignum_static_init(prime_len);
	t2 = crypto_bignum_static_init(prime_len);
	z = crypto_bignum_static_init_uint(abs(z_int), prime_len);
	t = crypto_bignum_static_init(prime_len);
	zero = crypto_bignum_static_init_uint(0, prime_len);
	one = crypto_bignum_static_init_uint(1, prime_len);
	two = crypto_bignum_static_init_uint(2, prime_len);
	three = crypto_bignum_static_init_uint(3, prime_len);
	x1a = crypto_bignum_static_init(prime_len);
	x1b = crypto_bignum_static_init(prime_len);
	x2 = crypto_bignum_static_init(prime_len);
	gx1 = crypto_bignum_static_init(prime_len);
	gx2 = crypto_bignum_static_init(prime_len);
	if (!u2 || !t1 || !t2 || !z || !t || !zero || !one || !two || !three ||
	    !x1a || !x1b || !x2 || !gx1 || !gx2)
		goto fail;

	if (z_int < 0 && crypto_bignum_static_sub(prime, z, z) < 0)
		goto fail;

	/* m = z^2 * u^4 + z * u^2 */
	/* --> tmp = z * u^2, m = tmp^2 + tmp */

	/* u2 = u^2
	 * t1 = z * u2
	 * t2 = t1^2
	 * m = t1 = t1 + t2 */
	if (crypto_bignum_static_sqrmod(u, prime, u2) < 0 ||
	    crypto_bignum_static_mulmod(z, u2, prime, t1) < 0 ||
	    crypto_bignum_static_sqrmod(t1, prime, t2) < 0 ||
	    crypto_bignum_static_addmod(t1, t2, prime, t1) < 0)
		goto fail;
	debug_print_bignum("SSWU: m", t1, prime_len);

	/* l = CEQ(m, 0)
	 * t = CSEL(l, 0, inverse(m); where inverse(x) is calculated as
	 * x^(p-2) modulo p which will handle m == 0 case correctly */
	/* TODO: Make sure crypto_bignum_static_is_zero () is constant time */
	m_is_zero = const_time_eq(crypto_bignum_static_is_zero (t1), 1);
	/* t = m^(p-2) modulo p */
	if (crypto_bignum_static_sub(prime, two, t2) < 0 ||
	    crypto_bignum_static_exptmod(t1, t2, prime, t) < 0)
		goto fail;
	debug_print_bignum("SSWU: t", t, prime_len);

	/* b / (z * a) */
	if (crypto_bignum_static_mulmod(z, a, prime, t1) < 0 ||
	    crypto_bignum_static_inverse(t1, prime, t1) < 0 ||
	    crypto_bignum_static_mulmod(b, t1, prime, x1a) < 0)
		goto fail;
	debug_print_bignum("SSWU: x1a = b / (z * a)", x1a, prime_len);

	/* (-b/a) * (1 + t) */
	if (crypto_bignum_static_sub(prime, b, t1) < 0 ||
	    crypto_bignum_static_inverse(a, prime, t2) < 0 ||
	    crypto_bignum_static_mulmod(t1, t2, prime, t1) < 0 ||
	    crypto_bignum_static_addmod(one, t, prime, t2) < 0 ||
	    crypto_bignum_static_mulmod(t1, t2, prime, x1b) < 0)
		goto fail;
	debug_print_bignum("SSWU: x1b = (-b/a) * (1 + t)", x1b, prime_len);

	/* x1 = CSEL(CEQ(m, 0), x1a, x1b) */
	if (crypto_bignum_static_to_bin(x1a, bin1, sizeof(bin1), prime_len) < 0 ||
	    crypto_bignum_static_to_bin(x1b, bin2, sizeof(bin2), prime_len) < 0)
		goto fail;
	const_time_select_bin(m_is_zero, bin1, bin2, prime_len, bin);
	x1 = crypto_bignum_static_init_set(bin, prime_len, prime_len);
	if (!x1)
		goto fail;
	debug_print_bignum("SSWU: x1 = CSEL(l, x1a, x1b)", x1, prime_len);

	/* gx1 = x1^3 + a * x1 + b */
	if (crypto_bignum_static_exptmod(x1, three, prime, t1) < 0 ||
	    crypto_bignum_static_mulmod(a, x1, prime, t2) < 0 ||
	    crypto_bignum_static_addmod(t1, t2, prime, t1) < 0 ||
	    crypto_bignum_static_addmod(t1, b, prime, gx1) < 0)
		goto fail;
	debug_print_bignum("SSWU: gx1 = x1^3 + a * x1 + b", gx1, prime_len);

	/* x2 = z * u^2 * x1 */
	if (crypto_bignum_static_mulmod(z, u2, prime, t1) < 0 ||
	    crypto_bignum_static_mulmod(t1, x1, prime, x2) < 0)
		goto fail;
	debug_print_bignum("SSWU: x2 = z * u^2 * x1", x2, prime_len);

	/* gx2 = x2^3 + a * x2 + b */
	if (crypto_bignum_static_exptmod(x2, three, prime, t1) < 0 ||
	    crypto_bignum_static_mulmod(a, x2, prime, t2) < 0 ||
	    crypto_bignum_static_addmod(t1, t2, prime, t1) < 0 ||
	    crypto_bignum_static_addmod(t1, b, prime, gx2) < 0)
		goto fail;
	debug_print_bignum("SSWU: gx2 = x2^3 + a * x2 + b", gx2, prime_len);

	/* l = gx1 is a quadratic residue modulo p
	 * --> gx1^((p-1)/2) modulo p is zero or one */
	if (crypto_bignum_static_sub(prime, one, t1) < 0 ||
	    crypto_bignum_static_rshift(t1, 1, t1) < 0 ||
	    crypto_bignum_static_exptmod(gx1, t1, prime, t1) < 0)
		goto fail;
	debug_print_bignum("SSWU: gx1^((p-1)/2) modulo p", t1, prime_len);
	is_qr = const_time_eq(crypto_bignum_static_is_zero (t1) |
			      crypto_bignum_static_is_one(t1), 1);

	/* v = CSEL(l, gx1, gx2) */
	if (crypto_bignum_static_to_bin(gx1, bin1, sizeof(bin1), prime_len) < 0 ||
	    crypto_bignum_static_to_bin(gx2, bin2, sizeof(bin2), prime_len) < 0)
		goto fail;
	const_time_select_bin(is_qr, bin1, bin2, prime_len, bin);
	v = crypto_bignum_static_init_set(bin, prime_len, prime_len);
	if (!v)
		goto fail;
	debug_print_bignum("SSWU: v = CSEL(l, gx1, gx2)", v, prime_len);

	/* x = CSEL(l, x1, x2) */
	if (crypto_bignum_static_to_bin(x1, bin1, sizeof(bin1), prime_len) < 0 ||
	    crypto_bignum_static_to_bin(x2, bin2, sizeof(bin2), prime_len) < 0)
		goto fail;
	const_time_select_bin(is_qr, bin1, bin2, prime_len, x_y);
	hexdump("SSWU: x = CSEL(l, x1, x2)", x_y, prime_len);

	/* y = sqrt(v) */
	y = crypto_bignum_static_init(prime_len);
	if (!y || dragonfly_sqrt(ec, v, y) < 0)
		goto fail;
	debug_print_bignum("SSWU: y = sqrt(v)", y, prime_len);

	/* l = CEQ(LSB(u), LSB(y)) */
	if (crypto_bignum_static_to_bin(u, bin1, sizeof(bin1), prime_len) < 0 ||
	    crypto_bignum_static_to_bin(y, bin2, sizeof(bin2), prime_len) < 0)
		goto fail;
	is_eq = const_time_eq(bin1[prime_len - 1] & 0x01,
			      bin2[prime_len - 1] & 0x01);

	/* P = CSEL(l, (x,y), (x, p-y)) */
	if (crypto_bignum_static_sub(prime, y, t1) < 0)
		goto fail;
	debug_print_bignum("SSWU: p - y", t1, prime_len);
	if (crypto_bignum_static_to_bin(y, bin1, sizeof(bin1), prime_len) < 0 ||
	    crypto_bignum_static_to_bin(t1, bin2, sizeof(bin2), prime_len) < 0)
		goto fail;
	const_time_select_bin(is_eq, bin1, bin2, prime_len, &x_y[prime_len]);

	/* output P */
	hexdump("SSWU: P.x", x_y, prime_len);
	hexdump("SSWU: P.y", &x_y[prime_len], prime_len);
	p = crypto_ec_point_from_bin(ec, x_y);

fail:
	crypto_bignum_static_deinit(u2, 1);
	crypto_bignum_static_deinit(t1, 1);
	crypto_bignum_static_deinit(t2, 1);
	crypto_bignum_static_deinit(z, 0);
	crypto_bignum_static_deinit(t, 1);
	crypto_bignum_static_deinit(x1a, 1);
	crypto_bignum_static_deinit(x1b, 1);
	crypto_bignum_static_deinit(x1, 1);
	crypto_bignum_static_deinit(x2, 1);
	crypto_bignum_static_deinit(gx1, 1);
	crypto_bignum_static_deinit(gx2, 1);
	crypto_bignum_static_deinit(y, 1);
	crypto_bignum_static_deinit(v, 1);
	crypto_bignum_static_deinit(zero, 0);
	crypto_bignum_static_deinit(one, 0);
	crypto_bignum_static_deinit(two, 0);
	crypto_bignum_static_deinit(three, 0);
	forced_memzero(bin, sizeof(bin));
	forced_memzero(bin1, sizeof(bin1));
	forced_memzero(bin2, sizeof(bin2));
	forced_memzero(x_y, sizeof(x_y));
	return p;
}


static int sae_pwd_seed(size_t hash_len, const u8 *ssid, size_t ssid_len,
			const u8 *password, size_t password_len,
			const char *identifier, u8 *pwd_seed)
{
	const u8 *addr[2];
	size_t len[2];
	size_t num_elem;

	/* pwd-seed = HKDF-Extract(ssid, password [ || identifier ]) */
	addr[0] = password;
	len[0] = password_len;
	num_elem = 1;
	// wpa_hexdump_ascii(DEBUG, "SAE: SSID", ssid, ssid_len);
	// wpa_hexdump_ascii_key(DEBUG, "SAE: password",
	// 		      password, password_len);
	if (identifier) {
		wpa_printf(DEBUG_flag, "SAE: password identifier: %s",
			   identifier);
		addr[num_elem] = (const u8 *) identifier;
		len[num_elem] = os_strlen(identifier);
		num_elem++;
	}
	if (hkdf_extract(hash_len, ssid, ssid_len, num_elem, addr, len,
			 pwd_seed) < 0)
		return -1;
	hexdump("SAE: pwd-seed", pwd_seed, hash_len);
	return 0;
}


size_t sae_ecc_prime_len_2_hash_len(size_t prime_len)
{
	if (prime_len <= 256 / 8)
		return 32;
	if (prime_len <= 384 / 8)
		return 48;
	return 64;
}


static struct crypto_ec_point *
sae_derive_pt_ecc(struct crypto_ec *ec, int group,
		  const u8 *ssid, size_t ssid_len,
		  const u8 *password, size_t password_len,
		  const char *identifier)
{
	u8 pwd_seed[64];
	u8 pwd_value[SAE_MAX_ECC_PRIME_LEN * 2];
	size_t pwd_value_len, hash_len, prime_len;
	const struct crypto_bignum_static *prime;
	struct crypto_bignum_static *bn = NULL, *tmp = NULL;
	struct crypto_ec_point *p1 = NULL, *p2 = NULL, *pt = NULL;

	prime = crypto_ec_get_prime_static(ec);
	prime_len = crypto_ec_prime_len(ec);
	if (prime_len > SAE_MAX_ECC_PRIME_LEN)
		goto fail;
	hash_len = sae_ecc_prime_len_2_hash_len(prime_len);

	/* len = olen(p) + ceil(olen(p)/2) */
	pwd_value_len = prime_len + (prime_len + 1) / 2;

	if (sae_pwd_seed(hash_len, ssid, ssid_len, password, password_len,
			 identifier, pwd_seed) < 0)
		goto fail;

	/* pwd-value = HKDF-Expand(pwd-seed, "SAE Hash to Element u1 P1", len)
	 */
	if (hkdf_expand(hash_len, pwd_seed, hash_len,
			"SAE Hash to Element u1 P1", pwd_value, pwd_value_len) <
	    0)
		goto fail;
	hexdump("SAE: pwd-value (u1 P1)",
			pwd_value, pwd_value_len);

	/* u1 = pwd-value modulo p */
	bn = crypto_bignum_static_init(prime_len);
	tmp = crypto_bignum_static_init_set(pwd_value, pwd_value_len, 2 * prime_len);
	if (!bn || !tmp || crypto_bignum_static_mod(tmp, prime, bn) < 0 ||
	    crypto_bignum_static_to_bin(bn, pwd_value, sizeof(pwd_value),
				 prime_len) < 0)
		goto fail;
	hexdump("SAE: u1", pwd_value, prime_len);

	/* P1 = SSWU(u1) */
	p1 = sswu(ec, group, bn);
	if (!p1)
		goto fail;

	/* pwd-value = HKDF-Expand(pwd-seed, "SAE Hash to Element u2 P2", len)
	 */
	if (hkdf_expand(hash_len, pwd_seed, hash_len,
			"SAE Hash to Element u2 P2", pwd_value,
			pwd_value_len) < 0)
		goto fail;
	hexdump("SAE: pwd-value (u2 P2)",
			pwd_value, pwd_value_len);

	/* u2 = pwd-value modulo p */
	crypto_bignum_static_deinit(bn, 1);
	crypto_bignum_static_deinit(tmp, 1);
	bn = crypto_bignum_static_init(prime_len);
	tmp = crypto_bignum_static_init_set(pwd_value, pwd_value_len, 2 * prime_len);
	if (!bn || !tmp || crypto_bignum_static_mod(tmp, prime, bn) < 0 ||
	    crypto_bignum_static_to_bin(bn, pwd_value, sizeof(pwd_value),
				 prime_len) < 0)
		goto fail;
	hexdump("SAE: u2", pwd_value, prime_len);

	/* P2 = SSWU(u2) */
	p2 = sswu(ec, group, bn);
	if (!p2)
		goto fail;

	/* PT = elem-op(P1, P2) */
	pt = crypto_ec_point_init(ec);
	if (!pt)
		goto fail;
	if (crypto_ec_point_add(ec, p1, p2, pt) < 0) {
		crypto_ec_point_deinit(pt, 1);
		pt = NULL;
	}

fail:
	forced_memzero(pwd_seed, sizeof(pwd_seed));
	forced_memzero(pwd_value, sizeof(pwd_value));
	crypto_bignum_static_deinit(bn, 1);
	crypto_bignum_static_deinit(tmp, 1);
	crypto_ec_point_deinit(p1, 1);
	crypto_ec_point_deinit(p2, 1);
	return pt;
}


static struct sae_pt *
sae_derive_pt_group(int group, const u8 *ssid, size_t ssid_len,
		    const u8 *password, size_t password_len,
		    const char *identifier)
{
	struct sae_pt *pt;

	wpa_printf(DEBUG_flag, "SAE: Derive PT - group %d", group);

	if (ssid_len > 32)
		return NULL;

	pt = os_zalloc(sizeof(*pt));
	if (!pt)
		return NULL;

#ifdef CONFIG_SAE_PK
	os_memcpy(pt->ssid, ssid, ssid_len);
	pt->ssid_len = ssid_len;
#endif /* CONFIG_SAE_PK */
	pt->group = group;
	pt->ec = crypto_ec_init(group);
	if (pt->ec) {
		pt->ecc_pt = sae_derive_pt_ecc(pt->ec, group, ssid, ssid_len,
					       password, password_len,
					       identifier);
		if (!pt->ecc_pt) {
			wpa_printf(DEBUG_flag, "SAE: Failed to derive PT");
			goto fail;
		}

		return pt;
	}

	// pt->dh = dh_groups_get(group);
	// if (!pt->dh) {
	// 	wpa_printf(DEBUG_flag, "SAE: Unsupported group %d", group);
	// 	goto fail;
	// }

	// pt->ffc_pt = sae_derive_pt_ffc(pt->dh, group, ssid, ssid_len,
	// 			       password, password_len, identifier);
	// if (!pt->ffc_pt) {
	// 	wpa_printf(DEBUG_flag, "SAE: Failed to derive PT");
	// 	goto fail;
	// }

	// return pt;
fail:
	sae_deinit_pt(pt);
	return NULL;
}


struct sae_pt * sae_derive_pt(int *groups, const u8 *ssid, size_t ssid_len,
			      const u8 *password, size_t password_len,
			      const char *identifier)
{
	struct sae_pt *pt = NULL, *last = NULL, *tmp;
	int default_groups[] = { 19, 0 };
	int i;

	if (!groups)
		groups = default_groups;
	for (i = 0; groups[i] > 0; i++) {
		tmp = sae_derive_pt_group(groups[i], ssid, ssid_len, password,
					  password_len, identifier);
		if (!tmp)
			continue;

		if (last)
			last->next = tmp;
		else
			pt = tmp;
		last = tmp;
	}

	return pt;
}


static void sae_max_min_addr(const u8 *addr[], size_t len[],
			     const u8 *addr1, const u8 *addr2)
{
	len[0] = ETH_ALEN;
	len[1] = ETH_ALEN;
	if (os_memcmp(addr1, addr2, ETH_ALEN) > 0) {
		addr[0] = addr1;
		addr[1] = addr2;
	} else {
		addr[0] = addr2;
		addr[1] = addr1;
	}
}


struct crypto_ec_point *
sae_derive_pwe_from_pt_ecc(const struct sae_pt *pt,
			   const u8 *addr1, const u8 *addr2)
{
	u8 bin[SAE_MAX_ECC_PRIME_LEN * 2];
	size_t prime_len;
	const u8 *addr[2];
	size_t len[2];
	u8 salt[64], hash[64];
	size_t hash_len;
	const struct crypto_bignum_static *order;
	struct crypto_bignum_static *tmp = NULL, *val = NULL, *one = NULL;
	struct crypto_ec_point *pwe = NULL;

	wpa_printf(DEBUG_flag, "SAE: Derive PWE from PT");
	prime_len = crypto_ec_prime_len(pt->ec);
	if (crypto_ec_point_to_bin(pt->ec, pt->ecc_pt,
				   bin, bin + prime_len) < 0)
		return NULL;
	hexdump("SAE: PT.x", bin, prime_len);
	hexdump("SAE: PT.y", bin + prime_len, prime_len);

	sae_max_min_addr(addr, len, addr1, addr2);

	/* val = H(0^n,
	 *         MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC)) */
	wpa_printf(DEBUG_flag, "SAE: val = H(0^n, MAX(addrs) || MIN(addrs))");
	hash_len = sae_ecc_prime_len_2_hash_len(prime_len);
	os_memset(salt, 0, hash_len);
	if (hkdf_extract(hash_len, salt, hash_len, 2, addr, len, hash) < 0)
		goto fail;
	hexdump("SAE: val", hash, hash_len);

	/* val = val modulo (q - 1) + 1 */
	order = crypto_ec_get_order_static(pt->ec);
	tmp = crypto_bignum_static_init(prime_len);
	val = crypto_bignum_static_init_set(hash, hash_len, prime_len);
	one = crypto_bignum_static_init_uint(1, prime_len);
	if (!tmp || !val || !one ||
	    crypto_bignum_static_sub(order, one, tmp) < 0 ||
	    crypto_bignum_static_mod(val, tmp, val) < 0 ||
	    crypto_bignum_static_add(val, one, val) < 0)
		goto fail;
	debug_print_bignum("SAE: val(reduced to 1..q-1)", val, prime_len);

	/* PWE = scalar-op(val, PT) */
	pwe = crypto_ec_point_init(pt->ec);
	if (!pwe ||
		crypto_ec_point_mul_static(pt->ec, pt->ecc_pt, val, pwe) < 0 ||
	    crypto_ec_point_to_bin(pt->ec, pwe, bin, bin + prime_len) < 0) {
		crypto_ec_point_deinit(pwe, 1);
		pwe = NULL;
		goto fail;
	}
	hexdump("SAE: PWE.x", bin, prime_len);
	hexdump("SAE: PWE.y", bin + prime_len, prime_len);

fail:
	crypto_bignum_static_deinit(tmp, 1);
	crypto_bignum_static_deinit(val, 1);
	crypto_bignum_static_deinit(one, 0);
	return pwe;
}


void sae_deinit_pt(struct sae_pt *pt)
{
	struct sae_pt *prev;

	while (pt) {
		crypto_ec_point_deinit(pt->ecc_pt, 1);
		// crypto_bignum_deinit(pt->ffc_pt, 1);
		crypto_ec_deinit(pt->ec);
		prev = pt;
		pt = pt->next;
		os_free(prev);
	}
}


static int sae_derive_commit_element_ecc(struct sae_data *sae,
					 struct crypto_bignum_static *mask)
{
	/* COMMIT-ELEMENT = inverse(scalar-op(mask, PWE)) */
	if (!sae->tmp->own_commit_element_ecc) {
		sae->tmp->own_commit_element_ecc =
			crypto_ec_point_init(sae->tmp->ec);
		if (!sae->tmp->own_commit_element_ecc)
			return -1;
	}

	if (crypto_ec_point_mul_static(sae->tmp->ec, sae->tmp->pwe_ecc, mask,
				sae->tmp->own_commit_element_ecc) < 0 ||
	    crypto_ec_point_invert(sae->tmp->ec,
				   sae->tmp->own_commit_element_ecc) < 0) {
		wpa_printf(DEBUG_flag, "SAE: Could not compute commit-element");
		return -1;
	}

	return 0;
}


static int sae_derive_commit(struct sae_data *sae)
{
	struct crypto_bignum_static *mask;
	int ret;
#ifdef DEBUG
    /* Here we set a constant mask to avoid its CF effects on the
     * secret point coordinates. The mask has been generated randomly in
     * python, and hardcoded. Original code is commented bellow. The idea is
     * basically that we generate mask and sae_rand, and compute
     * own_commit_scalar = mask + sae_rand mod p */
	uint8_t mask_bin[] = { 0x2b, 0x38, 0x7a, 0x22, 0xa5, 0xb3, 0x61, 0xf8, 0x0b, 0x0f, 0xc7, 0x27, 0x1e, 0x7f, 0xb4, 0x5e, 0xaa, 0x5d, 0x43, 0xa5, 0x55, 0x7a, 0xf8, 0x41, 0xd2, 0xcc, 0x65, 0x70, 0xd1, 0x4f, 0xfb, 0xdf };
	uint8_t sae_rand_bin[] = { 0x66, 0x11, 0xe9, 0xbc, 0x4c, 0x37, 0xd1, 0xc3, 0xd9, 0x7d, 0xe7, 0xad, 0x6b, 0x3e, 0x69, 0xcb, 0x00, 0x5f, 0xe9, 0xcb, 0xa0, 0x74, 0x52, 0xd0, 0xba, 0x16, 0x8a, 0xce, 0x53, 0xb0, 0x87, 0x56 };
	
	mask = crypto_bignum_static_init_set(mask_bin, 32, 32);
	if (!sae->tmp->sae_rand)
		sae->tmp->sae_rand = crypto_bignum_static_init_set(sae_rand_bin, 32, 32);
	if (!sae->tmp->own_commit_scalar)
		sae->tmp->own_commit_scalar = crypto_bignum_static_init(32);

	ret = !mask || !sae->tmp->sae_rand || !sae->tmp->own_commit_scalar ||
		crypto_bignum_static_addmod(sae->tmp->sae_rand, mask, sae->tmp->order, sae->tmp->own_commit_scalar) != 0 ||
		(sae->tmp->ec && sae_derive_commit_element_ecc(sae, mask) < 0);
		//  ||
		// (sae->tmp->dh && sae_derive_commit_element_ffc(sae, mask) < 0);
#else
	mask = crypto_bignum_static_init(32);
	if (!sae->tmp->sae_rand)
		sae->tmp->sae_rand = crypto_bignum_static_init(32);
	if (!sae->tmp->own_commit_scalar)
		sae->tmp->own_commit_scalar = crypto_bignum_static_init(32);
	ret = !mask || !sae->tmp->sae_rand || !sae->tmp->own_commit_scalar ||
		dragonfly_generate_scalar(sae->tmp->order, sae->tmp->sae_rand,
					  mask,
					  sae->tmp->own_commit_scalar) < 0 ||
		(sae->tmp->ec &&
		 sae_derive_commit_element_ecc(sae, mask) < 0);
		// (sae->tmp->dh &&
		//  sae_derive_commit_element_ffc(sae, mask) < 0);
#endif
	crypto_bignum_static_deinit(mask, 1);
	return ret ? -1 : 0;
}


int sae_prepare_commit(const u8 *addr1, const u8 *addr2,
		       const u8 *password, size_t password_len,
		       struct sae_data *sae)
{
	if (sae->tmp == NULL ||
		(sae->tmp->ec && sae_derive_pwe_ecc(sae, addr1, addr2, password,
			password_len) < 0))
		return -1;
	// if (sae->tmp == NULL ||
	//     (sae->tmp->ec && sae_derive_pwe_ecc(sae, addr1, addr2, password,
	// 					password_len) < 0) ||
	//     (sae->tmp->dh && sae_derive_pwe_ffc(sae, addr1, addr2, password,
	// 					password_len) < 0))
	// 	return -1;

	sae->h2e = 0;
	sae->pk = 0;
	return sae_derive_commit(sae);
}


int sae_prepare_commit_pt(struct sae_data *sae, const struct sae_pt *pt,
			  const u8 *addr1, const u8 *addr2,
			  int *rejected_groups, const struct sae_pk *pk)
{
	if (!sae->tmp)
		return -1;

	while (pt) {
		if (pt->group == sae->group)
			break;
		pt = pt->next;
	}
	if (!pt) {
		wpa_printf(DEBUG_flag, "SAE: Could not find PT for group %u",
			   sae->group);
		return -1;
	}

#ifdef CONFIG_SAE_PK
	os_memcpy(sae->tmp->ssid, pt->ssid, pt->ssid_len);
	sae->tmp->ssid_len = pt->ssid_len;
	sae->tmp->ap_pk = pk;
#endif /* CONFIG_SAE_PK */
	sae->tmp->own_addr_higher = os_memcmp(addr1, addr2, ETH_ALEN) > 0;
	wpabuf_free(sae->tmp->own_rejected_groups);
	sae->tmp->own_rejected_groups = NULL;
	if (rejected_groups) {
		int count, i;
		struct wpabuf *groups;

		count = int_array_len(rejected_groups);
		groups = wpabuf_alloc(count * 2);
		if (!groups)
			return -1;
		for (i = 0; i < count; i++)
			wpabuf_put_le16(groups, rejected_groups[i]);
		sae->tmp->own_rejected_groups = groups;
	}

	if (pt->ec) {
		crypto_ec_point_deinit(sae->tmp->pwe_ecc, 1);
		sae->tmp->pwe_ecc = sae_derive_pwe_from_pt_ecc(pt, addr1,
							       addr2);
		if (!sae->tmp->pwe_ecc)
			return -1;
	}

	// if (pt->dh) {
	// 	crypto_bignum_deinit(sae->tmp->pwe_ffc, 1);
	// 	sae->tmp->pwe_ffc = sae_derive_pwe_from_pt_ffc(pt, addr1,
	// 						       addr2);
	// 	if (!sae->tmp->pwe_ffc)
	// 		return -1;
	// }

	sae->h2e = 1;
	return sae_derive_commit(sae);
}


static int sae_derive_k_ecc(struct sae_data *sae, u8 *k)
{
	struct crypto_ec_point *K;
	int ret = -1;

	K = crypto_ec_point_init(sae->tmp->ec);
	if (K == NULL)
		goto fail;

	/*
	 * K = scalar-op(rand, (elem-op(scalar-op(peer-commit-scalar, PWE),
	 *                                        PEER-COMMIT-ELEMENT)))
	 * If K is identity element (point-at-infinity), reject
	 * k = F(K) (= x coordinate)
	 */

	if (crypto_ec_point_mul_static(sae->tmp->ec, sae->tmp->pwe_ecc,
				sae->peer_commit_scalar, K) < 0 ||
	    crypto_ec_point_add(sae->tmp->ec, K,
				sae->tmp->peer_commit_element_ecc, K) < 0 ||
		crypto_ec_point_mul_static(sae->tmp->ec, K, sae->tmp->sae_rand, K) < 0 ||
	    crypto_ec_point_is_at_infinity(sae->tmp->ec, K) ||
	    crypto_ec_point_to_bin(sae->tmp->ec, K, k, NULL) < 0) {
		wpa_printf(DEBUG_flag, "SAE: Failed to calculate K and k");
		goto fail;
	}

	hexdump("SAE: k", k, sae->tmp->prime_len);

	ret = 0;
fail:
	crypto_ec_point_deinit(K, 1);
	return ret;
}


static int sae_kdf_hash(size_t hash_len, const u8 *k, const char *label,
			const u8 *context, size_t context_len,
			u8 *out, size_t out_len)
{
	if (hash_len == 32)
		return sha256_prf(k, hash_len, label,
				  context, context_len, out, out_len);
#ifdef CONFIG_SHA384
	if (hash_len == 48)
		return sha384_prf(k, hash_len, label,
				  context, context_len, out, out_len);
#endif /* CONFIG_SHA384 */
#ifdef CONFIG_SHA512
	if (hash_len == 64)
		return sha512_prf(k, hash_len, label,
				  context, context_len, out, out_len);
#endif /* CONFIG_SHA512 */
	return -1;
}


static int sae_derive_keys(struct sae_data *sae, const u8 *k)
{
	u8 zero[SAE_MAX_HASH_LEN], val[SAE_MAX_PRIME_LEN];
	const u8 *salt;
	struct wpabuf *rejected_groups = NULL;
	u8 keyseed[SAE_MAX_HASH_LEN];
	u8 keys[2 * SAE_MAX_HASH_LEN + SAE_PMK_LEN];
	struct crypto_bignum_static *tmp;
	int ret = -1;
	size_t hash_len, salt_len, prime_len = sae->tmp->prime_len;
	const u8 *addr[1];
	size_t len[1];

	tmp = crypto_bignum_static_init(prime_len);
	if (tmp == NULL)
		goto fail;

	/* keyseed = H(salt, k)
	 * KCK || PMK = KDF-Hash-Length(keyseed, "SAE KCK and PMK",
	 *                      (commit-scalar + peer-commit-scalar) modulo r)
	 * PMKID = L((commit-scalar + peer-commit-scalar) modulo r, 0, 128)
	 *
	 * When SAE-PK is used,
	 * KCK || PMK || KEK = KDF-Hash-Length(keyseed, "SAE-PK keys", context)
	 */
	if (!sae->h2e)
		hash_len = SHA256_MAC_LEN;
	// else if (sae->tmp->dh)
	// 	hash_len = sae_ffc_prime_len_2_hash_len(prime_len);
	else
		hash_len = sae_ecc_prime_len_2_hash_len(prime_len);
	if (sae->h2e && (sae->tmp->own_rejected_groups ||
			 sae->tmp->peer_rejected_groups)) {
		struct wpabuf *own, *peer;

		own = sae->tmp->own_rejected_groups;
		peer = sae->tmp->peer_rejected_groups;
		salt_len = 0;
		if (own)
			salt_len += wpabuf_len(own);
		if (peer)
			salt_len += wpabuf_len(peer);
		rejected_groups = wpabuf_alloc(salt_len);
		if (!rejected_groups)
			goto fail;
		if (sae->tmp->own_addr_higher) {
			if (own)
				wpabuf_put_buf(rejected_groups, own);
			if (peer)
				wpabuf_put_buf(rejected_groups, peer);
		} else {
			if (peer)
				wpabuf_put_buf(rejected_groups, peer);
			if (own)
				wpabuf_put_buf(rejected_groups, own);
		}
		salt = wpabuf_head(rejected_groups);
		salt_len = wpabuf_len(rejected_groups);
	} else {
		os_memset(zero, 0, hash_len);
		salt = zero;
		salt_len = hash_len;
	}
	hexdump("SAE: salt for keyseed derivation",
		    salt, salt_len);
	addr[0] = k;
	len[0] = prime_len;
	if (hkdf_extract(hash_len, salt, salt_len, 1, addr, len, keyseed) < 0)
		goto fail;
	hexdump("SAE: keyseed", keyseed, hash_len);

	if (crypto_bignum_static_addmod(sae->tmp->own_commit_scalar,
		sae->peer_commit_scalar, sae->tmp->order,  tmp) < 0)
		goto fail;
	/* IEEE Std 802.11-2016 is not exactly clear on the encoding of the bit
	 * string that is needed for KCK, PMK, and PMKID derivation, but it
	 * seems to make most sense to encode the
	 * (commit-scalar + peer-commit-scalar) mod r part as a bit string by
	 * zero padding it from left to the length of the order (in full
	 * octets). */
	crypto_bignum_static_to_bin(tmp, val, sizeof(val), sae->tmp->order_len);
	hexdump("SAE: PMKID", val, SAE_PMKID_LEN);

#ifdef CONFIG_SAE_PK
	if (sae->pk) {
		if (sae_kdf_hash(hash_len, keyseed, "SAE-PK keys",
				 val, sae->tmp->order_len,
				 keys, 2 * hash_len + SAE_PMK_LEN) < 0)
			goto fail;
	} else {
		if (sae_kdf_hash(hash_len, keyseed, "SAE KCK and PMK",
				 val, sae->tmp->order_len,
				 keys, hash_len + SAE_PMK_LEN) < 0)
			goto fail;
	}
#else /* CONFIG_SAE_PK */
	if (sae_kdf_hash(hash_len, keyseed, "SAE KCK and PMK",
			 val, sae->tmp->order_len,
			 keys, hash_len + SAE_PMK_LEN) < 0)
		goto fail;
#endif /* !CONFIG_SAE_PK */

	forced_memzero(keyseed, sizeof(keyseed));
	os_memcpy(sae->tmp->kck, keys, hash_len);
	sae->tmp->kck_len = hash_len;
	os_memcpy(sae->pmk, keys + hash_len, SAE_PMK_LEN);
	os_memcpy(sae->pmkid, val, SAE_PMKID_LEN);
#ifdef CONFIG_SAE_PK
	if (sae->pk) {
		os_memcpy(sae->tmp->kek, keys + hash_len + SAE_PMK_LEN,
			  hash_len);
		sae->tmp->kek_len = hash_len;
		hexdump("SAE: KEK for SAE-PK",
				sae->tmp->kek, sae->tmp->kek_len);
	}
#endif /* CONFIG_SAE_PK */
	forced_memzero(keys, sizeof(keys));
	hexdump("SAE: KCK",
			sae->tmp->kck, sae->tmp->kck_len);
	hexdump("SAE: PMK", sae->pmk, SAE_PMK_LEN);

	ret = 0;
fail:
	wpabuf_free(rejected_groups);
	crypto_bignum_static_deinit(tmp, 0);
	return ret;
}


int sae_process_commit(struct sae_data *sae)
{
	u8 k[SAE_MAX_PRIME_LEN];
	if (sae->tmp == NULL ||
	    (sae->tmp->ec && sae_derive_k_ecc(sae, k) < 0) ||
	    // (sae->tmp->dh && sae_derive_k_ffc(sae, k) < 0) ||
	    sae_derive_keys(sae, k) < 0)
		return -1;
	return 0;
}


int sae_write_commit(struct sae_data *sae, struct wpabuf *buf,
		     const struct wpabuf *token, const char *identifier)
{
	u8 *pos;

	if (sae->tmp == NULL)
		return -1;

	wpabuf_put_le16(buf, sae->group); /* Finite Cyclic Group */
	if (!sae->h2e && token) {
		wpabuf_put_buf(buf, token);
		hexdump("SAE: Anti-clogging token",
			    wpabuf_head(token), wpabuf_len(token));
	}
	pos = wpabuf_put(buf, sae->tmp->prime_len);
	if (crypto_bignum_static_to_bin(sae->tmp->own_commit_scalar, pos,
				 sae->tmp->prime_len, sae->tmp->prime_len) < 0)
		return -1;
	hexdump("SAE: own commit-scalar",
		    pos, sae->tmp->prime_len);
	if (sae->tmp->ec) {
		pos = wpabuf_put(buf, 2 * sae->tmp->prime_len);
		if (crypto_ec_point_to_bin(sae->tmp->ec,
					   sae->tmp->own_commit_element_ecc,
					   pos, pos + sae->tmp->prime_len) < 0)
			return -1;
		hexdump("SAE: own commit-element(x)",
			    pos, sae->tmp->prime_len);
		hexdump("SAE: own commit-element(y)",
			    pos + sae->tmp->prime_len, sae->tmp->prime_len);
	} else {
		// pos = wpabuf_put(buf, sae->tmp->prime_len);
		// if (crypto_bignum_static_to_bin(sae->tmp->own_commit_element_ffc, pos,
		// 			 sae->tmp->prime_len,
		// 			 sae->tmp->prime_len) < 0)
		// 	return -1;
		// hexdump("SAE: own commit-element",
		// 	    pos, sae->tmp->prime_len);
	}

	if (identifier) {
		/* Password Identifier element */
		wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
		wpabuf_put_u8(buf, 1 + os_strlen(identifier));
		wpabuf_put_u8(buf, WLAN_EID_EXT_PASSWORD_IDENTIFIER);
		wpabuf_put_str(buf, identifier);
		wpa_printf(DEBUG_flag, "SAE: own Password Identifier: %s",
			   identifier);
	}

	if (sae->h2e && sae->tmp->own_rejected_groups) {
		// wpa_hexdump_buf(DEBUG, "SAE: own Rejected Groups",
		// 		sae->tmp->own_rejected_groups);
		wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
		wpabuf_put_u8(buf,
			      1 + wpabuf_len(sae->tmp->own_rejected_groups));
		wpabuf_put_u8(buf, WLAN_EID_EXT_REJECTED_GROUPS);
		wpabuf_put_buf(buf, sae->tmp->own_rejected_groups);
	}

	if (sae->h2e && token) {
		wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
		wpabuf_put_u8(buf, 1 + wpabuf_len(token));
		wpabuf_put_u8(buf, WLAN_EID_EXT_ANTI_CLOGGING_TOKEN);
		wpabuf_put_buf(buf, token);
		// wpa_hexdump_buf(DEBUG,
		// 		"SAE: Anti-clogging token (in container)",
		// 		token);
	}

	return 0;
}


u16 sae_group_allowed(struct sae_data *sae, int *allowed_groups, u16 group)
{
	if (allowed_groups) {
		int i;
		for (i = 0; allowed_groups[i] > 0; i++) {
			if (allowed_groups[i] == group)
				break;
		}
		if (allowed_groups[i] != group) {
			wpa_printf(DEBUG_flag, "SAE: Proposed group %u not "
				   "enabled in the current configuration",
				   group);
			return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
		}
	}

	if (sae->state == SAE_COMMITTED && group != sae->group) {
		wpa_printf(DEBUG_flag, "SAE: Do not allow group to be changed");
		return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
	}

	if (group != sae->group && sae_set_group(sae, group) < 0) {
		wpa_printf(DEBUG_flag, "SAE: Unsupported Finite Cyclic Group %u",
			   group);
		return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
	}

	if (sae->tmp == NULL) {
		wpa_printf(DEBUG_flag, "SAE: Group information not yet initialized");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	// if (sae->tmp->dh && !allowed_groups) {
	// 	wpa_printf(DEBUG_flag, "SAE: Do not allow FFC group %u without "
	// 		   "explicit configuration enabling it", group);
	// 	return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
	// }

	return WLAN_STATUS_SUCCESS;
}


static int sae_is_password_id_elem(const u8 *pos, const u8 *end)
{
	return end - pos >= 3 &&
		pos[0] == WLAN_EID_EXTENSION &&
		pos[1] >= 1 &&
		end - pos - 2 >= pos[1] &&
		pos[2] == WLAN_EID_EXT_PASSWORD_IDENTIFIER;
}


static int sae_is_rejected_groups_elem(const u8 *pos, const u8 *end)
{
	return end - pos >= 3 &&
		pos[0] == WLAN_EID_EXTENSION &&
		pos[1] >= 2 &&
		end - pos - 2 >= pos[1] &&
		pos[2] == WLAN_EID_EXT_REJECTED_GROUPS;
}


static int sae_is_token_container_elem(const u8 *pos, const u8 *end)
{
	return end - pos >= 3 &&
		pos[0] == WLAN_EID_EXTENSION &&
		pos[1] >= 1 &&
		end - pos - 2 >= pos[1] &&
		pos[2] == WLAN_EID_EXT_ANTI_CLOGGING_TOKEN;
}


static void sae_parse_commit_token(struct sae_data *sae, const u8 **pos,
				   const u8 *end, const u8 **token,
				   size_t *token_len, int h2e)
{
	size_t scalar_elem_len, tlen;

	if (token)
		*token = NULL;
	if (token_len)
		*token_len = 0;

	if (h2e)
		return; /* No Anti-Clogging Token field outside container IE */

	scalar_elem_len = (sae->tmp->ec ? 3 : 2) * sae->tmp->prime_len;
	if (scalar_elem_len >= (size_t) (end - *pos))
		return; /* No extra data beyond peer scalar and element */

	tlen = end - (*pos + scalar_elem_len);

	if (tlen < SHA256_MAC_LEN) {
		wpa_printf(DEBUG_flag,
			   "SAE: Too short optional data (%u octets) to include our Anti-Clogging Token",
			   (unsigned int) tlen);
		return;
	}

	hexdump("SAE: Anti-Clogging Token", *pos, tlen);
	if (token)
		*token = *pos;
	if (token_len)
		*token_len = tlen;
	*pos += tlen;
}


static void sae_parse_token_container(struct sae_data *sae,
				      const u8 *pos, const u8 *end,
				      const u8 **token, size_t *token_len)
{
	hexdump("SAE: Possible elements at the end of the frame",
		    pos, end - pos);
	if (!sae_is_token_container_elem(pos, end))
		return;
	*token = pos + 3;
	*token_len = pos[1] - 1;
	hexdump("SAE: Anti-Clogging Token (in container)",
		    *token, *token_len);
}


static u16 sae_parse_commit_scalar(struct sae_data *sae, const u8 **pos,
				   const u8 *end)
{
	struct crypto_bignum_static *peer_scalar;

	if (sae->tmp->prime_len > end - *pos) {
		wpa_printf(DEBUG_flag, "SAE: Not enough data for scalar");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	peer_scalar = crypto_bignum_static_init_set(*pos, sae->tmp->prime_len, sae->tmp->prime_len);
	if (peer_scalar == NULL)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	/*
	 * IEEE Std 802.11-2012, 11.3.8.6.1: If there is a protocol instance for
	 * the peer and it is in Authenticated state, the new Commit Message
	 * shall be dropped if the peer-scalar is identical to the one used in
	 * the existing protocol instance.
	 */
	if (sae->state == SAE_ACCEPTED && sae->peer_commit_scalar_accepted &&
	    crypto_bignum_static_cmp(sae->peer_commit_scalar_accepted,
			      peer_scalar) == 0) {
		wpa_printf(DEBUG_flag, "SAE: Do not accept re-use of previous "
			   "peer-commit-scalar");
		crypto_bignum_static_deinit(peer_scalar, 0);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	/* 1 < scalar < r */
	if (crypto_bignum_static_is_zero(peer_scalar) ||
	    crypto_bignum_static_is_one(peer_scalar) ||
	    crypto_bignum_static_cmp(peer_scalar, sae->tmp->order) >= 0) {
		wpa_printf(DEBUG_flag, "SAE: Invalid peer scalar");
		crypto_bignum_static_deinit(peer_scalar, 0);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}


	crypto_bignum_static_deinit(sae->peer_commit_scalar, 0);
	sae->peer_commit_scalar = peer_scalar;
	hexdump("SAE: Peer commit-scalar",
		    *pos, sae->tmp->prime_len);
	*pos += sae->tmp->prime_len;

	return WLAN_STATUS_SUCCESS;
}


static u16 sae_parse_commit_element_ecc(struct sae_data *sae, const u8 **pos,
					const u8 *end)
{
	u8 prime[SAE_MAX_ECC_PRIME_LEN];

	if (2 * sae->tmp->prime_len > end - *pos) {
		wpa_printf(DEBUG_flag, "SAE: Not enough data for "
			   "commit-element");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (crypto_bignum_static_to_bin(sae->tmp->prime, prime, sizeof(prime),
				 sae->tmp->prime_len) < 0)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	/* element x and y coordinates < p */
	if (os_memcmp(*pos, prime, sae->tmp->prime_len) >= 0 ||
	    os_memcmp(*pos + sae->tmp->prime_len, prime,
		      sae->tmp->prime_len) >= 0) {
		wpa_printf(DEBUG_flag, "SAE: Invalid coordinates in peer "
			   "element");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	hexdump("SAE: Peer commit-element(x)",
		    *pos, sae->tmp->prime_len);
	hexdump("SAE: Peer commit-element(y)",
		    *pos + sae->tmp->prime_len, sae->tmp->prime_len);

	crypto_ec_point_deinit(sae->tmp->peer_commit_element_ecc, 0);
	sae->tmp->peer_commit_element_ecc =
		crypto_ec_point_from_bin(sae->tmp->ec, *pos);
	if (sae->tmp->peer_commit_element_ecc == NULL)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	if (!crypto_ec_point_is_on_curve(sae->tmp->ec,
					 sae->tmp->peer_commit_element_ecc)) {
		wpa_printf(DEBUG_flag, "SAE: Peer element is not on curve");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	*pos += 2 * sae->tmp->prime_len;

	return WLAN_STATUS_SUCCESS;
}




static u16 sae_parse_commit_element(struct sae_data *sae, const u8 **pos,
				    const u8 *end)
{
	// if (sae->tmp->dh)
	// 	return sae_parse_commit_element_ffc(sae, pos, end);
	return sae_parse_commit_element_ecc(sae, pos, end);
}


static int sae_parse_password_identifier(struct sae_data *sae,
					 const u8 **pos, const u8 *end)
{
	const u8 *epos;
	u8 len;

	hexdump("SAE: Possible elements at the end of the frame",
		    *pos, end - *pos);
	if (!sae_is_password_id_elem(*pos, end)) {
		if (sae->tmp->pw_id) {
			wpa_printf(DEBUG_flag,
				   "SAE: No Password Identifier included, but expected one (%s)",
				   sae->tmp->pw_id);
			return WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER;
		}
		os_free(sae->tmp->pw_id);
		sae->tmp->pw_id = NULL;
		return WLAN_STATUS_SUCCESS; /* No Password Identifier */
	}

	epos = *pos;
	epos++; /* skip IE type */
	len = *epos++; /* IE length */
	if (len > end - epos || len < 1)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	epos++; /* skip ext ID */
	len--;

	if (sae->tmp->pw_id &&
	    (len != os_strlen(sae->tmp->pw_id) ||
	     os_memcmp(sae->tmp->pw_id, epos, len) != 0)) {
		wpa_printf(DEBUG_flag,
			   "SAE: The included Password Identifier does not match the expected one (%s)",
			   sae->tmp->pw_id);
		return WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER;
	}

	os_free(sae->tmp->pw_id);
	sae->tmp->pw_id = os_malloc(len + 1);
	if (!sae->tmp->pw_id)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	os_memcpy(sae->tmp->pw_id, epos, len);
	sae->tmp->pw_id[len] = '\0';
	// wpa_hexdump_ascii(DEBUG, "SAE: Received Password Identifier",
	// 		  sae->tmp->pw_id, len);
	*pos = epos + len;
	return WLAN_STATUS_SUCCESS;
}


static int sae_parse_rejected_groups(struct sae_data *sae,
				     const u8 **pos, const u8 *end)
{
	const u8 *epos;
	u8 len;

	hexdump("SAE: Possible elements at the end of the frame",
		    *pos, end - *pos);
	if (!sae_is_rejected_groups_elem(*pos, end))
		return WLAN_STATUS_SUCCESS;

	epos = *pos;
	epos++; /* skip IE type */
	len = *epos++; /* IE length */
	if (len > end - epos || len < 1)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	epos++; /* skip ext ID */
	len--;

	wpabuf_free(sae->tmp->peer_rejected_groups);
	sae->tmp->peer_rejected_groups = wpabuf_alloc(len);
	if (!sae->tmp->peer_rejected_groups)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	wpabuf_put_data(sae->tmp->peer_rejected_groups, epos, len);
	// wpa_hexdump_buf(DEBUG, "SAE: Received Rejected Groups list",
	// 		sae->tmp->peer_rejected_groups);
	*pos = epos + len;
	return WLAN_STATUS_SUCCESS;
}


u16 sae_parse_commit(struct sae_data *sae, const u8 *data, size_t len,
		     const u8 **token, size_t *token_len, int *allowed_groups,
		     int h2e)
{
	const u8 *pos = data, *end = data + len;
	u16 res;

	/* Check Finite Cyclic Group */
	if (end - pos < 2)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	res = sae_group_allowed(sae, allowed_groups, WPA_GET_LE16(pos));
	if (res != WLAN_STATUS_SUCCESS)
		return res;
	pos += 2;

	/* Optional Anti-Clogging Token */
	sae_parse_commit_token(sae, &pos, end, token, token_len, h2e);

	/* commit-scalar */
	res = sae_parse_commit_scalar(sae, &pos, end);
	if (res != WLAN_STATUS_SUCCESS)
		return res;

	/* commit-element */
	res = sae_parse_commit_element(sae, &pos, end);
	if (res != WLAN_STATUS_SUCCESS)
		return res;

	/* Optional Password Identifier element */
	res = sae_parse_password_identifier(sae, &pos, end);
	if (res != WLAN_STATUS_SUCCESS)
		return res;

	/* Conditional Rejected Groups element */
	if (h2e) {
		res = sae_parse_rejected_groups(sae, &pos, end);
		if (res != WLAN_STATUS_SUCCESS)
			return res;
	}

	/* Optional Anti-Clogging Token Container element */
	if (h2e)
		sae_parse_token_container(sae, pos, end, token, token_len);

	/*
	 * Check whether peer-commit-scalar and PEER-COMMIT-ELEMENT are same as
	 * the values we sent which would be evidence of a reflection attack.
	 */
	if (!sae->tmp->own_commit_scalar ||
	    crypto_bignum_static_cmp(sae->tmp->own_commit_scalar,
			      sae->peer_commit_scalar) != 0 ||
	    // (sae->tmp->dh &&
	    //  (!sae->tmp->own_commit_element_ffc ||
	    //   crypto_bignum_cmp(sae->tmp->own_commit_element_ffc,
		// 		sae->tmp->peer_commit_element_ffc) != 0)) ||
	    (sae->tmp->ec &&
	     (!sae->tmp->own_commit_element_ecc ||
	      crypto_ec_point_cmp(sae->tmp->ec,
				  sae->tmp->own_commit_element_ecc,
				  sae->tmp->peer_commit_element_ecc) != 0)))
		return WLAN_STATUS_SUCCESS; /* scalars/elements are different */

	/*
	 * This is a reflection attack - return special value to trigger caller
	 * to silently discard the frame instead of replying with a specific
	 * status code.
	 */
	return SAE_SILENTLY_DISCARD;
}


static int sae_cn_confirm(struct sae_data *sae, const u8 *sc,
			  const struct crypto_bignum_static*scalar1,
			  const u8 *element1, size_t element1_len,
			  const struct crypto_bignum_static*scalar2,
			  const u8 *element2, size_t element2_len,
			  u8 *confirm)
{
	const u8 *addr[5];
	size_t len[5];
	u8 scalar_b1[SAE_MAX_PRIME_LEN], scalar_b2[SAE_MAX_PRIME_LEN];

	/* Confirm
	 * CN(key, X, Y, Z, ...) =
	 *    HMAC-SHA256(key, D2OS(X) || D2OS(Y) || D2OS(Z) | ...)
	 * confirm = CN(KCK, send-confirm, commit-scalar, COMMIT-ELEMENT,
	 *              peer-commit-scalar, PEER-COMMIT-ELEMENT)
	 * verifier = CN(KCK, peer-send-confirm, peer-commit-scalar,
	 *               PEER-COMMIT-ELEMENT, commit-scalar, COMMIT-ELEMENT)
	 */
	if (crypto_bignum_static_to_bin(scalar1, scalar_b1, sizeof(scalar_b1),
				 sae->tmp->prime_len) < 0 ||
	    crypto_bignum_static_to_bin(scalar2, scalar_b2, sizeof(scalar_b2),
				 sae->tmp->prime_len) < 0)
		return -1;
	addr[0] = sc;
	len[0] = 2;
	addr[1] = scalar_b1;
	len[1] = sae->tmp->prime_len;
	addr[2] = element1;
	len[2] = element1_len;
	addr[3] = scalar_b2;
	len[3] = sae->tmp->prime_len;
	addr[4] = element2;
	len[4] = element2_len;
	return hkdf_extract(sae->tmp->kck_len, sae->tmp->kck, sae->tmp->kck_len,
			    5, addr, len, confirm);
}


static int sae_cn_confirm_ecc(struct sae_data *sae, const u8 *sc,
			      const struct crypto_bignum_static *scalar1,
			      const struct crypto_ec_point *element1,
			      const struct crypto_bignum_static *scalar2,
			      const struct crypto_ec_point *element2,
			      u8 *confirm)
{
	u8 element_b1[2 * SAE_MAX_ECC_PRIME_LEN];
	u8 element_b2[2 * SAE_MAX_ECC_PRIME_LEN];

	if (crypto_ec_point_to_bin(sae->tmp->ec, element1, element_b1,
				   element_b1 + sae->tmp->prime_len) < 0 ||
	    crypto_ec_point_to_bin(sae->tmp->ec, element2, element_b2,
				   element_b2 + sae->tmp->prime_len) < 0 ||
	    sae_cn_confirm(sae, sc, scalar1, element_b1,
			   2 * sae->tmp->prime_len,
			   scalar2, element_b2, 2 * sae->tmp->prime_len,
			   confirm) < 0)
		return -1;
	return 0;
}


// static int sae_cn_confirm_ffc(struct sae_data *sae, const u8 *sc,
// 			      const struct crypto_bignum *scalar1,
// 			      const struct crypto_bignum *element1,
// 			      const struct crypto_bignum *scalar2,
// 			      const struct crypto_bignum *element2,
// 			      u8 *confirm)
// {
// 	u8 element_b1[SAE_MAX_PRIME_LEN];
// 	u8 element_b2[SAE_MAX_PRIME_LEN];

// 	if (crypto_bignum_to_bin(element1, element_b1, sizeof(element_b1),
// 				 sae->tmp->prime_len) < 0 ||
// 	    crypto_bignum_to_bin(element2, element_b2, sizeof(element_b2),
// 				 sae->tmp->prime_len) < 0 ||
// 	    sae_cn_confirm(sae, sc, scalar1, element_b1, sae->tmp->prime_len,
// 			   scalar2, element_b2, sae->tmp->prime_len,
// 			   confirm) < 0)
// 		return -1;
// 	return 0;
// }


int sae_write_confirm(struct sae_data *sae, struct wpabuf *buf)
{
	const u8 *sc;
	size_t hash_len;
	int res = -1;

	if (sae->tmp == NULL)
		return -1;

	hash_len = sae->tmp->kck_len;

	/* Send-Confirm */
	if (sae->send_confirm < 0xffff)
		sae->send_confirm++;
	sc = wpabuf_put(buf, 0);
	wpabuf_put_le16(buf, sae->send_confirm);

	if (sae->tmp->ec)
		res = sae_cn_confirm_ecc(sae, sc, sae->tmp->own_commit_scalar,
					 sae->tmp->own_commit_element_ecc,
					 sae->peer_commit_scalar,
					 sae->tmp->peer_commit_element_ecc,
					 wpabuf_put(buf, hash_len));
	// else
	// 	res = sae_cn_confirm_ffc(sae, sc, sae->tmp->own_commit_scalar,
	// 				 sae->tmp->own_commit_element_ffc,
	// 				 sae->peer_commit_scalar,
	// 				 sae->tmp->peer_commit_element_ffc,
	// 				 wpabuf_put(buf, hash_len));
	if (res)
		return res;

#ifdef CONFIG_SAE_PK
	if (sae_write_confirm_pk(sae, buf) < 0)
		return -1;
#endif /* CONFIG_SAE_PK */

	return 0;
}


int sae_check_confirm(struct sae_data *sae, const u8 *data, size_t len)
{
	u8 verifier[SAE_MAX_HASH_LEN];
	size_t hash_len;

	if (!sae->tmp)
		return -1;

	hash_len = sae->tmp->kck_len;
	if (len < 2 + hash_len) {
		wpa_printf(DEBUG_flag, "SAE: Too short confirm message");
		return -1;
	}

	wpa_printf(DEBUG_flag, "SAE: peer-send-confirm %u", WPA_GET_LE16(data));

	if (!sae->peer_commit_scalar || !sae->tmp->own_commit_scalar) {
		wpa_printf(DEBUG_flag, "SAE: Temporary data not yet available");
		return -1;
	}

	if (sae->tmp->ec) {
		if (!sae->tmp->peer_commit_element_ecc ||
		    !sae->tmp->own_commit_element_ecc ||
		    sae_cn_confirm_ecc(sae, data, sae->peer_commit_scalar,
				       sae->tmp->peer_commit_element_ecc,
				       sae->tmp->own_commit_scalar,
				       sae->tmp->own_commit_element_ecc,
				       verifier) < 0)
			return -1;
	} 
	// else {
	// 	if (!sae->tmp->peer_commit_element_ffc ||
	// 	    !sae->tmp->own_commit_element_ffc ||
	// 	    sae_cn_confirm_ffc(sae, data, sae->peer_commit_scalar,
	// 			       sae->tmp->peer_commit_element_ffc,
	// 			       sae->tmp->own_commit_scalar,
	// 			       sae->tmp->own_commit_element_ffc,
	// 			       verifier) < 0)
	// 		return -1;
	// }
	
	if (os_memcmp_const(verifier, data + 2, hash_len) != 0) {
		wpa_printf(DEBUG_flag, "SAE: Confirm mismatch");
		hexdump( "SAE: Received confirm",
			    data + 2, hash_len);
		hexdump("SAE: Calculated verifier",
			    verifier, hash_len);
		return -1;
	}

#ifdef CONFIG_SAE_PK
	if (sae_check_confirm_pk(sae, data + 2 + hash_len,
				 len - 2 - hash_len) < 0)
		return -1;
#endif /* CONFIG_SAE_PK */

	return 0;
}


const char * sae_state_txt(enum sae_state state)
{
	switch (state) {
	case SAE_NOTHING:
		return "Nothing";
	case SAE_COMMITTED:
		return "Committed";
	case SAE_CONFIRMED:
		return "Confirmed";
	case SAE_ACCEPTED:
		return "Accepted";
	}
	return "?";
}
