/* This file only contains some structure instanciation and tests to see if
 * everything is working as intended.
 * None of the following code needs to be implemented in HaCl*
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sae.h"
#include "wpabuf.h"
#include "crypto.h"
#include "crypto_bignum_static.h"

#define SSID "My SSID"
#define GRP_ID 19
#define NB_TESTS 1000
static const uint8_t macA[] = { 0x98, 0xe7, 0x43, 0xd8, 0x6f, 0xbd };
static const uint8_t macB[] = { 0x04, 0xed, 0x33, 0xc0, 0x85, 0x9b };

static int sae_tests(void)
{
	struct sae_data sae;
	int ret = -1;
	/* IEEE Std 802.11-2020, Annex J.10 */
	const u8 addr1[ETH_ALEN] = { 0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87 };
	const u8 addr2[ETH_ALEN] = { 0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c };
	const char *ssid = "byteme";
	const char *pw = "mekmitasdigoat";
	const char *pwid = "psk4internet";
	const u8 local_rand[] = {
		0x99, 0x24, 0x65, 0xfd, 0x3d, 0xaa, 0x3c, 0x60,
		0xaa, 0x65, 0x65, 0xb7, 0xf6, 0x2a, 0x2a, 0x7f,
		0x2e, 0x12, 0xdd, 0x12, 0xf1, 0x98, 0xfa, 0xf4,
		0xfb, 0xed, 0x89, 0xd7, 0xff, 0x1a, 0xce, 0x94
	};
	const u8 local_mask[] = {
		0x95, 0x07, 0xa9, 0x0f, 0x77, 0x7a, 0x04, 0x4d,
		0x6a, 0x08, 0x30, 0xb9, 0x1e, 0xa3, 0xd5, 0xdd,
		0x70, 0xbe, 0xce, 0x44, 0xe1, 0xac, 0xff, 0xb8,
		0x69, 0x83, 0xb5, 0xe1, 0xbf, 0x9f, 0xb3, 0x22
	};
	const u8 local_commit[] = {
		0x13, 0x00, 0x2e, 0x2c, 0x0f, 0x0d, 0xb5, 0x24,
		0x40, 0xad, 0x14, 0x6d, 0x96, 0x71, 0x14, 0xce,
		0x00, 0x5c, 0xe1, 0xea, 0xb0, 0xaa, 0x2c, 0x2e,
		0x5c, 0x28, 0x71, 0xb7, 0x74, 0xf6, 0xc2, 0x57,
		0x5c, 0x65, 0xd5, 0xad, 0x9e, 0x00, 0x82, 0x97,
		0x07, 0xaa, 0x36, 0xba, 0x8b, 0x85, 0x97, 0x38,
		0xfc, 0x96, 0x1d, 0x08, 0x24, 0x35, 0x05, 0xf4,
		0x7c, 0x03, 0x53, 0x76, 0xd7, 0xac, 0x4b, 0xc8,
		0xd7, 0xb9, 0x50, 0x83, 0xbf, 0x43, 0x82, 0x7d,
		0x0f, 0xc3, 0x1e, 0xd7, 0x78, 0xdd, 0x36, 0x71,
		0xfd, 0x21, 0xa4, 0x6d, 0x10, 0x91, 0xd6, 0x4b,
		0x6f, 0x9a, 0x1e, 0x12, 0x72, 0x62, 0x13, 0x25,
		0xdb, 0xe1
	};
	const u8 peer_commit[] = {
		0x13, 0x00, 0x59, 0x1b, 0x96, 0xf3, 0x39, 0x7f,
		0xb9, 0x45, 0x10, 0x08, 0x48, 0xe7, 0xb5, 0x50,
		0x54, 0x3b, 0x67, 0x20, 0xd8, 0x83, 0x37, 0xee,
		0x93, 0xfc, 0x49, 0xfd, 0x6d, 0xf7, 0xe0, 0x8b,
		0x52, 0x23, 0xe7, 0x1b, 0x9b, 0xb0, 0x48, 0xd3,
		0x87, 0x3f, 0x20, 0x55, 0x69, 0x53, 0xa9, 0x6c,
		0x91, 0x53, 0x6f, 0xd8, 0xee, 0x6c, 0xa9, 0xb4,
		0xa6, 0x8a, 0x14, 0x8b, 0x05, 0x6a, 0x90, 0x9b,
		0xe0, 0x3e, 0x83, 0xae, 0x20, 0x8f, 0x60, 0xf8,
		0xef, 0x55, 0x37, 0x85, 0x80, 0x74, 0xdb, 0x06,
		0x68, 0x70, 0x32, 0x39, 0x98, 0x62, 0x99, 0x9b,
		0x51, 0x1e, 0x0a, 0x15, 0x52, 0xa5, 0xfe, 0xa3,
		0x17, 0xc2
	};
	const u8 kck[] = {
		0x1e, 0x73, 0x3f, 0x6d, 0x9b, 0xd5, 0x32, 0x56,
		0x28, 0x73, 0x04, 0x33, 0x88, 0x31, 0xb0, 0x9a,
		0x39, 0x40, 0x6d, 0x12, 0x10, 0x17, 0x07, 0x3a,
		0x5c, 0x30, 0xdb, 0x36, 0xf3, 0x6c, 0xb8, 0x1a
	};
	const u8 pmk[] = {
		0x4e, 0x4d, 0xfa, 0xb1, 0xa2, 0xdd, 0x8a, 0xc1,
		0xa9, 0x17, 0x90, 0xf9, 0x53, 0xfa, 0xaa, 0x45,
		0x2a, 0xe5, 0xc6, 0x87, 0x3a, 0xb7, 0x5b, 0x63,
		0x60, 0x5b, 0xa6, 0x63, 0xf8, 0xa7, 0xfe, 0x59
	};
	const u8 pmkid[] = {
		0x87, 0x47, 0xa6, 0x00, 0xee, 0xa3, 0xf9, 0xf2,
		0x24, 0x75, 0xdf, 0x58, 0xca, 0x1e, 0x54, 0x98
	};
	struct wpabuf *buf = NULL;
	struct crypto_bignum_static *mask = NULL;
	const u8 pwe_19_x[32] = {
		0xc9, 0x30, 0x49, 0xb9, 0xe6, 0x40, 0x00, 0xf8,
		0x48, 0x20, 0x16, 0x49, 0xe9, 0x99, 0xf2, 0xb5,
		0xc2, 0x2d, 0xea, 0x69, 0xb5, 0x63, 0x2c, 0x9d,
		0xf4, 0xd6, 0x33, 0xb8, 0xaa, 0x1f, 0x6c, 0x1e
	};
	const u8 pwe_19_y[32] = {
		0x73, 0x63, 0x4e, 0x94, 0xb5, 0x3d, 0x82, 0xe7,
		0x38, 0x3a, 0x8d, 0x25, 0x81, 0x99, 0xd9, 0xdc,
		0x1a, 0x5e, 0xe8, 0x26, 0x9d, 0x06, 0x03, 0x82,
		0xcc, 0xbf, 0x33, 0xe6, 0x14, 0xff, 0x59, 0xa0
	};
	int pt_groups[] = { 19, 0 };
	struct sae_pt *pt_info = NULL, *pt;
	const u8 addr1b[ETH_ALEN] = { 0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e };
	const u8 addr2b[ETH_ALEN] = { 0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46 };

	os_memset(&sae, 0, sizeof(sae));
	buf = wpabuf_alloc(1000);
	if (!buf ||
	    sae_set_group(&sae, 19) < 0 ||
	    sae_prepare_commit(addr1, addr2, (const u8 *) pw, os_strlen(pw),
			       &sae) < 0)
		goto fail;

	/* Override local values based on SAE test vector */
	crypto_bignum_static_deinit(sae.tmp->sae_rand, 1);
	sae.tmp->sae_rand = crypto_bignum_static_init_set(local_rand,
						   sizeof(local_rand), sizeof(local_rand));
	mask = crypto_bignum_static_init_set(local_mask, sizeof(local_mask), sizeof(local_mask));
	if (crypto_bignum_static_addmod(sae.tmp->sae_rand, mask, sae.tmp->order,
			      sae.tmp->own_commit_scalar) < 0 ||
	    crypto_bignum_static_mod(sae.tmp->own_commit_scalar, sae.tmp->order,
			      sae.tmp->own_commit_scalar) < 0 ||
	    crypto_ec_point_mul_static(sae.tmp->ec, sae.tmp->pwe_ecc, mask,
				sae.tmp->own_commit_element_ecc) < 0 ||
	    crypto_ec_point_invert(sae.tmp->ec,
				   sae.tmp->own_commit_element_ecc) < 0)
		goto fail;

	/* Check that output matches the test vector */
	if (sae_write_commit(&sae, buf, NULL, NULL) < 0)
		goto fail;
	// hexdump("SAE: Commit message", buf, wpabuf_len(buf));

	if (wpabuf_len(buf) != sizeof(local_commit) ||
	    os_memcmp(wpabuf_head(buf), local_commit,
		      sizeof(local_commit)) != 0) {
		wpa_printf(DEBUG_flag, "SAE: Mismatch in local commit");
		goto fail;
	}

	if (sae_parse_commit(&sae, peer_commit, sizeof(peer_commit), NULL, NULL,
			     NULL, 0) != 0 ||
	    sae_process_commit(&sae) < 0)
		goto fail;

	if (os_memcmp(kck, sae.tmp->kck, SAE_KCK_LEN) != 0) {
		wpa_printf(DEBUG_flag, "SAE: Mismatch in KCK");
		goto fail;
	}

	if (os_memcmp(pmk, sae.pmk, SAE_PMK_LEN) != 0) {
		wpa_printf(DEBUG_flag, "SAE: Mismatch in PMK");
		goto fail;
	}

	if (os_memcmp(pmkid, sae.pmkid, SAE_PMKID_LEN) != 0) {
		wpa_printf(DEBUG_flag, "SAE: Mismatch in PMKID");
		goto fail;
	}

	pt_info = sae_derive_pt(pt_groups,
				(const u8 *) ssid, os_strlen(ssid),
				(const u8 *) pw, os_strlen(pw), pwid);
	if (!pt_info)
		goto fail;

	for (pt = pt_info; pt; pt = pt->next) {
		if (pt->group == 19) {
			struct crypto_ec_point *pwe;
			u8 bin[SAE_MAX_ECC_PRIME_LEN * 2];
			size_t prime_len = sizeof(pwe_19_x);

			pwe = sae_derive_pwe_from_pt_ecc(pt, addr1b, addr2b);
			if (!pwe) {
				wpa_printf(DEBUG_flag,
					"SAE: PT/PWE no PWE");
				sae_deinit_pt(pt);
				goto fail;
			}
			if (crypto_ec_point_to_bin(pt->ec, pwe, bin,
						   bin + prime_len) < 0 ||
			    os_memcmp(pwe_19_x, bin, prime_len) != 0 ||
			    os_memcmp(pwe_19_y, bin + prime_len,
				      prime_len) != 0) {
				wpa_printf(DEBUG_flag,
					   "SAE: PT/PWE test vector mismatch");
				crypto_ec_point_deinit(pwe, 1);
				sae_deinit_pt(pt);
				goto fail;
			}
			crypto_ec_point_deinit(pwe, 1);
		}
	}

	sae_deinit_pt(pt_info);

	ret = 0;
fail:
	sae_clear_data(&sae);
	wpabuf_free(buf);
	crypto_bignum_static_deinit(mask, 1);
	return ret;
}

static struct wpabuf* auth_build_sae_commit(struct sae_data* sae, char* pwd, char* pwd_id, struct sae_pt* pt) {
	struct wpabuf* buf;
	int use_pt = 0;
	size_t pwd_len = strlen(pwd);

	use_pt = pt != NULL;

	if (use_pt &&
		sae_prepare_commit_pt(sae, pt, macA, macB,
			NULL, NULL) < 0) {
		sae_deinit_pt(pt);
		return NULL;
	}
	if (!use_pt &&
		sae_prepare_commit(macA, macB, (const u8*) pwd, pwd_len,
			sae) < 0) {
		fprintf(stderr, "SAE: Could not pick PWE\n");
		return NULL;
	}

	buf = wpabuf_alloc(SAE_COMMIT_MAX_LEN +
		(pwd_id ? 3 + strlen(pwd_id) : 0));
	if (buf &&
		sae_write_commit(sae, buf, sae->tmp ?
			sae->tmp->anti_clogging_token : NULL,
			pwd_id) < 0) {
		wpabuf_free(buf);
		buf = NULL;
	}

	return buf;
}


static struct wpabuf* auth_build_sae_confirm(struct sae_data* sae) {
	struct wpabuf* buf;

	buf = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
	if (buf == NULL)
		return NULL;

	if (sae_write_confirm(sae, buf) < 0) {
		wpabuf_free(buf);
		return NULL;
	}

	return buf;
}

static int sae_test_custom(int group_id, char* pwd, char* pwd_id, struct sae_pt* pt) {
	int err = -1;
	struct sae_data saeA, saeB;

	struct wpabuf* commitA = NULL, * commitB = NULL;
	struct wpabuf* confirmA = NULL, * confirmB = NULL;

	int h2e = pwd_id != NULL;

	memset(&saeA, 0, sizeof(saeA));
	memset(&saeB, 0, sizeof(saeB));

	// Set the group
	err = sae_set_group(&saeA, group_id);
	if (err) goto end;
	err = sae_set_group(&saeB, group_id);
	if (err) goto end;

	// Both part compute the commit message
	commitA = auth_build_sae_commit(&saeA, pwd, pwd_id, pt);
	if (commitA == NULL) goto end;
	commitB = auth_build_sae_commit(&saeB, pwd, pwd_id, pt);
	if (commitB == NULL) goto end;

	// Both part receive the commit, parse it, and process it
	err = sae_parse_commit(&saeA, wpabuf_mhead_u8(commitB), wpabuf_len(commitB),
		NULL, NULL, NULL, h2e);
	if (err < 0)  goto end;
	err = sae_process_commit(&saeA);
	if (err != 0) goto end;
	err = sae_parse_commit(&saeB, wpabuf_mhead_u8(commitA), wpabuf_len(commitA),
		NULL, NULL, NULL, h2e);
	if (err < 0) goto end;
	err = sae_process_commit(&saeB);
	if (err != 0) goto end;

	// Build the confirmation message
	confirmA = auth_build_sae_confirm(&saeA);
	if (confirmA == NULL) goto end;
	confirmB = auth_build_sae_confirm(&saeB);
	if (confirmB == NULL) goto end;

	// Both part verify the confirmation message of the other
	err = sae_check_confirm(&saeA, wpabuf_mhead_u8(confirmB), wpabuf_len(confirmB));
	if (err != 0) goto end;
	err = sae_check_confirm(&saeB, wpabuf_mhead_u8(confirmA), wpabuf_len(confirmA));
	if (err != 0) goto end;

end:
	sae_clear_data(&saeA);
	sae_clear_data(&saeB);
	if (commitA) wpabuf_free(commitA);
	if (commitB) wpabuf_free(commitB);
	if (confirmA) wpabuf_free(confirmA);
	if (confirmB) wpabuf_free(confirmB);

	return err;
}

int main(int argc, char** argv) {
	int err = 0;
	int idx = 1;
#ifndef PERF
	if (sae_tests())
		fprintf(stderr, "hostapd_test: NOK\n");
	else
		fprintf(stderr, "hostapd_test: OK\n");
#endif
	int group_id = 19;
	char* pwd_id = NULL;
	struct sae_pt* pt = NULL;
	if (strcmp(argv[idx], "-i") == 0) {
		idx++;
		pwd_id = argv[idx++];
	}

	// Go through all passwords
	for (int i = idx; i < argc; i++) {
		//Run two sessions (A and B) from commit to confirmation 
#ifndef PERF
		fprintf(stderr, "custom_pwd_test_%s\n", argv[i]);
#endif
		if (pwd_id) {
			pt = sae_derive_pt(NULL, (const uint8_t*) SSID, strlen(SSID),
				(const uint8_t*) argv[i], strlen(argv[i]), pwd_id);
			if (pt == NULL)
				fprintf(stderr, "error when computing pt\n");
}
#ifdef PERF
		for (int j = 0; j < NB_TESTS; j++) {
#endif
			err |= sae_test_custom(group_id, argv[i], pwd_id, pt);
#ifdef PERF
		}
#endif
		if (pt) { sae_deinit_pt(pt); pt = NULL; }
	}

	return err;
}