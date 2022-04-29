#ifndef CRYPTO_BIGNUM_STATIC_H
#define CRYPTO_BIGNUM_STATIC_H

#include <stdint.h>

/**
 * struct crypto_bignum_static_size - bignum oof a static size
 *
 * Internal data structure for bignum implementation. The contents is specific
 * to the used crypto library.
 */
struct crypto_bignum_static;

void crypto_bignum_static_print(char * label, const struct crypto_bignum_static* x);


/**
 * crypto_bignum_static_init - Allocate memory for bignum
 * Returns: Pointer to allocated bignum or %NULL on failure
 */
struct crypto_bignum_static* crypto_bignum_static_init(size_t len);

/**
 * crypto_bignum_static_init_set - Allocate memory for bignum and set the value
 * @buf: Buffer with unsigned binary value  - usually SECRET, but may be public in some cases
 * @buflen: Length of buf in octets - usually PUBLIC
 * @len: Length of the big number in bytes
 * Returns: Pointer to allocated bignum or %NULL on failure - same as @buf
 */
struct crypto_bignum_static* crypto_bignum_static_init_set(const uint8_t* buf, size_t buflen, size_t len);

/**
 * crypto_bignum_static_init_uint - Allocate memory for bignum and set the value
 * @val: unsigned value  - usually SECRET, but may be public in some cases
 * @len: Length of the big number in bytes
 * Returns: Pointer to allocated bignum or %NULL on failure - same as @val
 */
struct crypto_bignum_static* crypto_bignum_static_init_uint(unsigned int val, size_t len);

/**
 * crypto_bignum_static_deinit - Free bignum
 * @n: Bignum from crypto_bignum_static_init() or crypto_bignum_static_init_set() - usually SECRET
 * @clear: Whether to clear the value from memory
 */
void crypto_bignum_static_deinit(struct crypto_bignum_static* n, int clear);

/**
 * crypto_bignum_static_size - Return the size in bytes of a bignum
 * @n: Bignum 
 * Returns: The size in bytes of the bignum in input
 */ 
size_t crypto_bignum_static_size(const struct crypto_bignum_static* n);

/**
 * crypto_bignum_static_to_bin - Set binary buffer to unsigned bignum
 * @a: Bignum   - usually SECRET, but may vary
 * @buf: Buffer for the binary number - SECRET <=> @a is secret
 * @len: Length of @buf in octets - PUBLIC
 * @padlen: Length in octets to pad the result to or 0 to indicate no padding   - PUBLIC
 * Returns: Number of octets written on success, -1 on failure
 */
int crypto_bignum_static_to_bin(const struct crypto_bignum_static* a,
	uint8_t* buf, size_t buflen, size_t padlen);

/**
 * crypto_bignum_static_rand - Create a random number in range of modulus
 * @r: Bignum; set to a random value  - SECRET
 * @m: Bignum; modulus  - PUBLIC
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_static_rand(struct crypto_bignum_static* r, const struct crypto_bignum_static* m);

/**
 * crypto_bignum_static_add - c = a + b
 * @a: Bignum   - usually SECRET, but may be PUBLIC
 * @b: Bignum   - usually SECRET, but may be PUBLIC
 * @c: Bignum; used to store the result of a + b    - usually SECRET
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_static_add(const struct crypto_bignum_static* a,
	const struct crypto_bignum_static* b,
	struct crypto_bignum_static* c);

/**
 * crypto_bignum_static_mod - c = a % b
 * @a: Bignum - SECRET
 * @b: Bignum - PUBLIC
 * @c: Bignum; used to store the result of a % b    - SECRET
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_static_mod(const struct crypto_bignum_static* a,
	const struct crypto_bignum_static* b,
	struct crypto_bignum_static* c);

/**
 * crypto_bignum_static_exptmod - d = a^b % c
 * @a: Bignum - SECRET
 * @b: Bignum - SECRET
 * @c: Bignum - PUBLIC
 * @d: Bignum; used to store the result of a^b % c    - SECRET
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_static_exptmod(const struct crypto_bignum_static *a,
			  const struct crypto_bignum_static *b,
			  const struct crypto_bignum_static *c,
			  struct crypto_bignum_static *d);

int crypto_bignum_static_inverse(const struct crypto_bignum_static* a,
	const struct crypto_bignum_static* b,
	struct crypto_bignum_static* c);

/**
 * crypto_bignum_static_sub - c = a - b. Only used with public parameters for sae
 * @a: Bignum   - PUBLIC
 * @b: Bignum   - PUBLIC
 * @c: Bignum; used to store the result of a - b - PUBLIC
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_static_sub(const struct crypto_bignum_static* a,
	const struct crypto_bignum_static* b,
	struct crypto_bignum_static* c);


int crypto_bignum_static_addmod(const struct crypto_bignum_static* a,
	const struct crypto_bignum_static* b,
	const struct crypto_bignum_static* c,
	struct crypto_bignum_static* d);

/**
 * crypto_bignum_static_mulmod - d = a * b (mod c)
 * @a: Bignum   - SECRET
 * @b: Bignum   - SECRET
 * @c: Bignum   - PUBLIC
 * @d: Bignum; used to store the result of (a * b) % c  - PUBLIC (masked value in sae)
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_static_mulmod(const struct crypto_bignum_static* a,
	const struct crypto_bignum_static* b,
	const struct crypto_bignum_static* c,
	struct crypto_bignum_static* d);

int crypto_bignum_static_sqrmod(const struct crypto_bignum_static *a,
			 const struct crypto_bignum_static *b,
			 struct crypto_bignum_static *c);

/**
 * crypto_bignum_static_cmp - Compare two bignums.
 * @a: Bignum   - PUBLIC
 * @b: Bignum   - PUBLIC
 * Returns: -1 if a < b, 0 if a == b, or 1 if a > b
 */
int crypto_bignum_static_cmp(const struct crypto_bignum_static* a,
	const struct crypto_bignum_static* b);

/**
 * crypto_bignum_static_is_zero - Is the given bignum zero
 * @a: Bignum   - SECRET
 * Returns: 1 if @a is zero or 0 if not
 */
int crypto_bignum_static_is_zero(const struct crypto_bignum_static* a);

/**
 * crypto_bignum_static_is_one - Is the given bignum one
 * @a: Bignum   - SECRET
 * Returns: 1 if @a is one or 0 if not
 */
int crypto_bignum_static_is_one(const struct crypto_bignum_static* a);

/**
 * crypto_bignum_static_is_odd - Is the given bignum odd
 * @a: Bignum   - SECRET
 * Returns: 1 if @a is odd or 0 if not
 */
int crypto_bignum_static_is_odd(const struct crypto_bignum_static* a);

/**
 * crypto_bignum_static_rshift - right shift a n times, and store it in r
 * @a: Bignum   - SECRET
 * @n: Integer   - Public
 * @r: Bignum   - SECRET
 * Returns: 0 on success
 */
int crypto_bignum_static_rshift(const struct crypto_bignum_static* a, int n, struct crypto_bignum_static* r);


/**
 * crypto_bignum_static_legendre - Compute the Legendre symbol (a/p)
 * @a: Bignum   - SECRET (mask here)
 * @p: Bignum   - PUBLIC
 * Returns: Legendre symbol -1,0,1 on success; -2 on calculation failure
 */
int crypto_bignum_static_legendre(const struct crypto_bignum_static* a,
	const struct crypto_bignum_static* p);


/**
 * crypto_ec_get_prime_static - Get prime defining an EC group
 * @e: EC context from crypto_ec_init() - PUBLIC
 * Returns: Prime (bignum) defining the group   - PUBLIC
 */
const struct crypto_bignum_static* crypto_ec_get_prime_static(struct crypto_ec* e);


/**
 * crypto_ec_get_order_static - Get order of an EC group
 * @e: EC context from crypto_ec_init() - PUBLIC
 * Returns: Order (bignum) of the group - PUBLIC
 */
const struct crypto_bignum_static* crypto_ec_get_order_static(struct crypto_ec* e);

const struct crypto_bignum_static* crypto_ec_get_a_static(struct crypto_ec* e);
const struct crypto_bignum_static* crypto_ec_get_b_static(struct crypto_ec* e);

int crypto_ec_point_x_static(struct crypto_ec* e, const struct crypto_ec_point* p,
	struct crypto_bignum_static* x);

/**
 * crypto_ec_point_mul_static - res = b * p
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @p: EC point - SECRET
 * @b: Bignum   - SECRET
 * @res: EC point; used to store the result of b * p    - SECRET
 * Returns: 0 on success, -1 on failure
 */
int crypto_ec_point_mul_static(struct crypto_ec *e, const struct crypto_ec_point *p,
			const struct crypto_bignum_static *b,
			struct crypto_ec_point *res);

/**
 * crypto_ec_point_solve_y_coord_static - Solve y coordinate for an x coordinate
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @p: EC point to use for the returning the result - SECRET
 * @x: x coordinate - SECRET
 * @y_bit: y-bit (0 or 1) for selecting the y value to use  - SECRET
 *
 * We found a vulnerability in OpenSSL in this call because @y_bit is not handled as a secret.
 *
 * Returns: 0 on success, -1 on failure
 */
int crypto_ec_point_solve_y_coord_static(struct crypto_ec *e,
				  struct crypto_ec_point *p,
				  const struct crypto_bignum_static *x, int y_bit);

/**
 * crypto_ec_point_compute_y_sqr_static - Compute y^2 = x^3 + ax + b
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @x: x coordinate - SECRET
 * Returns: y^2 on success, %NULL failure   - SECRET
 */
struct crypto_bignum_static *
crypto_ec_point_compute_y_sqr_static(struct crypto_ec *e,
			      const struct crypto_bignum_static *x);

#endif