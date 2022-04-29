#include "common.h"

/** 
 * Right shift the value in buf
 * @param buf - SECRET
 * @param len - PUBLIC
 * @param bits - SECRET
 */
void buf_shift_right(uint8_t* buf, size_t len, size_t bits) {
    size_t i;

    for (i = len - 1; i > 0; i--)
        buf[i] = (buf[i - 1] << (8 - bits)) | (buf[i] >> bits);
    buf[0] >>= bits;
}

size_t int_array_len(const int* a) {
    size_t i;

    for (i = 0; a && a[i]; i++)
        ;
    return i;
}

/* Try to prevent most compilers from optimizing out clearing of memory that
 * becomes unaccessible after this function is called. This is mostly the case
 * for clearing local stack variables at the end of a function. This is not
 * exactly perfect, i.e., someone could come up with a compiler that figures out
 * the pointer is pointing to memset and then end up optimizing the call out, so
 * try go a bit further by storing the first octet (now zero) to make this even
 * a bit more difficult to optimize out. Once memset_s() is available, that
 * could be used here instead. */
static void* (* const volatile memset_func)(void*, int, size_t) = memset;
static u8 forced_memzero_val;

void forced_memzero(void* ptr, size_t len) {
    memset_func(ptr, 0, len);
    if (len)
        forced_memzero_val = ((u8*) ptr)[0];
}


void bin_clear_free(void* bin, size_t len) {
    if (bin) {
        forced_memzero(bin, len);
        os_free(bin);
    }
}

int os_memcmp_const(const void *a, const void *b, size_t len)
{
	const u8 *aa = a;
	const u8 *bb = b;
	size_t i;
	u8 res;

	for (res = 0, i = 0; i < len; i++)
		res |= aa[i] ^ bb[i];

	return res;
}