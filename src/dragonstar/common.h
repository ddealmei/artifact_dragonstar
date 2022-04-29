/*
 * wpa_supplicant/hostapd / common helper functions, etc.
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>


#define os_malloc(x) malloc((x))
#define os_zalloc(x) calloc((x), 1)
#define os_free(x) free((x))
#define os_strlen(x) strlen((x))
#define os_memcpy(x, y, z) memcpy((x), (y), (z))
#define os_memcmp(x, y, z) memcmp((x), (y), (z))
#define os_memset(x, y, z) memset((x), (y), (z))
int os_memcmp_const(const void* a, const void* b, size_t len);

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

// #define DEBUG 1
#ifdef DEBUG
    #define DEBUG_flag 1
#else
    #define DEBUG_flag 0
#endif
static inline void hexdump(const char* label, const uint8_t* buff, size_t len) {
#ifdef DEBUG
    fprintf(stderr, "%s: ", label);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02X", buff[i] & 0xFF);
    fprintf(stderr, "\n");
#endif
}

static inline void wpa_printf(int level, const char* fmt, ...) {
    va_list ap;
    if (level) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        fflush(stderr);
        va_end(ap);
    }
}

static inline void WPA_PUT_LE16(uint8_t* a, uint16_t val) {
    a[1] = val >> 8;
    a[0] = val & 0xff;
}

static inline uint16_t WPA_GET_LE16(const uint8_t* a) {
    return (a[1] << 8) | a[0];
}


size_t int_array_len(const int* a);

/** From common.c
 * Right shift the value in buf
 * @param buf - SECRET
 * @param len - PUBLIC
 * @param bits - SECRET
 */
void buf_shift_right(uint8_t* buf, size_t len, size_t bits);
void forced_memzero(void* ptr, size_t len);
void bin_clear_free(void* bin, size_t len);

#endif