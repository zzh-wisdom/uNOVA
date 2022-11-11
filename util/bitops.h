#ifndef UNOVA_UTIL_BITOPS_H_
#define UNOVA_UTIL_BITOPS_H_

#include <stdint.h>

#include "util/common.h"

/**
 * __ffs - find first set bit in word
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static force_inline unsigned long __ffs(unsigned long word) {
    asm("rep; bsf %1,%0" : "=r"(word) : "rm"(word));
    return word;
}

/**
 * ffz - find first zero bit in word
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
static force_inline unsigned long ffz(unsigned long word) {
    asm("rep; bsf %1,%0" : "=r"(word) : "r"(~word));
    return word;
}

/*
 * __fls: find last set bit in word
 * @word: The word to search
 *
 * Undefined if no set bit exists, so code should check against 0 first.
 */
static force_inline unsigned long __fls(unsigned long word) {
    asm("bsr %1,%0" : "=r"(word) : "rm"(word));
    return word;
}

// 寻找最后（最高位）一个为1的bit位的位置，从1开始
// 没有则返回0
static force_inline int fls(unsigned long x) {
    if (x == 0) return 0;
    return __fls(x) + 1;
}

static force_inline int is_pow2(uint64_t v) { return v && !(v & (v - 1)); }

#endif  // HLFS_UTIL_BITOPS_H_
