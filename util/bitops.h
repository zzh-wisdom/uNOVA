#ifndef UNOVA_UTIL_BITOPS_H_
#define UNOVA_UTIL_BITOPS_H_

#include <stdint.h>
#include <algorithm>

#include "util/common.h"
#include "util/util.h"

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

/********* bitmap *********/

/*
 * Macros to generate condition code outputs from inline assembly,
 * The output operand must be type "bool".
 */
#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define CC_OUT(c) "=@cc" #c
#else
# define CC_SET(c) "\n\tset" #c " %[_cc_" #c "]\n"
# define CC_OUT(c) [_cc_ ## c] "=qm"
#endif

//-----------------------------
#ifdef __ASSEMBLY__
# define __ASM_FORM(x, ...)		x,## __VA_ARGS__
# define __ASM_FORM_RAW(x, ...)		x,## __VA_ARGS__
# define __ASM_FORM_COMMA(x, ...)	x,## __VA_ARGS__,
#else
#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)
# define __ASM_FORM(x, ...)		" " __stringify(x,##__VA_ARGS__) " "
# define __ASM_FORM_RAW(x, ...)		    __stringify(x,##__VA_ARGS__)
# define __ASM_FORM_COMMA(x, ...)	" " __stringify(x,##__VA_ARGS__) ","
#endif

#ifndef __x86_64__
/* 32 bit */
# define __ASM_SEL(a,b)		__ASM_FORM(a)
# define __ASM_SEL_RAW(a,b)	__ASM_FORM_RAW(a)
#else
/* 64 bit */
# define __ASM_SEL(a,b)		__ASM_FORM(b)
# define __ASM_SEL_RAW(a,b)	__ASM_FORM_RAW(b)
#endif

#ifdef CONFIG_SMP
#define LOCK_PREFIX_HERE \
		".pushsection .smp_locks,\"a\"\n"	\
		".balign 4\n"				\
		".long 671f - .\n" /* offset */		\
		".popsection\n"				\
		"671:"

#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "

#else /* ! CONFIG_SMP */
#define LOCK_PREFIX_HERE ""
// #define LOCK_PREFIX ""
#ifndef LOCK_PREFIX
#define LOCK_PREFIX	"lock ; "
#endif
#endif

#define __ASM_SIZE(inst, ...)	__ASM_SEL(inst##l##__VA_ARGS__, \
					  inst##q##__VA_ARGS__)

#define RLONG_ADDR(x)			 "m" (*(volatile long *) (x))
#define WBYTE_ADDR(x)			"+m" (*(volatile char *) (x))

#define ADDR				RLONG_ADDR(addr)

#define CONST_MASK_ADDR(nr, addr)	WBYTE_ADDR((char *)(addr) + ((nr)>>3))
#define CONST_MASK(nr)			(1 << ((nr) & 7))

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define BITS_PER_BYTE		8
#define BITS_PER_TYPE(type)	(sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)	__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(long))

const int BITS_PER_LONG = sizeof(unsigned long)*BITS_PER_BYTE;
const int _BITOPS_LONG_SHIFT = BITS_PER_LONG == 32 ? 5 : 6;

static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
{
	return ((1UL << (nr & (BITS_PER_LONG-1))) &
		(addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
}

static __always_inline bool variable_test_bit(long nr, volatile const unsigned long *addr)
{
	bool oldbit;

	asm volatile(__ASM_SIZE(bt) " %2,%1"
		     CC_SET(c)
		     : CC_OUT(c) (oldbit)
		     : "m" (*(unsigned long *)addr), "Ir" (nr) : "memory");

	return oldbit;
}

/**
 * @brief 返回addr的第nr位值
 *
 */
#define arch_test_bit(nr, addr)			\
	(__builtin_constant_p((nr))		\
	 ? constant_test_bit((nr), (addr))	\
	 : variable_test_bit((nr), (addr)))

static force_inline void
bitmap_set_bit_atomic(long nr, volatile unsigned long *addr)
{
	if (__builtin_constant_p(nr)) {
		asm volatile(LOCK_PREFIX "orb %b1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" (CONST_MASK(nr))
			: "memory");
	} else {
		asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
	}
}

static force_inline void
bitmap_set_bit(long nr, unsigned long *addr) // volatile unsigned long *addr
{
	asm(__ASM_SIZE(bts) " %1,%0" : : ADDR, "Ir" (nr) : "memory"); // volatile
}

// 将某一位置为0
static force_inline void
bitmap_clear_bit_atomic(long nr, volatile unsigned long *addr)
{
	if (__builtin_constant_p(nr)) {
		asm volatile(LOCK_PREFIX "andb %b1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" (~CONST_MASK(nr)));
	} else {
		asm volatile(LOCK_PREFIX __ASM_SIZE(btr) " %1,%0"
			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
	}
}

static force_inline void
bitmap_clear_bit(long nr, unsigned long *addr) // volatile
{
	asm(__ASM_SIZE(btr) " %1,%0" : : ADDR, "Ir" (nr) : "memory"); // volatile
}

// 查找最后一个1的位置，如第一个bit为最后一个1，则返回1
static force_inline int bitmap_find_last_bit(unsigned long *bits, unsigned int nbits) {
	int index = nbits;
	for(int i = BITS_TO_LONGS(nbits)-1; i >= 0; i--) {
        if(bits[i] == 0) {
            index -= BITS_PER_TYPE(unsigned long);
        }
        else {
            index += __fls(bits[i]) + 1 - BITS_PER_TYPE(unsigned long);
            break;
        }
    }
	return index;
}

#define BITS_PER_LONG (sizeof(unsigned long)*BITS_PER_BYTE)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))

/*
 * This is a common helper function for find_next_bit, find_next_zero_bit, and
 * find_next_and_bit. The differences are:
 *  - The "invert" argument, which is XORed with each fetched word before
 *    searching it for one bits.
 *  - The optional "addr2", which is anded with "addr1" if present.
 */
static inline unsigned long _find_next_bit(const unsigned long *addr1,
		const unsigned long *addr2, unsigned long nbits,
		unsigned long start, unsigned long invert)
{
	unsigned long tmp;
	if (unlikely(start >= nbits))
		return nbits;
	tmp = addr1[start / BITS_PER_LONG];
	if (addr2)
		tmp &= addr2[start / BITS_PER_LONG];
	tmp ^= invert;
	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, BITS_PER_LONG);
	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;
		tmp = addr1[start / BITS_PER_LONG];
		if (addr2)
			tmp &= addr2[start / BITS_PER_LONG];
		tmp ^= invert;
	}
	return std::min(start + __ffs(tmp), nbits);
}

/*
 * Find the first set bit in a memory region.
 */
static inline unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;
	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx])
			return std::min(idx * BITS_PER_LONG + __ffs(addr[idx]), size);
	}
	return size;
}

/*
 * Find the next set bit in a memory region.
 */
static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset)
{
	return _find_next_bit(addr, NULL, size, offset, 0UL);
}

/*
 * Find the first cleared bit in a memory region.
 */
static inline unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;
	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx] != ~0UL)
			return std::min(idx * BITS_PER_LONG + ffz(addr[idx]), size);
	}
	return size;
}

static inline unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset)
{
	return _find_next_bit(addr, NULL, size, offset, ~0UL);
}

// size：bit大小
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

/* same as for_each_set_bit() but use bit as value to start with */
#define for_each_set_bit_from(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_clear_bit(bit, addr, size) \
	for ((bit) = find_first_zero_bit((addr), (size));	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

/* same as for_each_clear_bit() but use bit as value to start with */
#define for_each_clear_bit_from(bit, addr, size) \
	for ((bit) = find_next_zero_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

static force_inline int bitmap_set_weight(const unsigned long *addr, unsigned long size) {
	int bit;
	int sum = 0;
	for_each_set_bit(bit, addr, size) {
		++sum;
	}
	return sum;
}

#endif  // HLFS_UTIL_BITOPS_H_
