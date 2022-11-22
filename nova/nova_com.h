#ifndef UNOVA_NOVA_COM_H_
#define UNOVA_NOVA_COM_H_

#include <stdint.h>

#include "util/common.h"
#include "util/mem.h"

#define MAX_LFS_FILESIZE (128ul*1024*1024*1024)

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/*
 * Below are truly Linux-specific types that should never collide with
 * any application/library that wants linux/types.h.
 */

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#define __bitwise __bitwise__

typedef u16 __bitwise __le16;
typedef u16 __bitwise __be16;
typedef u32 __bitwise __le32;
typedef u32 __bitwise __be32;
typedef u64 __bitwise __le64;
typedef u64 __bitwise __be64;

typedef u64 kuid_t;
typedef u64 kgid_t;
typedef u64 umode_t;

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

#if __BYTE_ORDER__ ==__ORDER_BIG_ENDIAN__

// 不支持

#else //小端模式

#define cpu_to_le64(v) (v)
#define cpu_to_le32(v) (v)
#define cpu_to_le16(v) (v)

#define le32_to_cpu(v) (v)
#define le16_to_cpu(v) (v)
#define le64_to_cpu(v) (v)

static inline void le64_add_cpu(__le64 *var, u64 val)
{
	*var = cpu_to_le64(le64_to_cpu(*var) + val);
}

#endif

#endif
