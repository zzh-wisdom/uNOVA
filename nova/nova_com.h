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

#endif

// 假的cache，直接使用glic分配
struct kmem_cache {
    int slab_size;
    int align;
};

inline struct kmem_cache* kmem_cache_create(int slab_size, int align) {
    struct kmem_cache* cache = (struct kmem_cache*)MALLOC(sizeof(struct kmem_cache));
    if(cache == nullptr) return nullptr;
    cache->slab_size = slab_size;
    cache->align = align;
    return cache;
}

inline void kmem_cache_destroy(struct kmem_cache* cache) {
    FREE(cache);
}

inline void* kmem_cache_alloc(struct kmem_cache* cache) {
    return MALLOC(cache->slab_size);
}

inline void kmem_cache_free(struct kmem_cache* cache, void* node) {
    FREE(node);
}

#endif
