#ifndef UNOVA_UTIL_AEP_H_
#define UNOVA_UTIL_AEP_H_

#include <libpmem2.h>
#include <string>

#include "util/log.h"
#include "util/common.h"

// #if defined(__x86_64__)
// #include <mmintrin.h>
// #include <x86intrin.h>
// #else
// # error "Not support"
// #endif

#ifndef __x86_64__
#error "Not support, should run on __x86_64__"
#endif

#define CACHELINE_SIZE ((uintptr_t)64)
#define CACHELINE_MASK (CACHELINE_SIZE - 1)
#define CACHELINE_UNMASK (~CACHELINE_MASK)

#define clflush(addr) asm volatile("clflush %0" : "+m"(*(volatile char *)(addr)))
#define clflushopt(addr) asm volatile(".byte 0x66; clflush %0" : "+m"(*(volatile char *)(addr)));
#define clwb(addr) asm volatile(".byte 0x66; xsaveopt %0" : "+m"(*(volatile char *)(addr)));
#define lfence() __asm__ __volatile__("lfence" : : : "memory")
#define sfence() __asm__ __volatile__("sfence" : : : "memory")
#define mfence() __asm__ __volatile__("mfence" : : : "memory")
#define barrier() __asm__ __volatile__("" : : : "memory")

static force_inline void clwb_extent(const char *addr, size_t len) {
    uintptr_t uptr;
    for (uptr = (uintptr_t)addr & CACHELINE_UNMASK; uptr < (uintptr_t)addr + len;
         uptr += CACHELINE_SIZE) {
        clwb(uptr)
    }
}

struct pmem2_map *Pmem2Map(const std::string &dev_file);
struct pmem2_map *Pmem2MapFromFd(int fd);

struct pmem2_map *Pmem2MapAndTruncate(const std::string &file, uint64_t size);

void Pmem2UnMap(struct pmem2_map **map);

#endif  // HLFS_UTIL_AEP_H_
