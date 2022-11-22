
#ifndef UNOVA_UTIL_COMMON_H_
#define UNOVA_UTIL_COMMON_H_

#define force_inline __attribute__((always_inline)) inline

#define ATTR_CONSTRUCTOR __attribute__((constructor)) static
#define ATTR_DESTRUCTOR __attribute__((destructor)) static

#define CACHELINE_SIZE  (64)
#define CACHELINE_MASK  (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr)+CACHELINE_SIZE-1) & CACHELINE_MASK)

#endif
