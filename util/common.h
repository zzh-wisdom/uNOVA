
#ifndef UNOVA_UTIL_COMMON_H_
#define UNOVA_UTIL_COMMON_H_

#define force_inline __attribute__((always_inline)) inline

#define ATTR_CONSTRUCTOR __attribute__((constructor)) static
#define ATTR_DESTRUCTOR __attribute__((destructor)) static
#define ATTR_PRIORITY_ONE __attribute__((init_priority(1)))

#define CACHELINE_SIZE  (64)
#define CACHELINE_UMASK (CACHELINE_SIZE - 1)
#define CACHELINE_MASK (~CACHELINE_UMASK)
#define CACHELINE_ALIGN(addr) (((addr)+CACHELINE_SIZE-1) & CACHELINE_UMASK)

#define barrier() asm volatile("": : :"memory")

#endif
