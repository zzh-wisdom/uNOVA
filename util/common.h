
#ifndef UNOVA_UTIL_COMMON_H_
#define UNOVA_UTIL_COMMON_H_

#define force_inline __attribute__((always_inline)) inline

#define ATTR_CONSTRUCTOR __attribute__((constructor)) static
#define ATTR_DESTRUCTOR __attribute__((destructor)) static
#define ATTR_PRIORITY_ONE __attribute__((init_priority(1)))

#define CACHELINE_SIZE  (64)
#define CACHELINE_MASK (CACHELINE_SIZE - 1)
#define CACHELINE_UNMASK (~CACHELINE_MASK)
#define CACHELINE_ALIGN(addr) (((addr)+CACHELINE_SIZE-1) & CACHELINE_MASK)

#define barrier() asm volatile("": : :"memory")

#endif
