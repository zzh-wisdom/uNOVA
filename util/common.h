
#ifndef UNOVA_UTIL_COMMON_H_
#define UNOVA_UTIL_COMMON_H_

#define force_inline __attribute__((always_inline)) inline

#define ATTR_CONSTRUCTOR __attribute__((constructor)) static
#define ATTR_DESTRUCTOR __attribute__((destructor)) static

#define unlikely(cond) __glibc_unlikely(cond)

#endif
