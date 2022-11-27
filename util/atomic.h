#ifndef UNOVA_UTIL_ATOMIC_H_
#define UNOVA_UTIL_ATOMIC_H_

#include <stdint.h>

typedef int atomic_t;

#define atomic_load(a) __atomic_load_n(a, __ATOMIC_RELAXED)
#define atomic_set(a, v) __atomic_store_n(a, v, __ATOMIC_RELAXED)
#define atomic_add_fetch(a, v) __atomic_add_fetch(a, v, __ATOMIC_RELAXED)
#define atomic_fetch_add(a, v) __atomic_fetch_add(a, v, __ATOMIC_RELAXED)

#endif