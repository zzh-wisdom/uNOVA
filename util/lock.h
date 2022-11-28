#ifndef UNOVA_UTIL_LOCK_H_
#define UNOVA_UTIL_LOCK_H_

#include "util/common.h"

#ifdef __linux__

#include <pthread.h>

#define mutex_t pthread_mutex_t
#define mutex_init(a) pthread_mutex_init(a, NULL)
#define mutex_destroy(a) pthread_mutex_destroy(a)
#define mutex_lock(a) pthread_mutex_lock(a)
#define mutex_try_lock(a) pthread_mutex_trylock(a)
#define mutex_unlock(a) pthread_mutex_unlock(a)

// https://zhuanlan.zhihu.com/p/344896299
// linux 平台的锁
#define rwlock_t pthread_rwlock_t
#define rwlock_init(a) pthread_rwlock_init(a, NULL)
#define rwlock_destroy(a) pthread_rwlock_destroy(a)
#define read_lock(a) pthread_rwlock_rdlock(a)
#define read_try_lock(a) pthread_rwlock_tryrdlock(a)
#define read_unlock(a) pthread_rwlock_unlock(a)
#define write_lock(a) pthread_rwlock_wrlock(a)
#define write_try_lock(a) pthread_rwlock_trywrlock(a)
#define write_unlock(a) pthread_rwlock_unlock(a)
#define RWLOCK_STATIC_INIT PTHREAD_RWLOCK_INITIALIZER

// 条件变量
#define cond_t pthread_cond_t
#define cond_init(c)	    pthread_cond_init(c, NULL)
#define cond_destroy(c) 	pthread_cond_destroy(c)
#define cond_wait(c, l)   	pthread_cond_wait(c, l)
#define cond_signal(c)	    pthread_cond_signal(c)
#define cond_broadcast(c)	pthread_cond_broadcast(c)

/************************
 * 自旋锁
 ***********************/

#define atomic_xadd(P, V) __sync_fetch_and_add((P), (V))
#define cmpxchg(P, O, N) __sync_val_compare_and_swap((P), (O), (N))
#define bcmpxchg(P, O, N) __sync_bool_compare_and_swap((P), (O), (N))
#define atomic_inc(P) __sync_add_and_fetch((P), 1)
#define atomic_dec(P) __sync_add_and_fetch((P), -1)
#define atomic_add(P, V) __sync_add_and_fetch((P), (V))
#define atomic_set_bit(P, V) __sync_or_and_fetch((P), 1<<(V))
#define atomic_clear_bit(P, V) __sync_and_and_fetch((P), ~(1<<(V)))

#define cpu_relax() asm volatile("pause\n": : :"memory")

force_inline static void *xchg_64(void *ptr, void *x)
{
    __asm__ __volatile__("xchgq %0,%1"
    :"=r" ((unsigned long long) x)
    :"m" (*(volatile long long *)ptr), "0" ((unsigned long long) x)
    :"memory");

    return x;
}

force_inline static unsigned xchg_32(void *ptr, unsigned x)
{
    __asm__ __volatile__("xchgl %0,%1"
    :"=r" ((unsigned) x)
    :"m" (*(volatile unsigned *)ptr), "0" (x)
    :"memory");
    return x;
}

force_inline static unsigned short xchg_16(void *ptr, unsigned short x)
{
    __asm__ __volatile__("xchgw %0,%1"
    :"=r" ((unsigned short) x)
    :"m" (*(volatile unsigned short *)ptr), "0" (x)
    :"memory");
    return x;
}

force_inline static char atomic_bitsetandtest(void *ptr, int x)
{
    char out;
    __asm__ __volatile__("lock; bts %2,%1\n"
                         "sbb %0,%0\n"
    :"=r" (out), "=m" (*(volatile long long *)ptr)
    :"Ir" (x)
    :"memory");
    return out;
}

#define LBUSY 1

// naive spinlock
typedef unsigned spinlock_t;

force_inline static void spin_lock_init(spinlock_t *lock) {
    *lock = 0;
}

force_inline static void spin_lock(spinlock_t *lock)
{
    while (1)
    {
        if (!xchg_32(lock, LBUSY)) return;

        while (*lock) cpu_relax();
    }
}

force_inline static void spin_unlock(spinlock_t *lock)
{
    barrier();
    *lock = 0;
}

force_inline static int spin_trylock(spinlock_t *lock)
{
    return xchg_32(lock, LBUSY);
}

#elif _WIN32

error "Not support _WIN32"

#endif

#endif  // UNOVA_UTIL_LOCK_H_