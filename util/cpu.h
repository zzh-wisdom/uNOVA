#ifndef UNOVA_UTIL_CPU_H_
#define UNOVA_UTIL_CPU_H_

#include <pthread.h>
#include <sys/time.h>
#include <time.h>

#include <cstdint>
#include <vector>

#include "util/common.h"

#include "util/log.h"

// thread_t 不是thread id，只是类似一种句柄，
// 获取系统唯一的tid需要走系统调用，所以还是比较慢
// https://blog.csdn.net/sidemap/article/details/125151548

// cpuid 指令： https://blog.csdn.net/weixin_42522750/article/details/116862327

// 每个cpu变量，主要cacheline分离

static force_inline int get_cpu_id() {
    // 系统调用，比较慢，还得缓存与绑核
    rd_warning("TODO: 注意绑核+缓存, 需要转化从0开始\n");
    return sched_getcpu();
}

bool CoreBind(pthread_t t, uint32_t core_id);
std::vector<int> CoreBindQuery(pthread_t t);
int get_cpu_num_for_socket(int numa_socket);
void SetSocketAndPolicy(int socket, int strict);

static force_inline uint64_t GetTsSec() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

static force_inline uint64_t GetTsUsec() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec) * 1000000 + tv.tv_usec;
}

static force_inline uint64_t GetTsNsec() {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
    return tp.tv_sec * 1000000000ULL + tp.tv_nsec;
}

static force_inline struct timespec get_cur_time_spec() {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
    return tp;
}

// 由于cpu频率不定，这个很难转换成时间
static force_inline uint64_t GetTsTick() {
    uint32_t lo, hi;
    uint64_t o;
    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi) : : "%ecx");
    o = hi;
    o <<= 32;
    return (o | lo);
}

#endif