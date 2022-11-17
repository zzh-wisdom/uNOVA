#ifndef UNOVA_NOVA_CFG_H_
#define UNOVA_NOVA_CFG_H_

#include <libpmem2.h>
#include <numa.h>

#include "util/util.h"
#include "util/common.h"

#define NOVA_CUT_OUT

#define ALLOC_BLOCK_RETRY 3

int numa_socket = 1;

#define MAX_CPU_NUM 64

force_inline int num_online_cpus() {
    bitmask *mask = numa_allocate_cpumask();
    if (unlikely(mask == nullptr)) return -1;
    int ret = numa_node_to_cpus(numa_socket, mask);
    if (unlikely(ret != 0)) return -1;
    int num = numa_bitmask_weight(mask);
    numa_bitmask_free(mask);
    return num;
}

pmem2_memset_fn pmem_memset_func;
pmem2_memcpy_fn pmem_memcpy_func;
pmem2_drain_fn pmem_drain_func;

void InitCfg() {
    pmem_memset_func = nullptr;
    pmem_memcpy_func = nullptr;
    pmem_drain_func = nullptr;
}

force_inline void *pmem_memset_nt(void *pmem, int c, size_t n) {
    return pmem_memset_func(pmem, c, n, PMEM2_F_MEM_NONTEMPORAL);
}

force_inline void *pmem_memcpy_nt(void *pmem, const void *src, unsigned int size) {
    return pmem_memcpy_func(pmem, src, size, PMEM2_F_MEM_NONTEMPORAL);
}

force_inline int __copy_from_user_inatomic_nocache(void *dst, const void *src, unsigned int size) {
    pmem_memcpy_nt(dst, src, size);
    return 0;
}

// 返回未成功拷贝的字节数
force_inline int __copy_to_user(void *dst, const void *src, unsigned int size) {
    memcpy(dst, src, size);
    return 0;
}

force_inline int __clear_user(void *dst, unsigned int size) {
    memset(dst, 0, size);
    return 0;
}

#endif
