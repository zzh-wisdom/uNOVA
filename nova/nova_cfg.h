#ifndef UNOVA_NOVA_CFG_H_
#define UNOVA_NOVA_CFG_H_

#include <libpmem2.h>
#include <numa.h>
#include <pthread.h>

#include "nova/vfs_api.h"

#include "util/util.h"
#include "util/common.h"
#include "util/log.h"

#define NOVA_CUT_OUT

#define ALLOC_BLOCK_RETRY 3
#define NOVA_MAX_CPU_NUM 64

extern bool nova_cfg_inited;
extern int nova_cpu_num;
extern thread_local int processor_id;

extern pmem2_memset_fn pmem_memset_func;
extern pmem2_memcpy_fn pmem_memcpy_func;
extern pmem2_drain_fn pmem_drain_func;

void nova_cfg_init(pmem2_map* pmap, struct vfs_cfg* cfg);
// 返回线程id
int nova_register_thread(int* proc_id);

static force_inline int get_processor_id() {
    dlog_assert(nova_cfg_inited);
    dlog_assert(processor_id >= 0 && processor_id < nova_cpu_num);
    return processor_id;
}
static force_inline int num_online_cpus() {
    dlog_assert(nova_cfg_inited);
    return nova_cpu_num;
}

static force_inline void *pmem_memset_nt(void *pmem, int c, size_t n) {
    return pmem_memset_func(pmem, c, n, PMEM2_F_MEM_NONTEMPORAL);
}

static force_inline void *pmem_memcpy_nt(void *pmem, const void *src, unsigned int size) {
    return pmem_memcpy_func(pmem, src, size, PMEM2_F_MEM_NONTEMPORAL);
}

static force_inline int __copy_from_user_inatomic_nocache(void *dst, const void *src, unsigned int size) {
    pmem_memcpy_nt(dst, src, size);
    return 0;
}

// 返回未成功拷贝的字节数
static force_inline int __copy_to_user(void *dst, const void *src, unsigned int size) {
    memcpy(dst, src, size);
    return 0;
}

static force_inline int __clear_user(void *dst, unsigned int size) {
    memset(dst, 0, size);
    return 0;
}

#endif
