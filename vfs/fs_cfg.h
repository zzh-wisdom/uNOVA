#ifndef UNOVA_FS_CFG_H_
#define UNOVA_FS_CFG_H_

#include <libpmem2.h>
#include <numa.h>
#include <pthread.h>

#include "vfs/vfs_api.h"

#include "util/util.h"
#include "util/common.h"
#include "util/log.h"

#define NOVA_CUT_OUT
#define FINEFS_CUT_OUT

#define MAX_LFS_FILESIZE (128ul*1024*1024*1024)
#define ALLOC_BLOCK_RETRY 3
#define FS_MAX_CPU_NUM 64

extern bool fs_cfg_inited;
extern int fs_cpu_num;
extern thread_local int processor_id;

extern pmem2_memset_fn pmem_memset_func;
extern pmem2_memcpy_fn pmem_memcpy_func;
extern pmem2_drain_fn pmem_drain_func;

void fs_cfg_init(pmem2_map* pmap, struct vfs_cfg* cfg);
// 返回线程id
int fs_register_thread(int* proc_id);

static force_inline int get_processor_id() {
    dlog_assert(fs_cfg_inited);
    dlog_assert(processor_id >= 0 && processor_id < fs_cpu_num);
    return processor_id;
}
static force_inline int num_online_cpus() {
    dlog_assert(fs_cfg_inited);
    return fs_cpu_num;
}

static force_inline void *pmem_memset_nt(void *pmem, int c, size_t n) {
    return pmem_memset_func(pmem, c, n, PMEM2_F_MEM_NONTEMPORAL);
}

static force_inline void *pmem_memcpy_noflush(void *pmem, const void *src, unsigned int size) {
    return pmem_memcpy_func(pmem, src, size, PMEM2_F_MEM_NOFLUSH);
}

static force_inline void *pmem_memcpy_nt(void *pmem, const void *src, unsigned int size) {
    return pmem_memcpy_func(pmem, src, size, PMEM2_F_MEM_NONTEMPORAL);
}

static force_inline void *pmem_memcpy_nt_nodrain(void *pmem, const void *src, unsigned int size) {
    return pmem_memcpy_func(pmem, src, size, PMEM2_F_MEM_NONTEMPORAL | PMEM2_F_MEM_NODRAIN);
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
