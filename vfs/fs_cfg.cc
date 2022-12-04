#include "vfs/fs_cfg.h"

#include <assert.h>

#include "util/cpu.h"

struct cpu_id_t {
    uint64_t id;
    char padding[CACHELINE_SIZE - 8];
};

bool fs_cfg_inited = false;
int fs_numa_socket = 1;
int fs_cpu_num = 32;
cpu_id_t fs_cpu_ids[FS_MAX_CPU_NUM];
static int register_thread_num = 0;
thread_local int processor_id = -1;

int measure_timing = 0;
int pmem_nt_threshold = 256;

pmem2_memset_fn pmem_memset_func;
pmem2_memcpy_fn pmem_memcpy_func;
pmem2_drain_fn pmem_drain_func;

void fs_cfg_init(pmem2_map* pmap, struct vfs_cfg* cfg) {
    log_assert(!fs_cfg_inited);
    fs_numa_socket = cfg->numa_socket;
    fs_cpu_num = cfg->cpu_num;
    log_assert(fs_cpu_num <= FS_MAX_CPU_NUM);
    for(int i = 0; i < fs_cpu_num; ++i) {
        fs_cpu_ids[i].id = cfg->cpu_ids[i];
    }
    register_thread_num = 0;
    measure_timing = cfg->measure_timing;
    pmem_nt_threshold = cfg->pmem_nt_threshold;

    pmem_memcpy_func = pmem2_get_memcpy_fn(pmap);
    pmem_memset_func = pmem2_get_memset_fn(pmap);
    pmem_drain_func = pmem2_get_drain_fn(pmap);

    fs_cfg_inited = true;
}

// 注册并绑核，返回绑定的core_id
int fs_register_thread(int* proc_id) {
    log_assert(fs_cfg_inited);
    if(atomic_load(&register_thread_num) >= fs_cpu_num) {
        r_error("register_thread_num %d >= fs_cpu_num %d", register_thread_num, fs_cpu_num);
    }
    processor_id = atomic_fetch_add(&register_thread_num, 1);
    processor_id = processor_id % fs_cpu_num;
    int core_id = fs_cpu_ids[processor_id].id;
    // 让用户进行绑核
    // bool ret = CoreBind(pthread_self(), core_id);
    // log_assert(ret);
    // r_info("process_id=%d bind ===========================> core %d", processor_id, core_id);
    if(proc_id) *proc_id = processor_id;
    return core_id;
}
