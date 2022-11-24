#include "nova/nova_cfg.h"

#include <assert.h>

#include "util/cpu.h"

struct cpu_id_t {
    uint64_t id;
    char padding[CACHELINE_SIZE - 8];
};

bool nova_cfg_inited = false;
int nova_numa_socket = 1;
int nova_cpu_num = 32;
cpu_id_t nova_cpu_ids[NOVA_MAX_CPU_NUM];
static int register_thread_num = 0;
thread_local int processor_id = -1;

int measure_timing = 0;

pmem2_memset_fn pmem_memset_func;
pmem2_memcpy_fn pmem_memcpy_func;
pmem2_drain_fn pmem_drain_func;

void nova_cfg_init(pmem2_map* pmap, struct vfs_cfg* cfg) {
    log_assert(!nova_cfg_inited);
    nova_numa_socket = cfg->numa_socket;
    nova_cpu_num = cfg->cpu_num;
    log_assert(nova_cpu_num <= NOVA_MAX_CPU_NUM);
    for(int i = 0; i < nova_cpu_num; ++i) {
        nova_cpu_ids[i].id = cfg->cpu_ids[i];
    }
    register_thread_num = 0;
    measure_timing = cfg->measure_timing;

    pmem_memcpy_func = pmem2_get_memcpy_fn(pmap);
    pmem_memset_func = pmem2_get_memset_fn(pmap);
    pmem_drain_func = pmem2_get_drain_fn(pmap);

    nova_cfg_inited = true;
}

// 注册并绑核，返回绑定的core_id
int nova_register_thread(int* proc_id) {
    log_assert(nova_cfg_inited);
    log_assert(register_thread_num < nova_cpu_num);
    processor_id = register_thread_num;
    int core_id = nova_cpu_ids[register_thread_num].id;
    ++register_thread_num;
    bool ret = CoreBind(pthread_self(), core_id);
    log_assert(ret);
    r_info("process_id=%d bind ===========================> core %d", processor_id, core_id);
    if(proc_id) *proc_id = processor_id;
    return core_id;
}
