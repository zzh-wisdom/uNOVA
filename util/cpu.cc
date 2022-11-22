#include "util/cpu.h"

#include <assert.h>
#include <unistd.h>
#include <numa.h>
#include <iostream>

#include "util/util.h"

bool CoreBind(pthread_t t, uint32_t core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    int ret_error = pthread_setaffinity_np(t, sizeof(cpu_set_t), &cpuset);
    return (ret_error == 0);
}

std::vector<int> CoreBindQuery(pthread_t t) {
    // 查询绑核核优先级情况
    cpu_set_t cpuset;
    int ret_error = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    assert(ret_error == 0);
    std::vector<int> ret;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &cpuset)) {
            ret.push_back(i);
        }
    }
    return ret;
}

int get_cpu_num_for_socket(int numa_socket) {
    bitmask *mask = numa_allocate_cpumask();
    if (unlikely(mask == nullptr)) return -1;
    int ret = numa_node_to_cpus(numa_socket, mask);
    if (unlikely(ret != 0)) return -1;
    int num = numa_bitmask_weight(mask);
    numa_bitmask_free(mask);
    return num;
}

void SetSocketAndPolicy(int socket, int strict) {
    // numa set
    bitmask* node_mask = numa_get_mems_allowed();
    numa_bitmask_clearall(node_mask);
    numa_bitmask_setbit(node_mask, socket);
    numa_bind(node_mask);
    numa_bitmask_free(node_mask);
    numa_set_bind_policy(strict);
    // numa_set_strict();
    // numa_run_on_node(socket);
    // numa_set_membind();
    node_mask = numa_get_membind();
    assert(numa_bitmask_weight(node_mask) == 1);
    assert(numa_bitmask_isbitset(node_mask, socket));
}