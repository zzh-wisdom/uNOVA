/* Test directories functionalities
 *
 */
#include <dirent.h>
#include <fcntl.h>
#include <libsyscall_intercept_hook_point.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <dlfcn.h>

#include "util/cpu.h"
#include "util/log.h"
#include "util/aep.h"

const uint64_t FILE_SIZE = 1ul << 30; // 1GB
const uint64_t FILE_4KB_NUM = FILE_SIZE >> 12;

int main(int argc, char* argv[]) {
    LogCfg log_cfg = {
        .is_log_to_stderr = true,
        .vlog_level = 0,
        .min_log_level = 3,
    };
    InitLog(argv[0], &log_cfg);
    SetSocketAndPolicy(1, 1);
    CoreBind(pthread_self(), 20);

    log_assert(argc == 3);

    std::string mntdir = "/mnt/pmem2";
    int bs = atoi(argv[1]);
    uint64_t OP = atoi(argv[2]);
    uint64_t bs_num = FILE_SIZE / bs;
    bs_num = std::min(bs_num, OP);

    printf("mnt %s, bs: %d, OP: %lu\n", mntdir.c_str(), bs, OP);
    printf("file_size: %lu GB, page_num: %lu\n", FILE_SIZE >> 30, FILE_4KB_NUM);

    int ret;
    uint64_t start_us, end_us;
    double interval_s;
    const std::string dir1_file = mntdir + "/write_read.dat";

    void* buf = aligned_alloc(4096, bs < 4096 ? 4096 : bs);
    memset(buf, 0x3f, bs < 4096 ? 4096 : bs);
    pmem2_map* pmap = Pmem2MapAndTruncate(dir1_file, FILE_SIZE);
    log_assert(pmap);
    char* addr = (char*)pmem2_map_get_address(pmap);
    log_assert(pmem2_map_get_size(pmap) == FILE_SIZE);
    pmem2_memcpy_fn pmem_cpy_fn = pmem2_get_memcpy_fn(pmap);

    // load
    for(int i = 0; i < FILE_4KB_NUM; ++i) {
        pmem_cpy_fn(addr + i * 4096, buf, 4096, 0);
    }

    // seq write
    start_us = GetTsUsec();
    uint64_t bs_idx;
    for(int i = 0; i < OP; ++i) {
        bs_idx = i % bs_num;
        pmem_cpy_fn(addr + bs_idx * bs, buf, bs, 0);
    }
    end_us = GetTsUsec();
    interval_s = (double)(end_us - start_us) / 1000 / 1000;
    printf("write bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf us\n",
           OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_us - start_us)*1.0 / OP);

    // seq read
    void* read_buf = aligned_alloc(4096, bs < 4096 ? 4096 : bs);
    uint64_t start_ns = GetTsNsec();
    for(int i = 0; i < OP; ++i) {
        bs_idx = i % bs_num;
        memcpy(read_buf, addr + bs_idx * bs, bs);
        assert(memcmp(read_buf, buf, bs) == 0);
    }
    uint64_t end_ns = GetTsNsec();
    interval_s = (double)(end_ns - start_ns) / 1000 / 1000 / 1000;
    printf("read bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf ns\n",
           OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_ns - start_ns)*1.0 / OP);

    Pmem2UnMap(&pmap);
    free(buf);

    printf("Test pass\n");
}
