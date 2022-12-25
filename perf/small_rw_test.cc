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

const uint64_t FILE_SIZE = 1ul << 30; // 1GB
const uint64_t FILE_4KB_NUM = FILE_SIZE >> 12;

int main(int argc, char* argv[]) {
    assert(argc == 3);
    if (strcmp(argv[1], "nova") == 0) {
        printf("dlopen ./libnova_hook.so\n");
        void *handle = dlopen("./libnova_hook.so", RTLD_NOW);
    	assert(handle);
    } else if (strcmp(argv[1], "finefs") == 0) {
        printf("dlopen ./libfinefs_hook.so\n");
        void *handle = dlopen("./libfinefs_hook.so", RTLD_NOW);
    	assert(handle);
    } else {
        // exit(-1);
    }

    LogCfg log_cfg = {
        .is_log_to_stderr = true,
        .vlog_level = 0,
        .min_log_level = 3,
    };
    InitLog(argv[0], &log_cfg);
    CoreBind(pthread_self(), 25);
    srand(time(nullptr));

    std::string mntdir;
    if (strcmp(argv[1], "nova") == 0) {
        mntdir = "/tmp/nova";
    } else if (strcmp(argv[1], "finefs") == 0) {
        mntdir = "/tmp/finefs";
    } else if(strcmp(argv[1], "ext4") == 0){
        mntdir = "/mnt/pmem2/test";
    }
    int bs = atoi(argv[2]);
    uint64_t OP = FILE_SIZE / bs;
    printf("mnt %s, bs: %d, OP: %lu\n", mntdir.c_str(), bs, OP);
    printf("file_size: %lu GB, page_num: %lu\n", FILE_SIZE >> 30, FILE_4KB_NUM);

    int mkdir_flag = S_IRWXU | S_IRWXG | S_IRWXO;
    int open_flag = O_RDWR | O_CREAT;
    int ret;
    uint64_t start_us, end_us;
    double interval_s;
    const std::string dir1 = mntdir + "/dir1";
    const std::string dir1_file = dir1 + "/write_read";
    int fd;

    ret = mkdir(dir1.c_str(), mkdir_flag);
    log_assert(ret == 0 || errno == EEXIST);
    fd = open(dir1_file.c_str(), O_RDWR | O_CREAT | O_DIRECT, 666);
    log_assert(fd > 0);
    void* buf = aligned_alloc(4096, bs < 4096 ? 4096 : bs);
    memset(buf, 0x3f, bs < 4096 ? 4096 : bs);

    // load
    for(int i = 0; i < FILE_4KB_NUM; ++i) {
        ret = write(fd, buf, 4096);
        log_assert(ret == 4096);
    }

    size_t off;

    // small write
    start_us = GetTsUsec();
    for(int i = 0; i < OP; ++i) {
        off = (rand() % OP) * bs;
        ret = lseek(fd, off, SEEK_SET);
        log_assert(ret == off);
        ret = write(fd, buf, bs);
        log_assert(ret == bs);
    }
    end_us = GetTsUsec();
    interval_s = (double)(end_us - start_us) / 1000 / 1000;
    printf("readn write %d bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf us\n",
           bs, OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_us - start_us)*1.0 / OP);

    // rand read
    void* read_buf = aligned_alloc(4096, bs < 4096 ? 4096 : bs);
    uint64_t start_ns, end_ns;
    OP = FILE_4KB_NUM;
    bs = 4096;

    ret = lseek(fd, 0, SEEK_SET);
    log_assert(ret == 0);
    start_ns = GetTsNsec();
    for(int i = 0; i < OP; ++i) {
        // off = (rand() % OP) * bs;
        // ret = lseek(fd, off, SEEK_SET);
        // log_assert(ret == off);
        ret = read(fd, read_buf, bs);
        log_assert(ret == bs);
        assert(memcmp(read_buf, buf, bs) == 0);
    }
    end_ns = GetTsNsec();
    interval_s = (double)(end_ns - start_ns) / 1000 / 1000 / 1000;
    printf("1-read bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf ns\n",
           OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_ns - start_ns)*1.0 / OP);

    ret = lseek(fd, 0, SEEK_SET);
    log_assert(ret == 0);
    start_ns = GetTsNsec();
    for(int i = 0; i < OP; ++i) {
        // off = (rand() % OP) * bs;
        // ret = lseek(fd, off, SEEK_SET);
        // log_assert(ret == off);
        ret = read(fd, read_buf, bs);
        log_assert(ret == bs);
        assert(memcmp(read_buf, buf, bs) == 0);
    }
    end_ns = GetTsNsec();
    interval_s = (double)(end_ns - start_ns) / 1000 / 1000 / 1000;
    printf("2-read bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf ns\n",
           OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_ns - start_ns)*1.0 / OP);

    ret = lseek(fd, 0, SEEK_SET);
    log_assert(ret == 0);
    start_ns = GetTsNsec();
    for(int i = 0; i < OP; ++i) {
        // off = (rand() % OP) * bs;
        // ret = lseek(fd, off, SEEK_SET);
        // log_assert(ret == off);
        ret = read(fd, read_buf, bs);
        log_assert(ret == bs);
        assert(memcmp(read_buf, buf, bs) == 0);
    }
    end_ns = GetTsNsec();
    interval_s = (double)(end_ns - start_ns) / 1000 / 1000 / 1000;
    printf("3-read bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf ns\n",
           OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_ns - start_ns)*1.0 / OP);

    ret = lseek(fd, 0, SEEK_SET);
    log_assert(ret == 0);
    start_ns = GetTsNsec();
    for(int i = 0; i < OP; ++i) {
        // off = (rand() % OP) * bs;
        // ret = lseek(fd, off, SEEK_SET);
        // log_assert(ret == off);
        ret = read(fd, read_buf, bs);
        log_assert(ret == bs);
        assert(memcmp(read_buf, buf, bs) == 0);
    }
    end_ns = GetTsNsec();
    interval_s = (double)(end_ns - start_ns) / 1000 / 1000 / 1000;
    printf("4-read bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf ns\n",
           OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_ns - start_ns)*1.0 / OP);

    ret = lseek(fd, 0, SEEK_SET);
    log_assert(ret == 0);
    start_ns = GetTsNsec();
    for(int i = 0; i < OP; ++i) {
        // off = (rand() % OP) * bs;
        // ret = lseek(fd, off, SEEK_SET);
        // log_assert(ret == off);
        ret = read(fd, read_buf, bs);
        log_assert(ret == bs);
        assert(memcmp(read_buf, buf, bs) == 0);
    }
    end_ns = GetTsNsec();
    interval_s = (double)(end_ns - start_ns) / 1000 / 1000 / 1000;
    printf("5-read bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf ns\n",
           OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_ns - start_ns)*1.0 / OP);

    close(fd);
    ret = unlink(dir1_file.c_str());
    log_assert(ret == 0);

    printf("Test pass\n");
}
