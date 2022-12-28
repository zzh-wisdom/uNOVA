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

const uint64_t FILE_SIZE = 1ul << 30; // 3GB
#define O_ATOMIC 01000000000

// LD_PRELOAD=../../libnvmmio/src/libnvmmio.so

int main(int argc, char* argv[]) {
    // #if FS_HOOK==1
    //     printf("dlopen ./libnova_hook.so\n");
    //     void *handle = dlopen("./libnova_hook.so", RTLD_NOW);
    // 	assert(handle);
    //     const std::string mntdir = "/tmp/nova";
    // #else
    //     printf("dlopen ./libfinefs_hook.so\n");
    //     void *handle = dlopen("./libfinefs_hook.so", RTLD_NOW);
    // 	assert(handle);
    //     const std::string mntdir = "/tmp/finefs";
    // #endif
    assert(argc == 4);
    if (strcmp(argv[1], "nova") == 0) {
        printf("dlopen ./libnova_hook.so\n");
        void *handle = dlopen("./libnova_hook.so", RTLD_NOW);
    	assert(handle);
    } else if (strcmp(argv[1], "finefs") == 0) {
        printf("dlopen ./libfinefs_hook.so\n");
        void *handle = dlopen("./libfinefs_hook.so", RTLD_NOW);
    	assert(handle);
    } else if (strcmp(argv[1], "libnvmmio") == 0) {
        // printf("dlopen ../../libnvmmio/src/libnvmmio.so\n");
        // void *handle = dlopen("../../libnvmmio/src/libnvmmio.so", RTLD_NOW);
    	// assert(handle);
    } else {
        // exit(-1);
    }

    std::string mntdir;
    if (strcmp(argv[1], "nova") == 0) {
        mntdir = "/tmp/nova";
    } else if (strcmp(argv[1], "finefs") == 0) {
        mntdir = "/tmp/finefs";
    } else if(strcmp(argv[1], "ext4") == 0){
        mntdir = "/mnt/pmem2/";
    } else if(strcmp(argv[1], "libnvmmio") == 0) {
        mntdir = "/mnt/pmem2";
    }
    int bs = atoi(argv[2]);
    uint64_t OP = atoi(argv[3]);
    uint64_t bs_num = FILE_SIZE / bs;
    bs_num = std::min(bs_num, OP);
    // OP = bs_num;
    printf("mnt %s, bs: %d, OP: %lu\n", mntdir.c_str(), bs, OP);

    int mkdir_flag = S_IRWXU | S_IRWXG | S_IRWXO;
    const int open_flag = O_RDWR | O_CREAT | O_ATOMIC; // O_DIRECT
    int ret;
    uint64_t start_us, end_us;
    double interval_s;
    const std::string dir1 = mntdir + "/dir1";
    const std::string dir1_file = dir1 + "/write_read";
    int fd;

    ret = mkdir(dir1.c_str(), mkdir_flag);
    assert(ret == 0 || errno == EEXIST);
    fd = open(dir1_file.c_str(), open_flag, 666);
    assert(fd > 0);
    void* buf = aligned_alloc(4096, bs < 4096 ? 4096 : bs);
    memset(buf, 0x3f, bs < 4096 ? 4096 : bs);

    // load append
    start_us = GetTsUsec();
    for(int i = 0; i < bs_num; ++i) {
        ret = write(fd, buf, bs);
        assert(ret == bs);
        fsync(fd);
    }
    end_us = GetTsUsec();
    interval_s = (double)(end_us - start_us) / 1000 / 1000;
    printf("append bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf us\n",
           bs_num * (bs) / 1024.0 / 1024 / interval_s,
           bs_num / 1000.0 / interval_s, (end_us - start_us)*1.0 / bs_num);

    // write
    start_us = GetTsUsec();
    for(int i = 0; i < OP; ++i) {
        if(i % bs_num == 0) {
            ret = lseek(fd, 0, SEEK_SET);
            assert(ret == 0);
        }
        ret = write(fd, buf, bs);
        assert(ret == bs);
        fsync(fd);
    }
    end_us = GetTsUsec();
    interval_s = (double)(end_us - start_us) / 1000 / 1000;
    printf("write bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf us\n",
           OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_us - start_us)*1.0 / OP);

    // read
    void* read_buf = aligned_alloc(4096, bs < 4096 ? 4096 : bs);
    // OP = OP * bs / 4096;
    // bs = 4096;
    uint64_t start_ns = GetTsNsec();
    for(int i = 0; i < OP; ++i) {
        if(i % bs_num == 0) {
            ret = lseek(fd, 0, SEEK_SET);
            assert(ret == 0);
        }
        ret = read(fd, read_buf, bs);
        assert(ret == bs);
        assert(memcmp(read_buf, buf, bs) == 0);
    }
    uint64_t end_ns = GetTsNsec();
    interval_s = (double)(end_ns - start_ns) / 1000 / 1000 / 1000;
    printf("read bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf ns\n",
           OP * (bs) / 1024.0 / 1024 / interval_s,
           OP / 1000.0 / interval_s, (end_ns - start_ns)*1.0 / OP);

    close(fd);
    // ret = unlink(dir1_file.c_str());
    // assert(ret == 0);

    printf("Test pass\n");
}
