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

uint64_t TOTAL_OPS = 1e6;

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
    }

    std::string mntdir;
    if (strcmp(argv[1], "nova") == 0) {
        mntdir = "/tmp/nova";
    } else if (strcmp(argv[1], "finefs") == 0) {
        mntdir = "/tmp/finefs";
    } else if(strcmp(argv[1], "libnvmmio") == 0) {
        mntdir = "/mnt/pmem2";
    } else if(strcmp(argv[1], "ext4") == 0) {
        mntdir = "/mnt/pmem2";
    } else {
        printf("error\n");
        exit(-1);
    }
    int tmp = atoi(argv[2]);
    if(tmp) {
        TOTAL_OPS = tmp;
    }
    int files = atoi(argv[3]);
    printf("mnt %s, files: %d op: %lu\n", mntdir.c_str(), files, TOTAL_OPS);

    const std::string dir1 = mntdir + "/dir1";
    const std::string dir1_file = dir1 + "/ftruncate";
    int mkdir_flag = S_IRWXU | S_IRWXG | S_IRWXO;
    int ret;
    std::vector<int> fds(files);

    ret = mkdir(dir1.c_str(), mkdir_flag);
    assert(ret == 0);
    for(int i = 0; i < files; ++i) {
        const std::string file_name = dir1_file + "-" + std::to_string(i);
        fds[i] = open(file_name.c_str(), O_RDWR | O_CREAT, 666);
        assert(fds[i] > 0);
    }

    // printf("open %s, fd = %d\n", dir1_f1.c_str(), fd);

    uint64_t file_len = 0;
    uint64_t start_us = GetTsUsec();
    barrier();
    for (uint64_t i = 0; i < TOTAL_OPS; ++i) {
        ret = ftruncate(fds[i%files], file_len);
        assert(ret == 0);
        file_len += 64;
    }
    barrier();
    uint64_t end_us = GetTsUsec();
    double interval_s = (double)(end_us - start_us) / 1000 / 1000;
    printf("bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf us\n",
           TOTAL_OPS * 64.0 / 1024 / 1024 / interval_s,
           TOTAL_OPS / 1000.0 / interval_s, (end_us - start_us)*1.0 / TOTAL_OPS);

    for(int i = 0; i < files; ++i) {
        close(fds[i]);
        const std::string file_name = dir1_file + "-" + std::to_string(i);
        ret = unlink(file_name.c_str());
        assert(ret == 0);
    }
    printf("Test pass\n");
}
