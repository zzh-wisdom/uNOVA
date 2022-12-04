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
// #include <dlfcn.h>

#include "util/cpu.h"

const uint64_t TOTAL_OPS = 1e8;

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
    assert(argc == 2);
    std::string mntdir;
    if (strcmp(argv[1], "nova") == 0) {
        mntdir = "/tmp/nova";
    } else if (strcmp(argv[1], "finefs") == 0) {
        mntdir = "/tmp/finefs";
    } else {
        exit(-1);
    }
    printf("mnt %s\n", mntdir.c_str());

    const std::string dir1 = mntdir + "/dir1";
    const std::string dir1_f1 = dir1 + "/f1";
    int mkdir_flag = S_IRWXU | S_IRWXG | S_IRWXO;
    int ret;
    int fd;

    ret = mkdir(dir1.c_str(), mkdir_flag);
    assert(ret == 0);
    fd = open(dir1_f1.c_str(), O_RDWR | O_CREAT, 666);
    assert(fd > 0);
    printf("open %s, fd = %d\n", dir1_f1.c_str(), fd);

    uint64_t file_len = 0;
    uint64_t start_ns = GetTsUsec();
    barrier();
    for (uint64_t i = 0; i < TOTAL_OPS; ++i) {
        ret = ftruncate(fd, file_len);
        assert(ret == 0);
        file_len += 64;
    }
    barrier();
    uint64_t end_ns = GetTsUsec();
    double interval_s = (double)(end_ns - start_ns) / 1000 / 1000;
    printf("bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops\n",
           TOTAL_OPS * 64.0 / 1024 / 1024 / interval_s, TOTAL_OPS / 1000.0 / interval_s);

    printf("Test pass\n");
}
