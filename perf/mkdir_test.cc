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

const int MAX_FILE_PER_DIR=30000;

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
        exit(-1);
    }

    std::string mntdir;
    if (strcmp(argv[1], "nova") == 0) {
        mntdir = "/tmp/nova";
    } else if (strcmp(argv[1], "finefs") == 0) {
        mntdir = "/tmp/finefs";
    } else {
        exit(-1);
    }
    int files = atoi(argv[2]);
    int dir_num = (files + MAX_FILE_PER_DIR - 1) / MAX_FILE_PER_DIR;
    printf("mnt %s, files: %d, dir_num: %d\n", mntdir.c_str(), files, dir_num);

    int mkdir_flag = S_IRWXU | S_IRWXG | S_IRWXO;
    int ret;
    uint64_t start_us, end_us;
    double interval_s;

    const std::string dir = mntdir + "/dir";
    std::vector<std::string> p_dirs;
    for(int i = 0; i < dir_num; ++i) {
        p_dirs.push_back(dir + "-" + std::to_string(i));
        ret = mkdir(p_dirs.back().c_str(), mkdir_flag);
        assert(ret == 0);
    }

    int dir_idx;
    start_us = GetTsUsec();
    for(int i = 0; i < files; ++i) {
        dir_idx = i % dir_num;
        const std::string dir_name = p_dirs[dir_idx] + "/dir-" + std::to_string(i/dir_num);
        ret = mkdir(dir_name.c_str(), mkdir_flag);
        assert(ret == 0);
    }
    end_us = GetTsUsec();
    interval_s = (double)(end_us - start_us) / 1000 / 1000;
    printf("mkdir bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf us\n",
           files * (64*2 + 128 + 64) / 1024.0 / 1024 / interval_s,
           files / 1000.0 / interval_s, (end_us - start_us)*1.0 / files);

    start_us = GetTsUsec();
    for(int i = 0; i < files; ++i) {
        dir_idx = i % dir_num;
        const std::string dir_name = p_dirs[dir_idx] + "/dir-" + std::to_string(i/dir_num);
        ret = rmdir(dir_name.c_str());
        assert(ret == 0);
    }
    end_us = GetTsUsec();
    interval_s = (double)(end_us - start_us) / 1000 / 1000;
    printf("rmdir bandwidth: %0.2lf MB/s, IOPS: %0.2lf kops, lat: %0.2lf us\n",
           files * (64*2 + 128 + 64) / 1024.0 / 1024 / interval_s,
           files / 1000.0 / interval_s, (end_us - start_us)*1.0 / files);

    printf("Test pass\n");
}
