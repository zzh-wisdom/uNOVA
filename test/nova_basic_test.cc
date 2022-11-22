#include "nova/vfs_api.h"

#include "util/cpu.h"

int main(int argc, char* argv[]) {
    LogCfg log_cfg = {
        .is_log_to_stderr = true,
        .vlog_level = 3,
        .min_log_level = 0,
    };
    InitLog(argv[0], &log_cfg);

    vfs_cfg fs_cfg;
    vfs_cfg_default_init(&fs_cfg);
    // rand 随机数种子
    int seed = time(nullptr);
    srand((unsigned int)seed);
    // numa环境
    SetSocketAndPolicy(fs_cfg.numa_socket, 1);

    super_block *sb;
    int ret = 0;
    const std::string dev_name = "/dev/dax3.0";
    const std::string dir_name = "/tmp/nova";
    ret = fs_mount(&sb, dev_name, dir_name, &fs_cfg);
    log_assert(ret == 0);

    ret = vfs_mkdir("/tmp/nova/dir1", 0);
    log_assert(ret == 0);
    ret = vfs_mkdir("/tmp/nova/dir2", 0);
    log_assert(ret == 0);
    ret = vfs_mkdir("/tmp/nova/dir3/dir31", 0);
    log_assert(ret);

    fs_unmount(&sb);
    return 0;
}