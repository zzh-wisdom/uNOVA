#include "vfs/vfs_api.h"
#include "vfs/fs_cfg.h"
#include "syscall-intercept/hooks.h"
#include "util/cpu.h"

int finefs_fs_init(void** sb_, const std::string& dev_name, const std::string& root_path) {
    // rand 随机数种子
    int seed = time(nullptr);
    srand((unsigned int)seed);

    vfs_cfg fs_cfg;
    vfs_cfg_default_init(&fs_cfg);

    // numa环境
    SetSocketAndPolicy(fs_cfg.numa_socket, 1);

    int ret = 0;
    u64 start_ns = GetTsUsec();
    ret = fs_mount(sb_, dev_name, root_path, &fs_cfg);
    u64 end_ns = GetTsUsec();
    r_info("fs_mount spent %lu us", end_ns - start_ns);
    return ret;
}

struct hook_operations hook_op_finefs = {
    .label = "finefs",
    .root_name = "/tmp/finefs",
    .register_thread = fs_register_thread,
    .fs_init = finefs_fs_init,
    .fs_unmount = fs_unmount,
    .mkdir      = vfs_mkdir     ,
    .rmdir      = vfs_rmdir      ,
    .open       = vfs_open       ,
    .close      = vfs_close      ,
    .unlink     = vfs_unlink     ,
    .fsync      = vfs_fsync      ,
    .read       = vfs_read       ,
    .write      = vfs_write      ,
    .lseek      = vfs_lseek      ,
    .truncate   = vfs_truncate   ,
    .ftruncate  = vfs_ftruncate  ,
    .statfs     = statfs_native     ,
    .lstat      = vfs_lstat         ,
    .stat       = vfs_stat          ,
    .fstat      = fstat_native      ,
    .access     = access_native     ,
    .getdents   = getdents_native   ,
    .getdents64 = getdents64_native ,
};