#include "nova/vfs_api.h"
#include "syscall-intercept/hooks.h"
#include "util/cpu.h"

int nova_fs_init(const std::string& dev_name, const std::string& root_path) {
    // rand 随机数种子
    int seed = time(nullptr);
    srand((unsigned int)seed);

    vfs_cfg fs_cfg;
    vfs_cfg_default_init(&fs_cfg);

    // numa环境
    SetSocketAndPolicy(fs_cfg.numa_socket, 1);

    int ret = 0;
    ret = fs_mount(dev_name, root_path, &fs_cfg);
    return ret;
}

struct hook_operations hook_op_nova = {
    .lable = "nova",
    .root_name = "/tmp/nova",
    .register_thread = nova_register_thread,
    .fs_init = nova_fs_init,
    .fs_unmount = vfs_fs_unmount,
    .mkdir      = vfs_mkdir     ,
    .rmdir      = vfs_rmdir      ,
    .open       = vfs_open       ,
    .close      = vfs_close      ,
    .unlink     = vfs_unlink     ,
    .fsync      = vfs_fsync      ,
    .read       = vfs_read       ,
    .write      = vfs_write      ,
    .lseek      = vfs_lseek      ,
    .statfs     = statfs_native     ,
    .stat       = stat_native       ,
    .fstat      = fstat_native      ,
    .access     = access_native     ,
    .getdents   = getdents_native   ,
    .getdents64 = getdents64_native ,
};