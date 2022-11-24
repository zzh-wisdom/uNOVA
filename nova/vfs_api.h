#ifndef UNOVA_VFS_API_H_
#define UNOVA_VFS_API_H_

#include "nova/vfs.h"

#include "util/aep.h"

/**
 *
 * @brief 初始化一个文件
 *
 * @param dev_name NVM设备路径
 * @param dir_name 挂载路径
 *
 * sb 返回值，即文件句柄/文件实例
 *
 * 注意，需要先调用 vfs_init()
 *
 */
int fs_mount(struct super_block** sb, const std::string &dev_name, const std::string &dir_name,
             struct vfs_cfg* cfg);
int fs_unmount(struct super_block** sb);

// 0创建成功，-1创建失败
int vfs_mkdir(const char* pathname, umode_t mode);
int vfs_ls(const char* pathname);
int vfs_rmdir(const char *dirname);
int vfs_open(const char* filename, int flags, umode_t mode);
int vfs_close(int fd);
int vfs_unlink(const char *pathname);

// SYSCALL_DEFINE3(read
static force_inline ssize_t vfs_read(int fd, char* buf, size_t count) {
    return do_read(fd, buf, count);
}

// SYSCALL_DEFINE3(write
static force_inline ssize_t vfs_write(int fd, const char* buf, size_t count) {
    return do_write(fd, buf, count);
}

static force_inline off_t vfs_lseek(int fd, off_t offset, int whence) {
    return do_lseek(fd, offset, whence);
}

#endif
