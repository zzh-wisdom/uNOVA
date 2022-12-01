#ifndef UNOVA_VFS_API_H_
#define UNOVA_VFS_API_H_

#include "vfs/vfs.h"

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
int fs_mount(void** sb_, const std::string &dev_name, const std::string &root_path,
             struct vfs_cfg* cfg);
int fs_unmount(void** sb_, const std::string &root_path);

// 0创建成功，-1创建失败
int vfs_mkdir(const char* pathname, mode_t mode);
int vfs_ls(const char* pathname);
int vfs_rmdir(const char *dirname);
int vfs_open(const char* filename, int flags, mode_t mode);
int vfs_close(int fd);
int vfs_unlink(const char *pathname);

// SYSCALL_DEFINE3(read
static force_inline ssize_t vfs_read(int fd, void* buf, size_t count) {
    return do_read(fd, (char*)buf, count);
}

// SYSCALL_DEFINE3(write
static force_inline ssize_t vfs_write(int fd, const char* buf, size_t count) {
    return do_write(fd, buf, count);
}

static force_inline off_t vfs_lseek(int fd, off_t offset, int whence) {
    return do_lseek(fd, offset, whence);
}

// SYSCALL_DEFINE1(fsync
static force_inline int vfs_fsync(int fd) {
    return do_fsync(fd);
}

// SYSCALL_DEFINE2(stat
int vfs_stat(const char *path, struct stat *buf);
// 目前不支持文件link
static force_inline int vfs_lstat(const char *path, struct stat *buf) {
    return vfs_stat(path, buf);
}

int vfs_truncate(const char *path, off_t length);
static force_inline int vfs_ftruncate(int fd, off_t length) {
    return do_ftruncate(fd, length);
}

#endif
