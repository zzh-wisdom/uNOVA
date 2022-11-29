#include "syscall-intercept/hooks.h"

#include "util/log.h"
#include "util/cpu.h"

inline int mkdir_native(const char *path, mode_t mode) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline int rmdir_native(const char *cpath) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}

inline int open_native(const char* cpath, int flags, mode_t mode) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline int close_native(int fd) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline int unlink_native(const char *cpath) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline int fsync_native(int fd) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline ssize_t read_native(int fd, void *buf, size_t len) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline ssize_t write_native(int fd, const char *buf, size_t len) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline off_t lseek_native(int fd, off_t off, int flag) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}

inline int truncate_native(const char *path, off_t length) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline int ftruncate_native(int fd, off_t length) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}

inline int statfs_native(const char *path, struct statfs *sf) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline int lstat_native(const char *cpath, struct stat *st) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline int stat_native(const char *cpath, struct stat *st) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline int fstat_native(int fd, struct stat *st) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
int access_native(const char *path, int mask) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}

inline int getdents_native(int fd, struct linux_dirent *dirp, int count) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}
inline int getdents64_native(int fd, struct linux_dirent64 *dirp, int count) {
    r_error("Hook do nothing --------------------------- %s", __func__);
	return -ENOTSUP;
}

inline int register_thread_native(int* proc_id) {
    return 0;
}

inline int fs_init_native(void** sb_, const std::string& dev_name, const std::string& root_path) {
    // rand 随机数种子
    int seed = time(nullptr);
    srand((unsigned int)seed);

    // numa环境
    SetSocketAndPolicy(1, 1);
    return 0;
}

inline int fs_unmount_native(void** sb_, const std::string &root_path) {
    *sb_ = nullptr;
    return 0;
}

struct hook_operations hook_op_native = {
    .label = "native",
    .root_name = "",
    .register_thread = register_thread_native,
    .fs_init = fs_init_native,
    .fs_unmount = fs_unmount_native,
    .mkdir      = mkdir_native      ,
    .rmdir      = rmdir_native      ,
    .open       = open_native       ,
    .close      = close_native      ,
    .unlink     = unlink_native     ,
    .fsync      = fsync_native      ,
    .read       = read_native       ,
    .write      = write_native      ,
    .lseek      = lseek_native      ,
    .truncate   = truncate_native   ,
    .ftruncate  = ftruncate_native  ,
    .statfs     = statfs_native     ,
    .lstat      = lstat_native      ,
    .stat       = stat_native       ,
    .fstat      = fstat_native      ,
    .access     = access_native     ,
    .getdents   = getdents_native   ,
    .getdents64 = getdents64_native ,
};
