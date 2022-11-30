#pragma once

#include <sys/types.h>
#include <fcntl.h>
#include <unordered_map>

struct statfs;
struct linux_dirent;
struct linux_dirent64;

#define HOOK_REWRITE 0

#if HOOK_REWRITE
extern bool init_rewrite_flag;
#endif

extern int hook_start_fd;
int mkdir_native(const char *path, mode_t mode);
int rmdir_native(const char *cpath);
int open_native(const char* cpath, int flags, mode_t mode);
int close_native(int fd);
int unlink_native(const char *cpath);
int fsync_native(int fd);
ssize_t read_native(int fd, void *buf, size_t len);
ssize_t write_native(int fd, const char *buf, size_t len);
off_t lseek_native(int fd, off_t off, int flag);
int truncate_native(const char *path, off_t length);
int ftruncate_native(int fd, off_t length);
int statfs_native(const char *path, struct statfs *sf);
int stat_native(const char *cpath, struct stat *st);
int fstat_native(int fd, struct stat *st);
int access_native(const char *path, int mask);
int getdents_native(int fd, struct linux_dirent *dirp, int count);
int getdents64_native(int fd, struct linux_dirent64 *dirp, int count);


struct hook_operations {
    const std::string label;
    const std::string root_name;
    void* sb;
    int (*register_thread)(int* proc_id);
    int (*fs_init)(void** sb_, const std::string& dev_name, const std::string& root_path);
    int (*fs_unmount)(void** sb_, const std::string &root_path);

    int (*mkdir     )(const char *path, mode_t mode);
    int (*rmdir     )(const char *cpath);
    int (*open      )(const char* cpath, int flags, mode_t mode);
    int (*close     )(int fd);
    int (*unlink    )(const char *cpath);
    int (*fsync     )(int fd);
    ssize_t (*read      )(int fd, void *buf, size_t len);
    ssize_t (*write     )(int fd, const char *buf, size_t len);
    off_t (*lseek     )(int fd, off_t off, int flag);
    int (*truncate)(const char *path, off_t length);
    int (*ftruncate)(int fd, off_t length);
    int (*statfs    )(const char *path, struct statfs *sf);
    int (*lstat      )(const char *pathname, struct stat *st);
    int (*stat      )(const char *cpath, struct stat *st);
    int (*fstat     )(int fd, struct stat *st);
    int (*access    )(const char *path, int mask);
    int (*getdents  )(int fd, struct linux_dirent *dirp, int count);
    int (*getdents64)(int fd, struct linux_dirent64 *dirp, int count);
};

extern struct hook_operations* hook_op;
extern struct hook_operations hook_op_native;
extern struct hook_operations hook_op_nova;
extern struct hook_operations hook_op_finefs;

int wrapper_hook(long syscall_number,
                long a0, long a1,
                long a2, long a3,
                long a4, long a5,
                long *res);
