#include "hooks.h"

#include <assert.h>
#include <dlfcn.h>
#include <libsyscall_intercept_hook_point.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>

#include <string>
#include <unordered_map>
#include "util/common.h"

extern "C" {
#include <dirent.h>  // used for file types in the getdents{,64}() functions
#include <linux/const.h>
#include <linux/kernel.h>  // used for definition of alignment macros
#include <sys/statfs.h>
#include <sys/statvfs.h>
}

/*
 * linux_dirent is used in getdents() but is privately defined in the linux kernel: fs/readdir.c.
 */
struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};

/*
 * linux_dirent64 is used in getdents64() and defined in the linux kernel: include/linux/dirent.h.
 * However, it is not part of the kernel-headers and cannot be imported.
 */
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];  // originally `char d_name[0]` in kernel, but ISO C++ forbids zero-size array
                     // 'd_name'
};

/*
 * Macro used within getdents{,64} functions.
 * __ALIGN_KERNEL defined in linux/kernel.h
 */
#define ALIGN(x, a) __ALIGN_KERNEL((x), (a))

int hook_start_fd = 10000;
struct hook_operations *hook_op;

static inline bool is_hook(const char *pathname) {
    if (hook_op->root_name.empty()) return false;
    if (strncmp(pathname, hook_op->root_name.c_str(), hook_op->root_name.size()) == 0) return true;
    return false;
}

static inline void thread_bind() {
    thread_local static bool is_bind = false;
    if (!is_bind) {
        hook_op->register_thread(nullptr);
        is_bind = true;
    }
}

static inline int hook_mkdirat(int dirfd, const char *path, mode_t mode, long *res) {
    if (dirfd != AT_FDCWD) return -1;
    if (!is_hook(path)) return -1;
    // printf("%s %s\n", __func__, path);
    thread_bind();
    *res = hook_op->mkdir(path, mode);
    return 0;
}
static inline int hook_rmdir(int dirfd, const char *cpath, long *res) {
    if (dirfd != AT_FDCWD) return -1;
    if (!is_hook(cpath)) return -1;
    // printf("%s %s\n", __func__, cpath);
    thread_bind();
    *res = hook_op->rmdir(cpath);
    return 0;
}

static inline int hook_openat(int dirfd, const char *cpath, int flags, mode_t mode, long *res) {
    if (dirfd != AT_FDCWD) return -1;
    if (!is_hook(cpath)) return -1;
    if (flags & O_PATH || flags & O_EXCL) {  // TODO: flags & O_TRUNC
        *res = -ENOTSUP;
        return 0;
    }
    // printf("%s cpath = %s\n", __func__, cpath);
    thread_bind();
    *res = hook_op->open(cpath, flags, mode);
    return 0;
}
static inline int hook_close(int fd, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("%s fd = %d\n", __func__, fd);
    thread_bind();
    *res = hook_op->close(fd);
    return 0;
}
static inline int hook_unlinkat(int dirfd, const char *cpath, long *res) {
    if (dirfd != AT_FDCWD) return -1;
    if (!is_hook(cpath)) return -1;
    // printf("%s cpath = %s\n", __func__, cpath);
    thread_bind();
    *res = hook_op->unlink(cpath);
    return 0;
}
static inline int hook_fsync(int fd, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("%s fd = %d\n", __func__, fd);
    thread_bind();
    *res = hook_op->fsync(fd);
    return 0;
}
static inline int hook_read(int fd, void *buf, size_t len, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("%s fd = %d\n", __func__, fd);
    thread_bind();
    *res = hook_op->read(fd, buf, len);
    return 0;
}
static inline int hook_write(int fd, const char *buf, size_t len, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("%s fd = %d\n", __func__, fd);
    thread_bind();
    *res = hook_op->write(fd, buf, len);
    return 0;
}
static inline int hook_lseek(int fd, long off, int flag, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("%s fd = %d\n", __func__, fd);
    thread_bind();
    *res = hook_op->lseek(fd, off, flag);
    return 0;
}

static inline int hook_truncate(const char *path, off_t length, long *res) {
    // if (dirfd != AT_FDCWD) return -1;
    if (!is_hook(path)) return -1;
    // printf("%s path = %s\n", __func__, path);
    thread_bind();
    *res = hook_op->truncate(path, length);
    return 0;
}

static inline int hook_ftruncate(int fd, off_t length, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("%s fd = %d\n", __func__, fd);
    thread_bind();
    *res = hook_op->ftruncate(fd, length);
    return 0;
}

static inline int hook_statfs(const char *path, struct statfs *sf, long *res) {
    if (!is_hook(path)) return -1;
    sf->f_type = 0;
    sf->f_bsize = 0;
    sf->f_blocks = 40960;
    sf->f_bfree = 40960;
    sf->f_bavail = sf->f_bfree;
    sf->f_files = 0;
    sf->f_ffree = (unsigned long)-1;
    sf->f_fsid = {0, 0};
    sf->f_namelen = 0;
    sf->f_frsize = 0;
    sf->f_flags = ST_NOSUID | ST_NODEV;

    // printf("------------- %s path = %s\n", __func__, path);
    thread_bind();
    *res = 0;
    return 0;
}
static inline int hook_lstat(const char *pathname, struct stat *st, long *res) {
    if (!is_hook(pathname)) return -1;
    // printf("------------- %s path = %s\n", __func__, pathname);
    thread_bind();
    *res = hook_op->lstat(pathname, st);
    return 0;
}
static inline int hook_stat(const char *cpath, struct stat *st, long *res) {
    if (!is_hook(cpath)) return -1;
    // printf("------------- %s path = %s\n", __func__, cpath);
    thread_bind();
    *res = hook_op->stat(cpath, st);
    // printf("%s ret %ld\n", __func__, *res);
    // assert(*res == 0);
    return 0;
}
static inline int hook_fstat(int fd, struct stat *st, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("------------- %s fd = %d\n", __func__, fd);
    thread_bind();
    *res = 0;
    return 0;
}
static inline int hook_access(const char *path, int mask, long *res) {
    if (!is_hook(path)) return -1;
    // printf("------------- %s path = %s\n", __func__, path);
    thread_bind();
    *res = 0;
    return 0;
}

static inline int hook_ioctl(int fd, int cmd, unsigned long arg, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("------------- %s path = %s\n", __func__, path);
    // thread_bind();
    *res = 0;
    return 0;
}

static inline int hook_fadvise64(int fd, loff_t offset, loff_t len, int advise, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("------------- %s path = %s\n", __func__, path);
    // thread_bind();
    *res = 0;
    return 0;
}

static inline int hook_getdents(int fd, struct linux_dirent *dirp, int count, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("hook %s\n", __func__);
    thread_bind();
    *res = 0;
    return 0;
}
static inline int hook_getdents64(int fd, struct linux_dirent64 *dirp, int count, long *res) {
    if (fd < hook_start_fd) return -1;
    // printf("hook %s\n", __func__);
    thread_bind();
    *res = 0;
    return 0;
}

// 返回1表示
// mkdir时调用的似乎是SYS_create
// opendir内部还会调用SYS_close
static int hook(long syscall_number, long a0, long a1, long a2, long a3, long a4, long a5, long *res) {
    switch (syscall_number) {
        case SYS_mkdirat:
            // printf("=== SYS_mkdirat %s\n", (const char *)a1);
            return hook_mkdirat((int)a0, (const char *)a1, (mode_t)a2, res);
        case SYS_mkdir:
            // printf("=== SYS_mkdir %s\n", (const char *)a0);
            return hook_mkdirat(AT_FDCWD, (const char *)a0, (mode_t)a1, res);
        case SYS_rmdir:
            // printf("SYS_rmdir %s\n", (const char *)a0);
            return hook_rmdir(AT_FDCWD, (const char *)a0, res);
        case SYS_open:
            // printf("SYS_open %s\n", (char *)a0);
            return hook_openat(AT_FDCWD, (char *)a0, (int)a1, (mode_t)a2, res);
        case SYS_openat:
            // printf("SYS_openat %d %s\n", (int)a0, (char *)a1);
            return hook_openat((int)a0, (char *)a1, (int)a2, (mode_t)a3, res);
        case SYS_creat:
            // printf("SYS_create %s\n", (char *)a0);
            return hook_openat(AT_FDCWD, (char *)a0, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)a1, res);
        case SYS_close:
            // printf("SYS_close, fd: %d\n", (int)a0);
            return hook_close((int)a0, res);
        case SYS_write:
            // printf("SYS_write, fd: %d, %lu\n", (int)a0, (size_t)a2);
            return hook_write((int)a0, (char *)a1, (size_t)a2, res);
        case SYS_read:
            // printf("SYS_read, fd: %d\n", (int)a0);
            return hook_read((int)a0, (void *)a1, (size_t)a2, res);
        case SYS_lseek:
            // printf("SYS_lseek %d\n", (int)a0);
            return hook_lseek((int)a0, a1, (int)a2, res);
        case SYS_ftruncate:
            // printf("SYS_ftruncate fd=%d length=%d\n", (int)a0, (off_t)a1);
            return hook_ftruncate((int)a0, (off_t)a1, res);
        case SYS_truncate:
            // printf("SYS_truncate %s length=%d\n", (char *)a0, (off_t)a1);
            return hook_truncate((char *)a0, (off_t)a1, res);
        case SYS_fsync:
            // printf("SYS_fsync %d\n", (int)a0);
            return hook_fsync((int)a0, res);
        case SYS_unlink:
            // printf("SYS_unlink %s\n", (const char *)a0);
            return hook_unlinkat(AT_FDCWD, (const char *)a0, res);

        case SYS_lstat:
            // printf("=== SYS_lstat %s\n", (const char *)a0);
        case SYS_stat:
            // printf("=== SYS_stat %s\n", (const char *)a0);
            return hook_stat((const char *)a0, (struct stat *)a1, res);
        case SYS_fstat:
            // printf("SYS_fstat fd:%d\n", (int)a0);
            return hook_fstat((int)a0, (struct stat *)a1, res);
        case SYS_statfs:
            // printf("SYS_statfs %s\n", (const char *)a0);
            return hook_statfs((const char *)a0, (struct statfs *)a1, res);
        case SYS_access:
            // printf("SYS_access %s\n", (const char *)a0);
            return hook_access((const char *)a0, (int)a1, res);
        case SYS_ioctl:
            // printf("SYS_ioctl %d\n", (int)a0);
            return hook_ioctl((int)a0, (int)a1, (unsigned long)a2, res);
        // case SYS_fadvise64:
        //     // printf("SYS_fadvise64 %d\n", (int)a0);
        //     return hook_fadvise64((int)a0, (loff_t )a1, (loff_t )a2, (int)a3, res);
        case SYS_getdents:
            // printf("SYS_getdents %d\n", (int)a0);
            return hook_getdents((int)a0, (linux_dirent *)a1, (int)a2, res);
        case SYS_getdents64:
            // printf("SYS_getdents64 %d\n", (int)a0);
            return hook_getdents64((int)a0, (linux_dirent64 *)a1, (int)a3, res);
            // case SYS_rename:
            //     return hook_renameat(AT_FDCWD, (const char))
            // case SYS_renameat:

        default:
            // printf("=== SYS_unhook: %ld\n", syscall_number);
            // SYS_clone linux用来创建线程的
            // assert(syscall_number != SYS_fork && syscall_number != SYS_vfork);
            return -1;
    }
    exit(-1);
    return -1;
}

// std::unordered_map<long, bool> reentrance_thread_map;


        // case SYS_mkdirat:
        // case SYS_mkdir:
        // case SYS_rmdir:
        // case SYS_open:
        // case SYS_openat:
        // case SYS_creat:
        // case SYS_close:
        // case SYS_write:
        // case SYS_read:
        // case SYS_lseek:
        // case SYS_ftruncate:
        // case SYS_truncate:
        // case SYS_fsync:
        // case SYS_unlink:
        // case SYS_lstat:
        // case SYS_stat:
        // case SYS_fstat:
        // case SYS_statfs:
        // case SYS_access:
        // case SYS_ioctl:
        // case SYS_fadvise64:
        // case SYS_getdents:
        // case SYS_getdents64:
static bool is_hook_flags[496]; // ATTR_PRIORITY_ONE

void init_is_hook_flag() {
    memset(is_hook_flags, 0, sizeof(is_hook_flags));
    is_hook_flags[SYS_mkdirat] = 1;
    is_hook_flags[SYS_mkdir] = 1;
    is_hook_flags[SYS_rmdir] = 1;
    is_hook_flags[SYS_open] = 1;
    is_hook_flags[SYS_openat] = 1;
    is_hook_flags[SYS_creat] = 1;
    is_hook_flags[SYS_close] = 1;
    is_hook_flags[SYS_write] = 1;
    is_hook_flags[SYS_read] = 1;
    is_hook_flags[SYS_lseek] = 1;
    is_hook_flags[SYS_ftruncate] = 1;
    is_hook_flags[SYS_truncate] = 1;
    is_hook_flags[SYS_fsync] = 1;
    is_hook_flags[SYS_unlink] = 1;
    is_hook_flags[SYS_lstat] = 1;
    is_hook_flags[SYS_stat] = 1;
    is_hook_flags[SYS_fstat] = 1;
    is_hook_flags[SYS_statfs] = 1;
    is_hook_flags[SYS_access] = 1;
    is_hook_flags[SYS_ioctl] = 1;
    is_hook_flags[SYS_fadvise64] = 1;
    is_hook_flags[SYS_getdents] = 1;
    is_hook_flags[SYS_getdents64] = 1;
}

// thread_local static int reentrance_flag = false;

int wrapper_hook(long syscall_number, long a0, long a1, long a2, long a3, long a4, long a5,
                 long *res) {
    // if(syscall_number == 273) return -1;
    // if(syscall_number == __NR_madvise) return -1;
    // if(syscall_number == __NR_exit) return -1;
    // if(syscall_number == __NR_mmap) return -1;
    // if(syscall_number == __NR_mprotect) return -1;
    // if(syscall_number == __NR_munmap) return -1;
    if(is_hook_flags[syscall_number] != 1) return -1;
    if((syscall_number == 257) && (a0 == 4294967196ul)  // a1=140737351986384
        && (1) && (a2==524288) && (a3==0)) return -1;
    if((syscall_number == __NR_openat) && a0 < 10000 && a0 != AT_FDCWD) return -1;
    if((syscall_number == __NR_read) && a0 < 10000) return -1;
    if((syscall_number == __NR_close) && a0 < 10000) return -1;

    int was_hooked = -1;
    thread_local static int reentrance_flag = false; // 这个变量也需要分配的，所以在新建线程时可能会出现问题
    // 防止重复进入
    if (reentrance_flag) {
        return -1;
    }
    reentrance_flag = true;
    // if (reentrance_thread_map[syscall_number]) {
    //     return -1;
    // }
    // reentrance_thread_map[syscall_number] = true;

    *res = 0;
    was_hooked = hook(syscall_number, a0, a1, a2, a3, a4, a5, res);
    reentrance_flag = false;
    // reentrance_thread_map[syscall_number] = false;
    assert(*res != -EBADF);
    return was_hooked;
}

// rewrite syscall function, faster than hook.=_=实际是人为减少了一些Syscall
#if HOOK_REWRITE
bool init_rewrite_flag = false;

int rmdir(const char *path) {
    static int (*real_rmdir)(const char *path) = NULL;
    if (unlikely(real_rmdir == NULL)) {
        real_rmdir = (typeof(real_rmdir))dlsym(RTLD_NEXT, "rmdir");
    }
    long res;
    if (likely(init_rewrite_flag) && 0 == hook_unlink(path, &res)) return res;
    return real_rmdir(path);
}

int unlink(const char *path) {
    static int (*real_unlink)(const char *path) = NULL;
    if (unlikely(real_unlink == NULL)) {
        real_unlink = (typeof(real_unlink))dlsym(RTLD_NEXT, "unlink");
    }
    long res;
    if (likely(init_rewrite_flag) && 0 == hook_unlink(path, &res)) return res;
    return real_unlink(path);
}

int stat(const char *path, struct stat *buf) {
    static int (*real_stat)(const char *path, struct stat *buf) = NULL;
    if (unlikely(real_stat == NULL)) {
        real_stat = (typeof(real_stat))dlsym(RTLD_NEXT, "stat");
    }
    long res;
    if (likely(init_rewrite_flag) && 0 == hook_stat(path, buf, &res)) return res;
    return real_stat(path, buf);
}

int fsync(int fd) {
    static int (*real_sync)(int fd) = NULL;
    if (unlikely(real_sync == NULL)) {
        real_sync = (typeof(real_sync))dlsym(RTLD_NEXT, "fsync");
    }
    long res;
    if (likely(init_rewrite_flag) && 0 == hook_fsync(fd, &res)) return res;
    return real_sync(fd);
}

off_t lseek(int fd, off_t offset, int whence) {
    static int (*real_seek)(int fd, off_t offset, int whence) = NULL;
    if (unlikely(real_seek == NULL)) {
        real_seek = (typeof(real_seek))dlsym(RTLD_NEXT, "lseek");
    }
    long res;
    if (likely(init_rewrite_flag) && 0 == hook_lseek(fd, offset, whence, &res)) return res;
    return real_seek(fd, offset, whence);
}

ssize_t read(int fd, void *buf, size_t siz) {
    static int (*real_read)(int fd, void *buf, size_t siz) = NULL;
    if (unlikely(real_read == NULL)) {
        real_read = (typeof(real_read))dlsym(RTLD_NEXT, "read");
    }
    long res;
    if (likely(init_rewrite_flag) && 0 == hook_read(fd, (char *)buf, siz, &res)) return res;
    return real_read(fd, buf, siz);
}

ssize_t write(int fd, const void *buf, size_t siz) {
    static int (*real_write)(int fd, const void *buf, size_t siz) = NULL;
    if (unlikely(real_write == NULL)) {
        real_write = (typeof(real_write))dlsym(RTLD_NEXT, "write");
    }
    long res;
    if (likely(init_rewrite_flag) && 0 == hook_write(fd, (const char *)buf, siz, &res)) return res;
    return real_write(fd, buf, siz);
}

int close(int fd) {
    static int (*real_close)(int fd) = NULL;
    if (unlikely(real_close == NULL)) {
        real_close = (typeof(real_close))dlsym(RTLD_NEXT, "close");
    }
    long res;
    if (likely(init_rewrite_flag) && 0 == hook_close(fd, &res)) return res;
    return real_close(fd);
}

int create(const char *path, mode_t mode) {
    static int (*real_create)(const char *path, mode_t mode) = NULL;
    if (unlikely(real_create == NULL)) {
        real_create = (typeof(real_create))dlsym(RTLD_NEXT, "create");
    }
    long res;
    if (likely(init_rewrite_flag) &&
        0 == hook_openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, mode | S_IFREG, &res))
        return res;
    return real_create(path, mode);
}

int openat(int fd, const char *path, int oflag, ...) {
    static int (*real_openat)(int fd, const char *path, int oflag, ...) = NULL;
    if (unlikely(real_openat == NULL)) {
        real_openat = (typeof(real_openat))dlsym(RTLD_NEXT, "openat");
    }
    mode_t mode = 0;
    int was_hooked;
    long res;
    if (oflag & O_CREAT) {
        va_list argptr;
        va_start(argptr, oflag);
        mode = va_arg(argptr, mode_t);
        va_end(argptr);
    }
    if (likely(init_rewrite_flag) && 0 == hook_openat(fd, path, oflag, mode | S_IFREG, &res))
        return res;
    if (oflag & O_CREAT)
        return real_openat(fd, path, oflag, mode);
    else
        return real_openat(fd, path, oflag);
}

int open(const char *path, int oflag, ...) {
    static int (*real_open)(const char *path, int oflag, ...) = NULL;
    if (unlikely(real_open == NULL)) {
        real_open = (typeof(real_open))dlsym(RTLD_NEXT, "open");
    }
    mode_t mode = 0;
    long res;
    if (oflag & O_CREAT) {
        va_list argptr;
        va_start(argptr, oflag);
        mode = va_arg(argptr, mode_t);
        va_end(argptr);
    }
    if (likely(init_rewrite_flag) && 0 == hook_openat(AT_FDCWD, path, oflag, mode | S_IFREG, &res))
        return res;

    if (oflag & O_CREAT)
        return real_open(path, oflag, mode);
    else
        return real_open(path, oflag);
}

#endif
