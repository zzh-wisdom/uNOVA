#pragma once

#include <sys/types.h>
#include <fcntl.h>
#include <unordered_map>

struct statfs;
struct linux_dirent;
struct linux_dirent64;

#define HOOK_REWRITE 0
#define START_FD 10000

#if HOOK_REWRITE
extern bool init_rewrite_flag;
#endif

int wrapper_hook(long syscall_number,
                long a0, long a1,
                long a2, long a3,
                long a4, long a5,
                long *res);

