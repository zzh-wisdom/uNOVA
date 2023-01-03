#pragma once

#include <string>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "util/cpu.h"

using namespace std;

#define FILE_NAME_LEN 5
#define O_ATOMIC 01000000000

#define MKDIR_FLAG (S_IRWXU | S_IRWXG | S_IRWXO)
#define OPEN_FLAG (O_RDWR | O_DIRECT) // | O_DIRECT | O_ATOMIC
#define OPEN_CREAT_FLAG (O_RDWR | O_CREAT | O_DIRECT) // O_ATOMIC
#define OPEN_APPEND_FLAG (O_RDWR | O_APPEND | O_DIRECT) // | O_DIRECT | O_ATOMIC
#define CREATE_MODE (0666)
#define MAX_CPU_NUM 64

static const int numa_socket = 1;
static int cpu_ids[MAX_CPU_NUM];
static int cpu_num = 0;

static inline void SetEnv() {
    SetSocketAndPolicy(numa_socket, 1);
    for(int i = 24; i < 40; ++i) {
		cpu_ids[cpu_num++] = i;
	}
	for(int i = 60; i < 76; ++i) {
		cpu_ids[cpu_num++] = i;
	}
    srand(time(nullptr));
}

static inline size_t GetRandSize(size_t max_size, int block_bits) {
    int max_cache_num = (max_size >> block_bits);
    int cache_num = rand() % max_cache_num;
    return (cache_num + 1) << block_bits;
}

thread_local static char file_name_buf[FILE_NAME_LEN + 1];
static inline const char* GetFileName(int file_num) {
    sprintf(file_name_buf, "%0*d", FILE_NAME_LEN, file_num);
    return file_name_buf;
}

static inline string GetDirPath(const string& dir, int dir_width, int depth, int file_num, int *file_i) {
    string ret = dir;
    for(int i = 0; i < depth; ++i) {
        int dir_i = file_num % dir_width;
        ret += "/" + string(GetFileName(dir_i));
        file_num /= dir_width;
    }
    *file_i = file_num;
    return ret;
}

static inline void FileWrite(int fd, const char* buf, size_t iosize, size_t total_size) {
    int ops = total_size / iosize;
    size_t ret;
    for(int i = 0; i < ops; ++i) {
        ret = write(fd, buf, iosize);
        log_assert(ret == iosize);
    }
    size_t less = total_size % iosize;
    if(less == 0) return;
    ret = write(fd, buf, less);
    // printf("less: %lu\n", less);
    log_assert(ret == less);
}

static inline size_t FileReadWhole(int fd, char* buf, size_t iosize) {
    size_t total = 0;
    size_t ret;
    while(1) {
        ret = read(fd, buf, iosize);
        if(ret) {
            total += ret;
        } else {
            break;
        }
    }
    log_assert(total >= 64);
    return total;
}

static inline void FileRead(int fd, char* buf, size_t iosize, size_t total_size) {
    int ops = total_size / iosize;
    size_t ret;
    for(int i = 0; i < ops; ++i) {
        ret = read(fd, buf, iosize);
        log_assert(ret == iosize);
    }
    size_t less = total_size % iosize;
    if(less == 0) return;
    ret = read(fd, buf, less);
    log_assert(ret == less);
}

int InitFileSet(string dir, int files, int dir_width,
    size_t file_size, size_t iosize, const char* buf, int files_per_dir);
