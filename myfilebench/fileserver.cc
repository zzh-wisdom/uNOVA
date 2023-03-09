#include "myfilebench/filebench.h"

#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdlib.h>
// #include <glog/logging.h>

string dir = "/tmp/nova";
const int nfiles = 32*32*32*4;
const int dir_width = 32;
const int files_per_dir = 32*4;
const size_t file_size = 128*1024;
const size_t iosize = 4096;
size_t meanappendsize = 16*1024;
const int append_rand_bs_bits = 6;

// sudo ./fileserver nova 4 200000

char *bufs[MAX_CPU_NUM];

struct job_arg_t
{
    int thread_idx;
    uint64_t op_num;
    string dir;
    int nfiles;
    int fileset_depth;
    uint64_t rw_bytes;
};

// const int a = sizeof(job_arg_t);

job_arg_t job_args[MAX_CPU_NUM];
pthread_t thread_hds[MAX_CPU_NUM];

const string create_file_name = "newfile.dat";

void* fileserver_job(void* arg) {
    job_arg_t* job_arg = (job_arg_t*)arg;
    int thread_idx = job_arg->thread_idx;
    CoreBind(pthread_self(), cpu_ids[thread_idx]);
    printf("fileserver thread %d: cpu_id=%d, dir=%s, op_num=%lu, nfiles=%d\n",
        thread_idx, cpu_ids[thread_idx],
        job_arg->dir.c_str(), job_arg->op_num, job_arg->nfiles);
    string &dir = job_arg->dir;
    int depth = job_arg->fileset_depth;
    uint64_t &rw_bytes = job_arg->rw_bytes;
    int t_nfiles = job_arg->nfiles;
    string dir_path;
    string new_file;
    string tmp_file;
    size_t append_size;
    struct stat st;
    int ret;
    int file_idx;
    int fd;
    for(uint64_t i = 0; i < job_arg->op_num; ++i) {
        file_idx = i % t_nfiles;
        int write_file_i;
        dir_path = GetDirPath(dir, dir_width, depth, file_idx, &write_file_i);
        int read_file_i = (write_file_i + 1) % files_per_dir;
        rd_info("dir_path %s, write_file_i %d\n", dir_path.c_str(), write_file_i);

        new_file = dir_path + "/" + create_file_name;
        rd_info("open %s\n", new_file.c_str());
        // create
        fd = open(new_file.c_str(), OPEN_CREAT_FLAG, CREATE_MODE);
        log_assert(fd > 0);
        // write whole
        FileWrite(fd, bufs[thread_idx], iosize, file_size);
        rw_bytes += file_size;
        // close
        close(fd);

        // open
        tmp_file = dir_path + "/" + GetFileName(write_file_i);
        rd_info("open %s\n", tmp_file.c_str());
        fd = open(tmp_file.c_str(), OPEN_APPEND_FLAG, 0);
        log_assert(fd > 0);
        // append write
        append_size = GetRandSize(meanappendsize, append_rand_bs_bits);
        rd_info("append_size: %lu\n", append_size);
        FileWrite(fd, bufs[thread_idx], iosize, append_size);
        rw_bytes += append_size;
        // close
        close(fd);

        // open
        tmp_file = dir_path + "/" + GetFileName(read_file_i);
        rd_info("open %s\n", tmp_file.c_str());
        fd = open(tmp_file.c_str(), OPEN_FLAG, 0);
        log_assert(fd > 0);
        // read whole
        FileRead(fd, bufs[thread_idx], iosize, file_size);
        rw_bytes += file_size;
        // close
        close(fd);

        // delete
        ret = unlink(new_file.c_str());
        log_assert(ret == 0);

        // stat
        ret = stat(tmp_file.c_str(), &st);
        log_assert(ret == 0);
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if(argc >= 2) {
        if (strcmp(argv[1], "nova") == 0) {
            printf("dlopen ./libnova_hook.so\n");
            void *handle = dlopen("./libnova_hook.so", RTLD_NOW);
    	    log_assert(handle);
            dir = "/tmp/nova";
        } else if (strcmp(argv[1], "finefs") == 0) {
            printf("dlopen ./libfinefs_hook.so\n");
            void *handle = dlopen("./libfinefs_hook.so", RTLD_NOW);
        	log_assert(handle);
            dir = "/tmp/finefs";
        } else if(strcmp(argv[1], "ext4") == 0) {
            dir = "/mnt/pmem0";
        } else if(strcmp(argv[1], "libnvmmio") == 0) {
            dir = "/mnt/pmem0";
        }
    }

    LogCfg log_cfg = {
        .is_log_to_stderr = true,
        .vlog_level = 0,
        .min_log_level = 3,
    };
    InitLog(argv[0], &log_cfg);
    SetEnv();

    log_assert(argc == 4);
    int threads = atoi(argv[2]);
    uint64_t op_num = atoi(argv[3]);
    printf("dir:%s, threads: %d, op_num: %lu\n", dir.c_str(), threads, op_num);

    log_assert(threads <= cpu_num);
    op_num = (op_num + threads - 1) / threads * threads;
    for(int i = 0; i < threads; ++i) {
        bufs[i] = (char*)aligned_alloc(4096, iosize);
        memset(bufs[i], 0x3f, 4096);
    }

    // int fd = open("/mnt/pmem2/fileserver/00007/00022/00006", OPEN_CREAT_FLAG, 0777);
    //         log_assert(fd > 0);

    int depth = InitFileSet(dir, nfiles, dir_width, file_size, iosize, bufs[0], files_per_dir);
    printf("fileset depth:%d\n", depth);

    for(int i = 0; i < threads; ++i) {
        job_args[i].thread_idx = i;
        job_args[i].op_num = op_num / threads;
        job_args[i].dir = dir + "/" + string(GetFileName(i));
        job_args[i].nfiles = nfiles / dir_width;
        job_args[i].fileset_depth = depth - 1;
        job_args[i].rw_bytes = 0;
    }

    uint64_t start_us = GetTsUsec();
    for(int i = 0; i < threads; ++i) {
        int ret = pthread_create(&thread_hds[i], nullptr, fileserver_job, &job_args[i]);
        log_assert(ret == 0);
    }
    for(int i = 0; i < threads; ++i) {
        pthread_join(thread_hds[i], nullptr);
    }
    uint64_t end_us = GetTsUsec();
    double interval_sec = (end_us - start_us) / 1000.0 / 1000.0;
    uint64_t rw_bytes_sum = 0;
    for(int i = 0; i < threads; ++i) {
        rw_bytes_sum += job_args[i].rw_bytes;
    }
    printf("run %0.2lf s, rw_bytes_sum: %lu B, fileserver, bandwidth: %0.2lf MB/s, kops: %0.2lf kops\n",
        interval_sec, rw_bytes_sum, rw_bytes_sum / 1024 / 1024 / interval_sec,
        op_num / 1000 / interval_sec);

    for(int i = 0; i < threads; ++i) {
        free(bufs[i]);
    }

    printf("Test pass\n");
    return 0;
}