#include "myfilebench/filebench.h"

#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdlib.h>
// #include <glog/logging.h>

string dir = "/tmp/nova";
const int nfiles = 32*32; // *32*16
const int dir_width = 32;
const int files_per_dir = 32; // *32*16
const size_t file_size = 32*1024;
const size_t iosize = 4096;
size_t meanappendsize = 16*1024;
const int append_rand_bs_bits = 6;

// sudo ./webproxy nova 1 200000

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

void* webproxy_job(void* arg) {
    job_arg_t* job_arg = (job_arg_t*)arg;
    int thread_idx = job_arg->thread_idx;
    CoreBind(pthread_self(), cpu_ids[thread_idx]);
    printf("webproxy thread %d: cpu_id=%d, dir=%s, op_num=%lu, nfiles=%d\n",
        thread_idx, cpu_ids[thread_idx],
        job_arg->dir.c_str(), job_arg->op_num, job_arg->nfiles);
    string &dir = job_arg->dir;
    int depth = job_arg->fileset_depth;
    uint64_t &rw_bytes = job_arg->rw_bytes;
    int t_nfiles = job_arg->nfiles;
    string dir_path;
    string tmp_file;
    size_t append_size;
    struct stat st;
    size_t read_bytes;
    int ret;
    int file_idx = 0;
    int file_i;
    int fd;
    for(uint64_t i = 0; i < job_arg->op_num; ++i) {
        dir_path = GetDirPath(dir, dir_width, depth, file_idx, &file_i);
        tmp_file = dir_path + "/" + GetFileName(file_i);
        rd_info("dir_path %s, file_i %d", dir_path.c_str(), file_i);

        rd_info("unlink %s", tmp_file.c_str());
        // 删除文件
        ret = unlink(tmp_file.c_str());
        log_assert(ret == 0);
        // 创建文件
        fd = open(tmp_file.c_str(), OPEN_CREAT_FLAG, CREATE_MODE);
        log_assert(fd > 0);
        // append
        append_size = GetRandSize(meanappendsize, append_rand_bs_bits);
        rd_info("append_size: %lu\n", append_size);
        FileWrite(fd, bufs[thread_idx], iosize, append_size);
        rw_bytes += append_size;
        // close
        close(fd);
        file_idx = (file_idx + 1) % t_nfiles;

        for(int j = 0; j < 5; ++j) {
            dir_path = GetDirPath(dir, dir_width, depth, file_idx, &file_i);
            rd_info("dir_path %s, file_i %d", dir_path.c_str(), file_i);
            // open

            tmp_file = dir_path + "/" + GetFileName(file_i);
            fd = open(tmp_file.c_str(), OPEN_FLAG, 0);
            log_assert(fd > 0);
            // read whole
            read_bytes = FileReadWhole(fd, bufs[thread_idx], iosize);
            rd_info("read_bytes: %lu", read_bytes);
            rw_bytes += read_bytes;
            // close
            close(fd);

            file_idx = (file_idx + 1) % t_nfiles;
        }
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
            dir = "/mnt/pmem2/fileserver";
        } else if(strcmp(argv[1], "libnvmmio") == 0) {
            dir = "/mnt/pmem2";
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
    memset(bufs, 0x3f, sizeof(bufs));
    op_num = (op_num + threads - 1) / threads * threads;
    for(int i = 0; i < threads; ++i) {
        bufs[i] = (char*)aligned_alloc(4096, iosize);
    }

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
        int ret = pthread_create(&thread_hds[i], nullptr, webproxy_job, &job_args[i]);
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
    printf("run %0.2lf s, rw_bytes_sum: %lu B, webproxy, bandwidth: %0.2lf MB/s, kops: %0.2lf kops\n",
        interval_sec, rw_bytes_sum, rw_bytes_sum / 1024 / 1024 / interval_sec,
        op_num / 1000 / interval_sec);

    for(int i = 0; i < threads; ++i) {
        free(bufs[i]);
    }

    printf("Test pass\n");
    return 0;
}