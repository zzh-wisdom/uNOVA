#include <vector>
#include <string>

#include "util/cpu.h"
#include "util/log.h"
#include "vfs/fs_cfg.h"
#include "vfs/vfs_api.h"

using namespace std;

#define FILE_NAME_LEN 5

#define MKDIR_FLAG (S_IRWXU | S_IRWXG | S_IRWXO)
#define OPEN_FLAG (O_RDWR | O_DIRECT)
#define OPEN_CREAT_FLAG (O_RDWR | O_CREAT)
#define OPEN_APPEND_FLAG (O_RDWR | O_APPEND | O_DIRECT)
#define CREATE_MODE (666)

thread_local static char file_name_buf[FILE_NAME_LEN + 1];
static inline const char* GetFileName(int file_num) {
    sprintf(file_name_buf, "%0*d", FILE_NAME_LEN, file_num);
    return file_name_buf;
}

static inline void FileWrite(int fd, const char* buf, size_t iosize, size_t total_size) {
    int ops = total_size / iosize;
    size_t ret;
    for(int i = 0; i < ops; ++i) {
        ret = vfs_write(fd, buf, iosize);
        log_assert(ret == iosize);
    }
    size_t less = total_size % iosize;
    if(less == 0) return;
    ret = vfs_write(fd, buf, less);
    // printf("less: %lu\n", less);
    log_assert(ret == less);
}

int InitFileSet(string dir, int files, int dir_width,
    size_t file_size, size_t iosize, const char* buf, int files_per_dir)
{
    int ret;
    dir += "/";
    if(files <= files_per_dir) {
        log_assert(files == files_per_dir);
        for(int i = 0; i < files_per_dir; ++i) {
            const char* name = GetFileName(i);
            // printf("dir %s, file %d: %s\n", dir.c_str(), i, name);
            string tmp_file = dir + string(name);
            int fd = vfs_open(tmp_file.c_str(), OPEN_CREAT_FLAG, CREATE_MODE);
            log_assert(fd > 0);
            FileWrite(fd, buf, iosize, file_size);
            vfs_close(fd);
        }
        return 0;
    };
    int depth;
    for(int i = 0; i < dir_width; ++i) {
        const char* name = GetFileName(i);
        // printf("dir %s, dir %d: %s\n", dir.c_str(), i, name);
        string tmp_dir = dir + string(name);
        ret = vfs_mkdir(tmp_dir.c_str(), MKDIR_FLAG);
        log_assert(ret == 0 || errno == EEXIST);
        depth = InitFileSet(tmp_dir, (files+dir_width-1)/dir_width, dir_width,
            file_size, iosize, buf, files_per_dir);
    }
    return depth + 1;
}


string dir = "/tmp/nova";
const int nfiles = 32*32*400;
const int dir_width = 32;
const int files_per_dir = 400;
const size_t file_size = 128*1024;
const size_t iosize = 4096;

int main(int argc, char* argv[]) {
    LogCfg log_cfg = {
        .is_log_to_stderr = true,
        .vlog_level = 0,
        .min_log_level = 3,
    };
    InitLog(argv[0], &log_cfg);

    log_assert(argc == 2);
    bool is_init = false;
    bool is_nor = false;
    if (strcmp(argv[1], "init-nor") == 0) {
        is_init = true;
        is_nor = true;
    } else if (strcmp(argv[1], "init-crash") == 0) {
        is_init = true;
    }

    const std::string dev_name = "/dev/dax3.0";
    printf("mnt %s, is_init: %d, is_nor: %d\n", dir.c_str(), is_init, is_nor);

    void* write_buf = aligned_alloc(4096, iosize < 4096 ? 4096 : iosize);
    memset(write_buf, 0x3f, iosize < 4096 ? 4096 : iosize);
    void* read_buf = aligned_alloc(4096, iosize < 4096 ? 4096 : iosize);

    vfs_cfg fs_cfg;
    vfs_cfg_default_init(&fs_cfg);
    if (is_init)
        fs_cfg.format = true;
    else
        fs_cfg.format = false;

    // numa环境
    SetSocketAndPolicy(fs_cfg.numa_socket, 1);

    super_block* sb = nullptr;
    int ret = 0;

    ret = fs_mount((void**)&sb, dev_name, dir, &fs_cfg);
    log_assert(ret == 0);

    fs_register_thread(nullptr);

    if (is_init) {
        printf("Data init...\n");
        int depth = InitFileSet(dir, nfiles, dir_width, file_size, iosize, (char*)write_buf, files_per_dir);
        printf("fileset depth:%d\n", depth);

        if (!is_nor) {
            printf("init ok, abort\n");
        } else {
            printf("init ok, normal exit\n");
            fs_unmount((void**)&sb, dir);
        }

        return 0;
    }

    // recovery
    printf("Recovery test...\n");

    free(write_buf);
    free(read_buf);
    // fs_unmount((void**)&sb, dir);
    printf("Test pass\n");
}
