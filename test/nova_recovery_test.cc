#include <vector>

#include "util/cpu.h"
#include "util/log.h"
#include "vfs/fs_cfg.h"
#include "vfs/vfs_api.h"

const uint64_t FILE_SIZE = 1ul << 30;  // 1GB
const uint64_t BLOCK_SIZE = 4096;
const int DIR_NUM = 32;

int main(int argc, char* argv[]) {
    LogCfg log_cfg = {
        .is_log_to_stderr = true,
        .vlog_level = 0,
        .min_log_level = 3,
    };
    InitLog(argv[0], &log_cfg);

    log_assert(argc == 3);
    bool is_init = false;
    bool is_nor = false;
    if (strcmp(argv[1], "init-nor") == 0) {
        is_init = true;
        is_nor = true;
    } else if (strcmp(argv[1], "init-crash") == 0) {
        is_init = true;
    }
    int files = atoi(argv[2]);

    const std::string dev_name = "/dev/dax3.0";
    const std::string root_path = "/tmp/nova";
    printf("mnt %s, is_init: %d, is_nor: %d, files: %d\n", root_path.c_str(), is_init, is_nor,
           files);

    void* write_buf = aligned_alloc(4096, BLOCK_SIZE < 4096 ? 4096 : BLOCK_SIZE);
    memset(write_buf, 0x3f, BLOCK_SIZE < 4096 ? 4096 : BLOCK_SIZE);
    void* read_buf = aligned_alloc(4096, BLOCK_SIZE < 4096 ? 4096 : BLOCK_SIZE);

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

    ret = fs_mount((void**)&sb, dev_name, root_path, &fs_cfg);
    log_assert(ret == 0);

    fs_register_thread(nullptr);

    if (is_init) {
        printf("Data init...\n");
        int mkdir_flag = S_IRWXU | S_IRWXG | S_IRWXO;
        const int open_flag = O_RDWR | O_CREAT;  // O_DIRECT
        int ret;
        int fd;
        const std::string dir = root_path + "/dir";
        std::vector<std::string> p_dirs;
        for (int i = 0; i < DIR_NUM; ++i) {
            p_dirs.push_back(dir + "-" + std::to_string(i));
            ret = vfs_mkdir(p_dirs.back().c_str(), mkdir_flag);
            log_assert(ret == 0);
        }

        for (int i = 0; i < files; ++i) {
            int dir_idx = i % DIR_NUM;
            const std::string file_name = p_dirs[dir_idx] + "/file-" + std::to_string(i);
            fd = vfs_open(file_name.c_str(), open_flag, 666);
            log_assert(fd > 0);
            int bs_num = FILE_SIZE / BLOCK_SIZE;
            for (int i = 0; i < bs_num; ++i) {
                ret = vfs_write(fd, (const char*)write_buf, BLOCK_SIZE);
                log_assert(ret == BLOCK_SIZE);
            }
            vfs_close(fd);
        }
        ret = vfs_ls(root_path.c_str());
        log_assert(ret == 0);

        if (!is_nor) {
            printf("init ok, abort\n");
        } else {
            printf("init ok, normal exit\n");
            fs_unmount((void**)&sb, root_path);
        }

        return 0;
    }

    // recovery
    printf("Recovery test...\n");
    log_assert(strcmp(argv[1], "recovery") == 0);
    int fd;
    const std::string dir = root_path + "/dir";
    std::vector<std::string> p_dirs;
    for (int i = 0; i < DIR_NUM; ++i) {
        p_dirs.push_back(dir + "-" + std::to_string(i));
        struct stat st;
        ret = vfs_stat(p_dirs.back().c_str(), &st);
        log_assert(ret == 0);
        log_assert(S_ISDIR(st.st_mode));
    }

    const int open_flag = O_RDWR;  // O_DIRECT
    for (int i = 0; i < files; ++i) {
        int dir_idx = i % DIR_NUM;
        const std::string file_name = p_dirs[dir_idx] + "/file-" + std::to_string(i);
        struct stat st;
        ret = vfs_stat(file_name.c_str(), &st);
        log_assert(ret == 0);
        log_assert(S_ISREG(st.st_mode));
        log_assert(st.st_size == FILE_SIZE);

        // fd = vfs_open(file_name.c_str(), open_flag, 666);
        // log_assert(fd > 0);
        // int bs_num = FILE_SIZE / BLOCK_SIZE;
        // for (int i = 0; i < bs_num; ++i) {
        //     ret = vfs_read(fd, (char*)read_buf, BLOCK_SIZE);
        //     log_assert(ret == BLOCK_SIZE);
        //     log_assert(memcmp(read_buf, write_buf, BLOCK_SIZE) == 0);
        // }
        // vfs_close(fd);
    }

    // ret = vfs_ls(root_path.c_str());
    // log_assert(ret == 0);

    free(write_buf);
    free(read_buf);
    // fs_unmount((void**)&sb, root_path);
    printf("Test pass\n");
}
