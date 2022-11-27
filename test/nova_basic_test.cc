#include "nova/vfs_api.h"

#include "util/cpu.h"
#include "nova/nova_cfg.h"

int main(int argc, char* argv[]) {
    LogCfg log_cfg = {
        .is_log_to_stderr = true,
        .vlog_level = 3,
        .min_log_level = 0,
    };
    InitLog(argv[0], &log_cfg);

    // rand 随机数种子
    int seed = time(nullptr);
    srand((unsigned int)seed);

    vfs_cfg fs_cfg;
    vfs_cfg_default_init(&fs_cfg);

    // numa环境
    SetSocketAndPolicy(fs_cfg.numa_socket, 1);

    int ret = 0;
    const std::string dev_name = "/dev/dax3.0";
    const std::string root_path = "/tmp/nova";
    super_block* sb = nullptr;
    ret = fs_mount((void**)&sb, dev_name, root_path, &fs_cfg);
    log_assert(ret == 0);

    nova_register_thread(nullptr);

    ret = vfs_mkdir("/tmp/nova/dir1", 0);
    log_assert(ret == 0);
    ret = vfs_mkdir("/tmp/nova/dir1/d1", 0);
    log_assert(ret == 0);
    ret = vfs_mkdir("/tmp/nova/dir1/d2", 0);
    log_assert(ret == 0);
    ret = vfs_mkdir("/tmp/nova/dir2", 0);
    log_assert(ret == 0);
    ret = vfs_mkdir("/tmp/nova/dir2", 0);
    log_assert(ret);
    ret = vfs_mkdir("/tmp/nova/dir3/dir31", 0);
    log_assert(ret);

    ret = vfs_ls("/tmp/nova/dir3");
    log_assert(ret);
    ret = vfs_ls("/tmp/nova/dir1");
    log_assert(ret == 0);
    ret = vfs_ls("/tmp/nova/");
    log_assert(ret == 0);

    ret = vfs_rmdir("/tmp/nova/dir2");
    log_assert(ret == 0);
    ret = vfs_rmdir("/tmp/nova/dir1");
    log_assert(ret);
    ret = vfs_ls("/tmp/nova/");
    log_assert(ret == 0);

    // file open
    ret = vfs_mkdir("/tmp/nova/files", 0);
    log_assert(ret == 0);
    ret = vfs_open("/tmp/nova/dir2/f1", O_RDWR, 0);
    log_assert(ret < 0);
    ret = vfs_open("/tmp/nova/files", O_RDWR, 0);
    log_assert(ret < 0);
    ret = vfs_open("/tmp/nova/files/f1", O_RDWR, 0);
    log_assert(ret < 0);
    int fd1 = vfs_open("/tmp/nova/files/f1", O_RDWR | O_CREAT, 0);
    log_assert(fd1 > 0);
    printf("open %s, fd = %d\n", "/tmp/nova/files/f1", fd1);
    int fd2 = vfs_open("/tmp/nova/files/f1", O_RDWR | O_CREAT, 0);
    log_assert(fd2 > 0);
    printf("open %s, fd = %d\n", "/tmp/nova/files/f1", fd2);
    log_assert(vfs_close(fd1) == 0);
    log_assert(vfs_close(fd2) == 0);
    ret = vfs_open("/tmp/nova/files/f1/f11", O_RDWR, 0);
    log_assert(ret < 0);
    fd1 = vfs_open("/tmp/nova/files/f2", O_RDWR | O_CREAT, 0);
    log_assert(fd1 > 0);
    log_assert(vfs_close(fd1) == 0);
    printf("open %s, fd = %d\n", "/tmp/nova/files/f1", fd1);
    ret = vfs_ls("/tmp/nova/");
    log_assert(ret == 0);

    // 读写测试
    int fd_w = vfs_open("/tmp/nova/files/f1", O_RDWR | O_CREAT, 0);
    log_assert(fd_w > 0);
    int fd_r = vfs_open("/tmp/nova/files/f1", O_RDWR | O_CREAT, 0);
    log_assert(fd_r > 0);
    const int BUF_LEN = 20;
    char w_buffer[BUF_LEN+1];
    char r_buffer[BUF_LEN+1];
    memset(r_buffer, 0, sizeof(r_buffer));
    w_buffer[BUF_LEN] = '\0';
    for(int i = 0; i < BUF_LEN; ++i) {
        w_buffer[i] = 'a' + i;
    }
    ret = vfs_read(fd_r, r_buffer, BUF_LEN); // 空文件
    log_assert(ret == 0);
    ret = vfs_write(fd_w, w_buffer, BUF_LEN/2);
    log_assert(ret == BUF_LEN/2);
    ret = vfs_write(fd_w, w_buffer+BUF_LEN/2, BUF_LEN/2);
    log_assert(ret == BUF_LEN/2);
    ret = vfs_read(fd_r, r_buffer, BUF_LEN);
    log_assert(ret == BUF_LEN);
    log_assert(strcmp(r_buffer, w_buffer) == 0);
    ret = vfs_lseek(fd_r, 0, SEEK_SET);
    log_assert(ret == 0);
    for(int i = 0; i < BUF_LEN; ++i) {
        char c;
        ret = vfs_read(fd_r, &c, 1);
        log_assert(ret == 1);
        log_assert(c == 'a' + i);
    }
    ret = vfs_read(fd_r, r_buffer, BUF_LEN); // 文件尾部
    log_assert(ret == 0);

    // 重写
    ret = vfs_lseek(fd_w, 0, SEEK_SET);
    log_assert(ret == 0);
    for(int i = 0; i < BUF_LEN; ++i) {
        ret = vfs_write(fd_w, "a", 1);
        log_assert(ret == 1);
    }
    ret = vfs_lseek(fd_r, 0, SEEK_SET);
    log_assert(ret == 0);
    ret = vfs_read(fd_r, r_buffer, BUF_LEN);
    log_assert(ret == BUF_LEN);
    printf("%d r_buffer: %s\n", __LINE__, r_buffer);

    ret = vfs_lseek(fd_r, 0, SEEK_SET);
    log_assert(ret == 0);
    for(int i = 0; i < BUF_LEN; ++i) {
        char c;
        ret = vfs_read(fd_r, &c, 1);
        log_assert(ret == 1);
        log_assert(c == 'a');
    }
    log_assert(vfs_close(fd_w) == 0);
    log_assert(vfs_close(fd_r) == 0);
    ret = vfs_ls("/tmp/nova/");
    log_assert(ret == 0);

    int fd = vfs_open("/tmp/nova/files/f2", O_RDWR | O_CREAT, 666);
    log_assert(fd > 0);
    // 删除文件
    ret = vfs_unlink("/tmp/nova/dir1/d1");
    log_assert(ret);
    ret = vfs_unlink("/tmp/nova/file/f1");
    log_assert(ret);
    ret = vfs_unlink("/tmp/nova/files");
    log_assert(ret);
    ret = vfs_unlink("/tmp/nova/files/f2");
    log_assert(ret == 0);
    ret = vfs_unlink("/tmp/nova/files/f2");
    log_assert(ret);
    vfs_close(fd);
    ret = vfs_ls("/tmp/nova/");
    log_assert(ret == 0);

    vfs_fs_unmount((void**)&sb, root_path);
    return 0;
}