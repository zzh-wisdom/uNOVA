/* Test directories functionalities
 *
 */
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <cerrno>
#include <cassert>
#include <unordered_map>

#include <time.h>

#include <libsyscall_intercept_hook_point.h>
#include <dlfcn.h>

int main(int argc, char* argv[]) {

#if FS_HOOK==1
    printf("dlopen ./libnova_hook.so\n");
    void *handle = dlopen("./libnova_hook.so", RTLD_NOW);
	assert(handle);
    const std::string mntdir = "/tmp/nova";
#else
    printf("dlopen ./libfinefs_hook.so\n");
    void *handle = dlopen("./libfinefs_hook.so", RTLD_NOW);
	assert(handle);
    const std::string mntdir = "/tmp/finefs";
#endif

    const std::string dir1 = mntdir + "/dir1";
    const std::string dir2 = mntdir + "/dir2";
    const std::string dir1_d1 = mntdir + "/dir1" + "/d1";
    const std::string dir1_d2 = mntdir + "/dir1" + "/d2";
    const std::string files = mntdir + "/files";
    const std::string files_f1 = mntdir + "/files" + "/f1";
    const std::string files_f2 = mntdir + "/files" + "/f2";
    int mkdir_flag = S_IRWXU | S_IRWXG | S_IRWXO;

    int ret;
    // int fd;
    // DIR * dirstream = NULL;

    if(syscall_hook_in_process_allowed()) {
        printf("syscall Enable!\n");
    } else {
        printf("syscall Disable!\n");
    }

    // Create topdir
    ret = mkdir(dir1.c_str(), mkdir_flag);
    assert(ret == 0);
    ret = mkdir(dir1_d1.c_str(), mkdir_flag);
    assert(ret == 0);
    ret = mkdir(dir1_d2.c_str(), mkdir_flag);
    assert(ret == 0);
    ret = mkdir(dir2.c_str(), mkdir_flag);
    assert(ret == 0);
    ret = mkdir(dir2.c_str(), mkdir_flag);
    assert(ret);

    ret = rmdir(dir2.c_str());
    assert(ret == 0);
    ret = rmdir(dir1.c_str());
    assert(ret);

    // file open
    ret = mkdir(files.c_str(), mkdir_flag);
    assert(ret == 0);
    ret = open(files_f1.c_str(), O_RDWR, 666);
    assert(ret < 0);
    ret = open(files.c_str(), O_RDWR, 666);
    assert(ret < 0);
    int fd1 = open(files_f1.c_str(), O_RDWR | O_CREAT, 666);
    assert(fd1 > 0);
    printf("open %s, fd = %d\n", files_f1.c_str(), fd1);
    int fd2 = open(files_f1.c_str(), O_RDWR | O_CREAT, 666);  // 要sudo
    // printf("errno=%d\n", errno); // EACCES
    assert(fd2 > 0);
    printf("open %s, fd = %d\n", files_f1.c_str(), fd2);
    ret = close(fd1);
    assert(ret == 0);
    ret = close(fd2);
    assert(ret == 0);
    fd1 = open(files_f2.c_str(), O_RDWR | O_CREAT, 0);
    assert(fd1 > 0);
    ret = close(fd1);
    assert(ret == 0);
    printf("open %s, fd = %d\n", files_f2.c_str(), fd1);

    // 读写测试
    int fd_w = open(files_f1.c_str(), O_RDWR | O_CREAT, 0);
    assert(fd_w > 0);
    int fd_r = open(files_f1.c_str(), O_RDWR | O_CREAT, 0);
    assert(fd_r > 0);
    const int BUF_LEN = 20;
    char w_buffer[BUF_LEN+1];
    char r_buffer[BUF_LEN+1];
    memset(r_buffer, 0, sizeof(r_buffer));
    w_buffer[BUF_LEN] = '\0';
    for(int i = 0; i < BUF_LEN; ++i) {
        w_buffer[i] = 'a' + i;
    }
    ret = read(fd_r, r_buffer, BUF_LEN); // 空文件
    assert(ret == 0);
    ret = write(fd_w, w_buffer, BUF_LEN/2);
    assert(ret == BUF_LEN/2);
    ret = write(fd_w, w_buffer+BUF_LEN/2, BUF_LEN/2);
    assert(ret == BUF_LEN/2);
    ret = read(fd_r, r_buffer, BUF_LEN);
    assert(ret == BUF_LEN);
    assert(strcmp(r_buffer, w_buffer) == 0);
    ret = lseek(fd_r, 0, SEEK_SET);
    assert(ret == 0);
    for(int i = 0; i < BUF_LEN; ++i) {
        char c;
        ret = read(fd_r, &c, 1);
        assert(ret == 1);
        assert(c == 'a' + i);
    }
    ret = read(fd_r, r_buffer, BUF_LEN); // 文件尾部
    assert(ret == 0);

    // 重写
    ret = lseek(fd_w, 0, SEEK_SET);
    assert(ret == 0);
    for(int i = 0; i < BUF_LEN; ++i) {
        ret = write(fd_w, "a", 1);
        assert(ret == 1);
    }
    ret = lseek(fd_r, 0, SEEK_SET);
    assert(ret == 0);
    ret = read(fd_r, r_buffer, BUF_LEN);
    assert(ret == BUF_LEN);
    printf("%d r_buffer: %s\n", __LINE__, r_buffer);

    ret = lseek(fd_r, 0, SEEK_SET);
    assert(ret == 0);
    for(int i = 0; i < BUF_LEN; ++i) {
        char c;
        ret = read(fd_r, &c, 1);
        assert(ret == 1);
        assert(c == 'a');
    }
    ret = close(fd_w);
    assert(ret == 0);
    ret = close(fd_r);
    assert(ret == 0);

    int fd = open(files_f2.c_str(), O_RDWR | O_CREAT, 666);
    assert(fd > 0);
    // 删除文件
    ret = unlink(dir1_d1.c_str());
    assert(ret);
    ret = unlink(files.c_str());
    assert(ret);
    ret = unlink(files_f2.c_str());
    assert(ret == 0);
    ret = unlink(files_f2.c_str());
    assert(ret);
    close(fd);

    // Test stat on existing dir
    struct stat st;
    ret = stat(dir1.c_str(), &st);
    assert(ret == 0);
    assert(S_ISDIR(st.st_mode));
    ret = stat(files_f1.c_str(), &st);
    assert(ret == 0);
    assert(S_ISREG(st.st_mode));

    ret = stat(mntdir.c_str(), &st);
    assert(ret == 0);
    assert(S_ISDIR(st.st_mode));

    const std::string top_file = mntdir + "/fio-seq-reads";
    fd = open(top_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, 666);
    assert(fd > 0);
    ret = ftruncate(fd, 64);
    assert(ret == 0);
    ret = stat(top_file.c_str(), &st);
    assert(ret == 0);
    assert(st.st_size == 64);
    close(fd);
    ret = truncate(top_file.c_str(), 128);
    assert(ret == 0);
    ret = stat(top_file.c_str(), &st);
    assert(ret == 0);
    assert(st.st_size == 128);

    printf("Test pass\n");
}
