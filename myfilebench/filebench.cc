#include "myfilebench/filebench.h"

// 递归创建
// 返回目录树高度，即多少级目录
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
            int fd = open(tmp_file.c_str(), OPEN_CREAT_FLAG, CREATE_MODE);
            log_assert(fd > 0);
            FileWrite(fd, buf, iosize, file_size);
            close(fd);
        }
        return 0;
    };
    int depth;
    for(int i = 0; i < dir_width; ++i) {
        const char* name = GetFileName(i);
        // printf("dir %s, dir %d: %s\n", dir.c_str(), i, name);
        string tmp_dir = dir + string(name);
        ret = mkdir(tmp_dir.c_str(), MKDIR_FLAG);
        log_assert(ret == 0 || errno == EEXIST);
        depth = InitFileSet(tmp_dir, (files+dir_width-1)/dir_width, dir_width,
            file_size, iosize, buf, files_per_dir);
    }
    return depth + 1;
}