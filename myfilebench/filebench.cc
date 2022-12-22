#include "myfilebench/filebench.h"

// 递归创建
// 返回目录树高度，即多少级目录
int InitFileSet(string dir, int files, size_t file_size, size_t iosize, const char* buf) {
    int ret;
    dir += "/";
    if(files <= DIR_WIDTH) {
        for(int i = 0; i < DIR_WIDTH; ++i) {
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
    for(int i = 0; i < DIR_WIDTH; ++i) {
        const char* name = GetFileName(i);
        // printf("dir %s, dir %d: %s\n", dir.c_str(), i, name);
        string tmp_dir = dir + string(name);
        ret = mkdir(tmp_dir.c_str(), MKDIR_FLAG);
        log_assert(ret == 0 || errno == EEXIST);
        depth = InitFileSet(tmp_dir, (files+DIR_WIDTH-1)/DIR_WIDTH, file_size, iosize, buf);
    }
    return depth + 1;
}