
#include "util/file.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>

// mode: 读-写-执行 用户-组-other
int OpenAndAllocAtSize(const std::string &filename, uint64_t size) {
    int fd = ::open(filename.c_str(), O_RDWR | O_CREAT, 666); // 读写权限
    if(fd < 0) return -1;
    if(size == 0) return fd;
    int ret = ftruncate(fd, (off_t)size);
    if(ret != 0) goto err;
    ret = posix_fallocate(fd, 0, (off_t)size);
    if(ret != 0) goto err;
    return fd;
err:
    close(fd);
    return -1;
}

int OpenSimple(const std::string &filename) {
    return open(filename.c_str(), O_RDWR, 666);
}

void Close(int fd) {
    close(fd);
}

bool FileExists(const std::string &filename) {
    return ::access(filename.c_str(), F_OK) == 0;
}

int GetChildren(const std::string &directory_path, std::vector<std::string> *result) {
    result->clear();
    ::DIR *dir = ::opendir(directory_path.c_str());
    if (dir == nullptr) {
        return errno;
    }
    struct ::dirent *entry;
    while ((entry = ::readdir(dir)) != nullptr) {
        result->emplace_back(entry->d_name);
    }
    ::closedir(dir);
    return 0;
}

int RemoveFile(const std::string &filename) {
    if (::unlink(filename.c_str()) != 0) {
        return errno;
    }
    return 0;
}

int CreateDir(const std::string &dirname) {
    if (::mkdir(dirname.c_str(), 0755) != 0) {
        return errno;
    }
    return 0;
}

int RemoveDir(const std::string &dirname) {
    if (::rmdir(dirname.c_str()) != 0) {
        return errno;
    }
    return 0;
}

int RemoveDirRecursive(const std::string &dirname) {
    char cur_dir[] = ".";
    char up_dir[] = "..";
    DIR *dirp;
    struct dirent *dp;
    struct stat dir_stat;

    // 参数传递进来的目录不存在，直接返回
    if (::access(dirname.c_str(), F_OK) != 0) {
        return errno;
    }

    // 获取目录属性失败，返回错误
    if (stat(dirname.c_str(), &dir_stat)) {
        return errno;
    }

    if (S_ISREG(dir_stat.st_mode)) {  // 普通文件直接删除
        ::unlink(dirname.c_str());
    } else if (S_ISDIR(dir_stat.st_mode)) {  // 目录文件，递归删除目录中内容
        dirp = opendir(dirname.c_str());
        while ((dp = readdir(dirp)) != NULL) {
            // 忽略 . 和 ..
            if ((0 == strcmp(cur_dir, dp->d_name)) || (0 == strcmp(up_dir, dp->d_name))) {
                continue;
            }
            char dir_name_[512];
            sprintf(dir_name_, "%s/%s", dirname.c_str(), dp->d_name);
            int ret = RemoveDirRecursive(dir_name_);  // 递归调用
            if (ret) {
                return ret;
            }
        }
        closedir(dirp);
        ::rmdir(dirname.c_str());  // 删除空目录
    } else {
        fprintf(stderr, "%s unknow file type!\n", dirname.c_str());
        return -1;
    }
    return 0;
}

int GetFileSize(const std::string &filename, uint64_t *size) {
    struct ::stat file_stat;
    if (::stat(filename.c_str(), &file_stat) != 0) {
        *size = 0;
        return errno;
    }
    *size = file_stat.st_size;
    return 0;
}

int RenameFile(const std::string &from, const std::string &to) {
    if (std::rename(from.c_str(), to.c_str()) != 0) {
        return errno;
    }
    return 0;
}
