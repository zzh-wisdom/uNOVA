#ifndef HLFS_UTIL_FILE_H_
#define HLFS_UTIL_FILE_H_

#include <string>
#include <vector>

int OpenAndAllocAtSize(const std::string &filename, uint64_t size);
int OpenSimple(const std::string &filename);
void Close(int fd);

bool FileExists(const std::string &filename);
int GetChildren(const std::string &directory_path, std::vector<std::string> *result);
int RemoveFile(const std::string &filename);
int CreateDir(const std::string &dirname);
int RemoveDir(const std::string &dirname);
int RemoveDirRecursive(const std::string &dirname);
int GetFileSize(const std::string &filename, uint64_t *size);
int RenameFile(const std::string &from, const std::string &to);

#endif // HLFS_UTIL_FILE_H_
