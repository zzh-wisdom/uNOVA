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


int main(int argc, char* argv[]) {

    /**
        /tmp/mountdir
        ├── top_plus
        └── top
            ├── dir_a
            |   └── subdir_a
            ├── dir_b
            └── file_a
    */
    const std::string mntdir = "/tmp/metafs";
    const std::string nonexisting = mntdir + "/nonexisting";
    const std::string topdir = mntdir + "/top";
    const std::string longer = topdir + "_plus";
    const std::string dir_a  = topdir + "/dir_a";
    const std::string dir_b  = topdir + "/dir_b";
    const std::string file_a = topdir + "/file_a";
    const std::string subdir_a  = dir_a + "/subdir_a";

    int ret;
    int fd;
    DIR * dirstream = NULL;
    struct stat dirstat;

    printf("dfvdfv\n");
    if(syscall_hook_in_process_allowed()) {
        printf("syscall Enable!\n");
    } else {
        printf("syscall Disable!\n");
    }

    // Create topdir
    ret = mkdir(topdir.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    if(ret != 0){
        std::cerr << "Error creating topdir: " << std::strerror(errno) << std::endl;
        return -1;
    }

    //Test stat on existing dir
    ret = stat(topdir.c_str(), &dirstat);
    if(ret != 0){
        std::cerr << "Error stating topdir: " << std::strerror(errno) << std::endl;
        return -1;
    }
    // assert(S_ISDIR(dirstat.st_mode));

    printf("Test pass\n");
}
