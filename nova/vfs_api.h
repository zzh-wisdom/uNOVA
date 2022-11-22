#ifndef UNOVA_VFS_API_H_
#define UNOVA_VFS_API_H_

#include "nova/vfs.h"

#include "util/aep.h"

#define CFG_MAX_CPU_NUM 64
#define CFG_START_FD 1000

struct vfs_cfg {
    int numa_socket;
    int cpu_num;
    int cpu_ids[CFG_MAX_CPU_NUM];
    int bg_thread_cpu_id;
    int measure_timing;
    int start_fd;
	bool format;
};

void vfs_cfg_print(struct vfs_cfg* cfg);
static force_inline void vfs_cfg_default_init(struct vfs_cfg* cfg) {
	cfg->numa_socket = 1;
	cfg->cpu_num = 0;
	for(int i = 20; i < 40; ++i) {
		cfg->cpu_ids[cfg->cpu_num++] = i;
	}
	for(int i = 60; i < 72; ++i) {
		cfg->cpu_ids[cfg->cpu_num++] = i;
	}
	cfg->bg_thread_cpu_id = 79;
	cfg->measure_timing = 0;
	cfg->start_fd = CFG_START_FD;
	cfg->format = true;
}

/**
 *
 * @brief 初始化一个文件
 *
 * @param dev_name NVM设备路径
 * @param dir_name 挂载路径
 *
 * sb 返回值，即文件句柄/文件实例
 *
 * 注意，需要先调用 vfs_init()
 *
 */
int fs_mount(struct super_block** sb, const std::string &dev_name, const std::string &dir_name,
             struct vfs_cfg* cfg);
int fs_unmount(struct super_block** sb);

// 0创建成功，-1创建失败
int vfs_mkdir(const char* pathname, umode_t mode);
int vfs_ls(const char* pathname);
int vfs_rmdir( const char *dirname);


#endif
