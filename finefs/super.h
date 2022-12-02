#ifndef UFINEFS_FINEFS_SUPER_H_
#define UFINEFS_FINEFS_SUPER_H_

#include <libpmem2.h>

#include "vfs/com.h"
#include "vfs/vfs_api.h"
#include "util/atomic.h"
#include "util/lock.h"

#define FINEFS_SB_SIZE 512 /* must be power of two */

int init_finefs_fs(struct super_block *sb, const std::string &dev_name, const std::string &dir_name,
                   struct vfs_cfg *cfg);

#endif
