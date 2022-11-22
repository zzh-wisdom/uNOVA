#ifndef UNOVA_SUPER_H_
#define UNOVA_SUPER_H_

#include <libpmem2.h>

#include "nova/nova_com.h"
#include "nova/vfs_api.h"
#include "util/atomic.h"
#include "util/lock.h"

#define NOVA_SB_SIZE 512 /* must be power of two */

int init_nova_fs(struct super_block *sb, const std::string &dev_name, const std::string &dir_name,
                 struct vfs_cfg *cfg);
void exit_nova_fs(void);

#endif
