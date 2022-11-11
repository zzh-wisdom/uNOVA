#include "nova/super.h"

#include <stddef.h>
#include <errno.h>
#include <assert.h>

#include "nova/nova_def.h"
#include "nova/nova.h"
#include "nova/nova_cfg.h"

#include "util/mem.h"
#include "util/log.h"
#include "util/bitops.h"

static struct kmem_cache *nova_inode_cachep;
static struct kmem_cache *nova_range_node_cachep;

ATTR_CONSTRUCTOR int init_rangenode_cache(void)
{
	r_warning("TODO: 优化 kmem_cache");
	nova_range_node_cachep = kmem_cache_create(
		sizeof(struct nova_range_node), sizeof(struct nova_range_node));
	if (nova_range_node_cachep == NULL)
		return -ENOMEM;
	return 0;
}

ATTR_DESTRUCTOR void destroy_rangenode_cache(void)
{
	r_warning("TODO: 优化 kmem_cache");
	kmem_cache_destroy(nova_range_node_cachep);
}

static inline void set_default_opts(struct nova_sb_info *sbi)
{
	// set_opt(sbi->s_mount_opt, HUGEIOREMAP);
	// set_opt(sbi->s_mount_opt, ERRORS_CONT);
	sbi->reserved_blocks = RESERVED_BLOCKS;
	sbi->cpus = num_online_cpus();
	sbi->map_id = 0;
}

static int nova_get_block_info(struct super_block *sb,
							   struct nova_sb_info *sbi)
{
	fatal << "TODO: 初始化NVM设备并映射";
	void *virt_addr = NULL;

	unsigned long pfn;
	long size = 0;

	// sbi->s_bdev = sb->s_bdev;

	sbi->virt_addr = virt_addr;
	sbi->initsize = size;

	rd_info("%s: dev %s, virt_addr %p, size %ld\n",
			__func__, sbi->dev_name, sbi->virt_addr, size);

	return 0;
}

static void nova_set_blocksize(struct super_block *sb, unsigned long size)
{
	int bits;

	/*
	 * We've already validated the user input and the value here must be
	 * between NOVA_MAX_BLOCK_SIZE and NOVA_MIN_BLOCK_SIZE
	 * and it must be a power of 2.
	 */
	bits = fls(size) - 1;
	sb->s_blocksize_bits = bits;
	sb->s_blocksize = (1 << bits);
}

// 检查 NVM size 是否合法
static bool nova_check_size(struct super_block *sb, unsigned long size)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long minimum_size, num_blocks;

	/* space required for super block and root directory */
	minimum_size = 2 << sb->s_blocksize_bits;

	/* space required for inode table */
	if (sbi->num_inodes > 0)
		num_blocks = (sbi->num_inodes >>
					  (sb->s_blocksize_bits - NOVA_INODE_BITS)) +
					 1;
	else
		num_blocks = 1;
	minimum_size += (num_blocks << sb->s_blocksize_bits);

	if (size < minimum_size)
		return false;

	return true;
}

// 初始化文件系统
static struct nova_inode *nova_init(struct super_block *sb,
									unsigned long size)
{
	unsigned long blocksize;
	unsigned long reserved_space, reserved_blocks;
	struct nova_inode *root_i, *pi;
	struct nova_super_block *super;
	struct nova_sb_info *sbi = NOVA_SB(sb);

	r_info("creating an empty nova of size %lu\n", size);
	sbi->num_blocks = ((unsigned long)(size) >> PAGE_SHIFT);

	if (!sbi->virt_addr)
	{
		r_error("ioremap of the nova image failed(1)\n");
		return nullptr;
	}

	r_info("nova: Default block size set to 4K\n");
	blocksize = sbi->blocksize = NOVA_DEF_BLOCK_SIZE_4K;

	nova_set_blocksize(sb, blocksize);
	blocksize = sb->s_blocksize;

	if (sbi->blocksize && sbi->blocksize != blocksize)
		sbi->blocksize = blocksize;

	if (!nova_check_size(sb, size))
	{
		r_warning("Specified NOVA size too small 0x%lx.\n", size);
		return nullptr;
	}

	/* Reserve space for 8 special inodes */
	reserved_space = NOVA_SB_SIZE * 4;
	reserved_blocks = (reserved_space + blocksize - 1) / blocksize;
	if (reserved_blocks > sbi->reserved_blocks)
	{
		r_warning("Reserved %lu blocks, require %lu blocks. "
				  "Increase reserved blocks number.\n",
				  sbi->reserved_blocks, reserved_blocks);
		return nullptr;
	}

	r_info("max file name len %d\n", (unsigned int)NOVA_NAME_LEN);

	super = nova_get_super(sb);

	/* clear out super-block and inode table */
	pmem_memset_nt(super, 0, sbi->reserved_blocks * sbi->blocksize);

	super->s_size = cpu_to_le64(size);
	super->s_blocksize = cpu_to_le32(blocksize);
	super->s_magic = cpu_to_le32(NOVA_SUPER_MAGIC);

	nova_init_blockmap(sb, 0);

	if (nova_lite_journal_hard_init(sb) < 0)
	{
		r_error("Lite journal hard initialization failed\n");
		return nullptr;
	}

	if (nova_init_inode_inuse_list(sb) < 0)
		return nullptr;

	if (nova_init_inode_table(sb) < 0)
		return ERR_PTR(-EINVAL);

	pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	pi->nova_ino = NOVA_BLOCKNODE_INO;
	nova_flush_buffer(pi, CACHELINE_SIZE, 1);

	pi = nova_get_inode_by_ino(sb, NOVA_INODELIST_INO);
	pi->nova_ino = NOVA_INODELIST_INO;
	nova_flush_buffer(pi, CACHELINE_SIZE, 1);

	nova_memunlock_range(sb, super, NOVA_SB_SIZE * 2);
	nova_sync_super(super);
	nova_memlock_range(sb, super, NOVA_SB_SIZE * 2);

	nova_flush_buffer(super, NOVA_SB_SIZE, false);
	nova_flush_buffer((char *)super + NOVA_SB_SIZE, sizeof(*super), false);

	nova_dbg_verbose("Allocate root inode\n");
	root_i = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);

	nova_memunlock_inode(sb, root_i);
	root_i->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
	root_i->i_uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
	root_i->i_gid = cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
	root_i->i_links_count = cpu_to_le16(2);
	root_i->i_blk_type = NOVA_BLOCK_TYPE_4K;
	root_i->i_flags = 0;
	root_i->i_blocks = cpu_to_le64(1);
	root_i->i_size = cpu_to_le64(sb->s_blocksize);
	root_i->i_atime = root_i->i_mtime = root_i->i_ctime =
		cpu_to_le32(get_seconds());
	root_i->nova_ino = NOVA_ROOT_INO;
	root_i->valid = 1;
	/* nova_sync_inode(root_i); */
	nova_memlock_inode(sb, root_i);
	nova_flush_buffer(root_i, sizeof(*root_i), false);

	nova_append_dir_init_entries(sb, root_i, NOVA_ROOT_INO,
								 NOVA_ROOT_INO);

	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	return root_i;
}

static int nova_fill_super(struct super_block *sb, void *data, int silent)
{
	struct nova_super_block *super;
	struct nova_inode *root_pi;
	struct nova_sb_info *sbi = NULL;
	struct inode *root_i = NULL;
	struct inode_map *inode_map;
	unsigned long blocksize;
	u32 random = 0;
	int retval = -EINVAL;
	int i;
	// timing_t mount_time;

	// NOVA_START_TIMING(mount_t, mount_time);

	assert(sizeof(struct nova_super_block) <= NOVA_SB_SIZE);
	assert(sizeof(struct nova_inode) <= NOVA_INODE_SIZE);
	assert(sizeof(struct nova_inode_log_page) == PAGE_SIZE);

	sbi = (struct nova_sb_info *)zalloc(sizeof(struct nova_sb_info));
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;
	sbi->sb = sb;

	set_default_opts(sbi);

	/* Currently the log page supports 64 journal pointer pairs */
	if (sbi->cpus > MAX_CPU_NUM)
	{
		r_error("NOVA needs more log pointer pages "
				"to support more than 64 cpus.\n");
		goto out;
	}

	if (nova_get_block_info(sb, sbi))
		goto out;

	random = rand();
	atomic_set(&sbi->next_generation, random);

	/* Init with default values */
	sbi->shared_free_list.block_free_tree = RB_ROOT;
	spin_lock_init(&sbi->shared_free_list.s_lock);
	sbi->mode = 0;
	sbi->uid = 0;
	sbi->gid = 0;
	sbi->s_mount_opt = 0;

	sbi->inode_maps = (struct inode_map *)zalloc(sbi->cpus * sizeof(struct inode_map));
	if (!sbi->inode_maps)
	{
		retval = -ENOMEM;
		goto out;
	}

	// nova_sysfs_init(sb);

	for (i = 0; i < sbi->cpus; i++)
	{
		inode_map = &sbi->inode_maps[i];
		mutex_init(&inode_map->inode_table_mutex);
		inode_map->inode_inuse_tree = RB_ROOT;
	}

	mutex_init(&sbi->s_lock);

	sbi->zeroed_page = zalloc(PAGE_SIZE);
	if (!sbi->zeroed_page)
	{
		retval = -ENOMEM;
		goto out;
	}

	// if (nova_parse_options(data, sbi, 0))
	// 	goto out;

	// set_opt(sbi->s_mount_opt, MOUNTING);

	// init 每个cpu的block free list
	if (nova_alloc_block_free_lists(sb))
	{
		retval = -ENOMEM;
		goto out;
	}

	/* Init a new nova instance */
	if (sbi->s_mount_opt & NOVA_MOUNT_FORMAT)
	{ // 重新初始化挂载
		root_pi = nova_init(sb, sbi->initsize);
		if (IS_ERR(root_pi))
			goto out;
		super = nova_get_super(sb);
		goto setup_sb;
	}

	// 恢复
	// nova_dbg_verbose("checking physical address 0x%016llx for nova image\n",
	// 	  (u64)sbi->phys_addr);

	// super = nova_get_super(sb);

	// if (nova_check_integrity(sb, super) == 0) {
	// 	nova_dbg("Memory contains invalid nova %x:%x\n",
	// 			le32_to_cpu(super->s_magic), NOVA_SUPER_MAGIC);
	// 	goto out;
	// }

	// if (nova_lite_journal_soft_init(sb)) {
	// 	retval = -EINVAL;
	// 	printk(KERN_ERR "Lite journal initialization failed\n");
	// 	goto out;
	// }

	// blocksize = le32_to_cpu(super->s_blocksize);
	// nova_set_blocksize(sb, blocksize);

	// nova_dbg_verbose("blocksize %lu\n", blocksize);

	// /* Read the root inode */
	// root_pi = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);

	// /* Check that the root inode is in a sane state */
	// nova_root_check(sb, root_pi);

	/* Set it all up.. */
setup_sb:
	sb->s_magic = le32_to_cpu(super->s_magic);
	sb->s_op = &nova_sops;
	sb->s_maxbytes = nova_max_size(sb->s_blocksize_bits);
	sb->s_time_gran = 1;
	sb->s_export_op = &nova_export_ops;
	sb->s_xattr = NULL;
	sb->s_flags |= MS_NOSEC;

	/* If the FS was not formatted on this mount, scan the meta-data after
	 * truncate list has been processed */
	if ((sbi->s_mount_opt & NOVA_MOUNT_FORMAT) == 0)
		nova_recovery(sb);

	root_i = nova_iget(sb, NOVA_ROOT_INO);
	if (IS_ERR(root_i))
	{
		retval = PTR_ERR(root_i);
		goto out;
	}

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root)
	{
		printk(KERN_ERR "get nova root inode failed\n");
		retval = -ENOMEM;
		goto out;
	}

	if (!(sb->s_flags & MS_RDONLY))
	{
		u64 mnt_write_time;
		/* update mount time and write time atomically. */
		mnt_write_time = (get_seconds() & 0xFFFFFFFF);
		mnt_write_time = mnt_write_time | (mnt_write_time << 32);

		nova_memunlock_range(sb, &super->s_mtime, 8);
		nova_memcpy_atomic(&super->s_mtime, &mnt_write_time, 8);
		nova_memlock_range(sb, &super->s_mtime, 8);

		nova_flush_buffer(&super->s_mtime, 8, false);
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}

	clear_opt(sbi->s_mount_opt, MOUNTING);
	retval = 0;

	NOVA_END_TIMING(mount_t, mount_time);
	return retval;
out:
	if (sbi->zeroed_page)
	{
		kfree(sbi->zeroed_page);
		sbi->zeroed_page = NULL;
	}

	if (sbi->free_lists)
	{
		kfree(sbi->free_lists);
		sbi->free_lists = NULL;
	}

	if (sbi->journal_locks)
	{
		kfree(sbi->journal_locks);
		sbi->journal_locks = NULL;
	}

	if (sbi->inode_maps)
	{
		kfree(sbi->inode_maps);
		sbi->inode_maps = NULL;
	}

	kfree(sbi);
	return retval;
}

static inline struct nova_range_node *nova_alloc_range_node(struct super_block *sb)
{
	struct nova_range_node *p;
	p = (struct nova_range_node *)
		kmem_cache_alloc(nova_range_node_cachep);
	return p;
}

// 内存cache中申请一个空间
inline struct nova_range_node *nova_alloc_blocknode(struct super_block *sb)
{
	return nova_alloc_range_node(sb);
}

inline void nova_free_range_node(struct nova_range_node *node)
{
	kmem_cache_free(nova_range_node_cachep, node);
}

inline void nova_free_blocknode(struct super_block *sb,
	struct nova_range_node *node)
{
	nova_free_range_node(node);
}

inline void nova_free_inode_node(struct super_block *sb,
	struct nova_range_node *node)
{
	nova_free_range_node(node);
}