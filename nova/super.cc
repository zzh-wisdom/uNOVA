/*
 * BRIEF DESCRIPTION
 *
 * Super block operations.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "nova/super.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>

#include "nova/nova.h"
#include "vfs/fs_cfg.h"
#include "nova/nova_def.h"
#include "nova/wprotect.h"
#include "util/bitops.h"
#include "util/cpu.h"
#include "util/log.h"
#include "util/mem.h"
#include "util/rbtree.h"

// int support_clwb = 1;  // 默认支持clwb
// int support_pcommit = 0;

// static const struct export_operations nova_export_ops;
static struct kmem_cache *nova_inode_cachep;
static struct kmem_cache *nova_range_node_cachep;

/* FIXME: should the following variable be one per NOVA instance? */
unsigned int nova_dbgmask = 0;

int init_rangenode_cache(void) {
    rd_warning("TODO: 优化 kmem_cache");
    nova_range_node_cachep =
        kmem_cache_create(sizeof(struct nova_range_node), sizeof(struct nova_range_node));
    if (nova_range_node_cachep == NULL) return -ENOMEM;
    return 0;
}

void destroy_rangenode_cache(void) {
    rd_warning("TODO: 优化 kmem_cache");
    kmem_cache_destroy(&nova_range_node_cachep);
}

static void nova_set_blocksize(struct super_block *sb, unsigned long size) {
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

static int nova_get_block_info(struct super_block *sb, struct nova_sb_info *sbi) {
    void *virt_addr = pmem2_map_get_address(sb->pmap);
    long max_size = pmem2_map_get_size(sb->pmap);
    long size = max_size;
    // long size = 20ul << 30; // 20 G
    // log_assert(size <= max_size);

    // sbi->s_bdev = sb->s_bdev;

    sbi->virt_addr = virt_addr;
    sbi->initsize = size;

    rd_info("%s: dev=%s, virt_addr=%p, size=%ld", __func__, sb->dev_name.c_str(), sbi->virt_addr,
            size);

    return 0;
}

static size_t nova_max_size(int bits) {
    size_t res;

    res = (1ULL << 63) - 1;

    if (res > MAX_LFS_FILESIZE) res = MAX_LFS_FILESIZE;

    rd_info("max file size %lu bytes\n", res);
    return res;
}

enum {
    Opt_bpi,
    Opt_init,
    Opt_mode,
    Opt_uid,
    Opt_gid,
    Opt_blocksize,
    Opt_wprotect,
    Opt_err_cont,
    Opt_err_panic,
    Opt_err_ro,
    Opt_dbgmask,
    Opt_err
};

// static const match_table_t tokens = {
// 	{ Opt_bpi,	     "bpi=%u"		  },
// 	{ Opt_init,	     "init"		  },
// 	{ Opt_mode,	     "mode=%o"		  },
// 	{ Opt_uid,	     "uid=%u"		  },
// 	{ Opt_gid,	     "gid=%u"		  },
// 	{ Opt_wprotect,	     "wprotect"		  },
// 	{ Opt_err_cont,	     "errors=continue"	  },
// 	{ Opt_err_panic,     "errors=panic"	  },
// 	{ Opt_err_ro,	     "errors=remount-ro"  },
// 	{ Opt_dbgmask,	     "dbgmask=%u"	  },
// 	{ Opt_err,	     NULL		  },
// };

// static int nova_parse_options(char *options, struct nova_sb_info *sbi,
// 			       bool remount)
// {
// 	char *p;
// 	substring_t args[MAX_OPT_ARGS];
// 	int option;

// 	if (!options)
// 		return 0;

// 	while ((p = strsep(&options, ",")) != NULL) {
// 		int token;
// 		if (!*p)
// 			continue;

// 		token = match_token(p, tokens, args);
// 		switch (token) {
// 		case Opt_bpi:
// 			if (remount)
// 				goto bad_opt;
// 			if (match_int(&args[0], &option))
// 				goto bad_val;
// 			sbi->bpi = option;
// 			break;
// 		case Opt_uid:
// 			if (remount)
// 				goto bad_opt;
// 			if (match_int(&args[0], &option))
// 				goto bad_val;
// 			sbi->uid = make_kuid(current_user_ns(), option);
// 			break;
// 		case Opt_gid:
// 			if (match_int(&args[0], &option))
// 				goto bad_val;
// 			sbi->gid = make_kgid(current_user_ns(), option);
// 			break;
// 		case Opt_mode:
// 			if (match_octal(&args[0], &option))
// 				goto bad_val;
// 			sbi->mode = option & 01777U;
// 			break;
// 		case Opt_init:
// 			if (remount)
// 				goto bad_opt;
// 			set_opt(sbi->s_mount_opt, FORMAT);
// 			break;
// 		case Opt_err_panic:
// 			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
// 			clear_opt(sbi->s_mount_opt, ERRORS_RO);
// 			set_opt(sbi->s_mount_opt, ERRORS_PANIC);
// 			break;
// 		case Opt_err_ro:
// 			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
// 			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
// 			set_opt(sbi->s_mount_opt, ERRORS_RO);
// 			break;
// 		case Opt_err_cont:
// 			clear_opt(sbi->s_mount_opt, ERRORS_RO);
// 			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
// 			set_opt(sbi->s_mount_opt, ERRORS_CONT);
// 			break;
// 		case Opt_wprotect:
// 			if (remount)
// 				goto bad_opt;
// 			set_opt(sbi->s_mount_opt, PROTECT);
// 			nova_info("NOVA: Enabling new Write Protection "
// 				"(CR0.WP)\n");
// 			break;
// 		case Opt_dbgmask:
// 			if (match_int(&args[0], &option))
// 				goto bad_val;
// 			nova_dbgmask = option;
// 			break;
// 		default: {
// 			goto bad_opt;
// 		}
// 		}
// 	}

// 	return 0;

// bad_val:
// 	printk(KERN_INFO "Bad value '%s' for mount option '%s'\n", args[0].from,
// 	       p);
// 	return -EINVAL;
// bad_opt:
// 	printk(KERN_INFO "Bad mount option: \"%s\"\n", p);
// 	return -EINVAL;
// }

// 检查 NVM size 是否合法
static bool nova_check_size(struct super_block *sb, unsigned long size) {
    struct nova_sb_info *sbi = NOVA_SB(sb);
    unsigned long minimum_size, num_blocks;

    /* space required for super block and root directory */
    minimum_size = 2 << sb->s_blocksize_bits;

    /* space required for inode table */
    if (sbi->num_inodes > 0)
        num_blocks = (sbi->num_inodes >> (sb->s_blocksize_bits - NOVA_INODE_BITS)) + 1;
    else
        num_blocks = 1;
    minimum_size += (num_blocks << sb->s_blocksize_bits);

    if (size < minimum_size) return false;

    return true;
}

// 初始化文件系统
// 返回root inode
static struct nova_inode *nova_init(struct super_block *sb, unsigned long size) {
    unsigned long blocksize;
    unsigned long reserved_space, reserved_blocks;
    struct nova_inode *root_i, *pi;
    struct nova_super_block *super;
    struct nova_sb_info *sbi = NOVA_SB(sb);

    r_info("creating an empty nova of size %lu", size);
    sbi->num_blocks = ((unsigned long)(size) >> PAGE_SHIFT);

    if (!sbi->virt_addr) {
        r_error("ioremap of the nova image failed(1)");
        return nullptr;
    }

    r_info("nova: Default block size set to 4K");
    blocksize = sbi->blocksize = NOVA_DEF_BLOCK_SIZE_4K;

    nova_set_blocksize(sb, blocksize);
    blocksize = sb->s_blocksize;

    if (sbi->blocksize && sbi->blocksize != blocksize) sbi->blocksize = blocksize;

    if (!nova_check_size(sb, size)) {
        r_warning("Specified NOVA size too small 0x%lx.\n", size);
        return nullptr;
    }

    /* Reserve space for 8 special inodes */
    reserved_space = NOVA_SB_SIZE * 4;
    reserved_blocks = (reserved_space + blocksize - 1) / blocksize;
    if (reserved_blocks > sbi->reserved_blocks) {
        r_warning(
            "Reserved %lu blocks, require %lu blocks. "
            "Increase reserved blocks number.\n",
            sbi->reserved_blocks, reserved_blocks);
        return nullptr;
    }

    r_info("max file name len %d", (unsigned int)NOVA_NAME_LEN);

    super = nova_get_super(sb);

    /* clear out super-block and inode table */
    memset_nt(super, 0, sbi->reserved_blocks * sbi->blocksize);
    r_info("sbi->reserved_blocks=%ld", sbi->reserved_blocks);

    super->s_size = cpu_to_le64(size);
    super->s_blocksize = cpu_to_le32(blocksize);
    super->s_magic = cpu_to_le32(NOVA_SUPER_MAGIC);

    nova_init_blockmap(sb, 0);

    // 初始化并恢复journal
    if (nova_lite_journal_hard_init(sb) < 0) {
        r_error("Lite journal hard initialization failed\n");
        return nullptr;
    }

    // 初始化已经使用的inode列表，主要是处理预留的inode
    if (nova_init_inode_inuse_list(sb) < 0) return nullptr;

    // 分配每个cpu的NVM inode table
    if (nova_init_inode_table(sb) < 0) return nullptr;

    pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
    pi->nova_ino = NOVA_BLOCKNODE_INO;
    nova_flush_buffer(pi, CACHELINE_SIZE, 1);

    // pi = nova_get_inode_by_ino(sb, NOVA_INODELIST_INO);
    // pi->nova_ino = NOVA_INODELIST_INO;
    // nova_flush_buffer(pi, CACHELINE_SIZE, 1);

    nova_memunlock_range(sb, super, NOVA_SB_SIZE * 2);
    nova_sync_super(super);
    nova_memlock_range(sb, super, NOVA_SB_SIZE * 2);

    nova_flush_buffer(super, NOVA_SB_SIZE, false);
    nova_flush_buffer((char *)super + NOVA_SB_SIZE, sizeof(*super), false);

    rdv_proc("Allocate root inode\n");
    root_i = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);

    nova_memunlock_inode(sb, root_i);
    root_i->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
    // root_i->i_uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
    // root_i->i_gid = cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
    root_i->i_links_count = cpu_to_le16(2);
    root_i->i_blk_type = NOVA_BLOCK_TYPE_4K;
    root_i->i_flags = 0;
    root_i->i_blocks = cpu_to_le64(1);
    root_i->i_size = cpu_to_le64(sb->s_blocksize);
    root_i->i_atime = root_i->i_mtime = root_i->i_ctime = cpu_to_le32(GetTsSec());
    root_i->nova_ino = NOVA_ROOT_INO;
    root_i->valid = 1;
    /* nova_sync_inode(root_i); */
    nova_memlock_inode(sb, root_i);
    nova_flush_buffer(root_i, sizeof(*root_i), false);

    nova_append_dir_init_entries(sb, root_i, NOVA_ROOT_INO, NOVA_ROOT_INO, 0);

    PERSISTENT_MARK();
    PERSISTENT_BARRIER();
    return root_i;
}

static inline void set_default_opts(struct nova_sb_info *sbi) {
    // set_opt(sbi->s_mount_opt, HUGEIOREMAP);
    // set_opt(sbi->s_mount_opt, ERRORS_CONT);
    sbi->reserved_blocks = RESERVED_BLOCKS;
    sbi->cpus = num_online_cpus();
    sbi->map_id = 0;
}

static void nova_root_check(struct super_block *sb, struct nova_inode *root_pi)
{
	if (!S_ISDIR(le16_to_cpu(root_pi->i_mode)))
		r_warning("root is not a directory!\n");
}

int nova_check_integrity(struct super_block *sb,
			  struct nova_super_block *super)
{
	struct nova_super_block *super_redund;

	super_redund =
		(struct nova_super_block *)((char *)super + NOVA_SB_SIZE);

	/* Do sanity checks on the superblock */
	if (le32_to_cpu(super->s_magic) != NOVA_SUPER_MAGIC) {
		if (le32_to_cpu(super_redund->s_magic) != NOVA_SUPER_MAGIC) {
			r_error("Can't find a valid nova partition\n");
			goto out;
		} else {
			rd_warning
				("Error in super block: try to repair it with "
				"the redundant copy");
			/* Try to auto-recover the super block */
			if (sb)
				nova_memunlock_super(sb, super);
			memcpy(super, super_redund,
				sizeof(struct nova_super_block));
			if (sb)
				nova_memlock_super(sb, super);
			nova_flush_buffer(super, sizeof(*super), false);
			nova_flush_buffer((char *)super + NOVA_SB_SIZE,
				sizeof(*super), false);

		}
	}

	/* Read the superblock */
	if (nova_calc_checksum((u8 *)super, NOVA_SB_STATIC_SIZE(super))) {
		if (nova_calc_checksum((u8 *)super_redund,
					NOVA_SB_STATIC_SIZE(super_redund))) {
			r_error("checksum error in super block\n");
			goto out;
		} else {
			r_warning
				("Error in super block: try to repair it with "
				"the redundant copy");
			/* Try to auto-recover the super block */
			if (sb)
				nova_memunlock_super(sb, super);
			memcpy(super, super_redund,
				sizeof(struct nova_super_block));
			if (sb)
				nova_memlock_super(sb, super);
			nova_flush_buffer(super, sizeof(*super), false);
			nova_flush_buffer((char *)super + NOVA_SB_SIZE,
				sizeof(*super), false);
		}
	}

	return 1;
out:
	return 0;
}

static struct inode *nova_alloc_inode(struct super_block *sb) {
    rdv_proc("%s", __func__);
    struct nova_inode_info *vi;
    vi = (struct nova_inode_info *)kmem_cache_alloc(nova_inode_cachep);
    if (!vi) return NULL;
    // vi->vfs_inode.i_version = 1;
    return &vi->vfs_inode;
}

static void nova_destroy_inode(struct inode *inode) {
    rdv_proc("%s: %lu", __func__, inode->i_ino);
    // call_rcu(&inode->i_rcu, nova_i_callback);
    struct nova_inode_info *vi = NOVA_I(inode);
    kmem_cache_free(nova_inode_cachep, vi);
}

// int nova_statfs(struct dentry *d, struct kstatfs *buf)
// {
// 	struct super_block *sb = d->d_sb;
// 	struct nova_sb_info *sbi = (struct nova_sb_info *)sb->s_fs_info;

// 	buf->f_type = NOVA_SUPER_MAGIC;
// 	buf->f_bsize = sb->s_blocksize;

// 	buf->f_blocks = sbi->num_blocks;
// 	buf->f_bfree = buf->f_bavail = nova_count_free_blocks(sb);
// 	buf->f_files = LONG_MAX;
// 	buf->f_ffree = LONG_MAX - sbi->s_inodes_used_count;
// 	buf->f_namelen = NOVA_NAME_LEN;
// 	nova_dbg_verbose("nova_stats: total 4k free blocks 0x%lx\n",
// 		buf->f_bfree);
// 	return 0;
// }

// static int nova_show_options(struct seq_file *seq, struct dentry *root)
// {
// 	struct nova_sb_info *sbi = NOVA_SB(root->d_sb);

// 	seq_printf(seq, ",physaddr=0x%016llx", (u64)sbi->phys_addr);
// 	if (sbi->initsize)
// 		seq_printf(seq, ",init=%luk", sbi->initsize >> 10);
// 	if (sbi->blocksize)
// 		seq_printf(seq, ",bs=%lu", sbi->blocksize);
// 	if (sbi->bpi)
// 		seq_printf(seq, ",bpi=%lu", sbi->bpi);
// 	if (sbi->num_inodes)
// 		seq_printf(seq, ",N=%lu", sbi->num_inodes);
// 	if (sbi->mode != (S_IRWXUGO | S_ISVTX))
// 		seq_printf(seq, ",mode=%03o", sbi->mode);
// 	if (uid_valid(sbi->uid))
// 		seq_printf(seq, ",uid=%u", from_kuid(&init_user_ns, sbi->uid));
// 	if (gid_valid(sbi->gid))
// 		seq_printf(seq, ",gid=%u", from_kgid(&init_user_ns, sbi->gid));
// 	if (test_opt(root->d_sb, ERRORS_RO))
// 		seq_puts(seq, ",errors=remount-ro");
// 	if (test_opt(root->d_sb, ERRORS_PANIC))
// 		seq_puts(seq, ",errors=panic");
// 	/* memory protection disabled by default */
// 	if (test_opt(root->d_sb, PROTECT))
// 		seq_puts(seq, ",wprotect");
// 	if (test_opt(root->d_sb, DAX))
// 		seq_puts(seq, ",dax");

// 	return 0;
// }

// int nova_remount(struct super_block *sb, int *mntflags, char *data)
// {
// 	unsigned long old_sb_flags;
// 	unsigned long old_mount_opt;
// 	struct nova_super_block *ps;
// 	struct nova_sb_info *sbi = NOVA_SB(sb);
// 	int ret = -EINVAL;

// 	/* Store the old options */
// 	mutex_lock(&sbi->s_lock);
// 	old_sb_flags = sb->s_flags;
// 	old_mount_opt = sbi->s_mount_opt;

// 	if (nova_parse_options(data, sbi, 1))
// 		goto restore_opt;

// 	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
// 		      ((sbi->s_mount_opt & NOVA_MOUNT_POSIX_ACL) ? MS_POSIXACL : 0);

// 	if ((*mntflags & MS_RDONLY) != (sb->s_flags & MS_RDONLY)) {
// 		u64 mnt_write_time;
// 		ps = nova_get_super(sb);
// 		/* update mount time and write time atomically. */
// 		mnt_write_time = (get_seconds() & 0xFFFFFFFF);
// 		mnt_write_time = mnt_write_time | (mnt_write_time << 32);

// 		nova_memunlock_range(sb, &ps->s_mtime, 8);
// 		nova_memcpy_atomic(&ps->s_mtime, &mnt_write_time, 8);
// 		nova_memlock_range(sb, &ps->s_mtime, 8);

// 		nova_flush_buffer(&ps->s_mtime, 8, false);
// 		PERSISTENT_MARK();
// 		PERSISTENT_BARRIER();
// 	}

// 	mutex_unlock(&sbi->s_lock);
// 	ret = 0;
// 	return ret;

// restore_opt:
// 	sb->s_flags = old_sb_flags;
// 	sbi->s_mount_opt = old_mount_opt;
// 	mutex_unlock(&sbi->s_lock);
// 	return ret;
// }

void nova_free_range_node(struct nova_range_node *node) {
    kmem_cache_free(nova_range_node_cachep, node);
}

void nova_free_blocknode(struct super_block *sb, struct nova_range_node *node) {
    nova_free_range_node(node);
}

void nova_free_inode_node(struct super_block *sb, struct nova_range_node *node) {
    nova_free_range_node(node);
}

static inline struct nova_range_node *nova_alloc_range_node(struct super_block *sb) {
    struct nova_range_node *p;
    p = (struct nova_range_node *)kmem_cache_alloc(nova_range_node_cachep);
    return p;
}

// 内存cache中申请一个空间
struct nova_range_node *nova_alloc_blocknode(struct super_block *sb) {
    return nova_alloc_range_node(sb);
}

struct nova_range_node *nova_alloc_inode_node(struct super_block *sb) {
    return nova_alloc_range_node(sb);
}

// static void nova_i_callback(struct rcu_head *head)
// {
// 	struct inode *inode = container_of(head, struct inode, i_rcu);
// 	struct nova_inode_info *vi = NOVA_I(inode);

// 	nova_dbg_verbose("%s: ino %lu\n", __func__, inode->i_ino);
// 	kmem_cache_free(nova_inode_cachep, vi);
// }

// static void init_once(void *foo)
// {
// 	struct nova_inode_info *vi = foo;

// 	inode_init_once(&vi->vfs_inode);
// }

static int init_inodecache() {
    nova_inode_cachep =
        kmem_cache_create(sizeof(struct nova_inode_info), sizeof(struct nova_inode_info));
    if (nova_inode_cachep == NULL) return -ENOMEM;
    return 0;
}

static void destroy_inodecache(void) { kmem_cache_destroy(&nova_inode_cachep); }

// static struct dentry *nova_mount(struct file_system_type *fs_type, int flags, const char
// *dev_name,
//                                  void *data) {
//     return mount_bdev(fs_type, flags, dev_name, data, nova_fill_super);
// }

// static struct file_system_type nova_fs_type = {
// 	.owner		= THIS_MODULE,
// 	.name		= "NOVA",
// 	.mount		= nova_mount,
// 	.kill_sb	= kill_block_super,
// };

// static struct inode *nova_nfs_get_inode(struct super_block *sb,
// 					 u64 ino, u32 generation)
// {
// 	struct inode *inode;

// 	if (ino < NOVA_ROOT_INO)
// 		return ERR_PTR(-ESTALE);

// 	if (ino > LONG_MAX)
// 		return ERR_PTR(-ESTALE);

// 	inode = nova_iget(sb, ino);
// 	if (IS_ERR(inode))
// 		return ERR_CAST(inode);

// 	if (generation && inode->i_generation != generation) {
// 		/* we didn't find the right inode.. */
// 		iput(inode);
// 		return ERR_PTR(-ESTALE);
// 	}

// 	return inode;
// }

// static struct dentry *nova_fh_to_dentry(struct super_block *sb,
// 					 struct fid *fid, int fh_len,
// 					 int fh_type)
// {
// 	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
// 				    nova_nfs_get_inode);
// }

// static struct dentry *nova_fh_to_parent(struct super_block *sb,
// 					 struct fid *fid, int fh_len,
// 					 int fh_type)
// {
// 	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
// 				    nova_nfs_get_inode);
// }

// static const struct export_operations nova_export_ops = {
// 	.fh_to_dentry	= nova_fh_to_dentry,
// 	.fh_to_parent	= nova_fh_to_parent,
// 	.get_parent	= nova_get_parent,
// };

static void nova_put_super(struct super_block *sb) {
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct inode_map *inode_map;
    int i;

    /* It's unmount time, so unmap the nova memory */
    //	nova_print_free_lists(sb);
    if (sbi->virt_addr) {
        nova_save_inode_list_to_log(sb);
        /* Save everything before blocknode mapping! */
        nova_save_blocknode_mappings_to_log(sb);
        sbi->virt_addr = NULL;
    }

    nova_delete_free_lists(sb);

    // FREE(sbi->zeroed_page);
    nova_dbgmask = 0;
    FREE(sbi->free_lists);
    FREE(sbi->journal_locks);

    for (i = 0; i < sbi->cpus; i++) {
        inode_map = &sbi->inode_maps[i];
        rd_info("CPU %d: inode allocated %d, freed %d", i, inode_map->allocated, inode_map->freed);
    }

    FREE(sbi->inode_maps);

    // nova_sysfs_exit(sb);

    FREE(sbi);
    sb->s_fs_info = NULL;

    destroy_inodecache();
    destroy_rangenode_cache();
}

/*
 * the super block writes are all done "on the fly", so the
 * super block is never in a "dirty" state, so there's no need
 * for write_super.
 */
static struct super_operations nova_sops = {
    .alloc_inode = nova_alloc_inode,
    .destroy_inode = nova_destroy_inode,
    // .write_inode	= nova_write_inode,
    .dirty_inode	= nova_dirty_inode,
    .evict_inode	= nova_evict_inode,
    .put_super = nova_put_super,  // 删除sb时调用
                                  // .statfs		= nova_statfs,
                                  // .remount_fs	= nova_remount,
                                  // .show_options	= nova_show_options,
};

static int nova_fill_super(struct super_block *sb, bool format) {
    struct nova_super_block *super;
    struct nova_inode *root_pi;
    struct nova_sb_info *sbi = NULL;
    struct inode *root_i = NULL;
    struct inode_map *inode_map;
    unsigned long blocksize;
    u32 random = 0;
    int retval = -EINVAL;
    int i;
    timing_t mount_time;

    NOVA_START_TIMING(mount_t, mount_time);

    assert(sizeof(struct nova_super_block) <= NOVA_SB_SIZE);
    assert(sizeof(struct nova_inode) <= NOVA_INODE_SIZE);
    assert(sizeof(struct nova_inode_log_page) == PAGE_SIZE);

    sbi = (struct nova_sb_info *)ZALLOC(sizeof(struct nova_sb_info));
    if (!sbi) return -ENOMEM;
    sb->s_fs_info = sbi;
    sbi->sb = sb;

    set_default_opts(sbi);

    /* Currently the log page supports 64 journal pointer pairs */
    if (sbi->cpus > FS_MAX_CPU_NUM) {
        r_error(
            "NOVA needs more log pointer pages "
            "to support more than 64 cpus.\n");
        goto out;
    }

    if (nova_get_block_info(sb, sbi)) goto out;

    random = rand();
    atomic_set(&sbi->next_generation, random);

    /* Init with default values */
    sbi->shared_free_list.block_free_tree = RB_ROOT;
    spin_lock_init(&sbi->shared_free_list.s_lock);
    sbi->mode = 0;
    // sbi->uid = 0;
    // sbi->gid = 0;
    sbi->s_mount_opt = 0;

    sbi->inode_maps = (struct inode_map *)ZALLOC(sbi->cpus * sizeof(struct inode_map));
    if (!sbi->inode_maps) {
        retval = -ENOMEM;
        goto out;
    }

    // nova_sysfs_init(sb);

    for (i = 0; i < sbi->cpus; i++) {
        inode_map = &sbi->inode_maps[i];
        mutex_init(&inode_map->inode_table_mutex);
        inode_map->inode_inuse_tree = RB_ROOT;
    }

    mutex_init(&sbi->s_lock);

    // sbi->zeroed_page = ZALLOC(PAGE_SIZE);
    // if (!sbi->zeroed_page)
    // {
    // 	retval = -ENOMEM;
    // 	goto out;
    // }

    // if (nova_parse_options(data, sbi, 0))
    // 	goto out;

    // 设置选项
    if (format) {
        set_opt(sbi->s_mount_opt, FORMAT);
    }

    set_opt(sbi->s_mount_opt, MOUNTING);

    // init 每个cpu的block free list
    if (nova_alloc_block_free_lists(sb)) {
        retval = -ENOMEM;
        goto out;
    }

    /* Init a new nova instance */
    if (sbi->s_mount_opt & NOVA_MOUNT_FORMAT) {  // 重新初始化挂载
        root_pi = nova_init(sb, sbi->initsize);
        if (!root_pi) goto out;
        super = nova_get_super(sb);
        goto setup_sb;
    }

    // 恢复
    rd_info("checking physical address 0x%016llx for nova image\n",
    	  (u64)sbi->virt_addr);

    super = nova_get_super(sb);

    // 检查magic和校验和
    if (nova_check_integrity(sb, super) == 0) {
    	rd_info("Memory contains invalid nova %x:%x\n",
    			le32_to_cpu(super->s_magic), NOVA_SUPER_MAGIC);
    	goto out;
    }

    if (nova_lite_journal_soft_init(sb)) {
    	retval = -EINVAL;
    	r_error("Lite journal initialization failed\n");
    	goto out;
    }

    blocksize = le32_to_cpu(super->s_blocksize);
    nova_set_blocksize(sb, blocksize);

    rd_info("blocksize %lu\n", blocksize);

    /* Read the root inode */
    root_pi = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);

    /* Check that the root inode is in a sane state */
    nova_root_check(sb, root_pi);

    /* Set it all up.. */
setup_sb:
    sb->s_magic = le32_to_cpu(super->s_magic);
    sb->s_op = &nova_sops;
    sb->s_maxbytes = nova_max_size(sb->s_blocksize_bits);
    // sb->s_time_gran = 1;
    // sb->s_export_op = &nova_export_ops;
    // sb->s_xattr = NULL;
    sb->s_flags |= MS_NOSEC;

    /* If the FS was not formatted on this mount, scan the meta-data after
     * truncate list has been processed */
    if ((sbi->s_mount_opt & NOVA_MOUNT_FORMAT) == 0) {
        info << "nova recovery...";
        nova_recovery(sb);
    }

    root_i = nova_iget(sb, NOVA_ROOT_INO);
    if (root_i == nullptr) {
        retval = -1;
        goto out;
    }

    sb->s_root = d_make_root(root_i);
    inode_unref(root_i);
    if (!sb->s_root) {
        r_error("get nova root inode failed\n");
        retval = -ENOMEM;
        goto out;
    }

    // if (!(sb->s_flags & MS_RDONLY))
    // {
    // 	u64 mnt_write_time;
    // 	/* update mount time and write time atomically. */
    // 	mnt_write_time = (get_seconds() & 0xFFFFFFFF);
    // 	mnt_write_time = mnt_write_time | (mnt_write_time << 32);

    // 	nova_memunlock_range(sb, &super->s_mtime, 8);
    // 	nova_memcpy_atomic(&super->s_mtime, &mnt_write_time, 8);
    // 	nova_memlock_range(sb, &super->s_mtime, 8);

    // 	nova_flush_buffer(&super->s_mtime, 8, false);
    // 	PERSISTENT_MARK();
    // 	PERSISTENT_BARRIER();
    // }

    clear_opt(sbi->s_mount_opt, MOUNTING);
    retval = 0;

    NOVA_END_TIMING(mount_t, mount_time);
    return retval;
out:
    // if (sbi->zeroed_page)
    // {
    // 	FREE(sbi->zeroed_page);
    // 	sbi->zeroed_page = NULL;
    // }

    if (sbi->free_lists) {
        FREE(sbi->free_lists);
        sbi->free_lists = NULL;
    }

    if (sbi->journal_locks) {
        FREE(sbi->journal_locks);
        sbi->journal_locks = NULL;
    }

    if (sbi->inode_maps) {
        FREE(sbi->inode_maps);
        sbi->inode_maps = NULL;
    }

    FREE(sbi);
    return retval;
}


// 1. 初始化一些nova特有的配置+内存空间结构
// 2. 在nvm上创建nova fs
int init_nova_fs(struct super_block *sb, const std::string &dev_name, const std::string &dir_name,
                 struct vfs_cfg *cfg) {
    int rc = 0;
    timing_t init_time;
    NOVA_START_TIMING(init_t, init_time);

    fs_cfg_init(sb->pmap, cfg);

    rd_info("%s: %d cpus online\n", __func__, num_online_cpus());
    // if (arch_has_pcommit())
    // 	support_pcommit = 1;

    // if (arch_has_clwb())
    // 	support_clwb = 1;

    rd_info("Arch should have CLWB!");

    rd_info(
        "Data structure size: inode %lu, log_page %lu, "
        "file_write_entry %lu, dir_entry(max) %d, "
        "setattr_entry %lu, link_change_entry %lu",
        sizeof(struct nova_inode), sizeof(struct nova_inode_log_page),
        sizeof(struct nova_file_write_entry), NOVA_DIR_LOG_REC_LEN(NOVA_NAME_LEN),
        sizeof(struct nova_setattr_logentry), sizeof(struct nova_link_change_entry));

    rc = init_rangenode_cache();
    if (rc) {
        goto out0;
    }

    rc = init_inodecache();
    if (rc) goto out1;

    //
    // rc = register_filesystem(&nova_fs_type);
    // if (rc)
    // 	goto out2;

    rc = nova_fill_super(sb, cfg->format);
    if (rc) {
        r_error("%s fail.\n", "nova_fill_super");
        goto out2;
    }

    NOVA_END_TIMING(init_t, init_time);
    return 0;

out2:
    destroy_inodecache();
out1:
    destroy_rangenode_cache();
out0:
    NOVA_END_TIMING(init_t, init_time);
    return rc;
}

// MODULE_AUTHOR("Andiry Xu <jix024@cs.ucsd.edu>");
// MODULE_DESCRIPTION("NOVA: A Persistent Memory File System");
// MODULE_LICENSE("GPL");

// module_init(init_nova_fs)
// module_exit(exit_nova_fs)
