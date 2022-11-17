#include "nova/vfs.h"

static struct kmem_cache *inode_cachep;

static int no_open(struct inode *inode, struct file *file)
{
	return -ENXIO;
}

/**
 * inode_init_always - perform inode structure initialisation
 * @sb: superblock inode belongs to
 * @inode: inode to initialise
 *
 * These are initializations that need to be done on every inode
 * allocation as the fields are not initialised by slab allocation.
 */
int inode_init_always(struct super_block *sb, struct inode *inode)
{
	static const struct inode_operations empty_iops = {};
	static const struct file_operations no_open_fops = {.open = no_open};
	// struct address_space *const mapping = &inode->i_data;

	inode->i_sb = sb;
	inode->i_blkbits = sb->s_blocksize_bits;
	inode->i_flags = 0;
	// atomic_set(&inode->i_count, 1);
	inode->i_op = &empty_iops;
	inode->i_fop = &no_open_fops;
	inode->__i_nlink = 1;
	inode->i_opflags = 0;
	// if (sb->s_xattr)
	// 	inode->i_opflags |= IOP_XATTR;
	// i_uid_write(inode, 0);
	// i_gid_write(inode, 0);
	// atomic_set(&inode->i_writecount, 0);
	inode->i_size = 0;
	// inode->i_write_hint = WRITE_LIFE_NOT_SET;
	inode->i_blocks = 0;
	inode->i_bytes = 0;
	inode->i_generation = 0;
	// inode->i_pipe = NULL;
	// inode->i_bdev = NULL;
	// inode->i_cdev = NULL;
	// inode->i_link = NULL;
	// inode->i_dir_seq = 0;
	inode->i_rdev = 0;
	inode->dirtied_when = 0;

	// if (security_inode_alloc(inode))
	// 	goto out;
	spin_lock_init(&inode->i_lock);
	// lockdep_set_class(&inode->i_lock, &sb->s_type->i_lock_key);

	// init_rwsem(&inode->i_rwsem);
	// lockdep_set_class(&inode->i_rwsem, &sb->s_type->i_mutex_key);

	atomic_set(&inode->i_dio_count, 0);

	// mapping->a_ops = &empty_aops;
	// mapping->host = inode;
	// mapping->flags = 0;
	// mapping->wb_err = 0;
	// atomic_set(&mapping->i_mmap_writable, 0);
	// mapping_set_gfp_mask(mapping, GFP_HIGHUSER_MOVABLE);
	// mapping->private_data = NULL;
	// mapping->writeback_index = 0;
	inode->i_private = NULL;
	// inode->i_mapping = mapping;
	// INIT_HLIST_HEAD(&inode->i_dentry);	/* buggered by rcu freeing */

	// inode->i_flctx = NULL;
	// this_cpu_inc(nr_inodes);

	return 0;
// out:
// 	return -ENOMEM;
}

static struct inode *alloc_inode(struct super_block *sb)
{
	struct inode *inode;

	if (sb->s_op->alloc_inode)
		inode = sb->s_op->alloc_inode(sb);
	else
		inode = (struct inode *)kmem_cache_alloc(inode_cachep);

	if (!inode)
		return NULL;

	if (unlikely(inode_init_always(sb, inode))) {
		if (inode->i_sb->s_op->destroy_inode)
			inode->i_sb->s_op->destroy_inode(inode);
		else
			kmem_cache_free(inode_cachep, inode);
		return NULL;
	}

	return inode;
}

/**
 *	new_inode_pseudo 	- obtain an inode
 *	@sb: superblock
 *
 *	Allocates a new inode for given superblock.
 *	Inode wont be chained in superblock s_inodes list
 *	This means :
 *	- fs can't be unmount
 *	- quotas, fsnotify, writeback can't work
 */
struct inode *new_inode_pseudo(struct super_block *sb)
{
	struct inode *inode = alloc_inode(sb);

	if (inode) {
		spin_lock(&inode->i_lock);
		inode->i_state = 0;
		spin_unlock(&inode->i_lock);
		// INIT_LIST_HEAD(&inode->i_sb_list);
	}
	return inode;
}

/**
 *	new_inode 	- obtain an inode
 *	@sb: superblock
 *
 *	Allocates a new inode for given superblock. The default gfp_mask
 *	for allocations related to inode->i_mapping is GFP_HIGHUSER_MOVABLE.
 *	If HIGHMEM pages are unsuitable or it is known that pages allocated
 *	for the page cache are not reclaimable or migratable,
 *	mapping_set_gfp_mask() must be called with suitable flags on the
 *	newly created inode's mapping
 *
 */
struct inode *new_inode(struct super_block *sb)
{
	struct inode *inode;

	// spin_lock_prefetch(&sb->s_inode_list_lock);

	inode = new_inode_pseudo(sb);
	// if (inode)
	// 	inode_sb_list_add(inode);
	return inode;
}

/**
 * inode_init_owner - Init uid,gid,mode for new inode according to posix standards
 * @inode: New inode
 * @dir: Directory inode
 * @mode: mode of the new inode
 */
void inode_init_owner(struct inode *inode, const struct inode *dir,
			umode_t mode)
{
	// inode->i_uid = current_fsuid();
	// if (dir && dir->i_mode & S_ISGID) {
	// 	// inode->i_gid = dir->i_gid;

	// 	/* Directories are special, and always inherit S_ISGID */
	// 	if (S_ISDIR(mode))
	// 		mode |= S_ISGID;
	// 	else if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP) &&
	// 		 !in_group_p(inode->i_gid) &&
	// 		 !capable_wrt_inode_uidgid(dir, CAP_FSETID))
	// 		mode &= ~S_ISGID;
	// } else
	// 	inode->i_gid = current_fsgid();
	inode->i_mode = mode;
}

/**
 * clear_nlink - directly zero an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  See
 * drop_nlink() for why we care about i_nlink hitting zero.
 */
void clear_nlink(struct inode *inode)
{
	if (inode->i_nlink) {
		inode->__i_nlink = 0;
		atomic_inc(&inode->i_sb->s_remove_count);
	}
}

/**
 * set_nlink - directly set an inode's link count
 * @inode: inode
 * @nlink: new nlink (should be non-zero)
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.
 */
void set_nlink(struct inode *inode, unsigned int nlink)
{
	if (!nlink) {
		clear_nlink(inode);
	} else {
		/* Yes, some filesystems do change nlink from zero to one */
		if (inode->i_nlink == 0)
			atomic_dec(&inode->i_sb->s_remove_count);

		inode->__i_nlink = nlink;
	}
}

/**
 * inc_nlink - directly increment an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  Currently,
 * it is only here for parity with dec_nlink().
 */
void inc_nlink(struct inode *inode)
{
	if (unlikely(inode->i_nlink == 0)) {
		// WARN_ON(!(inode->i_state & I_LINKABLE));
		atomic_dec(&inode->i_sb->s_remove_count);
	}

	inode->__i_nlink++;
}

/**
 * drop_nlink - directly drop an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  In cases
 * where we are attempting to track writes to the
 * filesystem, a decrement to zero means an imminent
 * write when the file is truncated and actually unlinked
 * on the filesystem.
 */
void drop_nlink(struct inode *inode)
{
	WARN_ON(inode->i_nlink == 0);
	inode->__i_nlink--;
	if (!inode->i_nlink)
		atomic_inc(&inode->i_sb->s_remove_count);
}

/*
 * Called when an inode is about to be open.
 * We use this to disallow opening large files on 32bit systems if
 * the caller didn't specify O_LARGEFILE.  On 64bit systems we force
 * on this flag in sys_open.
 */
int generic_file_open(struct inode * inode, struct file * filp)
{
	// if (!(filp->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
	// 	return -EOVERFLOW;
	return 0;
}

/**
 *	touch_atime	-	update the access time
 *	@path: the &struct path to update
 *	@inode: inode to update
 *
 *	Update the accessed time on an inode and mark it for writeback.
 *	This function automatically handles read only file systems and media,
 *	as well as the "noatime" flag and inode specific "noatime" markers.
 */
// bool atime_needs_update(const struct path *path, struct inode *inode)
// {
// 	struct vfsmount *mnt = path->mnt;
// 	struct timespec now;

// 	if (inode->i_flags & S_NOATIME)
// 		return false;

// 	/* Atime updates will likely cause i_uid and i_gid to be written
// 	 * back improprely if their true value is unknown to the vfs.
// 	 */
// 	if (HAS_UNMAPPED_ID(inode))
// 		return false;

// 	if (IS_NOATIME(inode))
// 		return false;
// 	if ((inode->i_sb->s_flags & SB_NODIRATIME) && S_ISDIR(inode->i_mode))
// 		return false;

// 	if (mnt->mnt_flags & MNT_NOATIME)
// 		return false;
// 	if ((mnt->mnt_flags & MNT_NODIRATIME) && S_ISDIR(inode->i_mode))
// 		return false;

// 	now = current_time(inode);

// 	if (!relatime_need_update(mnt, inode, timespec64_to_timespec(now)))
// 		return false;

// 	if (timespec64_equal(&inode->i_atime, &now))
// 		return false;

// 	return true;
// }

// void touch_atime(const struct path *path)
// {
// 	struct vfsmount *mnt = path->mnt;
// 	struct inode *inode = d_inode(path->dentry);
// 	struct timespec now;

// 	if (!atime_needs_update(path, inode))
// 		return;

// 	if (!sb_start_write_trylock(inode->i_sb))
// 		return;

// 	if (__mnt_want_write(mnt) != 0)
// 		goto skip_update;
// 	/*
// 	 * File systems can error out when updating inodes if they need to
// 	 * allocate new space to modify an inode (such is the case for
// 	 * Btrfs), but since we touch atime while walking down the path we
// 	 * really don't care if we failed to update the atime of the file,
// 	 * so just ignore the return value.
// 	 * We may also fail on filesystems that have the ability to make parts
// 	 * of the fs read only, e.g. subvolumes in Btrfs.
// 	 */
// 	now = current_time(inode);
// 	update_time(inode, &now, S_ATIME);
// 	__mnt_drop_write(mnt);
// skip_update:
// 	sb_end_write(inode->i_sb);
// }
