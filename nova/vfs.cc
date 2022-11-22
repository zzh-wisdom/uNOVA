#include "nova/vfs.h"

#include <string.h>

#include "util/aep.h"
#include "util/log.h"
#include "util/mem.h"

const struct qstr empty_name = QSTR_INIT("", 0);
const struct qstr slash_name = QSTR_INIT("/", 1);

static struct kmem_cache *dentry_cache;

int init_dentry_cache(void) {
    r_warning("TODO: 优化 kmem_cache");
    dentry_cache = kmem_cache_create(sizeof(struct dentry), sizeof(struct dentry));
    if (dentry_cache == NULL) return -ENOMEM;
    return 0;
}

void destroy_dentry_cache(void) {
    r_warning("TODO: 优化 kmem_cache");
    kmem_cache_destroy(dentry_cache);
}

static int no_open(struct inode *inode, struct file *file) { return -ENXIO; }

/**
 *	alloc_super	-	create new superblock
 *	@type:	filesystem type superblock should belong to
 *	@flags: the mount flags
 *	@user_ns: User namespace for the super_block
 *
 *	Allocates and initializes a new &struct super_block.  alloc_super()
 *	returns a pointer new superblock or %NULL if allocation had failed.
 */
struct super_block *alloc_super(const std::string &dev_name, pmem2_map *pmap,
                                const std::string &root_path) {
    struct super_block *s = (struct super_block *)ZALLOC(sizeof(struct super_block));
    if (!s) return nullptr;
    new (s) super_block;

    s->dev_name = dev_name;
    s->pmap = pmap;
    s->root_path = root_path;
    spin_lock_init(&s->s_ino_2_inode_lock);
    spin_lock_init(&s->s_fd_2_inode_lock);
    return s;
}

void destroy_super(struct super_block *sb) {
	rd_info("%s", __func__);
	spin_lock(&sb->s_fd_2_inode_lock);
	for(auto p: sb->s_fd_2_inode) {
		inode_unref(p.second);
	}
	sb->s_fd_2_inode.clear();
	spin_unlock(&sb->s_fd_2_inode_lock);

	spin_lock(&sb->s_ino_2_inode_lock);
	for(auto p: sb->s_ino_2_inode) {
		inode_unref(p.second);
	}
	sb->s_ino_2_inode.clear();
	spin_unlock(&sb->s_ino_2_inode_lock);

	d_put_recursive(sb->s_root);
	int ret = dentry_unref(sb->s_root);
	rdv_proc("%s: ret %d", __func__, ret);
    FREE(sb);
}

int inode_default_init(struct super_block *sb, struct inode *inode) {
    static const struct inode_operations empty_iops = {};
    static const struct file_operations no_open_fops = {.open = no_open};

    memset(inode, 0, sizeof(struct inode));
    inode->i_op = &empty_iops;
    inode->i_sb = sb;
    inode->i_blkbits = sb->s_blocksize_bits;
    atomic_set(&inode->i_count, 1);
    inode->i_fop = &no_open_fops;
    inode->__i_nlink = 1;

    spin_lock_init(&inode->i_lock);
    return 0;
}

// 分配并默认初始化一个无效的inode，引用为1
struct inode *alloc_inode(struct super_block *sb) {
    struct inode *inode;

    dlog_assert(sb->s_op->alloc_inode);
    // 只分配，没有任何的初始化
    inode = sb->s_op->alloc_inode(sb);
    if (!inode) return NULL;

    if (unlikely(inode_default_init(sb, inode))) {
        dlog_assert(sb->s_op->destroy_inode);
        inode->i_sb->s_op->destroy_inode(inode);
        return NULL;
    }

    return inode;
}

void free_inode(struct super_block *sb, struct inode *inode) {
    dlog_assert(sb->s_op->destroy_inode);
    inode->i_sb->s_op->destroy_inode(inode);
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
// struct inode *new_inode(struct super_block *sb)
// {
// 	struct inode *inode;

// 	// spin_lock_prefetch(&sb->s_inode_list_lock);

// 	inode = new_inode_pseudo(sb);
// 	// if (inode)
// 	// 	inode_sb_list_add(inode);
// 	return inode;
// }

/**
 * inode_init_owner - Init uid,gid,mode for new inode according to posix standards
 * @inode: New inode
 * @dir: Directory inode
 * @mode: mode of the new inode
 */
void inode_init_owner(struct inode *inode, const struct inode *dir, umode_t mode) {
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
void clear_nlink(struct inode *inode) {
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
void set_nlink(struct inode *inode, unsigned int nlink) {
    if (!nlink) {
        clear_nlink(inode);
    } else {
        /* Yes, some filesystems do change nlink from zero to one */
        if (inode->i_nlink == 0) atomic_dec(&inode->i_sb->s_remove_count);
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
void inc_nlink(struct inode *inode) {
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
void drop_nlink(struct inode *inode) {
    WARN_ON(inode->i_nlink == 0);
    inode->__i_nlink--;
    if (!inode->i_nlink) atomic_inc(&inode->i_sb->s_remove_count);
}

/*
 * Called when an inode is about to be open.
 * We use this to disallow opening large files on 32bit systems if
 * the caller didn't specify O_LARGEFILE.  On 64bit systems we force
 * on this flag in sys_open.
 */
int generic_file_open(struct inode *inode, struct file *filp) {
    // if (!(filp->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
    // 	return -EOVERFLOW;
    return 0;
}

// 返回的inode如果是无效状态，则表明是新分配的，需要初始化，并设置i_state
// 否则返回已经在cache中的inode，并且没有上锁
// inode不用都要记得unref
struct inode *iget_or_alloc(struct super_block *sb, unsigned long ino) {
    struct inode *inode = nullptr;
    int time = 0;

again:
    inode = inode_get_by_ino(sb, ino);
    if (inode == nullptr) goto alloc;
    spin_lock(&inode->i_lock);
    if (inode->i_state == 1) {
        spin_unlock(&inode->i_lock);
        return inode;
    }
    spin_unlock(&inode->i_lock);
    rd_info("another reader init the same inode, ino: %d, wait_time: %d", inode->i_ino, ++time);
    inode_unref(inode);
    goto again;  // 可能会失败而释放，得重新查找

alloc:
    inode = alloc_inode(sb);
    if (inode == nullptr) {
        r_error("alloc_inode fail\n");
        return nullptr;
    }
    inode->i_ino = ino;
    assert(inode->i_state == 0);

    // 插入map
    bool ret = inode_insert(sb, inode);
    if (ret == false) {
        inode_unref(inode);
        rd_info("after alloc_inode, have the same inode: %d\n", inode->i_ino);
        goto again;
    }
    return inode;
}

void d_set_d_op(struct dentry *dentry, const struct dentry_operations *op) {
    WARN_ON_ONCE(dentry->d_op);
    WARN_ON_ONCE(dentry->d_flags & (DCACHE_OP_HASH | DCACHE_OP_COMPARE | DCACHE_OP_REVALIDATE |
                                    DCACHE_OP_WEAK_REVALIDATE | DCACHE_OP_DELETE | DCACHE_OP_REAL));
    dentry->d_op = op;
    if (!op) return;
    if (op->d_hash) dentry->d_flags |= DCACHE_OP_HASH;
    if (op->d_compare) dentry->d_flags |= DCACHE_OP_COMPARE;
    if (op->d_revalidate) dentry->d_flags |= DCACHE_OP_REVALIDATE;
    if (op->d_weak_revalidate) dentry->d_flags |= DCACHE_OP_WEAK_REVALIDATE;
    if (op->d_delete) dentry->d_flags |= DCACHE_OP_DELETE;
    if (op->d_prune) dentry->d_flags |= DCACHE_OP_PRUNE;
    if (op->d_real) dentry->d_flags |= DCACHE_OP_REAL;
}

/**
 * __d_alloc	-	allocate a dcache entry
 * @sb: filesystem it will belong to
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 * 初始化引用为1
 */
struct dentry *__d_alloc(struct super_block *sb, const struct qstr *name) {
    struct external_name *ext = NULL;
    struct dentry *new_dentry;
    char *dname;
    int err;

    new_dentry = (struct dentry *)kmem_cache_alloc(dentry_cache);
    if (!new_dentry) return NULL;

    /*
     * We guarantee that the inline name is always NUL-terminated.
     * This way the memcpy() done by the name switching in rename
     * will still always have a NUL at the end, even if we might
     * be overwriting an internal NUL character
     */
    new_dentry->d_iname[DNAME_INLINE_LEN - 1] = 0;
    if (unlikely(!name)) {
        name = &slash_name;  // 根目录
        dname = new_dentry->d_iname;
    } else if (name->len > DNAME_INLINE_LEN - 1) {
        size_t size = offsetof(struct external_name, name[1]);

        ext = (struct external_name *)MALLOC(size + name->len);
        if (!ext) {
            kmem_cache_free(dentry_cache, new_dentry);
            return NULL;
        }
        atomic_set(&ext->u.count, 1);
        dname = ext->name;
    } else {
        dname = new_dentry->d_iname;
    }

    new_dentry->d_flags = 0;
    new_dentry->d_op = NULL;
    new_dentry->d_sb = sb;
    new_dentry->d_parent = new_dentry;
    new_dentry->d_inode = NULL;
    d_set_d_op(new_dentry, new_dentry->d_sb->s_d_op);

    new_dentry->d_name.len = name->len;
    new_dentry->d_name.hash = name->hash;
    memcpy(dname, name->name, name->len);
    dname[name->len] = 0;
    new_dentry->d_name.name = dname;

    /* Make sure we always see the terminating NUL character */
    // smp_store_release(&dentry->d_name.name, dname); /* ^^^ */

    new_dentry->d_count = 1;
    spin_lock_init(&new_dentry->d_lock);
    new (&new_dentry->d_subdirs) std::unordered_map<u32, struct list_head>();
    INIT_LIST_HEAD(&new_dentry->d_child);

	rdv_proc("%s: %s", __func__, name->name);

    if (new_dentry->d_op && new_dentry->d_op->d_init) {
        err = new_dentry->d_op->d_init(new_dentry);
        if (err) {
            if (dname_external(new_dentry)) FREE(external_name(new_dentry));
            kmem_cache_free(dentry_cache, new_dentry);
            return NULL;
        }
    }

    // if (unlikely(ext)) {
    // 	pg_data_t *pgdat = page_pgdat(virt_to_page(ext));
    // 	mod_node_page_state(pgdat, NR_INDIRECTLY_RECLAIMABLE_BYTES,
    // 			    ksize(ext));
    // }

    // this_cpu_inc(nr_dentry);

    return new_dentry;
}

/**
 * d_alloc	-	allocate a dcache entry
 * @parent: parent of entry to allocate
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 * 返回的dentry已经引用
 */
struct dentry *d_alloc(struct dentry *parent, const struct qstr *name) {
    struct dentry *dentry = __d_alloc(parent->d_sb, name);
    if (!dentry) return NULL;
    dentry->d_flags |= DCACHE_RCUACCESS;
    dentry_insert_child(parent, dentry);
    return dentry;
}

// 内存中删除 dentry
void d_put(struct dentry *parent) {
	log_assert(parent->d_parent == nullptr);
	log_assert(parent->d_inode == nullptr);
	log_assert(list_empty(&parent->d_child));
	log_assert(parent->d_subdirs.empty());
	rdv_proc("%s: %s", __func__, parent->d_name.name);
    if (dname_external(parent)) {
        FREE(external_name(parent));
    }
	kmem_cache_free(dentry_cache, parent);
}

void d_put_recursive(struct dentry *parent) {
	rdv_proc("%s: %s", __func__, parent->d_name.name);
	if (parent->d_parent && parent->d_parent != parent) {
        dentry_unref(parent->d_parent);
    }
	parent->d_parent = nullptr;

	if(parent->d_inode) {
    	inode_unref(parent->d_inode);
		parent->d_inode = nullptr;
	}

	spin_lock(&parent->d_lock);
    for (auto p : parent->d_subdirs) {
        struct list_head *head = &parent->d_subdirs[p.first];
        struct dentry *cur, *tmp;
		rdv_proc("for %s: %s", __func__, parent->d_name.name);
        list_for_each_entry_safe(cur, tmp, head, d_child) {
			rdv_proc("list_for_each_entry_safe: %s: %s", parent->d_name.name, cur->d_name.name);
            list_del_init(&cur->d_child);
			d_put_recursive(cur);
            dentry_unref(cur);
        }
    }
	parent->d_subdirs.clear();
    spin_unlock(&parent->d_lock);
}

struct dentry *d_alloc_anon(struct super_block *sb) {
    return __d_alloc(sb, NULL);
}

// 为root inode创建dentry，并instantiate
struct dentry *d_make_root(struct inode *root_inode) {
    struct dentry *res = NULL;
    res = d_alloc_anon(root_inode->i_sb);
    if (res) {
        res->d_flags |= DCACHE_RCUACCESS;
        d_instantiate(res, root_inode);
    }
    return res;
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

void d_print(struct dentry* d, int space) {
	printf("%*s%s", space, "", d->d_name.name);
	if(!is_dir(d)) {
		printf("\n");
		return;
	}
	printf("/\n");
	for (auto p : d->d_subdirs) {
        struct list_head *head = &d->d_subdirs[p.first];
        struct dentry *cur, *tmp;
        list_for_each_entry_safe(cur, tmp, head, d_child) {
            d_print(cur, space+2);
        }
    }
}

int d_show(const char* path, struct dentry *parent) {
	printf("%s", path);
	if(!is_dir(parent)) {
		return 0;
	}
	printf("/\n");
	for (auto p : parent->d_subdirs) {
        struct list_head *head = &parent->d_subdirs[p.first];
        struct dentry *cur, *tmp;
        list_for_each_entry_safe(cur, tmp, head, d_child) {
            d_print(cur, 2);
        }
    }
	return 0;
}

void vfs_init() {
    int ret = 0;
    ret = init_dentry_cache();
    assert(!ret);
}

void vfs_destroy() {
    destroy_dentry_cache();
}
