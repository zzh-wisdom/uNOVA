#include "vfs/vfs.h"

#include <string.h>

#include "util/aep.h"
#include "util/log.h"
#include "util/mem.h"
#include "util/cpu.h"

const struct qstr empty_name = QSTR_INIT("", 0);
const struct qstr slash_name = QSTR_INIT("/", 1);

static struct kmem_cache *dentry_cache;
struct kmem_cache *file_cache;

static force_inline int init_dentry_cache(void) {
    rd_warning("TODO: 优化 kmem_cache");
    dentry_cache = kmem_cache_create(sizeof(struct dentry), sizeof(struct dentry));
    if (dentry_cache == NULL) return -ENOMEM;
    return 0;
}

static force_inline void destroy_dentry_cache(void) {
    rd_warning("TODO: 优化 kmem_cache");
    kmem_cache_destroy(&dentry_cache);
}

static force_inline int init_file_cache(void) {
    file_cache = kmem_cache_create(sizeof(struct file), sizeof(struct file));
    if (file_cache == NULL) return -ENOMEM;
    return 0;
}

static force_inline void destroy_file_cache(void) { kmem_cache_destroy(&file_cache); }

static force_inline file *file_alloc(int fd, int flags, dentry *dentry) {
    file *f = (struct file *)kmem_cache_alloc(file_cache);
    f->f_fd = fd;
    f->f_inode = dentry->d_inode;
    inode_ref(dentry->d_inode);
    f->f_dentry = dentry;
    dentry_ref(dentry);
    f->f_pos = 0;
    if (flags & O_APPEND) {
        f->f_pos = dentry->d_inode->i_size;
    }
    f->f_op = dentry->d_inode->i_fop;
    spin_lock_init(&f->f_lock);
    f->f_flags = flags;
    f->f_mode = OPEN_FMODE(flags);
    return f;
}
static force_inline void file_free(struct file *file) {
    if (file->f_inode) {
        inode_unref(file->f_inode);
    }
    if (file->f_dentry) {
        dentry_unref(file->f_dentry);
    }
    kmem_cache_free(file_cache, file);
}

static int no_open(struct inode *inode, struct file *file) { return -ENXIO; }

const int FG_FRA_BITS = 6;
const int FG_FRAS = 1 << FG_FRA_BITS;
const int FG_FRAS_MASK = FG_FRAS - 1;
rwlock_t global_fd_2_file_rwlock[FG_FRAS];
std::unordered_map<int, file *> global_fd_2_file[FG_FRAS];
atomic_t global_fd_seq = 1000;

void vfs_init(vfs_cfg *cfg) {
    int ret = 0;
    ret = init_dentry_cache();
    assert(!ret);
    ret = init_file_cache();
    assert(!ret);
    for (int i = 0; i < FG_FRAS; ++i) {
        rwlock_init(&global_fd_2_file_rwlock[i]);
    }
    global_fd_seq = cfg->start_fd;
}

// 用户可能未close的一些文件
void vfs_destroy_file() {
    // spin_lock(&global_fd_2_file_lock);
    for (int i = 0; i < FG_FRAS; ++i) {
        auto &map = global_fd_2_file[i];
        for (auto p : map) {
            file *file = p.second;
            r_warning("un close %s", file->f_dentry->d_name.name);
            file_free(p.second);
        }
        map.clear();
    }
    // spin_unlock(&global_fd_2_file_lock);
}
void vfs_destroy() {
    destroy_dentry_cache();
    destroy_file_cache();
}

force_inline static int vfs_get_fd() { return atomic_fetch_add(&global_fd_seq, 1); }

force_inline static bool vfs_file_insert(file *file) {
    dlog_assert(file->f_fd);
    dlog_assert(file->f_inode);
    int ret = false;

    int fra = file->f_fd & FG_FRAS_MASK;
    write_lock(&global_fd_2_file_rwlock[fra]);
    auto it = global_fd_2_file[fra].find(file->f_fd);
    if (it == global_fd_2_file[fra].end()) {
        global_fd_2_file[fra][file->f_fd] = file;
        ret = true;
    }
    write_unlock(&global_fd_2_file_rwlock[fra]);

    return ret;
}

force_inline static file *vfs_file_delete(int fd) {
    file *tmp = nullptr;
    int fra = fd & FG_FRAS_MASK;
    write_lock(&global_fd_2_file_rwlock[fra]);
    auto it = global_fd_2_file[fra].find(fd);
    if (it != global_fd_2_file[fra].end()) {
        tmp = it->second;
        global_fd_2_file[fra].erase(it);
    }
    write_unlock(&global_fd_2_file_rwlock[fra]);
    return tmp;
}

force_inline static file *vfs_file_get(int fd) {
    file *ret = nullptr;
    int fra = fd & FG_FRAS_MASK;
    write_lock(&global_fd_2_file_rwlock[fra]);
    auto it = global_fd_2_file[fra].find(fd);
    if (it != global_fd_2_file[fra].end()) {
        ret = it->second;
    }
    write_unlock(&global_fd_2_file_rwlock[fra]);
    return ret;
}

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
    return s;
}

void destroy_super(struct super_block *sb) {
    rd_info("%s", __func__);
    spin_lock(&sb->s_ino_2_inode_lock);
    for (auto p : sb->s_ino_2_inode) {
        inode_unref(p.second);
    }
    sb->s_ino_2_inode.clear();
    spin_unlock(&sb->s_ino_2_inode_lock);

    d_put_recursive(sb->s_root);
    int ret = dentry_unref(sb->s_root);
    // printf("ret: %d\n", ret);
    dlog_assert(ret == 0);
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
    dlog_assert(inode == nullptr);
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
 * 返回的dentry已经引用, 如果是新建的，会持有锁
 */
struct dentry *d_alloc(struct dentry *parent, const struct qstr *name, bool *is_new) {
    struct dentry *dentry = __d_alloc(parent->d_sb, name);
    log_assert(dentry);
    // if (!dentry) return NULL;
    dentry->d_flags |= DCACHE_RCUACCESS;
    *is_new = true;
    struct dentry* ret = dentry_insert_child(parent, dentry);
    if(ret) {
        dlog_assert(dentry->d_count == 1);
        d_delete(dentry);
        dentry = ret;
        *is_new = false;
    }
    return dentry;
}

// 内存中删除 dentry
void d_put(struct dentry *parent) {
    log_assert(parent->d_parent == nullptr);
    log_assert(parent->d_inode == nullptr);
    log_assert(list_empty(&parent->d_child));
    log_assert(parent->d_subdirs.empty());
    rd_info("%s: %s", __func__, parent->d_name.name);
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

    if (parent->d_inode) {
        int ret = inode_unref(parent->d_inode);
        dlog_assert(ret == 0);
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
            int ret = dentry_unref(cur);
            dlog_assert(ret == 0);
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

void d_print(struct dentry *d, int space) {
    printf("%*s%s", space, "", d->d_name.name);
    if (!is_dir(d)) {
        printf("\n");
        return;
    }
    printf("/\n");
    for (auto p : d->d_subdirs) {
        struct list_head *head = &d->d_subdirs[p.first];
        struct dentry *cur, *tmp;
        list_for_each_entry_safe(cur, tmp, head, d_child) { d_print(cur, space + 2); }
    }
}

int d_show(const char *path, struct dentry *parent) {
    printf("%s", path);
    if (!is_dir(parent)) {
        return 0;
    }
    printf("/\n");
    for (auto p : parent->d_subdirs) {
        struct list_head *head = &parent->d_subdirs[p.first];
        struct dentry *cur, *tmp;
        list_for_each_entry_safe(cur, tmp, head, d_child) { d_print(cur, 2); }
    }
    return 0;
}

static void dentry_unlink_inode(struct dentry *dentry) {
    struct inode *inode = dentry->d_inode;
    if (inode == nullptr) return;
    struct super_block *sb = inode->i_sb;
    // 从sb中删除
    inode_delete_from_sb(sb, inode);

    if (dentry->d_op && dentry->d_op->d_iput) {
        log_assert(0);  // 暂不支持
        dentry->d_op->d_iput(dentry, inode);
    } else {
        dlog_assert(inode->i_nlink == 0);
        dlog_assert(inode->i_state == 1);
        if (inode->i_sb->s_op->drop_inode) {
            int drop = inode->i_sb->s_op->drop_inode(inode);
            dlog_assert(!drop);
        }
        if (inode->i_sb->s_op->evict_inode) {
            inode->i_sb->s_op->evict_inode(inode);  // 真正从介质中删除
        }
    }
    // 内存中删除inode
    inode_unref(inode);  // 如果还有其他open，则不会删除
    dentry->d_inode = nullptr;
}

// 能删除成功，说明肯定没有孩子
void d_delete(struct dentry *dentry) {
    struct inode *inode = dentry->d_inode;
    struct dentry *parent = dentry->d_parent;
    // 父母中删除
    if(parent && parent != dentry) {
        struct dentry *tmp = dentry_delete_child(parent, &dentry->d_name, false);
        dlog_assert(tmp == dentry);
    } else {
        dentry->d_parent = nullptr;
    }

    // spin_lock(&inode->i_lock);
    // we should be the only user,
    dentry_unlink_inode(dentry);
    // spin_unlock(&inode->i_lock);

    // 内存中删除dentry
    int ret = dentry_unref(dentry);
    if (ret != 0) {
        rd_warning("unlink %s ino %d, but still has %d openers.", dentry->d_name.name, inode->i_ino,
                  ret);
    }
}

// 允许
int do_open(dentry *parent, qstr name, struct open_flags *op) {
    int fd = -1;
    int ret;
    struct inode *dir = parent->d_inode;
    file *file;
    inode_lock(dir);

    bool is_create = (op->open_flag & O_CREAT);
    dentry *cur = get_dentry_by_hash(parent, name, is_create, true);
    if(cur) {
        if (cur->d_inode && is_dir(cur)) {
            r_error("%s fail, %s exist and is a dir.", __func__, name.name);
            goto err1;
        }
        if(cur->d_inode) { // 文件已经存在
            goto succ;
        }
    } else { // 不创建文件
        r_error("open fail, %s not exist. open flag: %d", name.name, op->open_flag);
        goto err;
    }

    // 创建文件
    dlog_assert(cur->d_inode == nullptr);
    rd_info("create file:%s hash %d, inode->mode: %d\n", cur->d_name.name, cur->d_name.hash, op->mode);
    // 需要新建文件
    ret = dir->i_op->create(dir, cur, op->mode, op->open_flag & O_EXCL);
    if (ret != 0) {
        r_error("dir->i_op->create %s fail, ret = %d", name.name, ret);
        dentry_unref(cur);
        d_delete(cur);
        goto err;
    }

succ:
    fd = vfs_get_fd();
    file = file_alloc(fd, op->open_flag, cur);
    vfs_file_insert(file);
err1:
    dentry_unref(cur);
err:
    inode_unlock(dir);
    return fd;
}

int do_close(int fd) {
    file *file = vfs_file_delete(fd);
    if (file == nullptr) return -1;
    file_free(file);
    return 0;
}

// 读不加锁，用户自己互斥 读写 和 写写
ssize_t do_read(int fd, char *buf, size_t count) {
    // r_info("%s count: %lu", __func__, count);
    ssize_t ret = -1;
    struct file *file = vfs_file_get(fd);
    if (file == nullptr) {
        rd_error("%s fail, fd %d is illegal.", __func__, fd);
        return -EBADF;
    }
    log_assert(inode_is_valid(file->f_inode));
    loff_t pos = file_pos_read(file);
    rd_info("%s src_buf=%p, count=%lu, pos=%ld", __func__, buf, count, pos);

    if (file->f_op->read)
        ret = file->f_op->read(file, buf, count, &pos);
    else
        ret = EINVAL;
    if (ret >= 0) file_pos_write(file, pos);
    return ret;
}

ssize_t do_write(int fd, const char *buf, size_t count) {
    // r_info("%s count: %lu", __func__, count);
    struct file *file = vfs_file_get(fd);
    if (file == nullptr) {
        rd_error("%s fail, fd %d is illegal.", __func__, fd);
        return -EBADF;
    }
    log_assert(inode_is_valid(file->f_inode));
    loff_t pos = file_pos_read(file);
    if(file->f_flags & O_APPEND) {
        inode_lock(file->f_inode);
        pos = file->f_inode->i_size;
    }
    rd_info("%s src_buf=%p, count=%lu, pos=%ld", __func__, buf, count, pos);
    ssize_t ret = -1;
    if (file->f_op->read)
        ret = file->f_op->write(file, buf, count, &pos);
    else
        ret = EINVAL;
    if (ret >= 0) file_pos_write(file, pos);
    if(file->f_flags & O_APPEND) {
        inode_unlock(file->f_inode);
    }
    return ret;
}

loff_t vfs_setpos(struct file *file, loff_t offset, loff_t maxsize) {
    // if (offset < 0 && !unsigned_offsets(file))
    if (offset < 0) return -EINVAL;
    if (offset > maxsize) return -EINVAL;

    if (offset != file->f_pos) {
        file->f_pos = offset;
        // file->f_version = 0;
    }
    return offset;
}

loff_t generic_file_llseek_size(struct file *file, loff_t offset, int whence, loff_t maxsize,
                                loff_t eof) {
    switch (whence) {
        case SEEK_END:
            // offset += eof;
            offset == eof;
            break;
        case SEEK_CUR:
            /*
             * Here we special-case the lseek(fd, 0, SEEK_CUR)
             * position-querying operation.  Avoid rewriting the "same"
             * f_pos value back to the file because a concurrent read(),
             * write() or lseek() might have altered it
             */
            if (offset == 0) return file->f_pos;
            /*
             * f_lock protects against read/modify/write race with other
             * SEEK_CURs. Note that parallel writes and reads behave
             * like SEEK_SET.
             */
            spin_lock(&file->f_lock);
            offset = vfs_setpos(file, file->f_pos + offset, maxsize);
            spin_unlock(&file->f_lock);
            return offset;
        case SEEK_DATA:
            /*
             * In the generic case the entire file is data, so as long as
             * offset isn't at the end of the file then the offset is data.
             */
            if ((unsigned long long)offset >= eof) return -ENXIO;
            break;
        case SEEK_HOLE:
            /*
             * There is a virtual hole at the end of the file, so as long as
             * offset isn't i_size or larger, return i_size.
             */
            if ((unsigned long long)offset >= eof) return -ENXIO;
            offset = eof;
            break;
    }

    return vfs_setpos(file, offset, maxsize);
}

loff_t generic_file_llseek(struct file *file, loff_t offset, int whence) {
    // struct inode *inode = file->f_mapping->host;
    struct inode *inode = file->f_inode;

    return generic_file_llseek_size(file, offset, whence, inode->i_sb->s_maxbytes,
                                    i_size_read(inode));
}

static loff_t no_llseek(struct file *file, loff_t offset, int whence) { return -ESPIPE; }

off_t do_lseek(int fd, off_t offset, int whence) {
    struct file *file = vfs_file_get(fd);
    if (file == nullptr) {
        rd_error("%s fail, fd %d is illegal.", __func__, fd);
        return -1;
    }
    log_assert(inode_is_valid(file->f_inode));
    loff_t (*fn)(struct file *, loff_t, int);
    fn = no_llseek;
    if (file->f_op->llseek) fn = file->f_op->llseek;
    return fn(file, offset, whence);
}

int do_fsync(int fd) {
    struct file *file = vfs_file_get(fd);
    if (file == nullptr) {
        rd_error("%s fail, fd %d is illegal.", __func__, fd);
        return -1;
    }
    log_assert(inode_is_valid(file->f_inode));
    struct inode* inode = file->f_inode;
    super_block* sb = inode->i_sb;
    if (!file->f_op->fsync)
		return -EINVAL;
    if (sb->s_op->dirty_inode)
	    sb->s_op->dirty_inode(inode, I_DIRTY_INODE | I_DIRTY_TIME);

    return file->f_op->fsync(file, 0, __LONG_MAX__, 0);
}

static force_inline void truncate_setsize(struct inode *inode, loff_t newsize)
{
	loff_t oldsize = inode->i_size;

	i_size_write(inode, newsize);
	// if (newsize > oldsize)
	// 	pagecache_isize_extended(inode, oldsize, newsize);
	// truncate_pagecache(inode, newsize);
}

void setattr_copy(struct inode *inode, const struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid;

	// if (ia_valid & ATTR_UID)
	// 	inode->i_uid = attr->ia_uid;
	// if (ia_valid & ATTR_GID)
	// 	inode->i_gid = attr->ia_gid;
	if (ia_valid & ATTR_ATIME)
		inode->i_atime = attr->ia_atime;
	if (ia_valid & ATTR_MTIME)
		inode->i_mtime = attr->ia_mtime;
	if (ia_valid & ATTR_CTIME)
		inode->i_ctime = attr->ia_ctime;
	if (ia_valid & ATTR_MODE) {
		umode_t mode = attr->ia_mode;
		// if (!in_group_p(inode->i_gid) &&
		//     !capable_wrt_inode_uidgid(inode, CAP_FSETID))
		// 	mode &= ~S_ISGID;
		inode->i_mode = mode;
	}
}

static force_inline int simple_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
    int ret;

	// ret = setattr_prepare(dentry, iattr);
	// if (error)
	// 	return error; // 一些检查

	if (iattr->ia_valid & ATTR_SIZE)
		truncate_setsize(inode, iattr->ia_size);
	setattr_copy(inode, iattr);
	// mark_inode_dirty(inode);
	return 0;
}

static inline void fsnotify_change(struct dentry *dentry, unsigned int ia_valid)
{
	// struct inode *inode = dentry->d_inode;
	// __u32 mask = 0;

	// if (ia_valid & ATTR_UID)
	// 	mask |= FS_ATTRIB;
	// if (ia_valid & ATTR_GID)
	// 	mask |= FS_ATTRIB;
	// if (ia_valid & ATTR_SIZE)
	// 	mask |= FS_MODIFY;

	// /* both times implies a utime(s) call */
	// if ((ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME))
	// 	mask |= FS_ATTRIB;
	// else if (ia_valid & ATTR_ATIME)
	// 	mask |= FS_ACCESS;
	// else if (ia_valid & ATTR_MTIME)
	// 	mask |= FS_MODIFY;

	// if (ia_valid & ATTR_MODE)
	// 	mask |= FS_ATTRIB;

	// if (mask) {
	// 	if (S_ISDIR(inode->i_mode))
	// 		mask |= FS_ISDIR;

	// 	fsnotify_parent(NULL, dentry, mask);
	// 	fsnotify(inode, mask, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
	// }
}

int do_dentry_truncate(dentry* d, off_t length, unsigned int time_attrs, struct file *filp) {
    int ret;
    struct iattr newattrs;
    /* Not pretty: "inode->i_size" shouldn't really be signed. But it is. */
	if (length < 0)
		return -EINVAL;
    newattrs.ia_size = length;
	newattrs.ia_valid = ATTR_SIZE | time_attrs;
	if (filp) {
		newattrs.ia_file = filp;
		newattrs.ia_valid |= ATTR_FILE;
	}
    inode_lock(d->d_inode);
    mutex_lock(&d->d_inode->i_mutex);
    struct timespec now = get_cur_time_spec();
    newattrs.ia_ctime = now;
	if (!(newattrs.ia_valid & ATTR_ATIME_SET))
		newattrs.ia_atime = now;
	if (!(newattrs.ia_valid & ATTR_MTIME_SET))
		newattrs.ia_mtime = now;
	if (newattrs.ia_valid & ATTR_KILL_PRIV) {
		// error = security_inode_need_killpriv(dentry);
		// if (error < 0)
		// 	return error;
		// if (error == 0)
		// 	ia_valid = attr->ia_valid &= ~ATTR_KILL_PRIV;
	}
    if (d->d_inode->i_op->setattr)
		ret = d->d_inode->i_op->setattr(d, &newattrs);
	else
		ret = simple_setattr(d, &newattrs);

    if (!ret) {
		fsnotify_change(d, newattrs.ia_valid);
		// ima_inode_post_setattr(dentry);
		// evm_inode_post_setattr(dentry, ia_valid);
	}
    mutex_unlock(&d->d_inode->i_mutex);
    inode_unlock(d->d_inode);
	return ret;
}

#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)

int do_ftruncate(int fd, off_t length) {
    if (length < 0)
		return -EINVAL;
    struct file *file = vfs_file_get(fd);
    if (file == nullptr) {
        rd_error("%s fail, fd %d is illegal.", __func__, fd);
        return -EBADF;
    }
    log_assert(inode_is_valid(file->f_inode));
    // r_info("%s fd=%d length=%d", __func__, fd, length);
    dentry* den = file->f_dentry;
    if (!S_ISREG(den->d_inode->i_mode)) //  || !(f.file->f_mode & FMODE_WRITE)
		return -EINVAL;
    if (IS_APPEND(den->d_inode))
		return -EPERM;
    return do_dentry_truncate(den, length, ATTR_MTIME|ATTR_CTIME, file);
}
