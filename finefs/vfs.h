#ifndef UNOVA_VFS_H_
#define UNOVA_VFS_H_

#include <errno.h>
#include <fcntl.h>
#include <libpmem2.h>
#include <stdlib.h>

#include <string>
#include <unordered_map>
#include <vector>

#include "nova/nova_com.h"
#include "util/atomic.h"
#include "util/list.h"
#include "util/lock.h"
#include "util/log.h"
#include "util/util.h"

/*
 * Attribute flags.  These should be or-ed together to figure out what
 * has been changed!
 */
#define ATTR_MODE (1 << 0)
#define ATTR_UID (1 << 1)
#define ATTR_GID (1 << 2)
#define ATTR_SIZE (1 << 3)
#define ATTR_ATIME (1 << 4)
#define ATTR_MTIME (1 << 5)
#define ATTR_CTIME (1 << 6)
#define ATTR_ATIME_SET (1 << 7)
#define ATTR_MTIME_SET (1 << 8)
#define ATTR_FORCE (1 << 9) /* Not a change, but a change it */
#define ATTR_ATTR_FLAG (1 << 10)
#define ATTR_KILL_SUID (1 << 11)
#define ATTR_KILL_SGID (1 << 12)
#define ATTR_FILE (1 << 13)
#define ATTR_KILL_PRIV (1 << 14)
#define ATTR_OPEN (1 << 15) /* Truncating from open(O_TRUNC) */
#define ATTR_TIMES_SET (1 << 16)

/*
 * Inode flags (FS_IOC_GETFLAGS / FS_IOC_SETFLAGS)
 *
 * Note: for historical reasons, these flags were originally used and
 * defined for use by ext2/ext3, and then other file systems started
 * using these flags so they wouldn't need to write their own version
 * of chattr/lsattr (which was shipped as part of e2fsprogs).  You
 * should think twice before trying to use these flags in new
 * contexts, or trying to assign these flags, since they are used both
 * as the UAPI and the on-disk encoding for ext2/3/4.  Also, we are
 * almost out of 32-bit flags.  :-)
 *
 * We have recently hoisted FS_IOC_FSGETXATTR / FS_IOC_FSSETXATTR from
 * XFS to the generic FS level interface.  This uses a structure that
 * has padding and hence has more room to grow, so it may be more
 * appropriate for many new use cases.
 *
 * Please do not change these flags or interfaces before checking with
 * linux-fsdevel@vger.kernel.org and linux-api@vger.kernel.org.
 */
#define FS_SECRM_FL 0x00000001     /* Secure deletion */
#define FS_UNRM_FL 0x00000002      /* Undelete */
#define FS_COMPR_FL 0x00000004     /* Compress file */
#define FS_SYNC_FL 0x00000008      /* Synchronous updates */
#define FS_IMMUTABLE_FL 0x00000010 /* Immutable file */
#define FS_APPEND_FL 0x00000020    /* writes to file may only append */
#define FS_NODUMP_FL 0x00000040    /* do not dump file */
#define FS_NOATIME_FL 0x00000080   /* do not update atime */
/* Reserved for compression usage... */
#define FS_DIRTY_FL 0x00000100
#define FS_COMPRBLK_FL 0x00000200 /* One or more compressed clusters */
#define FS_NOCOMP_FL 0x00000400   /* Don't compress */
/* End compression flags --- maybe not all used */
#define FS_ENCRYPT_FL 0x00000800      /* Encrypted file */
#define FS_BTREE_FL 0x00001000        /* btree format dir */
#define FS_INDEX_FL 0x00001000        /* hash-indexed directory */
#define FS_IMAGIC_FL 0x00002000       /* AFS directory */
#define FS_JOURNAL_DATA_FL 0x00004000 /* Reserved for ext3 */
#define FS_NOTAIL_FL 0x00008000       /* file tail should not be merged */
#define FS_DIRSYNC_FL 0x00010000      /* dirsync behaviour (directories only) */
#define FS_TOPDIR_FL 0x00020000       /* Top of directory hierarchies*/
#define FS_HUGE_FILE_FL 0x00040000    /* Reserved for ext4 */
#define FS_EXTENT_FL 0x00080000       /* Extents */
#define FS_VERITY_FL 0x00100000       /* Verity protected inode */
#define FS_EA_INODE_FL 0x00200000     /* Inode used for large EA */
#define FS_EOFBLOCKS_FL 0x00400000    /* Reserved for ext4 */
#define FS_NOCOW_FL 0x00800000        /* Do not cow file */
#define FS_INLINE_DATA_FL 0x10000000  /* Reserved for ext4 */
#define FS_PROJINHERIT_FL 0x20000000  /* Create with parents projid */
#define FS_CASEFOLD_FL 0x40000000     /* Folder is case insensitive */
#define FS_RESERVED_FL 0x80000000     /* reserved for ext2 lib */

/*
 * Inode flags - they have no relation to superblock flags now
 */
#define S_SYNC 1         /* Writes are synced at once */
#define S_NOATIME 2      /* Do not update access times */
#define S_APPEND 4       /* Append-only file */
#define S_IMMUTABLE 8    /* Immutable file */
#define S_DEAD 16        /* removed, but still open directory */
#define S_NOQUOTA 32     /* Inode is not counted to quota */
#define S_DIRSYNC 64     /* Directory modifications are synchronous */
#define S_NOCMTIME 128   /* Do not update file c/mtime */
#define S_SWAPFILE 256   /* Do not truncate: swapon got its bmaps */
#define S_PRIVATE 512    /* Inode is fs-internal */
#define S_IMA 1024       /* Inode has an associated IMA struct */
#define S_AUTOMOUNT 2048 /* Automount/referral quasi-directory */
#define S_NOSEC 4096     /* no suid or xattr security attributes */
#ifdef CONFIG_FS_DAX
#define S_DAX 8192 /* Direct Access, avoiding the page cache */
#else
#define S_DAX 0 /* Make all the DAX code disappear */
#endif
#define S_ENCRYPTED 16384 /* Encrypted file (using fs/crypto/) */

// #define S_IFMT 00170000
// #define S_IFSOCK 0140000
// #define S_IFLNK 0120000
// #define S_IFREG 0100000
// #define S_IFBLK 0060000
// #define S_IFDIR 0040000
// #define S_IFCHR 0020000
// #define S_IFIFO 0010000
// #define S_ISUID 0004000
// #define S_ISGID 0002000
// #define S_ISVTX 0001000

// #define S_IRWXU 00700
// #define S_IRUSR 00400
// #define S_IWUSR 00200
// #define S_IXUSR 00100

// #define S_IRWXG 00070
// #define S_IRGRP 00040
// #define S_IWGRP 00020
// #define S_IXGRP 00010

// #define S_IRWXO 00007
// #define S_IROTH 00004
// #define S_IWOTH 00002
// #define S_IXOTH 00001

#define pgoff_t unsigned long
typedef unsigned __bitwise fmode_t;

#define __O_SYNC	04000000

#define VALID_OPEN_FLAGS \
	(O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | \
	 O_APPEND | O_NDELAY | O_NONBLOCK | O_NDELAY | __O_SYNC | O_DSYNC | \
	 FASYNC	| O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | \
	 O_NOATIME | O_CLOEXEC | O_PATH | __O_TMPFILE)

#define S_IRWXUGO	(S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
#define S_IRUGO		(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO		(S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO		(S_IXUSR|S_IXGRP|S_IXOTH)

#define MAY_EXEC		0x00000001
#define MAY_WRITE		0x00000002
#define MAY_READ		0x00000004
#define MAY_APPEND		0x00000008
#define MAY_ACCESS		0x00000010
#define MAY_OPEN		0x00000020
#define MAY_CHDIR		0x00000040
/* called from RCU mode, don't block */
#define MAY_NOT_BLOCK		0x00000080

#define FMODE_NONOTIFY		(0x4000000)
#define O_TMPFILE_MASK (__O_TMPFILE | O_DIRECTORY | O_CREAT)

#define LOOKUP_FOLLOW		0x0001
#define LOOKUP_DIRECTORY	0x0002
#define LOOKUP_AUTOMOUNT	0x0004

#define LOOKUP_PARENT		0x0010
#define LOOKUP_REVAL		0x0020
#define LOOKUP_RCU		0x0040
#define LOOKUP_NO_REVAL		0x0080
/*
 * Intent data
 */
#define LOOKUP_OPEN		0x0100
#define LOOKUP_CREATE		0x0200
#define LOOKUP_EXCL		0x0400
#define LOOKUP_RENAME_TARGET	0x0800

#define __FMODE_NONOTIFY	((int) FMODE_NONOTIFY)

#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define OPEN_FMODE(flag) ((fmode_t)(((flag + 1) & O_ACCMODE) | \
					    (flag & __FMODE_NONOTIFY)))

#define I_DIRTY_SYNC		(1 << 0)
#define I_DIRTY_DATASYNC	(1 << 1)
#define I_DIRTY_PAGES		(1 << 2)
#define __I_NEW			3
#define I_NEW			(1 << __I_NEW)
#define I_WILL_FREE		(1 << 4)
#define I_FREEING		(1 << 5)
#define I_CLEAR			(1 << 6)
#define __I_SYNC		7
#define I_SYNC			(1 << __I_SYNC)
#define I_REFERENCED		(1 << 8)
#define __I_DIO_WAKEUP		9
#define I_DIO_WAKEUP		(1 << __I_DIO_WAKEUP)
#define I_LINKABLE		(1 << 10)
#define I_DIRTY_TIME		(1 << 11)
#define __I_DIRTY_TIME_EXPIRED	12
#define I_DIRTY_TIME_EXPIRED	(1 << __I_DIRTY_TIME_EXPIRED)
#define I_WB_SWITCH		(1 << 13)
#define I_OVL_INUSE		(1 << 14)
#define I_CREATING		(1 << 15)

#define I_DIRTY_INODE (I_DIRTY_SYNC | I_DIRTY_DATASYNC)
#define I_DIRTY (I_DIRTY_INODE | I_DIRTY_PAGES)
#define I_DIRTY_ALL (I_DIRTY | I_DIRTY_TIME)

// 假的cache，直接使用glic分配
struct kmem_cache {
    int slab_size;
    int align;
};

static force_inline struct kmem_cache *kmem_cache_create(int slab_size, int align) {
    struct kmem_cache *cache = (struct kmem_cache *)MALLOC(sizeof(struct kmem_cache));
    if (cache == nullptr) return nullptr;
    cache->slab_size = slab_size;
    cache->align = align;
    return cache;
}

inline void kmem_cache_destroy(struct kmem_cache *cache) { FREE(cache); }

inline void *kmem_cache_alloc(struct kmem_cache *cache) { return MALLOC(cache->slab_size); }

inline void kmem_cache_free(struct kmem_cache *cache, void *node) { FREE(node); }

struct super_block;
struct file_operations;
struct dentry;
struct inode_operations;
struct inode;

static force_inline int inode_ref(struct inode *inode);
static force_inline int inode_unref(struct inode *inode);

struct inode *alloc_inode(struct super_block *sb);
void free_inode(struct super_block *sb, struct inode *inode);

struct super_operations {
    struct inode *(*alloc_inode)(struct super_block *sb);
    void (*destroy_inode)(struct inode *);

    void (*dirty_inode) (struct inode *, int flags);
    // int (*write_inode) (struct inode *, struct writeback_control *wbc);
    int (*drop_inode) (struct inode *);
    void (*evict_inode) (struct inode *);
    void (*put_super)(struct super_block *);
    // int (*sync_fs)(struct super_block *sb, int wait);
    // int (*freeze_super) (struct super_block *);
    // int (*freeze_fs) (struct super_block *);
    // int (*thaw_super) (struct super_block *);
    // int (*unfreeze_fs) (struct super_block *);
    // int (*statfs) (struct dentry *, struct kstatfs *);
    // int (*remount_fs) (struct super_block *, int *, char *);
    // void (*umount_begin) (struct super_block *);

    // int (*show_options)(struct seq_file *, struct dentry *);
    // int (*show_devname)(struct seq_file *, struct dentry *);
    // int (*show_path)(struct seq_file *, struct dentry *);
    // int (*show_stats)(struct seq_file *, struct dentry *);
    // int (*bdev_try_to_free_page)(struct super_block*, struct page*, gfp_t);
    // long (*nr_cached_objects)(struct super_block *,
    // 			  struct shrink_control *);
    // long (*free_cached_objects)(struct super_block *,
    // 			    struct shrink_control *);
};

/* These sb flags are internal to the kernel */
#define MS_SUBMOUNT (1 << 26)
#define MS_NOREMOTELOCK (1 << 27)
#define MS_NOSEC (1 << 28)
#define MS_BORN (1 << 29)
#define MS_ACTIVE (1 << 30)
#define MS_NOUSER (1 << 31)

// 内部没有任何的安全性并发保证，用户自己管理
struct super_block {
    // NVM设备名字，自添加
    std::string dev_name;
    pmem2_map *pmap = nullptr;  // 负责释放
    std::string root_path;
    // 自定义
    // 简单的保护，不测试元数据的高并发情况，影响不大
    // 读写锁，保护inode释放读。访问：加读锁，inode引用加一，解读锁
    spinlock_t s_ino_2_inode_lock;
    std::unordered_map<unsigned long, inode *> s_ino_2_inode;
    struct dentry *s_root;  // 需要释放

    unsigned char s_blocksize_bits;
    unsigned long s_blocksize;  // 空间管理的数据块大小
    loff_t s_maxbytes;          /* Max file size */
    const struct super_operations *s_op = nullptr;
    unsigned long s_flags;
    unsigned long s_magic;
    void *s_fs_info;                        /* Filesystem private info */
    const struct dentry_operations *s_d_op; /* default d_op for dentries */
    /* Number of inodes with nlink == 0 but still referenced */
    atomic_t s_remove_count;
    // ~super_block() {
    //     printf("destroy %s\n", root_path.c_str());
    // }
};

struct vfsmount {
    struct dentry *mnt_root;    /* root of the mounted tree */
    struct super_block *mnt_sb; /* pointer to superblock */
    int mnt_flags;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct address_space {
    struct inode *host; /* owner: inode, block_device */
                        // struct radix_tree_root	i_pages;	/* cached pages */
                        // atomic_t		i_mmap_writable;/* count VM_SHARED mappings */
                        // struct rb_root_cached	i_mmap;		/* tree of private and shared mappings */
                        // struct rw_semaphore	i_mmap_rwsem;	/* protect tree, count, list */
                        // /* Protected by the i_pages lock */
                        // unsigned long		nrpages;	/* number of total pages */
                        // /* number of shadow or DAX exceptional entries */
                        // unsigned long		nrexceptional;
                        // pgoff_t			writeback_index;/* writeback starts here */
                        // const struct address_space_operations *a_ops;	/* methods */
                        // unsigned long		flags;		/* error bits */
                        // spinlock_t		private_lock;	/* for use by the address_space */
                        // gfp_t			gfp_mask;	/* implicit gfp mask for allocations */
                        // struct list_head	private_list;	/* for use by the address_space */
                        // void			*private_data;	/* ditto */
                        // errseq_t		wb_err;
};

struct file {

    int f_fd;

    // union {
    // 	struct llist_node	fu_llist;
    // 	struct rcu_head 	fu_rcuhead;
    // } f_u;
    // struct path f_path;
    struct dentry *f_dentry;
    struct inode *f_inode; /* cached value */
    const struct file_operations *f_op;

    /*
     * Protects f_ep_links, f_flags.
     * Must not be taken from IRQ context.
     */
    spinlock_t f_lock;
    // enum rw_hint		f_write_hint;
    // atomic_long_t		f_count;
    unsigned int f_flags;
    fmode_t			f_mode;
    // struct mutex		f_pos_lock;
    loff_t			f_pos;
    // struct fown_struct	f_owner;
    // const struct cred	*f_cred;
    // struct file_ra_state	f_ra;

    // u64 f_version;

    /* needed for tty driver, and maybe others */
    // void *private_data;

    // struct address_space *f_mapping;
    // errseq_t		f_wb_err;
};

static force_inline loff_t file_pos_read(struct file *file)
{
	return file->f_pos;
}

static force_inline void file_pos_write(struct file *file, loff_t pos)
{
	file->f_pos = pos;
}

/* legacy typedef, should eventually be removed */
typedef void *fl_owner_t;

struct file_operations {
    struct module *owner;
    loff_t (*llseek)(struct file *, loff_t, int);
    ssize_t (*read)(struct file *, char *user, size_t, loff_t *);
    ssize_t (*write)(struct file *, const char *user, size_t, loff_t *);
    // ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
    // ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
    // int (*iterate) (struct file *, struct dir_context *);
    // int (*iterate_shared) (struct file *, struct dir_context *);
    // __poll_t (*poll) (struct file *, struct poll_table_struct *);
    // long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    // long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
    // int (*mmap) (struct file *, struct vm_area_struct *);
    // unsigned long mmap_supported_flags;
    int (*open)(struct inode *, struct file *);
    int (*flush)(struct file *, fl_owner_t id);
    // int (*release) (struct inode *, struct file *);
    int (*fsync)(struct file *, loff_t, loff_t, int datasync);
    // int (*fasync) (int, struct file *, int);
    int (*lock)(struct file *, int, struct file_lock *);
    // ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
    // unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned
    // long, unsigned long); int (*check_flags)(int); int (*flock) (struct file *, int, struct
    // file_lock *); ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *,
    // size_t, unsigned int); ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info
    // *, size_t, unsigned int); int (*setlease)(struct file *, long, struct file_lock **, void **);
    // long (*fallocate)(struct file *file, int mode, loff_t offset,
    // 		  loff_t len);
    // void (*show_fdinfo)(struct seq_file *m, struct file *f);

    // ssize_t (*copy_file_range)(struct file *, loff_t, struct file *,
    // 		loff_t, size_t, unsigned int);
    // int (*clone_file_range)(struct file *, loff_t, struct file *, loff_t,
    // 		u64);
    // int (*dedupe_file_range)(struct file *, loff_t, struct file *, loff_t,
    // 		u64);
    // int (*fadvise)(struct file *, loff_t, loff_t, int);
};

/*
 * Keep mostly read-only and often accessed (especially for
 * the RCU path lookup and 'stat' data) fields at the beginning
 * of the 'struct inode'
 *
 * 注意对应修改 inode_init_always 函数
 * vfs的实现中，一个inode可以有多个dentry对应，比较复杂
 * 这里简化时间，内存全cache，inode和dentry一一对应。
 */
struct inode {
    umode_t i_mode;
    unsigned int i_flags;

    const struct inode_operations *i_op;
    const struct file_operations *i_fop; /* former ->i_op->default_file_ops */
    struct dentry *i_dentry;             // 不需要ref，和inode和dentry是一一对应的关系

    struct super_block *i_sb;
    /* Stat data, not accessed from path walking */
    unsigned long i_ino;  // ino号，nova内部产生的

    u32 i_generation;
    // 保护下面两个初始化状态
    spinlock_t i_lock; /* i_state  */
    // unsigned short i_bytes;
    unsigned int i_blkbits;
    // 简化处理，为0说明无效，有线程正在初始化，为1则已经初始化成功
    unsigned long i_state;  // Inode的状态。为正常是，说明上述的字段都已经初始化好

    mutex_t i_mutex;  // 对文件操作需要上锁。简单的读写互斥，保护下面字段

    loff_t i_size;  // 文件大小, 初始化是0
    struct timespec i_atime;
    struct timespec i_mtime;
    struct timespec i_ctime;
    blkcnt_t i_blocks;
    /*
     * Filesystems may only read i_nlink directly.  They shall use the
     * following functions for modification:
     *
     *    (set|clear|inc|drop)_nlink
     *    inode_(inc|dec)_link_count
     */
    union {  // link个数，对于文件目录树而言
        const unsigned int i_nlink;
        unsigned int __i_nlink;
    };

    // 配合map锁管理内存安全
    atomic_t i_count;  // 引用计数
};

/************************super block*************************/
force_inline static struct inode *inode_get_by_ino(struct super_block *sb, unsigned long ino) {
    inode *ret = nullptr;
    spin_lock(&sb->s_ino_2_inode_lock);
    auto it = sb->s_ino_2_inode.find(ino);
    if (it != sb->s_ino_2_inode.end()) {
        ret = it->second;
        inode_ref(ret);
    }
    spin_unlock(&sb->s_ino_2_inode_lock);
    return ret;
}

force_inline static void inode_delete(struct super_block *sb, struct inode *inode) {
    spin_lock(&sb->s_ino_2_inode_lock);
    auto num = sb->s_ino_2_inode.erase(inode->i_ino);
    assert(num == 1);
    spin_unlock(&sb->s_ino_2_inode_lock);
    inode_unref(inode);
}

struct super_block *alloc_super(const std::string &dev_name, pmem2_map *pmap,
                                const std::string &root_path);
void destroy_super(struct super_block *sb);

force_inline static bool inode_insert(struct super_block *sb, struct inode *inode) {
    bool ret = false;

    spin_lock(&sb->s_ino_2_inode_lock);
    auto it = sb->s_ino_2_inode.find(inode->i_ino);
    if (it == sb->s_ino_2_inode.end()) {
        ret = true;
        inode_ref(inode);
        sb->s_ino_2_inode[inode->i_ino] = inode;
    }
    spin_unlock(&sb->s_ino_2_inode_lock);

    return ret;
}

force_inline static void inode_delete_from_sb(struct super_block *sb, struct inode *inode) {
    int ret = 0;
    spin_lock(&sb->s_ino_2_inode_lock);
    ret = sb->s_ino_2_inode.erase(inode->i_ino);
    dlog_assert(ret == 1);
    spin_unlock(&sb->s_ino_2_inode_lock);
    inode_unref(inode);
}

/************************inode*************************/
static force_inline void inode_lock(struct inode *inode) {
    spin_lock(&inode->i_lock);
}
static force_inline void inode_unlock(struct inode *inode) {
    spin_unlock(&inode->i_lock);
}
static force_inline void inode_set_valid(struct inode *inode) {
    spin_lock(&inode->i_lock);
    inode->i_state = 1;
    spin_unlock(&inode->i_lock);
}

// 返回修改后的引用计数
static force_inline int inode_ref(struct inode *inode) {
    return atomic_add_fetch(&inode->i_count, 1);
}

// 返回修改后的引用计数
static force_inline int inode_unref(struct inode *inode) {
    int ret = atomic_add_fetch(&inode->i_count, -1);
    assert(ret >= 0);
    if (ret == 0) {
        free_inode(inode->i_sb, inode);
    }
    return ret;
}

// #define HASH_LEN_DECLARE u32 hash; u32 len
/*
 * "quick string" -- eases parameter passing, but more importantly
 * saves "metadata" about the string (ie length and the hash).
 *
 * hash comes first so it snuggles against d_parent in the
 * dentry.
 */
struct qstr {
    // union {
    //     struct {
    //         // HASH_LEN_DECLARE;
    //         u32 hash;
    //         u32 len;
    //     };
    //     u64 hash_len;
    // };
    u32 hash;
    u32 len;
    const char *name;
};

#define QSTR_INIT(n, l) \
    { .len = l, .name = n }

#define DNAME_INLINE_LEN 40

struct external_name {
    union {
        atomic_t count;
        // struct rcu_head head;
    } u;
    char name[];
};

/* d_flags entries */
#define DCACHE_OP_HASH 0x00000001
#define DCACHE_OP_COMPARE 0x00000002
#define DCACHE_OP_REVALIDATE 0x00000004
#define DCACHE_OP_DELETE 0x00000008
#define DCACHE_OP_PRUNE 0x00000010

#define DCACHE_DISCONNECTED 0x00000020
/* This dentry is possibly not currently connected to the dcache tree, in
 * which case its parent will either be itself, or will have this flag as
 * well.  nfsd will not use a dentry with this bit set, but will first
 * endeavour to clear the bit either by discovering that it is connected,
 * or by performing lookup operations.   Any filesystem which supports
 * nfsd_operations MUST have a lookup function which, if it finds a
 * directory inode with a DCACHE_DISCONNECTED dentry, will d_move that
 * dentry into place and return that dentry rather than the passed one,
 * typically using d_splice_alias. */

#define DCACHE_REFERENCED 0x00000040 /* Recently used, don't discard. */
#define DCACHE_RCUACCESS 0x00000080  /* Entry has ever been RCU-visible */

#define DCACHE_CANT_MOUNT 0x00000100
#define DCACHE_GENOCIDE 0x00000200
#define DCACHE_SHRINK_LIST 0x00000400

#define DCACHE_OP_WEAK_REVALIDATE 0x00000800

#define DCACHE_NFSFS_RENAMED 0x00001000
/* this dentry has been "silly renamed" and has to be deleted on the last
 * dput() */
#define DCACHE_COOKIE 0x00002000 /* For use by dcookie subsystem */
#define DCACHE_FSNOTIFY_PARENT_WATCHED 0x00004000
/* Parent inode is watched by some fsnotify listener */

#define DCACHE_DENTRY_KILLED 0x00008000

#define DCACHE_MOUNTED 0x00010000        /* is a mountpoint */
#define DCACHE_NEED_AUTOMOUNT 0x00020000 /* handle automount on this dir */
#define DCACHE_MANAGE_TRANSIT 0x00040000 /* manage transit from this dirent */
#define DCACHE_MANAGED_DENTRY (DCACHE_MOUNTED | DCACHE_NEED_AUTOMOUNT | DCACHE_MANAGE_TRANSIT)

#define DCACHE_LRU_LIST 0x00080000

#define DCACHE_ENTRY_TYPE 0x00700000
#define DCACHE_MISS_TYPE 0x00000000      /* Negative dentry (maybe fallthru to nowhere) */
#define DCACHE_WHITEOUT_TYPE 0x00100000  /* Whiteout dentry (stop pathwalk) */
#define DCACHE_DIRECTORY_TYPE 0x00200000 /* Normal directory */
#define DCACHE_AUTODIR_TYPE 0x00300000   /* Lookupless directory (presumed automount) */
#define DCACHE_REGULAR_TYPE 0x00400000   /* Regular file type (or fallthru to such) */
#define DCACHE_SPECIAL_TYPE 0x00500000   /* Other file type (or fallthru to such) */
#define DCACHE_SYMLINK_TYPE 0x00600000   /* Symlink (or fallthru to such) */

#define DCACHE_MAY_FREE 0x00800000
#define DCACHE_FALLTHRU 0x01000000           /* Fall through to lower layer */
#define DCACHE_ENCRYPTED_WITH_KEY 0x02000000 /* dir is encrypted with a valid key */
#define DCACHE_OP_REAL 0x04000000

#define DCACHE_PAR_LOOKUP 0x10000000 /* being looked up (with parent locked shared) */
#define DCACHE_DENTRY_CURSOR 0x20000000

struct dentry_operations {
    int (*d_revalidate)(struct dentry *, unsigned int);
    int (*d_weak_revalidate)(struct dentry *, unsigned int);
    int (*d_hash)(const struct dentry *, struct qstr *);
    int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *);
    int (*d_delete)(const struct dentry *);
    int (*d_init)(struct dentry *);  // 初始化dentry
    void (*d_release)(struct dentry *);
    void (*d_prune)(struct dentry *);
    void (*d_iput)(struct dentry *, struct inode *);
    char *(*d_dname)(struct dentry *, char *, int);
    // struct vfsmount *(*d_automount)(struct path *);
    int (*d_manage)(const struct path *, bool);
    struct dentry *(*d_real)(struct dentry *, const struct inode *);
};

// https://www.cnblogs.com/linhaostudy/p/7428971.html
// 可以代表一个目录或者文件
// 这里的结构比较简单，因为采用前cache，所以不需要lru，dentry形成一棵目录树
struct dentry {
    unsigned int d_flags; /* protected by d_lock */
    const struct dentry_operations *d_op;
    struct super_block *d_sb; /* The root of the dentry tree */

    // 初始化为自己
    struct dentry *d_parent; /* parent directory */
    // 不要时，记得取消引用
    struct inode *d_inode;          /* Where the name belongs to - NULL is
                                     * negative */
    struct qstr d_name;             // 指向d_iname或者额外分配的空间
    char d_iname[DNAME_INLINE_LEN]; /* small names */

    /* Ref lookup also touches following */
    atomic_t d_count; /* protected by d_lock 单纯用于内存安全性, 每次访问都要加引用计数*/

    spinlock_t d_lock; /* per dentry lock 整体互斥锁，读写都要加*/

    struct list_head d_child; /* child of parent list */
    // struct list_head d_subdirs;	/* our children */
    // 自添加
    // 冲突概率应该不大，简单用vector也足够了
    // 需要对于.和..进行特殊判断，这两个没有存储在d_child中
    // std::unordered_map<u32, std::vector<struct dentry *>> d_subdirs;
    std::unordered_map<u32, struct list_head> d_subdirs;
};

struct dentry *__d_alloc(struct super_block *sb, const struct qstr *name);
struct dentry *d_alloc(struct dentry *parent, const struct qstr *name);
void d_put(struct dentry *parent);
void d_put_recursive(struct dentry *parent);
int d_show(const char* path, struct dentry *parent);
struct dentry *d_make_root(struct inode *root_inode);
static force_inline bool is_dir(struct dentry *parent) {
    if(S_ISDIR(parent->d_inode->i_mode)) {
        return true;
    }
    if(S_ISREG(parent->d_inode->i_mode)) {
        return false;
    }
    log_assert(0);
}

static inline int dname_external(const struct dentry *dentry) {
    return dentry->d_name.name != dentry->d_iname;
}

static inline struct external_name *external_name(struct dentry *dentry) {
    return container_of(dentry->d_name.name, struct external_name, name[0]);
}

// 返回修改后的引用计数
static force_inline int dentry_ref(struct dentry *dentry) {
    // printf("%s count: %d, name: %s\n", __func__, dentry->d_count + 1, dentry->d_name.name);
    return atomic_add_fetch(&dentry->d_count, 1);
}

// 返回修改后的引用计数
static force_inline int dentry_unref(struct dentry *dentry) {
    int ret = atomic_add_fetch(&dentry->d_count, -1);
    assert(ret >= 0);
    if (ret == 0) {
        d_put(dentry);
    }
    return ret;
}

static force_inline dentry *dentry_get_child(dentry *parent, qstr qs, bool lock) {
    dentry *ret = nullptr;
    struct list_head *head;
    struct dentry *cur;
    if(lock) spin_lock(&parent->d_lock);
    auto it = parent->d_subdirs.find(qs.hash);
    if (it == parent->d_subdirs.end()) goto out;
    head = &parent->d_subdirs[qs.hash];
    list_for_each_entry(cur, head, d_child) {
        if (cur->d_name.len == qs.len && strncmp(cur->d_name.name, qs.name, qs.len) == 0) {
            ret = cur;
            dentry_ref(ret);
            break;
        }
    }
out:
    if(lock) spin_unlock(&parent->d_lock);
    return ret;
}

static force_inline dentry *dentry_get_root(struct super_block *sb) {
    dentry_ref(sb->s_root);
    return sb->s_root;
}

static force_inline void dentry_insert_child(dentry *parent, dentry *child) {
    spin_lock(&parent->d_lock);
    /*
     * don't need child lock because it is not subject
     * to concurrency here
     */
    // __dget_dlock(parent);
    dentry_ref(parent);
    dentry_ref(child);
    child->d_parent = parent;
    struct qstr *name = &child->d_name;
    auto it = parent->d_subdirs.find(name->hash);
    struct list_head *head = nullptr;
    if (it != parent->d_subdirs.end()) {
        struct dentry *tmp = nullptr;
        head = &parent->d_subdirs[name->hash];
        list_for_each_entry(tmp, head, d_child) {
            log_assert(tmp->d_name.len != name->len ||
                       strncmp(tmp->d_name.name, name->name, name->len) != 0);
        }
    } else {
        head = &parent->d_subdirs[name->hash];
        INIT_LIST_HEAD(head);
    }
    list_add(&child->d_child, head);
    spin_unlock(&parent->d_lock);
}

// 并取消对父母的引用
static force_inline dentry *dentry_delete_child(dentry *parent, struct qstr *qs, bool lock) {
    struct dentry *ret = nullptr;
    struct dentry *tmp;
    struct list_head *head = nullptr;
    if(lock) spin_lock(&parent->d_lock);
    auto it = parent->d_subdirs.find(qs->hash);
    if (it == parent->d_subdirs.end()) goto out;
    head = &parent->d_subdirs[qs->hash];
    list_for_each_entry(tmp, head, d_child) {
        if (tmp->d_name.len == qs->len && strncmp(tmp->d_name.name, qs->name, qs->len) == 0) {
            ret = tmp;
            break;
        }
    }
    if (ret == nullptr) goto out;
    list_del_init(&ret->d_child);
    if (list_empty(head)) {
        parent->d_subdirs.erase(it);
    }
    ret->d_parent = nullptr;
    dentry_unref(parent);
out:
    if(lock) spin_unlock(&parent->d_lock);
    return ret;
}

// 删除指定inode，父母dentry已经上锁
void d_delete(struct dentry * dentry);

/*
 * This is the Inode Attributes structure, used for notify_change().  It
 * uses the above definitions as flags, to know which values have changed.
 * Also, in this manner, a Filesystem can look at only the values it cares
 * about.  Basically, these are the attributes that the VFS layer can
 * request to change from the FS layer.
 *
 * Derek Atkins <warlord@MIT.EDU> 94-10-20
 */
struct iattr {
    unsigned int ia_valid;
    umode_t ia_mode;
    kuid_t ia_uid;
    kgid_t ia_gid;
    loff_t ia_size;
    struct timespec ia_atime;
    struct timespec ia_mtime;
    struct timespec ia_ctime;

    /*
     * Not an attribute, but an auxiliary info for filesystems wanting to
     * implement an ftruncate() like method.  NOTE: filesystem should
     * check for (ia_valid & ATTR_FILE), and not for (ia_file != NULL).
     */
    struct file *ia_file;
};

struct kstat {
	u32		result_mask;	/* What fields the user got */
	umode_t		mode;
	unsigned int	nlink;
	uint32_t	blksize;	/* Preferred I/O size */
	u64		attributes;
	u64		attributes_mask;
#define KSTAT_ATTR_FS_IOC_FLAGS				\
	(STATX_ATTR_COMPRESSED |			\
	 STATX_ATTR_IMMUTABLE |				\
	 STATX_ATTR_APPEND |				\
	 STATX_ATTR_NODUMP |				\
	 STATX_ATTR_ENCRYPTED				\
	 )/* Attrs corresponding to FS_*_FL flags */
	u64		ino;
	dev_t		dev;
	dev_t		rdev;
	kuid_t		uid;
	kgid_t		gid;
	loff_t		size;
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
	struct timespec btime;			/* File creation time */
	u64		blocks;
};


struct inode_operations {
    int (*create)(struct inode *, struct dentry *, umode_t, bool);
    struct dentry *(*lookup)(struct inode *, struct dentry *, unsigned int);
    int (*link)(struct dentry *, struct inode *, struct dentry *);
    int (*unlink)(struct inode *, struct dentry *);
    int (*symlink)(struct inode *, struct dentry *, const char *);
    int (*mkdir)(struct inode *, struct dentry *, umode_t);
    int (*rmdir)(struct inode *, struct dentry *);
    int (*mknod)(struct inode *, struct dentry *, umode_t, dev_t);
    int (*rename)(struct inode *, struct dentry *, struct inode *, struct dentry *);
    int (*rename2)(struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int);
    int (*readlink)(struct dentry *, char *__user, int);
    // void *(*follow_link)(struct dentry *, struct nameidata *);
    void *(*follow_link)(struct dentry *, void **);
    // void (*put_link)(struct dentry *, struct nameidata *, void *);
    int (*permission)(struct inode *, int);
    int (*get_acl)(struct inode *, int);
    int (*setattr)(struct dentry *, struct iattr *);
    int (*getattr)(struct vfsmount *mnt, struct dentry *, struct kstat *);
    int (*setxattr)(struct dentry *, const char *, const void *, size_t, int);
    ssize_t (*getxattr)(struct dentry *, const char *, void *, size_t);
    ssize_t (*listxattr)(struct dentry *, char *, size_t);
    int (*removexattr)(struct dentry *, const char *);
    void (*update_time)(struct inode *, struct timespec *, int);
    int (*atomic_open)(struct inode *, struct dentry *, struct file *, unsigned open_flag,
                       umode_t create_mode, int *opened);
    int (*tmpfile)(struct inode *, struct dentry *, umode_t);
    int (*dentry_open)(struct dentry *, struct file *, const struct cred *);
};

static inline unsigned int i_blocksize(const struct inode *node)
{
	return (1 << node->i_blkbits);
}

/*
 * NOTE: in a 32bit arch with a preemptable kernel and
 * an UP compile the i_size_read/write must be atomic
 * with respect to the local cpu (unlike with preempt disabled),
 * but they don't need to be atomic with respect to other cpus like in
 * true SMP (so they need either to either locally disable irq around
 * the read or for example on x86 they can be still implemented as a
 * cmpxchg8b without the need of the lock prefix). For SMP compiles
 * and 64bit archs it makes no difference if preempt is enabled or not.
 */
static inline loff_t i_size_read(const struct inode *inode) {
    // #if BITS_PER_LONG==32 && defined(CONFIG_SMP)
    // 	loff_t i_size;
    // 	unsigned int seq;

    // 	do {
    // 		seq = read_seqcount_begin(&inode->i_size_seqcount);
    // 		i_size = inode->i_size;
    // 	} while (read_seqcount_retry(&inode->i_size_seqcount, seq));
    // 	return i_size;
    // #elif BITS_PER_LONG==32 && defined(CONFIG_PREEMPT)
    // 	loff_t i_size;

    // 	preempt_disable();
    // 	i_size = inode->i_size;
    // 	preempt_enable();
    // 	return i_size;
    // #else
    return inode->i_size;
    // #endif
}

/*
 * NOTE: unlike i_size_read(), i_size_write() does need locking around it
 * (normally i_mutex), otherwise on 32bit/SMP an update of i_size_seqcount
 * can be lost, resulting in subsequent i_size_read() calls spinning forever.
 */
static inline void i_size_write(struct inode *inode, loff_t i_size) {
    // #if BITS_PER_LONG==32 && defined(CONFIG_SMP)
    // 	preempt_disable();
    // 	write_seqcount_begin(&inode->i_size_seqcount);
    // 	inode->i_size = i_size;
    // 	write_seqcount_end(&inode->i_size_seqcount);
    // 	preempt_enable();
    // #elif BITS_PER_LONG==32 && defined(CONFIG_PREEMPT)
    // 	preempt_disable();
    // 	inode->i_size = i_size;
    // 	preempt_enable();
    // #else
    inode->i_size = i_size;
    // #endif
}

static force_inline void generic_fillattr(struct inode *inode, struct kstat *stat)
{
	// stat->dev = inode->i_sb->s_dev;
	stat->dev = 0;
	stat->ino = inode->i_ino;
	stat->mode = inode->i_mode;
	stat->nlink = inode->i_nlink;
	// stat->uid = inode->i_uid;
	// stat->gid = inode->i_gid;
    stat->uid = 0;
	stat->gid = 0;
	stat->rdev = 0;
	stat->size = i_size_read(inode);
	stat->atime = inode->i_atime;
	stat->mtime = inode->i_mtime;
	stat->ctime = inode->i_ctime;
	stat->blksize = i_blocksize(inode);
	stat->blocks = inode->i_blocks;

	// if (IS_NOATIME(inode))
	// 	stat->result_mask &= ~STATX_ATIME;
	// if (IS_AUTOMOUNT(inode))
	// 	stat->attributes |= STATX_ATTR_AUTOMOUNT;
}

static force_inline void cp_kstat_2_stat(struct stat *s, struct kstat *ks) {
    memset(s, 0, sizeof(struct stat));
    // s->st_dev = old_encode_dev(ks->dev);
	s->st_ino = ks->ino;
	// if (sizeof(s->st_ino) < sizeof(ks->ino) && s->st_ino != ks->ino)
	// 	return -EOVERFLOW;
	s->st_mode = ks->mode;
	s->st_nlink = ks->nlink;
	// if (s->st_nlink != ks->nlink)
	// 	return -EOVERFLOW;
	// SET_UID(s->st_uid, from_kuid_munged(current_user_ns(), ks->uid));
	// SET_GID(s->st_gid, from_kgid_munged(current_user_ns(), ks->gid));
	// s->st_rdev = old_encode_dev(ks->rdev);
// #if BITS_PER_LONG == 32
// 	if (ks->size > MAX_NON_LFS)
// 		return -EOVERFLOW;
// #endif
	s->st_size = ks->size;
    s->st_blksize = ks->blksize;
    s->st_blocks = ks->blocks;
	s->st_atime = ks->atime.tv_sec;
	s->st_mtime = ks->mtime.tv_sec;
	s->st_ctime = ks->ctime.tv_sec;
}

// extern bool atime_needs_update(const struct path *, struct inode *);
// extern void touch_atime(const struct path *);

// static inline void file_accessed(struct file *file)
// {
// 	if (!(file->f_flags & O_NOATIME))
// 		touch_atime(&file->f_path);
// }
struct inode *iget_or_alloc(struct super_block *sb, unsigned long ino);

static force_inline void clear_inode(struct inode *inode)
{
	/*
	 * We have to cycle the i_pages lock here because reclaim can be in the
	 * process of removing the last page (in __delete_from_page_cache())
	 * and we must not free the mapping under it.
	 */
	// xa_lock_irq(&inode->i_data.i_pages);
	// BUG_ON(inode->i_data.nrpages);
	// BUG_ON(inode->i_data.nrexceptional);
	// xa_unlock_irq(&inode->i_data.i_pages);
	// BUG_ON(!list_empty(&inode->i_data.private_list));
	// BUG_ON(!(inode->i_state & I_FREEING));
	// BUG_ON(inode->i_state & I_CLEAR);
	// BUG_ON(!list_empty(&inode->i_wb_list));
	/* don't need i_lock here, no concurrent mods to i_state */
	inode->i_state = I_FREEING | I_CLEAR;
}

static force_inline bool inode_is_valid(inode* inode) {
    return (inode->i_state & (I_FREEING | I_CLEAR)) == 0 && inode->i_state;
}

void inode_init_owner(struct inode *inode, const struct inode *dir, umode_t mode);
void set_nlink(struct inode *inode, unsigned int nlink);
void inc_nlink(struct inode *inode);
void clear_nlink(struct inode *inode);
void drop_nlink(struct inode *inode);

int generic_file_open(struct inode *inode, struct file *filp);

// 将dentry和inode关联起来
static force_inline void d_instantiate(struct dentry *dentry, struct inode *inode) {
    inode_ref(inode);
    assert(dentry->d_inode == nullptr);
    dentry->d_inode = inode;
    // dentry_ref(dentry); // 一一对应的关系，不需要ref
    assert(inode->i_dentry == nullptr);
    inode->i_dentry = dentry;
}

/**
 * d_splice_alias - splice a disconnected dentry into the tree if one exists
 * @inode:  the inode which may have a disconnected dentry
 * @dentry: a negative dentry which we want to point to the inode.
 *
 * If inode is a directory and has an IS_ROOT alias, then d_move that in
 * place of the given dentry and return it, else simply d_add the inode
 * to the dentry and return NULL.
 *
 * If a non-IS_ROOT directory is found, the filesystem is corrupt, and
 * we should error out: directories can't have multiple aliases.
 *
 * This is needed in the lookup routine of any filesystem that is exportable
 * (via knfsd) so that we can build dcache paths to directories effectively.
 *
 * If a dentry was found and moved, then it is returned.  Otherwise NULL
 * is returned.  This matches the expected return value of ->lookup.
 *
 * Cluster filesystems may call this function with a negative, hashed dentry.
 * In that case, we know that the inode will be a regular file, and also this
 * will only occur during atomic_open. So we need to check for the dentry
 * being already hashed only in the final case.
 */
static force_inline struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry)
{
	if (!inode)
		goto out;
    d_instantiate(dentry, inode);
    // 不支持别名
	// security_d_instantiate(dentry, inode);
	// spin_lock(&inode->i_lock);
	// if (S_ISDIR(inode->i_mode)) {
	// 	struct dentry *new = __d_find_any_alias(inode);
	// 	if (unlikely(new)) {
	// 		/* The reference to new ensures it remains an alias */
	// 		spin_unlock(&inode->i_lock);
	// 		write_seqlock(&rename_lock);
	// 		if (unlikely(d_ancestor(new, dentry))) {
	// 			write_sequnlock(&rename_lock);
	// 			dput(new);
	// 			new = ERR_PTR(-ELOOP);
	// 			pr_warn_ratelimited(
	// 				"VFS: Lookup of '%s' in %s %s"
	// 				" would have caused loop\n",
	// 				dentry->d_name.name,
	// 				inode->i_sb->s_type->name,
	// 				inode->i_sb->s_id);
	// 		} else if (!IS_ROOT(new)) {
	// 			struct dentry *old_parent = dget(new->d_parent);
	// 			int err = __d_unalias(inode, dentry, new);
	// 			write_sequnlock(&rename_lock);
	// 			if (err) {
	// 				dput(new);
	// 				new = ERR_PTR(err);
	// 			}
	// 			dput(old_parent);
	// 		} else {
	// 			__d_move(new, dentry, false);
	// 			write_sequnlock(&rename_lock);
	// 		}
	// 		iput(inode);
	// 		return new;
	// 	}
	// }
out:
	// __d_add(dentry, inode);
	return NULL;
}

// 返回的dentry已经被引用
static force_inline dentry *get_dentry_by_hash(dentry *parent, qstr qs, bool create, bool lock) {
    if (strncmp(qs.name, ".", 1) == 0) {
        dentry_ref(parent);
        return parent;
    }
    if (strncmp(qs.name, "..", 2) == 0) {
        dentry_ref(parent->d_parent);
        return parent->d_parent;
    }
    dentry *child = dentry_get_child(parent, qs, lock);
    if (child) return child;
    rd_warning("%s not in dentry hash, lookup from nvm", qs.name);
    if (create == false) return nullptr; // TODO: 恢复时需要完善

    child = d_alloc(parent, &qs);
    if (unlikely(!child)) {
        r_error("no memory\n");
        return nullptr;
    }
    struct inode *dir = parent->d_inode;
    dentry *old = dir->i_op->lookup(dir, child, 0);
    if (unlikely(old)) {
        r_fatal("unexpected!, 还需要将child从parent的map中删除");
        dentry_unref(child);
        child = old;
    }
    return child;
}

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

#define CFG_MAX_CPU_NUM 64
#define CFG_START_FD 10000

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

void setattr_copy(struct inode *inode, const struct iattr *attr);

void vfs_init(vfs_cfg* cfg);
void vfs_destroy_file();
void vfs_destroy();

int do_open(dentry* parent, qstr name, struct open_flags* op);
int do_close(int fd);
ssize_t do_read(int fd, char* buf, size_t count);
ssize_t do_write(int fd, const char* buf, size_t count);
loff_t generic_file_llseek(struct file *file, loff_t offset, int whence);
off_t do_lseek(int fd, off_t offset, int whence);
int do_fsync(int fd);
int do_dentry_truncate(dentry* d, off_t length, unsigned int time_attrs, struct file *filp);
int do_ftruncate(int fd, off_t length);

#endif