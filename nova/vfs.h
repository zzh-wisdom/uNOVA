#ifndef UNOVA_VFS_H_
#define UNOVA_VFS_H_

#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>

#include "nova/nova_com.h"
#include "util/lock.h"
#include "util/atomic.h"
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
#define	FS_SECRM_FL			0x00000001 /* Secure deletion */
#define	FS_UNRM_FL			0x00000002 /* Undelete */
#define	FS_COMPR_FL			0x00000004 /* Compress file */
#define FS_SYNC_FL			0x00000008 /* Synchronous updates */
#define FS_IMMUTABLE_FL			0x00000010 /* Immutable file */
#define FS_APPEND_FL			0x00000020 /* writes to file may only append */
#define FS_NODUMP_FL			0x00000040 /* do not dump file */
#define FS_NOATIME_FL			0x00000080 /* do not update atime */
/* Reserved for compression usage... */
#define FS_DIRTY_FL			0x00000100
#define FS_COMPRBLK_FL			0x00000200 /* One or more compressed clusters */
#define FS_NOCOMP_FL			0x00000400 /* Don't compress */
/* End compression flags --- maybe not all used */
#define FS_ENCRYPT_FL			0x00000800 /* Encrypted file */
#define FS_BTREE_FL			0x00001000 /* btree format dir */
#define FS_INDEX_FL			0x00001000 /* hash-indexed directory */
#define FS_IMAGIC_FL			0x00002000 /* AFS directory */
#define FS_JOURNAL_DATA_FL		0x00004000 /* Reserved for ext3 */
#define FS_NOTAIL_FL			0x00008000 /* file tail should not be merged */
#define FS_DIRSYNC_FL			0x00010000 /* dirsync behaviour (directories only) */
#define FS_TOPDIR_FL			0x00020000 /* Top of directory hierarchies*/
#define FS_HUGE_FILE_FL			0x00040000 /* Reserved for ext4 */
#define FS_EXTENT_FL			0x00080000 /* Extents */
#define FS_VERITY_FL			0x00100000 /* Verity protected inode */
#define FS_EA_INODE_FL			0x00200000 /* Inode used for large EA */
#define FS_EOFBLOCKS_FL			0x00400000 /* Reserved for ext4 */
#define FS_NOCOW_FL			0x00800000 /* Do not cow file */
#define FS_INLINE_DATA_FL		0x10000000 /* Reserved for ext4 */
#define FS_PROJINHERIT_FL		0x20000000 /* Create with parents projid */
#define FS_CASEFOLD_FL			0x40000000 /* Folder is case insensitive */
#define FS_RESERVED_FL			0x80000000 /* reserved for ext2 lib */

/*
 * Inode flags - they have no relation to superblock flags now
 */
#define S_SYNC		1	/* Writes are synced at once */
#define S_NOATIME	2	/* Do not update access times */
#define S_APPEND	4	/* Append-only file */
#define S_IMMUTABLE	8	/* Immutable file */
#define S_DEAD		16	/* removed, but still open directory */
#define S_NOQUOTA	32	/* Inode is not counted to quota */
#define S_DIRSYNC	64	/* Directory modifications are synchronous */
#define S_NOCMTIME	128	/* Do not update file c/mtime */
#define S_SWAPFILE	256	/* Do not truncate: swapon got its bmaps */
#define S_PRIVATE	512	/* Inode is fs-internal */
#define S_IMA		1024	/* Inode has an associated IMA struct */
#define S_AUTOMOUNT	2048	/* Automount/referral quasi-directory */
#define S_NOSEC		4096	/* no suid or xattr security attributes */
#ifdef CONFIG_FS_DAX
#define S_DAX		8192	/* Direct Access, avoiding the page cache */
#else
#define S_DAX		0	/* Make all the DAX code disappear */
#endif
#define S_ENCRYPTED	16384	/* Encrypted file (using fs/crypto/) */

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#define pgoff_t unsigned long

struct super_block;
struct file_operations;
struct dentry;

struct super_operations {
    struct inode *(*alloc_inode)(struct super_block *sb);
    void (*destroy_inode)(struct inode *);

    // void (*dirty_inode) (struct inode *, int flags);
    // int (*write_inode) (struct inode *, struct writeback_control *wbc);
    // int (*drop_inode) (struct inode *);
    // void (*evict_inode) (struct inode *);
    // void (*put_super) (struct super_block *);
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

struct super_block {
    // struct list_head	s_list;		/* Keep this first */
    dev_t s_dev; /* search index; _not_ kdev_t */
    unsigned char s_blocksize_bits;
    unsigned long s_blocksize;  // 空间管理的数据块大小
    loff_t s_maxbytes; /* Max file size */
    // struct file_system_type *s_type;
    const struct super_operations *s_op;
    // const struct dquot_operations *dq_op;
    // const struct quotactl_ops *s_qcop;
    // const struct export_operations *s_export_op;
    unsigned long s_flags;
    unsigned long s_iflags; /* internal SB_I_* flags */
    unsigned long s_magic;
    struct dentry *s_root;
    // struct rw_semaphore	s_umount;
    int s_count;
    atomic_t s_active;

    // const struct xattr_handler **s_xattr;

    // struct hlist_bl_head	s_roots;	/* alternate root dentries for NFS */
    // struct list_head	s_mounts;	/* list of mounts; _not_ for fs use */
    struct block_device *s_bdev;
    struct backing_dev_info *s_bdi;
    struct mtd_info *s_mtd;
    // struct hlist_node	s_instances;
    unsigned int s_quota_types; /* Bitmask of supported quota types */
    // struct quota_info	s_dquot;	/* Diskquota specific options */

    // struct sb_writers	s_writers;

    char s_id[32]; /* Informational name */
    // uuid_t			s_uuid;		/* UUID */

    void *s_fs_info; /* Filesystem private info */
    unsigned int s_max_links;
    // fmode_t			s_mode;

    /* Granularity of c/m/atime in ns.
       Cannot be worse than a second */
    u32 s_time_gran;

    /*
     * The next field is for VFS *only*. No filesystems have any business
     * even looking at it. You had been warned.
     */
    mutex_t s_vfs_rename_mutex; /* Kludge */

    /*
     * Filesystem subtype.  If non-empty the filesystem type field
     * in /proc/mounts will be "type.subtype"
     */
    char *s_subtype;

    // const struct dentry_operations *s_d_op; /* default d_op for dentries */

    /*
     * Saved pool identifier for cleancache (-1 means none)
     */
    // int cleancache_poolid;

    // struct shrinker s_shrink;	/* per-sb shrinker handle */

    /* Number of inodes with nlink == 0 but still referenced */
    atomic_t s_remove_count;

    /* Being remounted read-only */
    // int s_readonly_remount;

    /* AIO completions deferred from interrupt context */
    // struct workqueue_struct *s_dio_done_wq;
    // struct hlist_head s_pins;

    /*
     * Owning user namespace and default context in which to
     * interpret filesystem uids, gids, quotas, device nodes,
     * xattrs and security labels.
     */
    // struct user_namespace *s_user_ns;

    /*
     * Keep the lru lists last in the structure so they always sit on their
     * own individual cachelines.
     */
    // struct list_lru		s_dentry_lru;
    // struct list_lru		s_inode_lru;
    // struct rcu_head		rcu;
    // struct work_struct	destroy_work;

    mutex_t s_sync_lock; /* sync serialisation lock */

    /*
     * Indicates how deep in a filesystem stack this SB is
     */
    int s_stack_depth;

    /* s_inode_list_lock protects s_inodes */
    spinlock_t s_inode_list_lock;
    // struct list_head	s_inodes;	/* all inodes */

    spinlock_t s_inode_wblist_lock;
    // struct list_head	s_inodes_wb;	/* writeback inodes */
};

struct vfsmount {
	struct dentry *mnt_root;	/* root of the mounted tree */
	struct super_block *mnt_sb;	/* pointer to superblock */
	int mnt_flags;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct address_space {
	struct inode		*host;		/* owner: inode, block_device */
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
    // union {
    // 	struct llist_node	fu_llist;
    // 	struct rcu_head 	fu_rcuhead;
    // } f_u;
    struct path		f_path;
    struct inode *f_inode; /* cached value */
    const struct file_operations *f_op;

    /*
     * Protects f_ep_links, f_flags.
     * Must not be taken from IRQ context.
     */
    spinlock_t f_lock;
    // enum rw_hint		f_write_hint;
    // atomic_long_t		f_count;
    unsigned int 		f_flags;
    // fmode_t			f_mode;
    // struct mutex		f_pos_lock;
    // loff_t			f_pos;
    // struct fown_struct	f_owner;
    // const struct cred	*f_cred;
    // struct file_ra_state	f_ra;

    u64 f_version;

    /* needed for tty driver, and maybe others */
    void *private_data;

    struct address_space	*f_mapping;
    // errseq_t		f_wb_err;
};

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
 */
struct inode {
    umode_t i_mode;
    unsigned short i_opflags;
    // kuid_t i_uid;
    // kgid_t i_gid;
    unsigned int i_flags;

    const struct inode_operations *i_op;
    struct super_block *i_sb;
    // struct address_space *i_mapping;

    /* Stat data, not accessed from path walking */
    unsigned long i_ino;  // ino号，nova内部产生的
    /*
     * Filesystems may only read i_nlink directly.  They shall use the
     * following functions for modification:
     *
     *    (set|clear|inc|drop)_nlink
     *    inode_(inc|dec)_link_count
     */
    union {
        const unsigned int i_nlink;
        unsigned int __i_nlink;
    };
    dev_t i_rdev;
    loff_t i_size;  // 文件大小, 初始化是0
    struct timespec i_atime;
    struct timespec i_mtime;
    struct timespec i_ctime;
    spinlock_t i_lock; /* i_blocks, i_bytes, maybe i_size */
    unsigned short i_bytes;
    unsigned int i_blkbits;
    blkcnt_t i_blocks;

    /* Misc */
    unsigned long i_state;
    mutex_t i_mutex;

    unsigned long dirtied_when; /* jiffies of first dirtying */
    unsigned long dirtied_time_when;

    // struct hlist_node	i_hash;
    // struct list_head	i_wb_list;	/* backing dev IO list */
    // struct list_head	i_lru;		/* inode LRU list */
    // struct list_head	i_sb_list;
    // union {
    // 	struct hlist_head	i_dentry;
    // 	struct rcu_head		i_rcu;
    // };
    u64 i_version;
    atomic_t i_count;
    atomic_t i_dio_count;
    // atomic_t i_writecount;
    // #ifdef CONFIG_IMA
    // 	atomic_t		i_readcount; /* struct files open RO */
    // #endif
    const struct file_operations *i_fop; /* former ->i_op->default_file_ops */
    // struct file_lock_context *i_flctx;
    // struct address_space	i_data;
    // struct list_head	i_devices;
    // union {
    //     struct pipe_inode_info *i_pipe;
    //     struct block_device *i_bdev;
    //     struct cdev *i_cdev;
    // };

    u32 i_generation;

#ifdef CONFIG_FSNOTIFY
    __u32 i_fsnotify_mask; /* all events this inode cares about */
    struct hlist_head i_fsnotify_marks;
#endif

    void *i_private; /* fs or device private pointer */
};

#define HASH_LEN_DECLARE \
    u32 len;             \
    u32 hash;
/*
 * "quick string" -- eases parameter passing, but more importantly
 * saves "metadata" about the string (ie length and the hash).
 *
 * hash comes first so it snuggles against d_parent in the
 * dentry.
 */
struct qstr {
    union {
        struct {
            HASH_LEN_DECLARE;
        };
        u64 hash_len;
    };
    const char *name;
};

#define DNAME_INLINE_LEN 40

// https://www.cnblogs.com/linhaostudy/p/7428971.html
// 可以代表一个目录或者文件
struct dentry {
    /* RCU lookup touched fields */
    unsigned int d_flags; /* protected by d_lock */
    // seqcount_t d_seq;        /* per dentry seqlock */
    // struct hlist_bl_node d_hash;    /* lookup hash list */
    struct dentry *d_parent; /* parent directory */
    struct qstr d_name;
    struct inode *d_inode;                   /* Where the name belongs to - NULL is
                                              * negative */
    unsigned char d_iname[DNAME_INLINE_LEN]; /* small names */

    /* Ref lookup also touches following */
    unsigned int d_count; /* protected by d_lock */
    spinlock_t d_lock;    /* per dentry lock */
    const struct dentry_operations *d_op;
    struct super_block *d_sb; /* The root of the dentry tree */
    unsigned long d_time;     /* used by d_revalidate */
    void *d_fsdata;           /* fs-specific data */

    // struct list_head d_lru;        /* LRU list */
    /*
     * d_child and d_rcu can share memory
     */
    // union {
    //     struct list_head d_child;    /* child of parent list */
    //      struct rcu_head d_rcu;
    // } d_u;
    // struct list_head d_subdirs;    /* our children */
    // struct list_head d_alias;    /* inode alias list */
};

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
	unsigned int	ia_valid;
	umode_t		ia_mode;
	kuid_t		ia_uid;
	kgid_t		ia_gid;
	loff_t		ia_size;
	struct timespec ia_atime;
	struct timespec ia_mtime;
	struct timespec ia_ctime;

	/*
	 * Not an attribute, but an auxiliary info for filesystems wanting to
	 * implement an ftruncate() like method.  NOTE: filesystem should
	 * check for (ia_valid & ATTR_FILE), and not for (ia_file != NULL).
	 */
	struct file	*ia_file;
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
static inline loff_t i_size_read(const struct inode *inode)
{
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
static inline void i_size_write(struct inode *inode, loff_t i_size)
{
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

// extern bool atime_needs_update(const struct path *, struct inode *);
// extern void touch_atime(const struct path *);

// static inline void file_accessed(struct file *file)
// {
// 	if (!(file->f_flags & O_NOATIME))
// 		touch_atime(&file->f_path);
// }

struct inode *new_inode(struct super_block *sb);

void inode_init_owner(struct inode *inode, const struct inode *dir,
			umode_t mode);
void set_nlink(struct inode *inode, unsigned int nlink);
void inc_nlink(struct inode *inode);
void clear_nlink(struct inode *inode);
void drop_nlink(struct inode *inode);

int generic_file_open(struct inode * inode, struct file * filp);

#endif