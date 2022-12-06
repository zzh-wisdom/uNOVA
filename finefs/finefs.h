/*
 * BRIEF DESCRIPTION
 *
 * Definitions for the FINEFS filesystem.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#ifndef __FINEFS_H
#define __FINEFS_H

#include <stdlib.h>

#include "vfs/fs_cfg.h"
#include "finefs/journal.h"
// #include "finefs/wprotect.h"
#include "finefs/stats.h"
#include "vfs/vfs.h"
#include "finefs/finefs_def.h"

#include "util/lock.h"
#include "util/atomic.h"
#include "util/util.h"
#include "util/rbtree.h"
#include "util/log.h"
#include "util/radix-tree.h"

#define PAGE_SHIFT_2M 21
#define PAGE_SHIFT_1G 30

/*
 * Debug code
 */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define finefs_dbg(s, args...)         pr_debug(s, ## args) */
// #define finefs_dbg(s, args ...)           pr_info(s, ## args)
// #define finefs_dbg1(s, args ...)
// #define finefs_err(sb, s, args ...)       finefs_error_mng(sb, s, ## args)
// #define finefs_warn(s, args ...)          pr_warning(s, ## args)
// #define finefs_info(s, args ...)          pr_info(s, ## args)

extern unsigned int finefs_dbgmask;
#define FINEFS_DBGMASK_MMAPHUGE          (0x00000001)
#define FINEFS_DBGMASK_MMAP4K            (0x00000002)
#define FINEFS_DBGMASK_MMAPVERBOSE       (0x00000004)
#define FINEFS_DBGMASK_MMAPVVERBOSE      (0x00000008)
#define FINEFS_DBGMASK_VERBOSE           (0x00000010)
#define FINEFS_DBGMASK_TRANSACTION       (0x00000020)

#define finefs_dbg_mmap4k(s, args ...)		 \
	((finefs_dbgmask & FINEFS_DBGMASK_MMAP4K) ? finefs_dbg(s, args) : 0)
#define finefs_dbg_mmapv(s, args ...)		 \
	((finefs_dbgmask & FINEFS_DBGMASK_MMAPVERBOSE) ? finefs_dbg(s, args) : 0)
#define finefs_dbg_mmapvv(s, args ...)		 \
	((finefs_dbgmask & FINEFS_DBGMASK_MMAPVVERBOSE) ? finefs_dbg(s, args) : 0)

#define finefs_dbg_verbose(s, args ...)		 \
	((finefs_dbgmask & FINEFS_DBGMASK_VERBOSE) ? finefs_dbg(s, ##args) : 0)
#define finefs_dbgv(s, args ...)	finefs_dbg_verbose(s, ##args)
#define finefs_dbg_trans(s, args ...)		 \
	((finefs_dbgmask & FINEFS_DBGMASK_TRANSACTION) ? finefs_dbg(s, ##args) : 0)

#define finefs_set_bit                   __test_and_set_bit_le
#define finefs_clear_bit                 __test_and_clear_bit_le
#define finefs_find_next_zero_bit                find_next_zero_bit_le

#define clear_opt(o, opt)       (o &= ~FINEFS_MOUNT_ ## opt)
#define set_opt(o, opt)         (o |= FINEFS_MOUNT_ ## opt)
#define test_opt(sb, opt)       (FINEFS_SB(sb)->s_mount_opt & FINEFS_MOUNT_ ## opt)

#define FINEFS_LARGE_INODE_TABLE_SIZE    (0x200000)
/* FINEFS size threshold for using 2M blocks for inode table */
#define FINEFS_LARGE_INODE_TABLE_THREASHOLD    (0x20000000)
/*
 * finefs inode flags
 *
 * FINEFS_EOFBLOCKS_FL	There are blocks allocated beyond eof
 */
#define FINEFS_EOFBLOCKS_FL      0x20000000
/* Flags that should be inherited by new inodes from their parent. */
#define FINEFS_FL_INHERITED (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | \
			    FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL |	\
			    FS_COMPRBLK_FL | FS_NOCOMP_FL | FS_JOURNAL_DATA_FL | \
			    FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define FINEFS_REG_FLMASK (~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define FINEFS_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)
#define FINEFS_FL_USER_VISIBLE (FS_FL_USER_VISIBLE | FINEFS_EOFBLOCKS_FL)

/* IOCTLs */
#define	FINEFS_PRINT_TIMING		0xBCD00010
#define	FINEFS_CLEAR_STATS		0xBCD00011
#define	FINEFS_PRINT_LOG			0xBCD00013
#define	FINEFS_PRINT_LOG_BLOCKNODE	0xBCD00014
#define	FINEFS_PRINT_LOG_PAGES		0xBCD00015
#define	FINEFS_PRINT_FREE_LISTS		0xBCD00018


#define	READDIR_END			(ULONG_MAX)
#define	INVALID_CPU			(-1)
#define	SHARED_CPU			(65536)
#define FREE_BATCH			(16)

extern int measure_timing;

/* ======================= block size ========================= */
extern unsigned int finefs_blk_type_to_shift[FINEFS_BLOCK_TYPE_MAX];
extern unsigned int finefs_blk_type_to_size[FINEFS_BLOCK_TYPE_MAX];
extern unsigned int finefs_blk_type_to_blk_num[FINEFS_BLOCK_TYPE_MAX];

static inline unsigned int finefs_inode_blk_shift (struct finefs_inode *pi)
{
	return finefs_blk_type_to_shift[pi->i_blk_type];
}

static inline uint32_t finefs_inode_blk_size(struct finefs_inode *pi)
{
	return finefs_blk_type_to_size[pi->i_blk_type];
}

// 获取该枚举类型，对应的block个数
static inline unsigned long
finefs_get_numblocks(unsigned short btype)
{
	return finefs_blk_type_to_blk_num[btype];
}

static inline unsigned long
finefs_get_blocknr(struct super_block *sb, u64 block, unsigned short btype)
{
	return block >> FINEFS_BLOCK_SHIFT;
}

// static inline unsigned long finefs_get_pfn(struct super_block *sb, u64 block)
// {
// 	return (FINEFS_SB(sb)->phys_addr + block) >> PAGE_SHIFT;
// }

/* ======================= Log entry ========================= */

struct finefs_inode_page_tail {
	__le64	padding1;
	__le64	padding2;
	__le64	padding3;
	__le64	next_page;
} __attribute((__packed__));

/* FINEFS_LOG_BLOCK_TYPE 和 FINEFS_LOG_NUM_BLOCKS 需要一起修改 */
// log的大小必须等于基本lock大小，否则一些掩码的操作会存在问题，
// FIXME：或者改用伙伴算法，每次分配的大小都按照大小对齐
#define FINEFS_LOG_BLOCK_TYPE 	FINEFS_DEFAULT_DATA_BLOCK_TYPE
#define FINEFS_LOG_NUM_BLOCKS  	(1)
#define FINEFS_LOG_SHIFT        (FINEFS_BLOCK_SHIFT)
#define FINEFS_LOG_SIZE         (1 << FINEFS_LOG_SHIFT)
#define FINEFS_LOG_UMASK         (FINEFS_LOG_SIZE-1)
#define FINEFS_LOG_MASK        (~(FINEFS_LOG_SIZE-1))
#define	FINEFS_LOG_LAST_ENTRY	(FINEFS_LOG_SIZE-sizeof(struct finefs_inode_page_tail))
#define	FINEFS_LOG_TAIL(p)	   	(((p) & FINEFS_LOG_MASK) + FINEFS_LOG_LAST_ENTRY)

#define	FINEFS_LOG_BLOCK_OFF(p)	    ((p) & FINEFS_LOG_MASK)
#define	FINEFS_LOG_ENTRY_LOC(p)		((p) & FINEFS_LOG_UMASK)

/* Fit in PAGE_SIZE */
// TODO: 增大page的大小
struct	finefs_inode_log_page {
	char padding[FINEFS_LOG_LAST_ENTRY];
	struct finefs_inode_page_tail page_tail;
} __attribute((__packed__));

#define	EXTEND_THRESHOLD	256

/* Inode entry in the log */
enum finefs_entry_type {
	FILE_WRITE = 1,
	// TODO:
	FILE_WRITE_BEGIN,
	FILE_WRITE_MIDDLE,
	FILE_WRITE_END,
	DIR_LOG,  // 新建一个dir
	SET_ATTR,
	LINK_CHANGE,
	NEXT_PAGE,
};

#define LOG_ENTRY_SIZE 64

#if LOG_ENTRY_SIZE==64
struct finefs_file_write_entry {
	/* ret of find_nvmm_block, the lowest byte is entry type */
	__le64	block;   // 起始block的NVM偏移地址
	__le64	pgoff;   // page 偏移
	__le32	num_pages;  // 写的page个数
	// TODO： invalid_pages字段是否可以丢弃
	__le32	invalid_pages; // 为什么这两个不相等就是有效的，其他原因导致无效的page个数？
	/* For both ctime and mtime */
	__le32	mtime;
	__le32	padding;
	__le64	size;  // 文件的大小, 不要移动定义位置
	u8      paddings[16];
	__le64 entry_version;
} __attribute((__packed__));

#else
// 40B
struct finefs_file_write_entry {
	/* ret of find_nvmm_block, the lowest byte is entry type */
	__le64	block;   // 起始block的NVM偏移地址
	__le64	pgoff;   // page 偏移
	__le32	num_pages;  // 写的page个数
	__le32	invalid_pages; // 为什么这两个不相等就是有效的，其他原因导致无效的page个数？
	/* For both ctime and mtime */
	__le32	mtime;
	__le32	padding;
	__le64	size;  // 文件的大小
} __attribute((__packed__));

#endif

static inline u8 finefs_get_entry_type(void *p)
{
	return *(u8 *)p;
}

static inline void finefs_set_entry_type(void *p, enum finefs_entry_type type)
{
	*(u8 *)p = type;
}

/*
 * Structure of a directory log entry in FINEFS.
 * Update DIR_LOG_REC_LEN if modify this struct!
 */
struct finefs_dentry {
	u8	entry_type;
	u8	name_len;               /* length of the dentry name */
	u8	file_type;              /* file type 没有作用，entry_type已经足够*/
	u8	invalid;		/* Invalid now? 恢复时，不应该依赖于该标志*/
	__le16	de_len;                 /* length of this dentry 即log entry大小*/
	__le16	links_count;		// 自身的link count
	__le32	mtime;			/* For both mtime and ctime */
	__le64	ino;                    /* inode no pointed to by this entry */
	__le64	size;             // 这个是什么大小？文件吗
	char	name[FINEFS_NAME_LEN + 1];	/* File name */
} __attribute((__packed__));

#define FINEFS_DIR_PAD			8	/* Align to 8 bytes boundary */
#define FINEFS_DIR_ROUND			(FINEFS_DIR_PAD - 1)
#define FINEFS_DIR_LOG_REC_LEN(name_len)	(((name_len) + 29 + FINEFS_DIR_ROUND) & \
				      ~FINEFS_DIR_ROUND)

#if LOG_ENTRY_SIZE==64

struct finefs_setattr_logentry {
	u8	entry_type;
	u8	attr;
	__le16	mode;
	__le32	uid;
	__le32	gid;
	__le32	atime;
	__le32	mtime;
	__le32	ctime;
	__le64	size;
	u8      padding[24];
	__le64 entry_version;
} __attribute((__packed__));
#else
/* Struct of inode attributes change log (setattr) */
// 32B
struct finefs_setattr_logentry {
	u8	entry_type;
	u8	attr;
	__le16	mode;
	__le32	uid;
	__le32	gid;
	__le32	atime;
	__le32	mtime;
	__le32	ctime;
	__le64	size;
} __attribute((__packed__));
#endif

/* Do we need this to be 32 bytes? */
struct finefs_link_change_entry {
	u8	entry_type;
	u8	padding;
	__le16	links;  // 等于0表示删除
	__le32	ctime;
	__le32	flags;
	__le32	generation;
	__le64	paddings[2];
} __attribute((__packed__));

enum alloc_type {
	LOG = 1,
	DATA,
};

#define	MMAP_WRITE_BIT	0x20UL	// mmaped for write
#define	IS_MAP_WRITE(p)	((p) & (MMAP_WRITE_BIT))
#define	MMAP_ADDR(p)	((p) & (PAGE_MASK))

static inline void finefs_update_tail(struct finefs_inode *pi, u64 new_tail)
{
	log_assert(0);
	timing_t update_time;

	FINEFS_START_TIMING(update_tail_t, update_time);

	PERSISTENT_BARRIER();
	pi->log_tail = new_tail;
	finefs_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 1);

	FINEFS_END_TIMING(update_tail_t, update_time);
}

/* symlink.c */
int finefs_block_symlink(struct super_block *sb, struct finefs_inode *pi,
	struct inode *inode, u64 log_block,
	unsigned long name_blocknr, const char *symname, int len);

/* Inline functions start here */

/* Mask out flags that are inappropriate for the given type of inode. */
static inline __le32 finefs_mask_flags(umode_t mode, __le32 flags)
{
	flags &= cpu_to_le32(FINEFS_FL_INHERITED);
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & cpu_to_le32(FINEFS_REG_FLMASK);
	else
		return flags & cpu_to_le32(FINEFS_OTHER_FLMASK);
}

// static inline int finefs_calc_checksum(u8 *data, int n)
// {
// 	u16 crc = 0;

// 	crc = crc16(~0, (__u8 *)data + sizeof(__le16), n - sizeof(__le16));
// 	if (*((__le16 *)data) == cpu_to_le16(crc))
// 		return 0;
// 	else
// 		return 1;
// }

struct finefs_range_node_lowhigh {
	__le64 range_low;  // 保存到NVM时，高1bytes保存cpuid
	__le64 range_high;
};

#define	RANGENODE_PER_PAGE	254

struct finefs_range_node {
	struct rb_node node;
	unsigned long range_low;
	unsigned long range_high;
};

// 这是inode的在内存中的数据结构
struct finefs_inode_info_header {
	// 文件数据是按照blocknr来索引的？感觉还是红黑树，或者跳表好
	struct radix_tree_root tree;	/* Dir name entry tree root 或者文件数据*/
	// struct radix_tree_root cache_tree;	/* Mmap cache tree root */
	unsigned short i_mode;		/* Dir or file? */
	unsigned long log_pages;	/* Num of log pages */
	unsigned long i_size;
	// 以上 finefs_init_header 中初始化
	// 下面两个外部初始化
	unsigned long ino;
	unsigned long pi_addr;
	// unsigned long mmap_pages;	/* Num of mmap pages */
	// unsigned long low_dirty;	/* Mmap dirty low range */
	// unsigned long high_dirty;	/* Mmap dirty high range */

	// 下面是统计的信息，不用初始化，随着操作而改变
	unsigned long valid_bytes;	/* For thorough GC, log page中有效entry的总字节数*/
	// 随着 GC/op 的进行而修改
	u64 last_setattr;		/* Last setattr entry ,当前已经应用的setattr log地址*/
	u64 last_link_change;		/* Last link change entry */

	// TODO:
	__le64	i_log_tail;
};

static inline void finefs_update_volatile_tail(struct finefs_inode_info_header *sih, u64 new_tail)
{
	// timing_t update_time;

	// FINEFS_START_TIMING(update_tail_t, update_time);

	PERSISTENT_BARRIER();
	sih->i_log_tail = new_tail;

	// finefs_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 1);
	// FINEFS_END_TIMING(update_tail_t, update_time);
}

struct finefs_inode_info {
	struct finefs_inode_info_header header;
	struct inode vfs_inode;
};

enum bm_type {
	BM_4K = 0,
	BM_2M,
	BM_1G,
};

struct single_scan_bm {
	unsigned long bitmap_size;
	unsigned long *bitmap;
};

struct scan_bitmap {
	struct single_scan_bm scan_bm_4K;
	struct single_scan_bm scan_bm_2M;
	struct single_scan_bm scan_bm_1G;
};

struct free_list {
	spinlock_t s_lock;
	struct rb_root	block_free_tree;
	struct finefs_range_node *first_node;  // 红黑树按序的第一个node？
	unsigned long	block_start;
	unsigned long	block_end;
	unsigned long	num_free_blocks; // 初始化 sbi->num_blocks / sbi->cpus。空闲的page个数
	unsigned long	num_blocknode;  // 红黑树的node个数

	/* Statistics */
	unsigned long	alloc_log_count;  // 分配的log个数
	unsigned long	alloc_data_count; // 分配data的次数
	unsigned long	free_log_count;
	unsigned long	free_data_count;
	unsigned long	alloc_log_pages;  // 用于分配log的page总数
	unsigned long	alloc_data_pages; // 用于分配data的page总数
	unsigned long	freed_log_pages;
	unsigned long	freed_data_pages;

	u64		padding[8];	/* Cache line break */
};

/*
 * The first block contains super blocks and reserved inodes;
 * The second block contains pointers to journal pages.
 * The third block contains pointers to inode tables.
 */
#define	RESERVED_BLOCKS	3

struct inode_map {
	mutex_t inode_table_mutex;
	struct rb_root	inode_inuse_tree;
	unsigned long	num_range_node_inode; // 红黑树中节点个数
	struct finefs_range_node *first_inode_range;  // 红黑树中按顺序的第一个节点
	int allocated;  // 统计信息，分配的个数
	int freed;
};

/*
 * FINEFS super-block data in memory
 */
struct finefs_sb_info {
	struct super_block *sb;
	// struct block_device *s_bdev;  // NVM设备

	/*
	 * base physical and virtual address of FINEFS (which is also
	 * the pointer to the super block)
	 * NVM的物理地址
	 */
	// phys_addr_t	phys_addr;
	void		*virt_addr;  // NVM映射的虚拟地址

	unsigned long	num_blocks;  // 整个NVM的page的个数

	/*
	 * Backing store option:
	 * 1 = no load, 2 = no store,
	 * else do both
	 */
	unsigned int	finefs_backing_option;

	/* Mount options */
	unsigned long	bpi;
	unsigned long	num_inodes;
	unsigned long	blocksize;  // block 大小，block和page是不同的概念。block可以由多个连续的page组成
	unsigned long	initsize;    // NVM盘大小
	unsigned long	s_mount_opt;
	// kuid_t		uid;    /* Mount uid for root directory */
	// kgid_t		gid;    /* Mount gid for root directory */
	umode_t		mode;   /* Mount mode for root directory */
	atomic_t	next_generation;
	/* inode tracking */
	unsigned long	s_inodes_used_count;  // 已使用的inode个数
	unsigned long	reserved_blocks;  // 保留的block个数

	mutex_t 	s_lock;	/* protects the SB's buffer-head */

	int cpus;  // 在线的cpu个数
	// struct proc_dir_entry *s_proc;  // 系统的文件目录

	/* ZEROED page for cache page initialized */
	// void *zeroed_page;  // 缓存第一page？

	/* Per-CPU journal lock */
	spinlock_t *journal_locks;

	/* Per-CPU inode map */
	struct inode_map	*inode_maps;

	/* Decide new inode map id */
	// TODO： 需要原子变量递增吧
	unsigned long map_id;

	/* Per-CPU free block list */
	struct free_list *free_lists;

	/* Shared free block list */
	unsigned long per_list_blocks;  // 每个cpu的block个数 sbi->num_blocks / sbi->cpus;
	struct free_list shared_free_list;  // 平均分不完全时，管理剩下多余的
};

static inline struct finefs_sb_info *FINEFS_SB(struct super_block *sb)
{
	return (struct finefs_sb_info *)sb->s_fs_info;
}

static inline struct finefs_inode_info *FINEFS_I(struct inode *inode)
{
	return container_of(inode, struct finefs_inode_info, vfs_inode);
}

/* If this is part of a read-modify-write of the super block,
 * finefs_memunlock_super() before calling! */
static inline struct finefs_super_block *finefs_get_super(struct super_block *sb)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);

	return (struct finefs_super_block *)sbi->virt_addr;
}

static inline struct finefs_super_block *finefs_get_redund_super(struct super_block *sb)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);

	return (struct finefs_super_block *)(sbi->virt_addr + FINEFS_SB_SIZE);
}

/* If this is part of a read-modify-write of the block,
 * finefs_memunlock_block() before calling! */
// 获取block的映射地址
static inline void *finefs_get_block(struct super_block *sb, u64 block)
{
	struct finefs_super_block *ps = finefs_get_super(sb);

	return block ? ((char *)ps + block) : NULL;
}

static inline u64
finefs_get_addr_off(struct finefs_sb_info *sbi, void *addr)
{
	dlog_assert((addr >= sbi->virt_addr) &&
			((char*)addr < ((char*)(sbi->virt_addr) + sbi->initsize)));
	return (u64)((char*)addr - (char*)sbi->virt_addr);
}

// 获取block的nvm相对偏移
static inline u64
finefs_get_block_off(struct super_block *sb, unsigned long blocknr,
		    unsigned short btype)
{
	return (u64)blocknr << FINEFS_BLOCK_SHIFT;
}

static inline
struct free_list *finefs_get_free_list(struct super_block *sb, int cpu)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);

	if (cpu < sbi->cpus)
		return &sbi->free_lists[cpu];
	else {
		rdv_verb("%s: cpu:%d, sbi->cpus:%d", __func__, cpu, sbi->cpus);
		return &sbi->shared_free_list;
	}
}

struct ptr_pair {
	__le64 journal_head;
	__le64 journal_tail;
};

static inline
struct ptr_pair *finefs_get_journal_pointers(struct super_block *sb, int cpu)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);

	if (cpu >= sbi->cpus)
		return NULL;

	return (struct ptr_pair *)((char *)finefs_get_block(sb,
		FINEFS_BLOCK_SIZE)	+ cpu * CACHELINE_SIZE);
}

struct inode_table {
	__le64 log_head;
};

static inline
struct inode_table *finefs_get_inode_table(struct super_block *sb, int cpu)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);

	if (cpu >= sbi->cpus)
		return NULL;

	return (struct inode_table *)((char *)finefs_get_block(sb,
		FINEFS_BLOCK_SIZE * 2) + cpu * CACHELINE_SIZE);
}

// BKDR String Hash Function
static inline unsigned long BKDRHash(const char *str, int length)
{
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned long hash = 0;
	int i;

	for (i = 0; i < length; i++) {
		hash = hash * seed + (*str++);
	}

	return hash;
}

/* uses CPU instructions to atomically write up to 8 bytes */
static inline void finefs_memcpy_atomic(void *dst, const void *src, u8 size)
{
	switch (size) {
		case 1: {
			volatile u8 *daddr = (volatile u8*)dst;
			const u8 *saddr = (const u8*)src;
			*daddr = *saddr;
			break;
		}
		case 2: {
			volatile __le16 *daddr = (volatile __le16 *)dst;
			const u16 *saddr = (const u16 *)src;
			*daddr = cpu_to_le16(*saddr);
			break;
		}
		case 4: {
			volatile __le32 *daddr = (volatile __le32 *)dst;
			const u32 *saddr = (const u32 *)src;
			*daddr = cpu_to_le32(*saddr);
			break;
		}
		case 8: {
			volatile __le64 *daddr = (volatile __le64 *)dst;
			const u64 *saddr = (const u64 *)src;
			*daddr = cpu_to_le64(*saddr);
			break;
		}
		default:
			rd_info("error: memcpy_atomic called with %d bytes\n",
					size);
			BUG();
	}
}

static force_inline int memcpy_to_pmem_nocache(void *dst, const void *src,
	unsigned int size, bool fence = false)
{
	int ret;

	// 从用户空间拷贝数据
	ret = __copy_from_user_inatomic_nocache(dst, src, size, fence);

	return ret;
}

/* assumes the length to be 4-byte aligned */
static inline void memset_nt(void *dest, uint32_t dword, size_t length)
{
	uint64_t dummy1, dummy2;
	uint64_t qword = ((uint64_t)dword << 32) | dword;

	asm volatile ("movl %%edx,%%ecx\n"
		"andl $63,%%edx\n"
		"shrl $6,%%ecx\n"
		"jz 9f\n"
		"1:      movnti %%rax,(%%rdi)\n"
		"2:      movnti %%rax,1*8(%%rdi)\n"
		"3:      movnti %%rax,2*8(%%rdi)\n"
		"4:      movnti %%rax,3*8(%%rdi)\n"
		"5:      movnti %%rax,4*8(%%rdi)\n"
		"8:      movnti %%rax,5*8(%%rdi)\n"
		"7:      movnti %%rax,6*8(%%rdi)\n"
		"8:      movnti %%rax,7*8(%%rdi)\n"
		"leaq 64(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 1b\n"
		"9:     movl %%edx,%%ecx\n"
		"andl $7,%%edx\n"
		"shrl $3,%%ecx\n"
		"jz 11f\n"
		"10:     movnti %%rax,(%%rdi)\n"
		"leaq 8(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 10b\n"
		"11:     movl %%edx,%%ecx\n"
		"shrl $2,%%ecx\n"
		"jz 12f\n"
		"movnti %%eax,(%%rdi)\n"
		"12:\n"
		: "=D"(dummy1), "=d" (dummy2) : "D" (dest), "a" (qword), "d" (length) : "memory", "rcx");
}

static inline struct finefs_file_write_entry *
finefs_get_write_entry(struct super_block *sb,
	struct finefs_inode_info *si, unsigned long blocknr)
{
	struct finefs_inode_info_header *sih = &si->header;
	struct finefs_file_write_entry *entry;

	entry = (struct finefs_file_write_entry *)radix_tree_lookup(&sih->tree, blocknr);

	return entry;
}

void finefs_print_curr_log_page(struct super_block *sb, u64 curr);
void finefs_print_finefs_log(struct super_block *sb,
	struct finefs_inode_info_header *sih, struct finefs_inode *pi);
int finefs_get_finefs_log_pages(struct super_block *sb,
	struct finefs_inode_info_header *sih, struct finefs_inode *pi);
void finefs_print_finefs_log_pages(struct super_block *sb,
	struct finefs_inode_info_header *sih, struct finefs_inode *pi);

// 获取偏移 pgoff 对应的块号
static inline unsigned long get_nvmm(struct super_block *sb,
	struct finefs_inode_info_header *sih,
	struct finefs_file_write_entry *data, unsigned long pgoff)
{
	if (data->pgoff > pgoff || (unsigned long)data->pgoff +
			(unsigned long)data->num_pages <= pgoff) {
		struct finefs_sb_info *sbi = FINEFS_SB(sb);
		struct finefs_inode *pi;
		u64 curr;

		curr = finefs_get_addr_off(sbi, data);
		rd_info("Entry ERROR: inode %lu, curr 0x%lx, pgoff %lu, "
			"entry pgoff %lu, num %u", sih->ino,
			curr, pgoff, data->pgoff, data->num_pages);
		pi = (struct finefs_inode *)finefs_get_block(sb, sih->pi_addr);
		finefs_print_finefs_log_pages(sb, sih, pi);
		finefs_print_finefs_log(sb, sih, pi);
		log_assert(0);
	}

	return (unsigned long)(data->block >> FINEFS_BLOCK_SHIFT) + pgoff
		- data->pgoff;
}

static inline u64 finefs_find_nvmm_block(struct super_block *sb,
	struct finefs_inode_info *si, struct finefs_file_write_entry *entry,
	unsigned long blocknr)
{
	unsigned long nvmm;

	if (!entry) {
		entry = finefs_get_write_entry(sb, si, blocknr);
		if (!entry)
			return 0;
	}

	nvmm = get_nvmm(sb, &si->header, entry, blocknr);
	return nvmm << FINEFS_BLOCK_SHIFT;
}

// static inline unsigned long finefs_get_cache_addr(struct super_block *sb,
// 	struct finefs_inode_info *si, unsigned long blocknr)
// {
// 	struct finefs_inode_info_header *sih = &si->header;
// 	unsigned long addr;

// 	addr = (unsigned long)radix_tree_lookup(&sih->cache_tree, blocknr);
// 	finefs_dbgv("%s: inode %lu, blocknr %lu, addr 0x%lx\n",
// 		__func__, sih->ino, blocknr, addr);
// 	return addr;
// }

/*
 * ROOT_INO: Start from FINEFS_SB_SIZE * 2
 */
static inline struct finefs_inode *finefs_get_basic_inode(struct super_block *sb,
	u64 inode_number)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);

	return (struct finefs_inode *)(sbi->virt_addr + FINEFS_SB_SIZE * 2 +
			 (inode_number - FINEFS_ROOT_INO) * FINEFS_INODE_SIZE);
}

/* If this is part of a read-modify-write of the inode metadata,
 * finefs_memunlock_inode() before calling! */
static inline struct finefs_inode *finefs_get_inode_by_ino(struct super_block *sb,
						  u64 ino)
{
	if (ino == 0 || ino >= FINEFS_NORMAL_INODE_START)
		return NULL;

	return finefs_get_basic_inode(sb, ino);
}

// 获取NVM中对应的inode地址
// inode存储着偏移，可以直接加上base得到地址
static inline struct finefs_inode *finefs_get_inode(struct super_block *sb,
	struct inode *inode)
{
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;

	return (struct finefs_inode *)finefs_get_block(sb, sih->pi_addr);
}

static inline int finefs_is_mounting(struct super_block *sb)
{
	struct finefs_sb_info *sbi = (struct finefs_sb_info *)sb->s_fs_info;
	return sbi->s_mount_opt & FINEFS_MOUNT_MOUNTING;
}

static inline void check_eof_blocks(struct super_block *sb,
		struct finefs_inode *pi, loff_t size)
{
	if ((pi->i_flags & cpu_to_le32(FINEFS_EOFBLOCKS_FL)) &&
		(size + sb->s_blocksize) > (le64_to_cpu(pi->i_blocks)
			<< sb->s_blocksize_bits))
		pi->i_flags &= cpu_to_le32(~FINEFS_EOFBLOCKS_FL);
}

enum finefs_new_inode_type {
	TYPE_CREATE = 0,
	TYPE_MKNOD,
	TYPE_SYMLINK,
	TYPE_MKDIR
};

// 返回下一个log的指针
static inline u64 next_log_page(struct super_block *sb, u64 curr_p)
{
	void *curr_addr = finefs_get_block(sb, curr_p);
	unsigned long page_tail = ((unsigned long)curr_addr & FINEFS_LOG_MASK)
					+ FINEFS_LOG_LAST_ENTRY;
	return ((struct finefs_inode_page_tail *)page_tail)->next_page;
}

static inline void finefs_set_next_page_address(struct super_block *sb,
	struct finefs_inode_log_page *curr_page, u64 next_page, int fence)
{
	curr_page->page_tail.next_page = next_page;
	finefs_flush_buffer(&curr_page->page_tail,
				sizeof(struct finefs_inode_page_tail), 0);
	if (fence)
		PERSISTENT_BARRIER();
}

#define	CACHE_ALIGN(p)	((p) & ~(CACHELINE_SIZE - 1))

// 判断能否容下size大小的entry
static inline bool is_last_entry(u64 curr_p, size_t size)
{
	unsigned int entry_end;

	entry_end = FINEFS_LOG_ENTRY_LOC(curr_p) + size;

	return entry_end > FINEFS_LOG_LAST_ENTRY;
}

// 判断curr_p位置是否到达log page的尾部，需要跳转到下一个page了？
static inline bool goto_next_page(struct super_block *sb, u64 curr_p)
{
	void *addr;
	u8 type;

	/* Each kind of entry takes at least 32 bytes */
	if (FINEFS_LOG_ENTRY_LOC(curr_p) + CACHELINE_SIZE > FINEFS_LOG_LAST_ENTRY)
		return true;

	addr = finefs_get_block(sb, curr_p);
	type = finefs_get_entry_type(addr);
	if (type == NEXT_PAGE)
		return true;

	return false;
}

static inline int is_dir_init_entry(struct super_block *sb,
	struct finefs_dentry *entry)
{
	if (entry->name_len == 1 && strncmp(entry->name, ".", 1) == 0)
		return 1;
	if (entry->name_len == 2 && strncmp(entry->name, "..", 2) == 0)
		return 1;

	return 0;
}

// #include "finefs/wprotect.h"

/* Function Prototypes */
extern void finefs_error_mng(struct super_block *sb, const char *fmt, ...);

/* balloc.c */
int finefs_alloc_block_free_lists(struct super_block *sb);
void finefs_delete_free_lists(struct super_block *sb);
struct finefs_range_node *finefs_alloc_blocknode(struct super_block *sb);
struct finefs_range_node *finefs_alloc_inode_node(struct super_block *sb);
void finefs_free_range_node(struct finefs_range_node *node);
void finefs_free_blocknode(struct super_block *sb,
	struct finefs_range_node *bnode);
void finefs_free_inode_node(struct super_block *sb,
	struct finefs_range_node *bnode);
extern void finefs_init_blockmap(struct super_block *sb, int recovery);
extern int finefs_free_data_blocks(struct super_block *sb, struct finefs_inode *pi,
	unsigned long blocknr, int num);
extern int finefs_free_log_blocks(struct super_block *sb, struct finefs_inode *pi,
	unsigned long blocknr, int num);
extern int finefs_new_data_blocks(struct super_block *sb, struct finefs_inode *pi,
	unsigned long *blocknr, unsigned int num, unsigned long start_blk,
	int zero, int cow);
extern int finefs_new_log_blocks(struct super_block *sb, struct finefs_inode *pi,
	unsigned long *blocknr, unsigned int num, int zero, int cpuid = -1);
extern unsigned long finefs_count_free_blocks(struct super_block *sb);
int finefs_search_inodetree(struct finefs_sb_info *sbi,
	unsigned long ino, struct finefs_range_node **ret_node);
inline int finefs_insert_blocktree(struct finefs_sb_info *sbi,
	struct rb_root *tree, struct finefs_range_node *new_node);
int finefs_insert_inodetree(struct finefs_sb_info *sbi,
	struct finefs_range_node *new_node, int cpu);
int finefs_find_free_slot(struct finefs_sb_info *sbi,
	struct rb_root *tree, unsigned long range_low,
	unsigned long range_high, struct finefs_range_node **prev,
	struct finefs_range_node **next);

/* bbuild.c */
inline void set_bm(unsigned long bit, struct scan_bitmap *bm,
	enum bm_type type);
int finefs_rebuild_inode(struct super_block *sb, struct finefs_inode_info *si,
	u64 pi_addr);
void finefs_save_blocknode_mappings_to_log(struct super_block *sb);
void finefs_save_inode_list_to_log(struct super_block *sb);
void finefs_init_header(struct super_block *sb,
	struct finefs_inode_info_header *sih, u16 i_mode);
int finefs_recovery(struct super_block *sb);

/*
 * Inodes and files operations
 */

/* dax.c */
int finefs_reassign_file_tree(struct super_block *sb,
	struct finefs_inode *pi, struct finefs_inode_info_header *sih,
	u64 begin_tail);
ssize_t finefs_dax_file_read(struct file *filp, char *buf, size_t len,
			    loff_t *ppos);
ssize_t finefs_dax_file_write(struct file *filp, const char *buf,
		size_t len, loff_t *ppos);
// int finefs_dax_get_block(struct inode *inode, sector_t iblock,
// 	struct buffer_head *bh, int create);
int finefs_dax_file_mmap(struct file *file, struct vm_area_struct *vma);

/* dir.c */
extern const struct file_operations finefs_dir_operations;
int finefs_append_root_init_entries(struct super_block *sb,
	struct finefs_inode *pi, u64 self_ino, u64 parent_ino, u64 *log_tail, int cpuid = -1);
int finefs_append_dir_init_entries(struct super_block *sb,
	struct finefs_inode *pi, struct inode* inode, u64 parent_ino, int cpuid = -1);
extern int finefs_add_dentry(struct dentry *dentry, u64 ino,
	int inc_link, u64 tail, u64 *new_tail);
extern int finefs_remove_dentry(struct dentry *dentry, int dec_link, u64 tail,
	u64 *new_tail);
void finefs_print_dir_tree(struct super_block *sb,
	struct finefs_inode_info_header *sih, unsigned long ino);
void finefs_delete_dir_tree(struct super_block *sb,
	struct finefs_inode_info_header *sih);
struct finefs_dentry *finefs_find_dentry(struct super_block *sb,
	struct finefs_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len);
int finefs_rebuild_dir_inode_tree(struct super_block *sb,
	struct finefs_inode *pi, u64 pi_addr,
	struct finefs_inode_info_header *sih);

/* file.c */
extern const struct inode_operations finefs_file_inode_operations;
extern const struct file_operations finefs_dax_file_operations;
int finefs_fsync(struct file *file, loff_t start, loff_t end, int datasync);

/* inode.c */
// extern const struct address_space_operations finefs_aops_dax;
int finefs_init_inode_inuse_list(struct super_block *sb);
extern int finefs_init_inode_table(struct super_block *sb);
unsigned long finefs_get_last_blocknr(struct super_block *sb,
	struct finefs_inode_info_header *sih);
int finefs_get_inode_address(struct super_block *sb, u64 ino,
	u64 *pi_addr, int extendable);
int finefs_set_blocksize_hint(struct super_block *sb, struct inode *inode,
	struct finefs_inode *pi, loff_t new_size);
struct finefs_file_write_entry *finefs_find_next_entry(struct super_block *sb,
	struct finefs_inode_info_header *sih, pgoff_t pgoff);
extern struct inode *finefs_iget(struct super_block *sb, unsigned long ino);
extern void finefs_evict_inode(struct inode *inode);
extern int finefs_write_inode(struct inode *inode, struct writeback_control *wbc);
extern void finefs_dirty_inode(struct inode *inode, int flags);
extern int finefs_notify_change(struct dentry *dentry, struct iattr *attr);
int finefs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat);
extern void finefs_set_inode_flags(struct inode *inode, struct finefs_inode *pi,
	unsigned int flags);
extern unsigned long finefs_find_region(struct inode *inode, loff_t *offset,
		int hole);
void finefs_apply_setattr_entry(struct super_block *sb, struct finefs_inode *pi,
	struct finefs_inode_info_header *sih,
	struct finefs_setattr_logentry *entry);
int finefs_free_inode_log(struct super_block *sb, struct finefs_inode *pi);
int finefs_allocate_inode_log_pages(struct super_block *sb,
	struct finefs_inode *pi, unsigned long num_pages,
	u64 *new_block, int cpuid=-1);
int finefs_delete_file_tree(struct super_block *sb,
	struct finefs_inode_info_header *sih, unsigned long start_blocknr,
	unsigned long last_blocknr, bool delete_nvmm, bool delete_mmap);
u64 finefs_get_append_head(struct super_block *sb, struct finefs_inode *pi,
	struct finefs_inode_info_header *sih, u64 tail, size_t size,
	int *extended);
u64 finefs_append_file_write_entry(struct super_block *sb, struct finefs_inode *pi,
	struct inode *inode, struct finefs_file_write_entry *data, u64 tail);
int finefs_rebuild_file_inode_tree(struct super_block *sb,
	struct finefs_inode *pi, u64 pi_addr,
	struct finefs_inode_info_header *sih);
u64 finefs_new_finefs_inode(struct super_block *sb, u64 *pi_addr);
extern struct inode *finefs_new_vfs_inode(enum finefs_new_inode_type,
	struct inode *dir, u64 pi_addr, u64 ino, umode_t mode,
	size_t size, dev_t rdev, const struct qstr *qstr);
int finefs_assign_write_entry(struct super_block *sb,
	struct finefs_inode *pi,
	struct finefs_inode_info_header *sih,
	struct finefs_file_write_entry *entry,
	bool free);

/* ioctl.c */
extern long finefs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
extern long finefs_compat_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg);
#endif

/* namei.c */
extern const struct inode_operations finefs_dir_inode_operations;
extern const struct inode_operations finefs_special_inode_operations;
extern struct dentry *finefs_get_parent(struct dentry *child);
int finefs_append_link_change_entry(struct super_block *sb,
	struct finefs_inode *pi, struct inode *inode, u64 tail, u64 *new_tail);
void finefs_apply_link_change_entry(struct finefs_inode *pi,
	struct finefs_link_change_entry *entry);

/* super.c */
extern struct super_block *finefs_read_super(struct super_block *sb, void *data,
	int silent);
extern int finefs_statfs(struct dentry *d, struct kstatfs *buf);
extern int finefs_remount(struct super_block *sb, int *flags, char *data);
// int finefs_check_integrity(struct super_block *sb,
// 	struct finefs_super_block *super);
// void *finefs_ioremap(struct super_block *sb, phys_addr_t phys_addr,
// 	ssize_t size);

/* symlink.c */
extern const struct inode_operations finefs_symlink_inode_operations;

/* sysfs.c */
// extern const char *proc_dirname;
// extern struct proc_dir_entry *finefs_proc_root;
// void finefs_sysfs_init(struct super_block *sb);
// void finefs_sysfs_exit(struct super_block *sb);

/* finefs_stats.c */
void finefs_get_timing_stats(void);
void finefs_print_timing_stats(struct super_block *sb);
void finefs_clear_stats(void);
void finefs_print_inode_log(struct super_block *sb, struct inode *inode);
void finefs_print_inode_log_pages(struct super_block *sb, struct inode *inode);
void finefs_print_free_lists(struct super_block *sb);

#endif /* __FINEFS_H */
