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

#include <map>
#include <unordered_set>

#include "finefs/journal.h"
#include "vfs/fs_cfg.h"
// #include "finefs/wprotect.h"
#include "finefs/finefs_def.h"
#include "finefs/stats.h"
#include "util/atomic.h"
#include "util/list.h"
#include "util/lock.h"
#include "util/log.h"
#include "util/radix-tree.h"
#include "util/rbtree.h"
#include "util/util.h"
#include "vfs/vfs.h"

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
#define FINEFS_DBGMASK_MMAPHUGE (0x00000001)
#define FINEFS_DBGMASK_MMAP4K (0x00000002)
#define FINEFS_DBGMASK_MMAPVERBOSE (0x00000004)
#define FINEFS_DBGMASK_MMAPVVERBOSE (0x00000008)
#define FINEFS_DBGMASK_VERBOSE (0x00000010)
#define FINEFS_DBGMASK_TRANSACTION (0x00000020)

#define finefs_dbg_mmap4k(s, args...) \
    ((finefs_dbgmask & FINEFS_DBGMASK_MMAP4K) ? finefs_dbg(s, args) : 0)
#define finefs_dbg_mmapv(s, args...) \
    ((finefs_dbgmask & FINEFS_DBGMASK_MMAPVERBOSE) ? finefs_dbg(s, args) : 0)
#define finefs_dbg_mmapvv(s, args...) \
    ((finefs_dbgmask & FINEFS_DBGMASK_MMAPVVERBOSE) ? finefs_dbg(s, args) : 0)

#define finefs_dbg_verbose(s, args...) \
    ((finefs_dbgmask & FINEFS_DBGMASK_VERBOSE) ? finefs_dbg(s, ##args) : 0)
#define finefs_dbgv(s, args...) finefs_dbg_verbose(s, ##args)
#define finefs_dbg_trans(s, args...) \
    ((finefs_dbgmask & FINEFS_DBGMASK_TRANSACTION) ? finefs_dbg(s, ##args) : 0)

#define finefs_set_bit __test_and_set_bit_le
#define finefs_clear_bit __test_and_clear_bit_le
#define finefs_find_next_zero_bit find_next_zero_bit_le

#define clear_opt(o, opt) (o &= ~FINEFS_MOUNT_##opt)
#define set_opt(o, opt) (o |= FINEFS_MOUNT_##opt)
#define test_opt(sb, opt) (FINEFS_SB(sb)->s_mount_opt & FINEFS_MOUNT_##opt)

#define FINEFS_LARGE_INODE_TABLE_SIZE (0x200000)
/* FINEFS size threshold for using 2M blocks for inode table */
#define FINEFS_LARGE_INODE_TABLE_THREASHOLD (0x20000000)
/*
 * finefs inode flags
 *
 * FINEFS_EOFBLOCKS_FL	There are blocks allocated beyond eof
 */
#define FINEFS_EOFBLOCKS_FL 0x20000000
/* Flags that should be inherited by new inodes from their parent. */
#define FINEFS_FL_INHERITED                                                               \
    (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL | \
     FS_COMPRBLK_FL | FS_NOCOMP_FL | FS_JOURNAL_DATA_FL | FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define FINEFS_REG_FLMASK (~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define FINEFS_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)
#define FINEFS_FL_USER_VISIBLE (FS_FL_USER_VISIBLE | FINEFS_EOFBLOCKS_FL)

/* IOCTLs */
#define FINEFS_PRINT_TIMING 0xBCD00010
#define FINEFS_CLEAR_STATS 0xBCD00011
#define FINEFS_PRINT_LOG 0xBCD00013
#define FINEFS_PRINT_LOG_BLOCKNODE 0xBCD00014
#define FINEFS_PRINT_LOG_PAGES 0xBCD00015
#define FINEFS_PRINT_FREE_LISTS 0xBCD00018

#define READDIR_END (ULONG_MAX)
#define INVALID_CPU (-1)
#define SHARED_CPU (65536)
#define FREE_BATCH (16)

/************************ 类型定义 *******************************/

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
    struct rb_root block_free_tree;
    struct finefs_range_node *first_node;  // 红黑树按序的第一个node？
    unsigned long block_start;
    unsigned long block_end;
    unsigned long num_free_blocks;  // 初始化 sbi->num_blocks / sbi->cpus。空闲的page个数
    unsigned long num_blocknode;    // 红黑树的node个数

    /* Statistics */
    unsigned long alloc_log_count;   // 分配的log个数
    unsigned long alloc_data_count;  // 分配data的次数
    unsigned long free_log_count;
    unsigned long free_data_count;
    unsigned long alloc_log_pages;   // 用于分配log的page总数
    unsigned long alloc_data_pages;  // 用于分配data的page总数
    unsigned long freed_log_pages;
    unsigned long freed_data_pages;

    u64 padding[8]; /* Cache line break */
};

extern struct kmem_cache *finefs_slab_page_cachep;
static inline struct slab_page *finefs_alloc_slab_page(struct super_block *sb) {
    struct slab_page *p;
    p = (struct slab_page *)kmem_cache_alloc(finefs_slab_page_cachep);
    return p;
}
static inline void finefs_free_slab_page(struct slab_page *node) {
    kmem_cache_free(finefs_slab_page_cachep, node);
}

#define SLAB_MIN_BITS CACHELINE_SHIFT
#define SLAB_MIN_SIZE (1 << SLAB_MIN_BITS)
#define SLAB_MAX_BITS (FINEFS_BLOCK_SHIFT - 1)
#define SLAB_MAX_SIZE (1 << SLAB_MAX_BITS)
#define SLAB_LEVELS (SLAB_MAX_SIZE - SLAB_MIN_SIZE + 1)

struct slab_page {
    unsigned long block_off;  // page 不能跨线程
    unsigned long bitmap;     // 标志哪一个slab是空闲的
    u32 num_free_slab;        // 空闲的slab个数
    u32 slab_bits;
    struct list_head entry;
};

struct slab_free_list {
    u32 slab_bits;
    u32 next_alloc_pages;  // 下一次分配的pages个数
    u32 page_num;
    u32 next_slab_idx;  // 下一次分配的page内slab序号
    slab_page *cur_page;
    struct list_head page_head;
    std::map<u64, slab_page *> page_off_2_slab_page;

    slab_free_list() {
        page_num = 0;
        next_slab_idx = 0;
        next_alloc_pages = 1;
        cur_page = nullptr;
        INIT_LIST_HEAD(&page_head);
    }
    ~slab_free_list() {
        log_assert(page_num && cur_page || !page_num && !cur_page);
        slab_page *cur;
        for (auto p : page_off_2_slab_page) {
            cur = p.second;
            finefs_free_slab_page(cur);
            --page_num;
        }
        log_assert(page_num == 0);
    }
};

struct slab_heap {
    spinlock_t slab_lock;
    slab_free_list slab_lists[SLAB_LEVELS];

    slab_heap() {
        spin_lock_init(&slab_lock);
        for (int i = 0; i < SLAB_LEVELS; ++i) {
            u32 slab_bits = i + SLAB_MIN_BITS;
            slab_lists[i].slab_bits = slab_bits;
        }
    }
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
    void *virt_addr;  // NVM映射的虚拟地址

    unsigned long num_blocks;  // 整个NVM的page的个数

    /*
     * Backing store option:
     * 1 = no load, 2 = no store,
     * else do both
     */
    unsigned int finefs_backing_option;

    /* Mount options */
    unsigned long bpi;
    unsigned long num_inodes;
    unsigned long blocksize;  // block 大小，block和page是不同的概念。block可以由多个连续的page组成
    unsigned long initsize;  // NVM盘大小
    unsigned long s_mount_opt;
    // kuid_t		uid;    /* Mount uid for root directory */
    // kgid_t		gid;    /* Mount gid for root directory */
    umode_t mode; /* Mount mode for root directory */
    atomic_t next_generation;
    /* inode tracking */
    unsigned long s_inodes_used_count;  // 已使用的inode个数
    unsigned long reserved_blocks;      // 保留的block个数

    mutex_t s_lock; /* protects the SB's buffer-head */

    int cpus;  // 在线的cpu个数
    // struct proc_dir_entry *s_proc;  // 系统的文件目录

    /* ZEROED page for cache page initialized */
    // void *zeroed_page;  // 缓存第一page？

    /* Per-CPU journal lock */
    spinlock_t *journal_locks;

    /* Per-CPU inode map */
    struct inode_map *inode_maps;

    /* Decide new inode map id */
    // TODO： 需要原子变量递增吧
    unsigned long map_id;

    /* Per-CPU free block list */
    struct free_list *data_free_lists;
    struct free_list *log_free_lists;
    struct slab_heap *slab_heaps;

    /* Shared free block list */
    unsigned long per_list_blocks;      // 每个cpu的block个数 sbi->num_blocks / sbi->cpus;
    unsigned long per_list_log_blocks;      // 每个cpu的block个数 sbi->num_blocks / sbi->cpus;
    unsigned long per_list_data_blocks;      // 每个cpu的block个数 sbi->num_blocks / sbi->cpus;
    struct free_list shared_free_list;  // 平均分不完全时，管理剩下多余的
};

struct finefs_range_node_lowhigh {
    __le64 range_low;  // 保存到NVM时，高1bytes保存cpuid
    __le64 range_high;
};

#define RANGENODE_PER_PAGE 254

struct finefs_range_node {
    struct rb_node node;
    unsigned long range_low;
    unsigned long range_high;
};

// 这是inode的在内存中的数据结构
// 这是针对某个inode， 包含管理的一些统计信息
struct finefs_inode_info_header {
    // 文件数据是按照blocknr来索引的？感觉还是红黑树，或者跳表好
    spinlock_t tree_lock;
    struct radix_tree_root tree; /* Dir name entry tree root 或者文件数据*/
    // set是inode独享的，后台gc不会修改它，因此它不会出现冲突
    std::unordered_set<void *> cachelines_to_flush;

    // struct radix_tree_root cache_tree;	/* Mmap cache tree root */
    unsigned short i_mode; /* Dir or file? */
    unsigned long i_size;
    // 以上 finefs_init_header 中初始化
    // 下面两个外部初始化
    unsigned long ino;
    unsigned long pi_addr;
    // unsigned long mmap_pages;	/* Num of mmap pages */
    // unsigned long low_dirty;	/* Mmap dirty low range */
    // unsigned long high_dirty;	/* Mmap dirty high range */

    // 下面是统计的信息，不用初始化，随着操作而改变
    // 对于inode，写log entry的时候才进行统计
    // TODO: 额外添加全局的统计的数据，每个线程的已分配的log个数、有效的entry_bytes等等
    // 每个线程的slab 分配器也需要添加统计数据
    // 每个线程log时，下面的三个都需要去除
    unsigned long h_log_tail;
    unsigned int log_pages;       /* Num of log pages */
    unsigned int log_valid_bytes; /* For thorough GC, log page中有效entry的总字节数*/

    // finefs_init_header 中初始化
    unsigned long h_blocks;
    unsigned int h_slabs;
    unsigned int h_slab_bytes;
    unsigned long h_ts;

    // TODO: gc need lock，所以目前后台只负责删除inode的回收、log page的垃圾回收
    //
    // TODO:快速gc其实也可以放后台，用每个线程的set，标志当前线程导致失效的log page有哪些，
    // 然后由后台线程统一回收，但我感觉没有太大的必要。

    /*
     * 后台gc时也会修改下面两个值，因此需要一个lock互斥
     */

    // 更新：
    // 注意set应该记录在每个inode中，write操作时也需要将
    // 之前失效的entry bitmap所在的cacheline加入到set)，
    // 1. 写setattr entry，flush+fence
    // 2. 应用entry，更新set记录
    // 3. 放到batch队列。batch的方式回收entry。
    // 4. 回收时，要保留最后一个entry，flush set中的cacheline，再将旧的entry失效

    // 对于last_link_change，不需要batch
    // 1. 写log，
    // 2. 将前一个last_link_change entry失效
    // 3. 更新last idx

    // batch设置为64，刚好一个page，而且需要通过锁管理，防止和后台gc竞争。

    // 随着操作的进行而修改
    // 系统关闭时, 应用所有队列的log h_entry_p, 但保留最后一个

    // 注意，ftruncate时，如果设置的size比当前文件的大小要大，
    // 那么应用后，是可以直接丢弃该entry的，因为它不影响任何的write entry
    // 而不需要放在batch队列
    spinlock_t h_entry_lock;
    u64 h_setattr_entry_p[FINEFS_INODE_META_FLUSH_BATCH];
    bool h_can_just_drop;  // h_setattr_entry_p中的entry可否直接丢弃
    int cur_setattr_idx;   /* Last setattr entry index*/
    u64 last_link_change;  /* Last link change entry index */
};

static force_inline void finefs_sih_bitmap_cache_flush(finefs_inode_info_header *sih, bool fence) {
    for (auto p : sih->cachelines_to_flush) {
        finefs_flush_cacheline(p, 0);
    }
    if (!sih->cachelines_to_flush.empty() && fence) PERSISTENT_BARRIER();
    sih->cachelines_to_flush.clear();
}

struct finefs_inode_info {
    struct finefs_inode_info_header header;
    struct inode vfs_inode;
};

extern int measure_timing;

struct slab_heap;
static inline u64 finefs_get_addr_off(struct super_block *sb, const void *addr);
static inline u8 finefs_get_entry_type(void *p);

/* ======================= block size ========================= */

extern unsigned int finefs_blk_type_to_shift[FINEFS_BLOCK_TYPE_MAX];
extern unsigned int finefs_blk_type_to_size[FINEFS_BLOCK_TYPE_MAX];
extern unsigned int finefs_blk_type_to_blk_num[FINEFS_BLOCK_TYPE_MAX];

static inline unsigned int finefs_inode_blk_shift(struct finefs_inode *pi) {
    return finefs_blk_type_to_shift[pi->i_blk_type];
}

static inline uint32_t finefs_inode_blk_size(struct finefs_inode *pi) {
    return finefs_blk_type_to_size[pi->i_blk_type];
}

// 获取该枚举类型，对应的block个数
static inline unsigned long finefs_get_numblocks(unsigned short btype) {
    return finefs_blk_type_to_blk_num[btype];
}

static inline unsigned long finefs_get_blocknr(struct super_block *sb, u64 block,
                                               unsigned short btype) {
    return block >> FINEFS_BLOCK_SHIFT;
}

static inline struct finefs_sb_info *FINEFS_SB(struct super_block *sb) {
    return (struct finefs_sb_info *)sb->s_fs_info;
}

static inline struct finefs_inode_info *FINEFS_I(struct inode *inode) {
    return container_of(inode, struct finefs_inode_info, vfs_inode);
}

/* If this is part of a read-modify-write of the super block,
 * finefs_memunlock_super() before calling! */
static inline struct finefs_super_block *finefs_get_super(struct super_block *sb) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);

    return (struct finefs_super_block *)sbi->virt_addr;
}

/* If this is part of a read-modify-write of the block,
 * finefs_memunlock_block() before calling! */
// 获取block的映射地址
static inline void *finefs_get_block(struct super_block *sb, u64 block) {
    struct finefs_super_block *ps = finefs_get_super(sb);

    return block ? ((char *)ps + block) : NULL;
}

static force_inline int get_cpuid(struct finefs_sb_info *sbi, unsigned long blocknr) {
    int cpuid;

    cpuid = blocknr / sbi->per_list_blocks;

    if (cpuid >= sbi->cpus) cpuid = SHARED_CPU;

    return cpuid;
}

static force_inline bool finefs_is_log_area(struct finefs_sb_info *sbi, unsigned long blocknr) {
    unsigned long blocknr_in_cpu = blocknr % sbi->per_list_blocks;
    return blocknr_in_cpu < sbi->per_list_log_blocks;
}

static inline struct finefs_super_block *finefs_get_redund_super(struct super_block *sb) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);

    return (struct finefs_super_block *)(sbi->virt_addr + FINEFS_SB_SIZE);
}

static inline u64 finefs_get_addr_off(struct finefs_sb_info *sbi, const void *addr) {
    dlog_assert((addr >= sbi->virt_addr) &&
                ((char *)addr < ((char *)(sbi->virt_addr) + sbi->initsize)));
    return (u64)((char *)addr - (char *)sbi->virt_addr);
}

static inline u64 finefs_get_addr_off(struct super_block *sb, const void *addr) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    dlog_assert((addr >= sbi->virt_addr) &&
                ((char *)addr < ((char *)(sbi->virt_addr) + sbi->initsize)));
    return (u64)((char *)addr - (char *)sbi->virt_addr);
}

// 获取block的nvm相对偏移
static inline u64 finefs_get_block_off(struct super_block *sb, unsigned long blocknr,
                                       unsigned short btype) {
    return (u64)blocknr << FINEFS_BLOCK_SHIFT;
}

static inline struct free_list *finefs_get_log_free_list(struct super_block *sb, int cpu) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);

    if (cpu < sbi->cpus)
        return &sbi->log_free_lists[cpu];
    else {
        return nullptr;
    }
}

static inline struct free_list *finefs_get_data_free_list(struct super_block *sb, int cpu) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);

    if (cpu < sbi->cpus)
        return &sbi->data_free_lists[cpu];
    else {
        rdv_verb("%s: cpu:%d, sbi->cpus:%d", __func__, cpu, sbi->cpus);
        return &sbi->shared_free_list;
    }
}

static inline struct slab_heap *finefs_get_slab_heap(struct super_block *sb, int cpu) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);

    if (cpu < sbi->cpus)
        return &sbi->slab_heaps[cpu];
    else {
        r_error("%s: cpu:%d, sbi->cpus:%d", __func__, cpu, sbi->cpus);
        log_assert(0);
        return nullptr;
    }
}

/************************* log page ***************************/

struct finefs_inode_page_tail {
    __le64 paddings[3];
    __le32 padding;
    __le32 valid_num;  // atomic，减为0的线程负责回收
    __le64 bitmap;
    __le64 log_version;
    struct finefs_log_page_link page_link;
} __attribute((__packed__));

/* FINEFS_LOG_BLOCK_TYPE 和 FINEFS_LOG_NUM_BLOCKS 需要一起修改 */
// log的大小必须等于基本lock大小，否则一些掩码的操作会存在问题，
// FIXME：或者改用伙伴算法，每次分配的大小都按照大小对齐
#define FINEFS_LOG_BLOCK_TYPE FINEFS_DEFAULT_DATA_BLOCK_TYPE
#define FINEFS_LOG_NUM_BLOCKS (1)
#define FINEFS_LOG_SHIFT (FINEFS_BLOCK_SHIFT)
#define FINEFS_LOG_SIZE (1 << FINEFS_LOG_SHIFT)
#define FINEFS_LOG_UMASK (FINEFS_LOG_SIZE - 1)
#define FINEFS_LOG_MASK (~(FINEFS_LOG_SIZE - 1))
#define FINEFS_LOG_LAST_ENTRY (FINEFS_LOG_SIZE - sizeof(struct finefs_inode_page_tail))
#define FINEFS_LOG_TAIL(p) (((p)&FINEFS_LOG_MASK) + FINEFS_LOG_LAST_ENTRY)
#define FINEFS_LOG_LINK_PAGE_OFF (FINEFS_LOG_SIZE - sizeof(struct finefs_log_page_link))
#define FINEFS_LOG_LINK_NVM_OFF(cur_p) (((cur_p)&FINEFS_LOG_MASK) + FINEFS_LOG_LINK_PAGE_OFF)

#define FINEFS_LOG_BLOCK_OFF(p) ((p)&FINEFS_LOG_MASK)
#define FINEFS_LOG_ENTRY_LOC(p) ((p)&FINEFS_LOG_UMASK)

/* Fit in PAGE_SIZE */
// TODO: 增大page的大小
struct finefs_inode_log_page {
    char padding[FINEFS_LOG_LAST_ENTRY];
    struct finefs_inode_page_tail page_tail;
} __attribute((__packed__));

static force_inline void finefs_log_link_init(struct finefs_log_page_link *curr_link) {
    curr_link->prev_page_ = 0;
    curr_link->next_page_ = 0;
}

// static force_inline bool finefs_log_is_link(u64 cur_link) {
// 	return (cur_link & FINEFS_LOG_UMASK) == FINEFS_LOG_LINK_PAGE_OFF;
// }

static force_inline bool finefs_log_link_is_end(u64 cur_link) { return cur_link == 0; }

// 根据link全局偏移，得到finefs_log_page_link*
static force_inline struct finefs_log_page_link *finefs_log_link_addr(struct super_block *sb,
                                                                      u64 cur_page) {
    // dlog_assert(finefs_log_is_link(next_link));
    finefs_inode_log_page *curr_page = (finefs_inode_log_page *)finefs_get_block(sb, cur_page);
    return &curr_page->page_tail.page_link;
}

static force_inline finefs_inode_log_page *finefs_log_page_addr(struct super_block *sb,
                                                                u64 cur_page) {
    return (finefs_inode_log_page *)finefs_get_block(sb, cur_page);
}

// static force_inline u64 finefs_log_next_link_from_link(struct super_block *sb, u64 cur_link)
// {
// 	dlog_assert(!finefs_log_link_is_end(cur_link));
// 	finefs_log_link_addr(sb, cur_link)->next_page_;
// }

// static force_inline u64 finefs_log_next_page_from_link(struct super_block *sb, u64 cur_link)
// {
// 	// dlog_assert(!finefs_log_link_is_end(cur_link));
// 	return finefs_log_link_addr(sb, cur_link)->next_page_;
// }

// 返回下一个log的起始偏移
static force_inline u64 finefs_log_next_page(struct super_block *sb, u64 curr_p) {
    u64 cur_page = curr_p & FINEFS_LOG_MASK;
    return finefs_log_page_addr(sb, cur_page)->page_tail.page_link.next_page_;
}

// 返回下一个log的link位置
// static force_inline u64 finefs_log_next_link(struct super_block *sb, u64 curr_p)
// {
// 	u64 cur_link = FINEFS_LOG_LINK_NVM_OFF(curr_p);
// 	return finefs_log_next_link_from_link(sb, cur_link);
// }

#define FINEFS_LOG_NEXT_PAGE(curr_page) (curr_page->page_tail.page_link.next_page_)

static force_inline u64 finefs_log_get_next_page(struct super_block *sb, u64 cur_page) {
    return FINEFS_LOG_NEXT_PAGE(finefs_log_page_addr(sb, cur_page));
}

/****************************** log tail *********************/

static force_inline void finefs_link_set_next_page(struct super_block *sb,
                                                   struct finefs_log_page_link *curr_link,
                                                   u64 next_page, int fence) {
    if (next_page) {
        u64 cur_page = finefs_get_addr_off(sb, curr_link) - FINEFS_LOG_LINK_PAGE_OFF;
        finefs_log_link_addr(sb, next_page)->prev_page_ = cur_page;
    }
    curr_link->next_page_ = next_page;
    finefs_flush_cacheline(curr_link, fence);
}

static force_inline void finefs_log_delete(struct super_block *sb,
                                           struct finefs_inode_log_page *curr_page) {
    dlog_assert(!finefs_log_link_is_end(curr_page->page_tail.page_link.prev_page_));
    finefs_log_page_link *prev_link =
        finefs_log_link_addr(sb, curr_page->page_tail.page_link.prev_page_);
    finefs_link_set_next_page(sb, prev_link, curr_page->page_tail.page_link.next_page_, 1);
}

static inline void finefs_log_set_next_page(struct super_block *sb,
                                            struct finefs_inode_log_page *curr_page, u64 next_page,
                                            int fence) {
    dlog_assert((next_page & FINEFS_LOG_UMASK) == 0);
    finefs_link_set_next_page(sb, &(curr_page->page_tail.page_link), next_page, fence);
}

#define FINEFS_LOG_ENTRY_VALID_NUM_INIT (63)
#define FINEFS_LOG_BITMAP_INIT ((~(0ul)) >> 1)

static inline void finefs_log_page_tail_init(struct super_block *sb,
                                             struct finefs_inode_log_page *curr_page, u64 next_page,
                                             bool for_gc, int fence) {
    dlog_assert((next_page & FINEFS_LOG_UMASK) == 0);
    curr_page->page_tail.valid_num = FINEFS_LOG_ENTRY_VALID_NUM_INIT;
    curr_page->page_tail.bitmap = FINEFS_LOG_BITMAP_INIT;
    if (for_gc) {
        curr_page->page_tail.log_version = 0;
    } else {
        curr_page->page_tail.log_version++;
    }
    finefs_log_set_next_page(sb, curr_page, next_page, fence);
}

static force_inline bool finefs_log_page_tail_remain_init(struct super_block *sb,
                                                          struct finefs_inode_log_page *curr_page) {
    return (curr_page->page_tail.valid_num == FINEFS_LOG_ENTRY_VALID_NUM_INIT) &&
           (curr_page->page_tail.bitmap == FINEFS_LOG_BITMAP_INIT);
}

#define FINEFS_LOG_ENTRY_NR(entry) ((((uintptr_t)entry) & FINEFS_LOG_UMASK) >> CACHELINE_SHIFT)

// 判断能否容下size大小的entry
static inline bool is_last_entry(u64 curr_p, size_t size) {
    unsigned int entry_end;

    entry_end = FINEFS_LOG_ENTRY_LOC(curr_p) + size;

    return entry_end > FINEFS_LOG_LAST_ENTRY;
}

/***************************** log entry *******************************/

/* Inode entry in the log */
// 占8bits
enum finefs_entry_type {
    // TODO: 暂时实现write的事务，其他的有待实现
    FILE_PAGES_WRITE = 1,
    FILE_SMALL_WRITE,
    SET_ATTR,
    DIR_LOG,  // 新建一个dir
    LINK_CHANGE,
    NEXT_PAGE,
    // 具体操作类型，占6bit，最多支持 1<<6=64 种log
    LOG_ENTRY_TYPE_MASK = (1 << 6) - 1,
    // 最后2bit表示事务的起始
    TX_BEGIN = 1 << 6,
    TX_END = 1 << 7,
    TX_ATOMIC = TX_BEGIN | TX_END,

    TX_BEGIN_FILE_PAGES_WRITE = TX_BEGIN | FILE_PAGES_WRITE,
    TX_END_FILE_PAGES_WRITE = TX_END | FILE_PAGES_WRITE,

    TX_BEGIN_FILE_SMALL_WRITE = TX_BEGIN | FILE_SMALL_WRITE,
    TX_END_FILE_SMALL_WRITE = TX_END | FILE_SMALL_WRITE,

    TX_BEGIN_DIR_LOG = TX_BEGIN | DIR_LOG,
    TX_END_DIR_LOG = TX_END | DIR_LOG,      // root初始化和，mkdir时用到

    TX_END_LINK_CHANGE = TX_END | LINK_CHANGE, // 创建文件、删除文件和删除目录时用到

    TX_ATOMIC_FILE_PAGES_WRITE = TX_ATOMIC | FILE_PAGES_WRITE,
    TX_ATOMIC_FILE_SMALL_WRITE = TX_ATOMIC | FILE_SMALL_WRITE,
    TX_ATOMIC_SET_ATTR = TX_ATOMIC | SET_ATTR,

};

struct finefs_file_pages_write_entry;
struct finefs_file_small_write_entry;

struct finefs_file_small_entry {
    u32 slab_bits;
    u32 bytes;
    u64 file_off;
    const char *nvm_data;
    finefs_file_small_write_entry *nvm_entry_p;
#ifdef FINEFS_SMALL_ENTRY_USE_LIST
    list_head entry;
#endif
};

// TODO: use jemalloc
struct finefs_file_page_entry {
    int num_small_write;
#ifdef FINEFS_SMALL_ENTRY_USE_LIST
    list_head small_write_head;
#else
    std::map<u64, finefs_file_small_entry *> file_off_2_small;
#endif

    // TODO: page cache for small write
    // cache page in dram befor write
    u64 file_pgoff;  // page 偏移（编号）
    void *nvm_block_p;
    finefs_file_pages_write_entry *nvm_entry_p;
};

static force_inline void finefs_page_write_entry_init(finefs_file_page_entry *page_entry,
                                                      u64 pgoff) {
    page_entry->num_small_write = 0;
#ifdef FINEFS_SMALL_ENTRY_USE_LIST
    INIT_LIST_HEAD(&page_entry->small_write_head);
#else
    new (&page_entry->file_off_2_small) std::map<u64, finefs_file_small_entry *>();
#endif

    page_entry->file_pgoff = pgoff;
    page_entry->nvm_block_p = nullptr;
    page_entry->nvm_entry_p = nullptr;
}

void finefs_page_write_entry_set(finefs_file_page_entry *entry,
                                 finefs_file_pages_write_entry *nvm_entry_p, u64 file_pgoff,
                                 void *nvm_block_p);
bool finefs_page_entry_is_right(super_block *sb, finefs_file_page_entry *page_entry);

extern struct kmem_cache *finefs_file_page_entry_cachep;
static inline struct finefs_file_page_entry *finefs_alloc_page_entry(struct super_block *sb) {
    struct finefs_file_page_entry *p;
    p = (struct finefs_file_page_entry *)kmem_cache_alloc(finefs_file_page_entry_cachep);
    return p;
}
static inline void finefs_free_page_entry(struct finefs_file_page_entry *node) {
    kmem_cache_free(finefs_file_page_entry_cachep, node);
}

extern struct kmem_cache *finefs_file_small_entry_cachep;
static inline struct finefs_file_small_entry *finefs_alloc_small_entry(struct super_block *sb) {
    struct finefs_file_small_entry *p;
    p = (struct finefs_file_small_entry *)kmem_cache_alloc(finefs_file_small_entry_cachep);
    return p;
}
static inline void finefs_free_small_entry(struct finefs_file_small_entry *node) {
    kmem_cache_free(finefs_file_small_entry_cachep, node);
}

struct finefs_file_pages_write_entry {
    u8 entry_type;
    u8 is_old;  // 当前这个entry是否因为其他写导致不是最新的数据
    __le16 padding;
    /* For both ctime and mtime */
    __le32 mtime;
    __le64 block;          // 起始block的NVM偏移地址
    __le64 pgoff;          // page 偏移(编号)
    __le32 num_pages;      // 写的page个数
    __le32 invalid_pages;  // 覆盖写导致无效的page个数？
    __le64 size;           // 文件的大小
    __le64 finefs_ino;     // 所属于的ino
    __le64 entry_ts;
    __le64 entry_version;
} __attribute((__packed__));

struct finefs_file_small_write_entry {
    u8 entry_type;
    u8 slab_bits;  // 从slab_off总空间大小
    __le16 bytes;  // 从slab_off开始的有效字节数
    /* For both ctime and mtime */
    __le32 mtime;
    __le64 slab_off;    // NVM偏移地址
    __le64 file_off;    // 文件的偏移
    __le64 size;        // 文件的大小, 不要移动定义位置
    __le64 finefs_ino;  // 所属于的ino
    __le64 entry_ts;
    u8 padding2[8];
    __le64 entry_version;
} __attribute((__packed__));

static force_inline u8 finefs_get_entry_type(void *p) { return *(u8 *)p; }

static force_inline u8 finefs_get_entry_type_except_tx(void *p) {
    return (*(u8 *)p) & LOG_ENTRY_TYPE_MASK;
}

static force_inline void finefs_set_entry_type(void *p, enum finefs_entry_type type) {
    *(u8 *)p = type;
}

/*
 * Structure of a directory log entry in FINEFS.
 * Update DIR_LOG_REC_LEN if modify this struct!
 */
struct finefs_dentry {
    u8 entry_type;
    u8 name_len;         /* length of the dentry name */
    __le16 links_count;  // 自身的link count
    __le32 mtime;        /* For both mtime and ctime */
    union {
        __le64 name_off__;              // TODO: 变长文件名
        char name[FINEFS_NAME_LEN + 1]; /* File name */
    } __attribute((__packed__));
    __le64 ino;         /* inode no pointed to by this entry, 0表示该dentry被删除*/
    __le64 finefs_ino;  // 所属于的ino
    __le64 entry_ts;
    // __le64	size;             // 目录不需要大小，去除
    __le64 entry_version;
} __attribute((__packed__));

#define FINEFS_DIR_PAD 8 /* Align to 8 bytes boundary */
#define FINEFS_DIR_ROUND (FINEFS_DIR_PAD - 1)
// #define FINEFS_DIR_LOG_REC_LEN(name_len)	(((name_len) + 29 + FINEFS_DIR_ROUND) & \
// 				      ~FINEFS_DIR_ROUND)
#define FINEFS_DIR_LOG_REC_LEN(name_len) (sizeof(struct finefs_dentry))

/* Struct of inode attributes change log (setattr) */
struct finefs_setattr_logentry {
    u8 entry_type;
    u8 attr;  // 表示哪些属性有效
    __le16 mode;
    __le32 uid;
    __le32 gid;
    __le32 atime;
    __le32 mtime;
    __le32 ctime;
    __le64 size;
    __le64 finefs_ino;  // 所属于的ino
    __le64 entry_ts;
    u8 padding[8];
    __le64 entry_version;
} __attribute((__packed__));

struct finefs_link_change_entry {
    u8 entry_type;
    u8 padding;
    __le16 links;  // 等于0表示删除
    __le32 ctime;
    __le32 flags;
    __le32 generation;
    __le64 finefs_ino;  // 所属于的ino
    __le64 entry_ts;
    __le64 paddings[3];
    __le64 entry_version;
} __attribute((__packed__));

// 判断curr_p位置是否到达log page的尾部，需要跳转到下一个page了？
static inline bool goto_next_page(struct super_block *sb, u64 curr_p) {
    void *addr;
    u8 type;

    /* Each kind of entry takes at least 32 bytes */
    if (FINEFS_LOG_ENTRY_LOC(curr_p) + CACHELINE_SIZE > FINEFS_LOG_LAST_ENTRY) return true;

    addr = finefs_get_block(sb, curr_p);
    type = finefs_get_entry_type(addr);
    if (type == NEXT_PAGE) {
        log_assert(0);
        return true;
    }

    return false;
}

enum alloc_type {
    LOG = 1,
    DATA,
};

#define MMAP_WRITE_BIT 0x20UL  // mmaped for write
#define IS_MAP_WRITE(p) ((p) & (MMAP_WRITE_BIT))
#define MMAP_ADDR(p) ((p) & (PAGE_MASK))

static inline void finefs_update_tail(struct finefs_inode *pi, u64 new_tail) {
    log_assert(0);
    timing_t update_time;

    FINEFS_START_TIMING(update_tail_t, update_time);

    PERSISTENT_BARRIER();
    pi->log_tail = new_tail;
    finefs_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 1);

    FINEFS_END_TIMING(update_tail_t, update_time);
}

/* symlink.c */
// int finefs_block_symlink(struct super_block *sb, struct finefs_inode *pi,
// 	struct inode *inode, u64 log_block,
// 	unsigned long name_blocknr, const char *symname, int len);

/* Inline functions start here */

/* Mask out flags that are inappropriate for the given type of inode. */
static inline __le32 finefs_mask_flags(umode_t mode, __le32 flags) {
    flags &= cpu_to_le32(FINEFS_FL_INHERITED);
    if (S_ISDIR(mode))
        return flags;
    else if (S_ISREG(mode))
        return flags & cpu_to_le32(FINEFS_REG_FLMASK);
    else
        return flags & cpu_to_le32(FINEFS_OTHER_FLMASK);
}

static inline void finefs_update_volatile_tail(struct finefs_inode_info_header *sih, u64 new_tail) {
    // timing_t update_time;

    // FINEFS_START_TIMING(update_tail_t, update_time);

    PERSISTENT_BARRIER();
    sih->h_log_tail = new_tail;

    // finefs_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 1);
    // FINEFS_END_TIMING(update_tail_t, update_time);
}

static force_inline inode *finefs_get_vfs_inode_from_header(finefs_inode_info_header *sih) {
    finefs_inode_info *fi = container_of(sih, finefs_inode_info, header);
    return &fi->vfs_inode;
}

static inline u32 finefs_get_num_slab_for_page(slab_page *page) {
    return 1 << (FINEFS_BLOCK_SHIFT - (page->slab_bits));
}

static inline void finefs_slab_page_init_full(slab_page *page, u64 block_off, u32 slab_bits) {
    unsigned long slab_num = 1 << (FINEFS_BLOCK_SHIFT - slab_bits);

    page->block_off = block_off;
    page->bitmap = 0;
    page->num_free_slab = 0;
    page->slab_bits = slab_bits;
    INIT_LIST_HEAD(&page->entry);
}

static inline void finefs_slab_page_init_empty(slab_page *page, u64 block_off, u32 slab_bits) {
    unsigned long slab_num = 1 << (FINEFS_BLOCK_SHIFT - slab_bits);
    page->block_off = block_off;
    page->bitmap = (~0ul) >> (BITS_PER_TYPE(page->bitmap) - slab_num);
    page->num_free_slab = slab_num;
    page->slab_bits = slab_bits;
    INIT_LIST_HEAD(&page->entry);
}

// 整个page是否满, 分配完成
static inline bool finefs_slab_page_set_alloc(slab_page *page, u32 slab_idx) {
    dlog_assert(arch_test_bit(slab_idx, &page->bitmap));
    bitmap_clear_bit(slab_idx, &page->bitmap);
    dlog_assert(page->num_free_slab > 0);
    --page->num_free_slab;
    return page->num_free_slab == 0;
}

// 整个page是否为free
static inline bool finefs_slab_page_set_free(slab_page *page, u32 slab_idx) {
    dlog_assert(!arch_test_bit(slab_idx, &page->bitmap));
    bitmap_set_bit(slab_idx, &page->bitmap);
    ++page->num_free_slab;
    dlog_assert(page->num_free_slab <= (1 << (FINEFS_BLOCK_SHIFT - page->slab_bits)));
    return page->num_free_slab == (1 << (FINEFS_BLOCK_SHIFT - page->slab_bits));
}

// 	返回slab bits
static force_inline int finefs_get_slab_size(size_t size) {
    int size_bits = 0;
    size_bits = __fls(size);
    if ((1ul << size_bits) < size) {
        ++size_bits;
    }
    size_bits = (size_bits >= SLAB_MIN_BITS) ? size_bits : SLAB_MIN_BITS;
    return size_bits;
}

// 返回nvm off, actual_size实际分配的2的幂大小
// size不能为0
u64 finefs_slab_alloc(super_block *sb, size_t size, int *s_bits);
void finefs_slab_free(super_block *sb, u64 nvm_off, size_t size);

/*
 * The first block contains super blocks and reserved inodes;
 * The second block contains pointers to journal pages.
 * The third block contains pointers to inode tables.
 */
#define RESERVED_BLOCKS 3

struct inode_map {
    mutex_t inode_table_mutex;
    struct rb_root inode_inuse_tree;
    unsigned long num_range_node_inode;           // 红黑树中节点个数
    struct finefs_range_node *first_inode_range;  // 红黑树中按顺序的第一个节点
    int allocated;                                // 统计信息，分配的个数
    int freed;
};

struct ptr_pair {
    __le64 journal_head;
    __le64 journal_tail;
};

static inline struct ptr_pair *finefs_get_journal_pointers(struct super_block *sb, int cpu) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);

    if (cpu >= sbi->cpus) return NULL;

    return (struct ptr_pair *)((char *)finefs_get_block(sb, FINEFS_BLOCK_SIZE) +
                               cpu * CACHELINE_SIZE);
}

struct inode_table {
    __le64 log_head;
};

static inline struct inode_table *finefs_get_inode_table(struct super_block *sb, int cpu) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);

    if (cpu >= sbi->cpus) return NULL;

    return (struct inode_table *)((char *)finefs_get_block(sb, FINEFS_BLOCK_SIZE * 2) +
                                  cpu * CACHELINE_SIZE);
}

// BKDR String Hash Function
static inline unsigned long BKDRHash(const char *str, int length) {
    unsigned int seed = 131;  // 31 131 1313 13131 131313 etc..
    unsigned long hash = 0;
    int i;

    for (i = 0; i < length; i++) {
        hash = hash * seed + (*str++);
    }

    return hash;
}

/* uses CPU instructions to atomically write up to 8 bytes */
static inline void finefs_memcpy_atomic(void *dst, const void *src, u8 size) {
    switch (size) {
        case 1: {
            volatile u8 *daddr = (volatile u8 *)dst;
            const u8 *saddr = (const u8 *)src;
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
            rd_info("error: memcpy_atomic called with %d bytes\n", size);
            BUG();
    }
}

static force_inline int memcpy_to_pmem_nocache(void *dst, const void *src, unsigned int size,
                                               bool fence = false) {
    int ret;

    // 从用户空间拷贝数据
    ret = __copy_from_user_inatomic_nocache(dst, src, size, fence);

    return ret;
}

/* assumes the length to be 4-byte aligned */
static inline void memset_nt(void *dest, uint32_t dword, size_t length) {
    uint64_t dummy1, dummy2;
    uint64_t qword = ((uint64_t)dword << 32) | dword;

    asm volatile(
        "movl %%edx,%%ecx\n"
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
        : "=D"(dummy1), "=d"(dummy2)
        : "D"(dest), "a"(qword), "d"(length)
        : "memory", "rcx");
}

// static inline struct finefs_file_pages_write_entry *
// finefs_get_write_entry(struct super_block *sb,
// 	struct finefs_inode_info *si, unsigned long blocknr)
// {
// 	struct finefs_inode_info_header *sih = &si->header;
// 	struct finefs_file_pages_write_entry *entry;

// 	entry = (struct finefs_file_pages_write_entry *)radix_tree_lookup(&sih->tree, blocknr);

// 	return entry;
// }

static inline struct finefs_file_page_entry *finefs_get_page_entry(struct super_block *sb,
                                                                   struct finefs_inode_info *si,
                                                                   unsigned long blocknr) {
    struct finefs_inode_info_header *sih = &si->header;
    struct finefs_file_page_entry *page_entry_dram;

    page_entry_dram = (struct finefs_file_page_entry *)radix_tree_lookup(&sih->tree, blocknr);

    return page_entry_dram;
}

void finefs_print_curr_log_page(struct super_block *sb, u64 curr);
void finefs_print_finefs_log(struct super_block *sb, struct finefs_inode_info_header *sih,
                             struct finefs_inode *pi);
int finefs_get_finefs_log_pages(struct super_block *sb, struct finefs_inode_info_header *sih,
                                struct finefs_inode *pi);
void finefs_print_finefs_log_pages(struct super_block *sb, struct finefs_inode_info_header *sih,
                                   struct finefs_inode *pi);

// 获取偏移 pgoff 对应的块号
static inline unsigned long get_nvmm(struct super_block *sb, struct finefs_inode_info_header *sih,
                                     struct finefs_file_pages_write_entry *data,
                                     unsigned long pgoff) {
    if (data->pgoff > pgoff ||
        (unsigned long)data->pgoff + (unsigned long)data->num_pages <= pgoff) {
        struct finefs_sb_info *sbi = FINEFS_SB(sb);
        struct finefs_inode *pi;
        u64 curr;

        curr = finefs_get_addr_off(sbi, data);
        rd_info(
            "Entry ERROR: inode %lu, curr 0x%lx, pgoff %lu, "
            "entry pgoff %lu, num %u",
            sih->ino, curr, pgoff, data->pgoff, data->num_pages);
        pi = (struct finefs_inode *)finefs_get_block(sb, sih->pi_addr);
        finefs_print_finefs_log_pages(sb, sih, pi);
        finefs_print_finefs_log(sb, sih, pi);
        log_assert(0);
    }

    return (unsigned long)(data->block >> FINEFS_BLOCK_SHIFT) + pgoff - data->pgoff;
}

// 获取偏移 pgoff 对应的块号
static inline unsigned long get_blocknr_from_page_entry(struct super_block *sb,
                                                        struct finefs_inode_info_header *sih,
                                                        finefs_file_page_entry *data,
                                                        unsigned long pgoff) {
    // if (data->pgoff > pgoff || (unsigned long)data->pgoff +
    // 		(unsigned long)data->num_pages <= pgoff) {
    // 	struct finefs_sb_info *sbi = FINEFS_SB(sb);
    // 	struct finefs_inode *pi;
    // 	u64 curr;

    // 	curr = finefs_get_addr_off(sbi, data);
    // 	rd_info("Entry ERROR: inode %lu, curr 0x%lx, pgoff %lu, "
    // 		"entry pgoff %lu, num %u", sih->ino,
    // 		curr, pgoff, data->pgoff, data->num_pages);
    // 	pi = (struct finefs_inode *)finefs_get_block(sb, sih->pi_addr);
    // 	finefs_print_finefs_log_pages(sb, sih, pi);
    // 	finefs_print_finefs_log(sb, sih, pi);
    // 	log_assert(0);
    // }
    finefs_file_pages_write_entry *nvm_write_entry = data->nvm_entry_p;
    dlog_assert(data->file_pgoff == pgoff);
    dlog_assert(nvm_write_entry->pgoff <= pgoff &&
                nvm_write_entry->pgoff + nvm_write_entry->num_pages > pgoff);
    u64 block_off = finefs_get_addr_off(sb, data->nvm_block_p);
    u64 write_entry_block = nvm_write_entry->block & FINEFS_BLOCK_MASK;
    dlog_assert(write_entry_block <= block_off &&
                write_entry_block + (nvm_write_entry->num_pages << FINEFS_BLOCK_SHIFT) > block_off);
    return block_off >> FINEFS_BLOCK_SHIFT;
}

static inline u64 finefs_find_nvmm_block(struct super_block *sb, struct finefs_inode_info *si,
                                         struct finefs_file_page_entry *page_entry,
                                         unsigned long blocknr) {
    unsigned long nvmm;

    if (!page_entry) {
        page_entry = finefs_get_page_entry(sb, si, blocknr);
        if (!page_entry) return 0;
    }

    nvmm = get_blocknr_from_page_entry(sb, &si->header, page_entry, blocknr);
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
                                                          u64 inode_number) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);

    return (struct finefs_inode *)(sbi->virt_addr + FINEFS_SB_SIZE * 2 +
                                   (inode_number - FINEFS_ROOT_INO) * FINEFS_INODE_SIZE);
}

/* If this is part of a read-modify-write of the inode metadata,
 * finefs_memunlock_inode() before calling! */
static inline struct finefs_inode *finefs_get_inode_by_ino(struct super_block *sb, u64 ino) {
    if (ino == 0 || ino >= FINEFS_NORMAL_INODE_START) return NULL;

    return finefs_get_basic_inode(sb, ino);
}

// 获取NVM中对应的inode地址
// inode存储着偏移，可以直接加上base得到地址
static inline struct finefs_inode *finefs_get_inode(struct super_block *sb, struct inode *inode) {
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;

    return (struct finefs_inode *)finefs_get_block(sb, sih->pi_addr);
}

static inline int finefs_is_mounting(struct super_block *sb) {
    struct finefs_sb_info *sbi = (struct finefs_sb_info *)sb->s_fs_info;
    return sbi->s_mount_opt & FINEFS_MOUNT_MOUNTING;
}

static inline void check_eof_blocks(struct super_block *sb, finefs_inode_info_header *sih,
                                    struct finefs_inode *pi, loff_t size) {
    if ((pi->i_flags & cpu_to_le32(FINEFS_EOFBLOCKS_FL)) &&
        (size + sb->s_blocksize) > (le64_to_cpu(sih->h_blocks) << sb->s_blocksize_bits))
        pi->i_flags &= cpu_to_le32(~FINEFS_EOFBLOCKS_FL);
}

enum finefs_new_inode_type { TYPE_CREATE = 0, TYPE_MKNOD, TYPE_SYMLINK, TYPE_MKDIR };

static inline int is_dir_init_entry(struct super_block *sb, struct finefs_dentry *entry) {
    if (entry->name_len == 1 && strncmp(entry->name, ".", 1) == 0) return 1;
    if (entry->name_len == 2 && strncmp(entry->name, "..", 2) == 0) return 1;

    return 0;
}

// #include "finefs/wprotect.h"

/* Function Prototypes */
extern void finefs_error_mng(struct super_block *sb, const char *fmt, ...);

/* salloc.c */
int finefs_alloc_slab_heaps(struct super_block *sb);
void finefs_delete_slab_heaps(struct super_block *sb);

/* balloc.c */
int finefs_alloc_log_free_lists(struct super_block *sb);
void finefs_delete_log_free_lists(struct super_block *sb);
int finefs_alloc_data_free_lists(struct super_block *sb);
void finefs_delete_data_free_lists(struct super_block *sb);
void* finefs_init_log_block_area(super_block* sb, int cpu_id);
struct finefs_range_node *finefs_alloc_blocknode(struct super_block *sb);
struct finefs_range_node *finefs_alloc_inode_node(struct super_block *sb);
void finefs_free_range_node(struct finefs_range_node *node);
void finefs_free_blocknode(struct super_block *sb, struct finefs_range_node *bnode);
void finefs_free_inode_node(struct super_block *sb, struct finefs_range_node *bnode);
extern void finefs_init_blockmap(struct super_block *sb, double log_block_occupy, int recovery);
extern int finefs_free_data_blocks(struct super_block *sb, struct finefs_inode *pi,
                                   unsigned long blocknr, int num);
extern int finefs_free_log_blocks(struct super_block *sb, struct finefs_inode *pi,
                                  unsigned long blocknr, int num);
extern int finefs_new_data_blocks(struct super_block *sb, struct finefs_inode *pi,
                                  unsigned long *blocknr, unsigned int num, unsigned long start_blk,
                                  int zero, int cow, int cpuid = -1);
extern int finefs_new_log_blocks(struct super_block *sb, struct finefs_inode *pi,
                                 unsigned long *blocknr, unsigned int num, int zero,
                                 int cpuid = -1);
extern unsigned long finefs_count_free_blocks(struct super_block *sb);
int finefs_search_inodetree(struct finefs_sb_info *sbi, unsigned long ino,
                            struct finefs_range_node **ret_node);
inline int finefs_insert_blocktree(struct finefs_sb_info *sbi, struct rb_root *tree,
                                   struct finefs_range_node *new_node);
int finefs_insert_inodetree(struct finefs_sb_info *sbi, struct finefs_range_node *new_node,
                            int cpu);
int finefs_find_free_slot(struct finefs_sb_info *sbi, struct rb_root *tree, unsigned long range_low,
                          unsigned long range_high, struct finefs_range_node **prev,
                          struct finefs_range_node **next);

// 0 分配失败
static force_inline u64 finefs_less_page_alloc(struct super_block *sb, struct finefs_inode *pi,
                                               size_t size, int *s_bits, unsigned long start_blk,
                                               int zero, int cow) {
    dlog_assert(size < FINEFS_BLOCK_SIZE);
    dlog_assert(pi->i_blk_type == FINEFS_DEFAULT_DATA_BLOCK_TYPE);
    u64 nvm_off;
    if (size > (FINEFS_BLOCK_SIZE >> 1)) {
        unsigned long blocknr = 0;
        finefs_new_data_blocks(sb, pi, &blocknr, 1, start_blk, zero, cow);
        nvm_off = finefs_get_block_off(sb, blocknr, pi->i_blk_type);
        r_info("%s: size: %lu, one page: %lu", __func__, size, nvm_off);
        *s_bits = FINEFS_BLOCK_SHIFT;
    } else {
        nvm_off = finefs_slab_alloc(sb, size, s_bits);
    }
    return nvm_off;
}

// 0 分配失败
static force_inline void finefs_less_page_free(struct super_block *sb, struct finefs_inode *pi,
                                               u64 nvm_off, size_t size) {
    dlog_assert(size < FINEFS_BLOCK_SIZE);
    if (size > (FINEFS_BLOCK_SIZE >> 1)) {
        u64 blocknr = finefs_get_blocknr(sb, nvm_off, pi->i_blk_type);
        finefs_free_data_blocks(sb, pi, blocknr, 1);
    } else {
        finefs_slab_free(sb, nvm_off, size);
    }
}

/* bbuild.c */
inline void set_bm(unsigned long bit, struct scan_bitmap *bm, enum bm_type type);
int finefs_rebuild_inode(struct super_block *sb, struct finefs_inode_info *si, u64 pi_addr);
void finefs_save_blocknode_mappings_to_log(struct super_block *sb);
void finefs_save_inode_list_to_log(struct super_block *sb);
void finefs_init_header(struct super_block *sb, struct finefs_inode_info_header *sih,
                        struct finefs_inode *pi, u16 i_mode);
int finefs_recovery(struct super_block *sb);

/*
 * Inodes and files operations
 */

/* dax.c */
int finefs_reassign_file_tree(struct super_block *sb, struct finefs_inode *pi,
                              struct finefs_inode_info_header *sih, u64 begin_tail, u64 *tail);
ssize_t finefs_dax_file_read(struct file *filp, char *buf, size_t len, loff_t *ppos);
ssize_t finefs_dax_file_write(struct file *filp, const char *buf, size_t len, loff_t *ppos);
// int finefs_dax_get_block(struct inode *inode, sector_t iblock,
// 	struct buffer_head *bh, int create);
int finefs_dax_file_mmap(struct file *file, struct vm_area_struct *vma);

/* dir.c */
extern const struct file_operations finefs_dir_operations;
int finefs_append_root_init_entries(struct super_block *sb, struct finefs_inode *pi, u64 self_ino,
                                    u64 parent_ino, u64 *log_tail, int cpuid = -1);
int finefs_append_dir_init_entries(struct super_block *sb, struct finefs_inode *pi,
                                   struct inode *inode, u64 parent_ino, int cpuid = -1);
extern int finefs_add_dentry(struct dentry *dentry, u64 ino, int inc_link, u64 tail, u64 *new_tail);
extern int finefs_remove_dentry(struct dentry *dentry, int dec_link, u64 tail, u64 *new_tail);
void finefs_print_dir_tree(struct super_block *sb, struct finefs_inode_info_header *sih,
                           unsigned long ino);
void finefs_delete_dir_tree(struct super_block *sb, struct finefs_inode_info_header *sih,
                            bool delete_nvmm);
struct finefs_dentry *finefs_find_dentry(struct super_block *sb, struct finefs_inode *pi,
                                         struct inode *inode, const char *name,
                                         unsigned long name_len);
int finefs_rebuild_dir_inode_tree(struct super_block *sb, struct finefs_inode *pi, u64 pi_addr,
                                  struct finefs_inode_info_header *sih);

/* file.c */
extern const struct inode_operations finefs_file_inode_operations;
extern const struct file_operations finefs_dax_file_operations;
int finefs_fsync(struct file *file, loff_t start, loff_t end, int datasync);

/* inode.c */
// extern const struct address_space_operations finefs_aops_dax;
int finefs_init_inode_inuse_list(struct super_block *sb);
extern int finefs_init_inode_table(struct super_block *sb);
extern int finefs_init_slab_page_inode(struct super_block *sb);
unsigned long finefs_get_last_blocknr(struct super_block *sb, struct finefs_inode_info_header *sih);
int finefs_get_inode_address(struct super_block *sb, u64 ino, u64 *pi_addr, int extendable);
// int finefs_set_blocksize_hint(struct super_block *sb, struct inode *inode,
// 	struct finefs_inode *pi, loff_t new_size);
// struct finefs_file_pages_write_entry *finefs_find_next_entry(struct super_block *sb,
// 	struct finefs_inode_info_header *sih, pgoff_t pgoff);
struct finefs_file_page_entry *finefs_find_next_page_entry(struct super_block *sb,
                                                           struct finefs_inode_info_header *sih,
                                                           pgoff_t pgoff);
extern struct inode *finefs_iget(struct super_block *sb, unsigned long ino);
extern void finefs_evict_inode(struct inode *inode);
extern int finefs_write_inode(struct inode *inode, struct writeback_control *wbc);
extern void finefs_dirty_inode(struct inode *inode, int flags);
extern int finefs_notify_change(struct dentry *dentry, struct iattr *attr);
int finefs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat);
extern void finefs_set_inode_flags(struct inode *inode, struct finefs_inode *pi,
                                   unsigned int flags);
extern unsigned long finefs_find_region(struct inode *inode, loff_t *offset, int hole);
void finefs_apply_setattr_entry(struct super_block *sb, struct finefs_inode *pi,
                                struct finefs_inode_info_header *sih,
                                struct finefs_setattr_logentry *entry);
int finefs_free_inode_log(struct super_block *sb, struct finefs_inode *pi,
                          struct finefs_inode_info_header *sih);
int finefs_allocate_inode_log_pages(struct super_block *sb, struct finefs_inode *pi,
                                    unsigned long num_pages, u64 *new_block, bool for_gc,
                                    int cpuid = -1);
int finefs_delete_file_tree(struct super_block *sb, struct finefs_inode_info_header *sih,
                            unsigned long start_blocknr, unsigned long last_blocknr,
                            bool delete_nvmm, bool delete_mmap);
u64 finefs_get_append_head(struct super_block *sb, struct finefs_inode *pi,
                           struct finefs_inode_info_header *sih, u64 tail, size_t size,
                           int *extended, bool for_gc);
u64 finefs_append_file_write_entry(struct super_block *sb, struct finefs_inode *pi,
                                   struct inode *inode, struct finefs_file_pages_write_entry *data,
                                   u64 tail);
int finefs_rebuild_file_inode_tree(struct super_block *sb, struct finefs_inode *pi, u64 pi_addr,
                                   struct finefs_inode_info_header *sih);
u64 finefs_new_finefs_inode(struct super_block *sb, u64 *pi_addr);
extern struct inode *finefs_new_vfs_inode(enum finefs_new_inode_type, struct inode *dir,
                                          u64 pi_addr, u64 ino, umode_t mode, size_t size,
                                          dev_t rdev, const struct qstr *qstr);
int finefs_assign_write_entry(struct super_block *sb, struct finefs_inode *pi,
                              struct finefs_inode_info_header *sih, void *entry, u64 *tail,
                              bool free);

/* ioctl.c */
extern long finefs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
extern long finefs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#endif

/* namei.c */
extern const struct inode_operations finefs_dir_inode_operations;
extern const struct inode_operations finefs_special_inode_operations;
extern struct dentry *finefs_get_parent(struct dentry *child);
int finefs_append_link_change_entry(struct super_block *sb, struct finefs_inode *pi,
                                    struct inode *inode, u64 tail, u64 *new_tail);
void finefs_apply_link_change_entry(struct finefs_inode *pi,
                                    struct finefs_link_change_entry *entry);

/* super.c */
extern struct super_block *finefs_read_super(struct super_block *sb, void *data, int silent);
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

static force_inline bool log_entry_is_set_valid(void *entry) {
    finefs_inode_page_tail *page_tail = (finefs_inode_page_tail *)FINEFS_LOG_TAIL((uintptr_t)entry);
    int entry_nr = FINEFS_LOG_ENTRY_NR(entry);
    return ((page_tail->bitmap >> (entry_nr)) & 1);
}

// FIXME: THREADS
static force_inline void log_entry_set_invalid(struct super_block *sb,
                                               struct finefs_inode_info_header *sih, void *entry,
                                               bool is_write_entry) {
    finefs_inode_page_tail *page_tail = (finefs_inode_page_tail *)FINEFS_LOG_TAIL((uintptr_t)entry);
    int entry_nr = FINEFS_LOG_ENTRY_NR(entry);
    dlog_assert((page_tail->bitmap >> (entry_nr)) & 1);
    u32 remain_num = atomic_add_fetch(&page_tail->valid_num, -1);
    // bitmap_clear_bit_atomic
    bitmap_clear_bit(entry_nr, (unsigned long *)&(page_tail->bitmap));
    dlog_assert(((page_tail->bitmap >> (entry_nr)) & 1) == 0);
    dlog_assert(page_tail->valid_num == bitmap_set_weight((unsigned long *)&(page_tail->bitmap),
                                                          BITS_PER_TYPE(page_tail->bitmap)));
    sih->log_valid_bytes -= CACHELINE_SIZE;

    dlog_assert(!is_write_entry ||
                (finefs_get_entry_type(entry) & LOG_ENTRY_TYPE_MASK) == FILE_PAGES_WRITE ||
                (finefs_get_entry_type(entry) & LOG_ENTRY_TYPE_MASK) == FILE_SMALL_WRITE);
    if (remain_num == 0) {  // 此时是log回收，恢复时不可能会扫描到该log，因此不需要添加到set
        finefs_inode_log_page *curr_page =
            (finefs_inode_log_page *)((uintptr_t)entry & FINEFS_LOG_MASK);
        rd_info("Delete log page: %lu", finefs_get_addr_off(sb, curr_page) >> FINEFS_LOG_SHIFT);
        finefs_log_delete(sb, curr_page);
        finefs_inode *pi = (struct finefs_inode *)finefs_get_block(sb, sih->pi_addr);
        u64 curr_p = finefs_get_addr_off(sb, entry);
        int ret = finefs_free_log_blocks(sb, pi, finefs_get_blocknr(sb, curr_p, pi->i_blk_type), 1);
        dlog_assert(ret == 0);
        sih->log_pages--;
        sih->h_blocks--;
    } else {  // 说明: 增加的时延不多，1%-2%不到
        // if (is_write_entry) {

        // }
		sih->cachelines_to_flush.insert(page_tail);
        if (sih->cachelines_to_flush.size() == FINEFS_BITMAP_CACHELINE_FLUSH_BATCH) {
			// 对于单纯增大的ftruncate，到不了这里，因为page立即回收，最终循环使用两个page而已
            rd_info("ino: %lu flush cacheline set.", sih->ino);
            finefs_sih_bitmap_cache_flush(sih, false);
        }
    }
}

static force_inline void finefs_file_small_entry_set(super_block *sb,
                                                     finefs_file_small_entry *dram_entry,
                                                     finefs_file_small_write_entry *nvm_entry) {
    dram_entry->slab_bits = nvm_entry->slab_bits;
    dram_entry->bytes = nvm_entry->bytes;
    dram_entry->file_off = nvm_entry->file_off;
    dram_entry->nvm_data = (const char *)finefs_get_block(sb, nvm_entry->slab_off);
    dram_entry->nvm_entry_p = nvm_entry;
}

static force_inline void finefs_sih_flush_setattr_entry(super_block* sb,
	finefs_inode_info_header* sih, bool include_the_last)
{
	int end = include_the_last ? sih->cur_setattr_idx : sih->cur_setattr_idx - 1;
	for(int i = 0; i < end; ++i) {
        void *entry = finefs_get_block(sb, sih->h_setattr_entry_p[i]);
        log_entry_set_invalid(sb, sih, entry, false);
    }
}

static force_inline void finefs_sih_flush_link_change_entry(super_block* sb,
	finefs_inode_info_header* sih) {
	if(sih->last_link_change == 0) return;
	void* entry = finefs_get_block(sb, sih->last_link_change);
	log_entry_set_invalid(sb, sih, entry, false);
}

#endif /* __FINEFS_H */
