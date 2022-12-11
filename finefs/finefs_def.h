/*
 * FILE NAME include/linux/finefs_fs.h
 *
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
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#ifndef _LINUX_FINEFS_DEF_H
#define _LINUX_FINEFS_DEF_H

#include <sys/types.h>

#include "vfs/com.h"
#include "util/aep.h"

/* ======================= fs config ========================= */

/*
 * Maximal count of links to a file
 */
#define FINEFS_LINK_MAX          32000

#define FINEFS_INODE_SIZE 128    /* must be power of two */
#define FINEFS_INODE_BITS   7

#define FINEFS_NAME_LEN 27

/* ======================= size config ========================= */

// FINEFS中block的概念等同于page，是heap管理的基本单元
#define FINEFS_BLOCK_SHIFT 12
#define FINEFS_BLOCK_SIZE  	 	(1 << FINEFS_BLOCK_SHIFT)
#define FINEFS_BLOCK_UMASK   	(FINEFS_BLOCK_SIZE-1)
#define FINEFS_BLOCK_MASK  	(~(FINEFS_BLOCK_SIZE-1))
// 获取block的起始偏移，相对NVM的起始位置
#define FINEFS_BLOCK_OFF(p)  ((p) & FINEFS_BLOCK_MASK)

/* FINEFS supported data blocks */
enum blk_type_t {
	FINEFS_BLOCK_TYPE_4K = 0,
	FINEFS_BLOCK_TYPE_8K    ,
	FINEFS_BLOCK_TYPE_16K   ,
	FINEFS_BLOCK_TYPE_32K   ,
	FINEFS_BLOCK_TYPE_64K   ,
	FINEFS_BLOCK_TYPE_128K  ,
	FINEFS_BLOCK_TYPE_256K  ,
	FINEFS_BLOCK_TYPE_512K  ,
	FINEFS_BLOCK_TYPE_1M    ,
	FINEFS_BLOCK_TYPE_2M    ,
	FINEFS_BLOCK_TYPE_1G    ,
	FINEFS_BLOCK_TYPE_MAX   ,
};

#define FINEFS_4K_BLK_NUM_BITS     0
#define FINEFS_8K_BLK_NUM_BITS     1
#define FINEFS_16K_BLK_NUM_BITS    2
#define FINEFS_32K_BLK_NUM_BITS    3
#define FINEFS_64K_BLK_NUM_BITS    4
#define FINEFS_128K_BLK_NUM_BITS   5
#define FINEFS_256K_BLK_NUM_BITS   6
#define FINEFS_512K_BLK_NUM_BITS   7
#define FINEFS_1M_BLK_NUM_BITS     8
#define FINEFS_2M_BLK_NUM          9
#define FINEFS_1G_BLK_NUM          18 // 0x40000

/*
 * Play with this knob to change the default block type.
 * By changing the FINEFS_DEFAULT_DATA_BLOCK_TYPE to 2M or 1G,
 * we should get pretty good coverage in testing.
 */
#define FINEFS_DEFAULT_DATA_BLOCK_TYPE FINEFS_BLOCK_TYPE_4K

/* ======================= finefs_super_block ========================= */

/*
 * Mount flags
 */
#define FINEFS_MOUNT_PROTECT 0x000001            /* wprotect CR0.WP */
#define FINEFS_MOUNT_XATTR_USER 0x000002         /* Extended user attributes */
#define FINEFS_MOUNT_POSIX_ACL 0x000004          /* POSIX Access Control Lists */
#define FINEFS_MOUNT_DAX 0x000008                /* Direct Access */
#define FINEFS_MOUNT_ERRORS_CONT 0x000010        /* Continue on errors */
#define FINEFS_MOUNT_ERRORS_RO 0x000020          /* Remount fs ro on errors */
#define FINEFS_MOUNT_ERRORS_PANIC 0x000040       /* Panic on errors */
#define FINEFS_MOUNT_HUGEMMAP 0x000080           /* Huge mappings with mmap */
#define FINEFS_MOUNT_HUGEIOREMAP 0x000100        /* Huge mappings with ioremap */
#define FINEFS_MOUNT_FORMAT      0x000200        /* was FS formatted on mount? */
#define FINEFS_MOUNT_MOUNTING    0x000400        /* FS currently being mounted */

#define	FINEFS_SUPER_MAGIC	0x4E4F5641	/* FINEFS */
#define FINEFS_SB_SIZE 512       /* must be power of two */

/*
 * Structure of the super block in FINEFS
 * The fields are partitioned into static and dynamic fields. The static fields
 * never change after file system creation. This was primarily done because
 * finefs_get_block() returns NULL if the block offset is 0 (helps in catching
 * bugs). So if we modify any field using journaling (for consistency), we
 * will have to modify s_sum which is at offset 0. So journaling code fails.
 * This (static+dynamic fields) is a temporary solution and can be avoided
 * once the file system becomes stable and finefs_get_block() returns correct
 * pointers even for offset 0.
 */
struct finefs_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below */
	__le16		s_sum;              /* checksum of this sb */
	__le16		s_padding16;
	__le32		s_magic;            /* magic signature */
	__le32		s_padding32;
	__le32		s_blocksize;        /* blocksize in bytes */
	__le64		s_size;             /* total size of fs in bytes */
	char		s_volume_name[16];  /* volume name */

	__le64		s_start_dynamic;

	/* all the dynamic fields should go here */
	/* s_mtime and s_wtime should be together and their order should not be
	 * changed. we use an 8 byte write to update both of them atomically */
	__le32		s_mtime;            /* mount time */
	__le32		s_wtime;            /* write time */
	/* fields for fast mount support. Always keep them together */
	__le64		s_num_free_blocks;
} __attribute((__packed__));  // 取消对齐

#define FINEFS_SB_STATIC_SIZE(ps) ((u64)&ps->s_start_dynamic - (u64)ps)

/* the above fast mount fields take total 32 bytes in the super block */
#define FINEFS_FAST_MOUNT_FIELD_SIZE  (36)

/* ======================= finefs inode ========================= */

struct finefs_log_page_link {
	__le64	prev_page_;  // 这个不用持久化，只为了方便维护, 指向前一个page
	__le64	next_page_;  // 0 表示null
} __attribute((__packed__));

/*
 * Structure of an inode in FINEFS.
 * Keep the inode size to within 120 bytes: We use the last eight bytes
 * as inode table tail pointer.
 *
 * TODO: 添加version
 */
struct finefs_inode {
	/* first 48 bytes */
	__le16	i_rsvd;		/* reserved. used to be checksum */
	u8	valid;		/* Is this inode valid? 新建inode时和父母tail一起journal方式写*/
	u8	i_blk_type;	/* data block size this inode uses ,是一个枚举值。修改：data page固定4KB，这个枚举用来控制log大小*/
	__le32	i_flags;	/* Inode flags */
	__le64	i_size;		/* Size of data in bytes */
	__le32	i_ctime;	/* Inode modification time */
	__le32	i_mtime;	/* Inode b-tree Modification time */
	__le32	i_atime;	/* Access time */
	__le16	i_mode;		/* File mode 文件类型*/
	__le16	i_links_count;	/* Links count */

	/*
	 * Blocks count. This field is updated in-place;
	 * We just make sure it is consistent upon clean umount,
	 * and it is recovered in DFS recovery if power failure occurs.
	 * 持有的block个数，包括log page
	 * TODO: 不要随机访问
	 */
	__le64	i_blocks;
	// __le64	i_xattr;	/* Extended attribute block */

	/* second 48 bytes */
	__le32	i_uid;		/* Owner Uid */
	__le32	i_gid;		/* Group Id */
	__le32	i_generation;	/* File version (for NFS) */
	__le32	padding;
	__le64	finefs_ino;	/* finefs inode number */

	finefs_log_page_link log_head;
	// __le64	log_head;	/* Log head pointer */
	__le64	log_tail;	/* Log tail pointer */

	// struct {
	// 	__le32 rdev;	/* major/minor # */
	// } dev;			/* device inode */

	/* Leave 8 bytes for inode table tail pointer */
} __attribute((__packed__));

// 实际上为了方便空间管理，空间管理器只实现了按照inode来分配空间的接口。
// 为了分配其他类型的空间，这里预留了几个ino

/* The root inode follows immediately after the redundant super block */
#define FINEFS_ROOT_INO		(1)
// 用于分配innode table空间(每次2MB)的inode
#define FINEFS_INODETABLE_INO	(2)	/* Temporaty inode table */
// 用于分配 数据block
#define FINEFS_BLOCKNODE_INO	(3)
// 用于分配slab page
#define FINEFS_SLAB_PAGE_INO	(4)
// 用于分配journal的空间（每次4KB）
#define FINEFS_LITEJOURNAL_INO	(5)
#define FINEFS_INODELIST1_INO	(6)

#define	FINEFS_ROOT_INO_START	(FINEFS_SB_SIZE * 2)

/* Normal inode starts at 16 */
#define FINEFS_NORMAL_INODE_START      (16)

/* ======================= Write ordering ========================= */

#define X86_FEATURE_PCOMMIT	( 9*32+22) /* PCOMMIT instruction */
#define X86_FEATURE_CLFLUSHOPT	( 9*32+23) /* CLFLUSHOPT instruction */
#define X86_FEATURE_CLWB	( 9*32+24) /* CLWB instruction */

// static inline bool arch_has_pcommit(void)
// {
// 	return static_cpu_has(X86_FEATURE_PCOMMIT);
// }

// static inline bool arch_has_clwb(void)
// {
// 	return static_cpu_has(X86_FEATURE_CLWB);
// }

// extern int support_clwb;
// extern int support_pcommit;

#define _mm_clflush(addr)\
	asm volatile("clflush %0" : "+m" (*(volatile char *)(addr)))
#define _mm_clflushopt(addr)\
	asm volatile(".byte 0x66; clflush %0" : "+m" (*(volatile char *)(addr)))
#define _mm_clwb(addr)\
	asm volatile(".byte 0x66; xsaveopt %0" : "+m" (*(volatile char *)(addr)))
#define _mm_pcommit()\
	asm volatile(".byte 0x66, 0x0f, 0xae, 0xf8")

/* Provides ordering from all previous clflush too */
static inline void PERSISTENT_MARK(void)
{
	/* TODO: Fix me. */
}

static inline void PERSISTENT_BARRIER(void)
{
	// asm volatile ("sfence\n" : : );
	sfence();
	// if (support_pcommit) {
	// 	/* Do nothing */
	// }
}

static force_inline void finefs_flush_cacheline(void *buf, bool fence) {
	clwb((uintptr_t)buf & CACHELINE_MASK);
	if (fence)
		PERSISTENT_BARRIER();
}

static inline void finefs_flush_buffer(void *buf, uint32_t len, bool fence)
{
	uint32_t i;
	len = len + ((unsigned long)(buf) & CACHELINE_UMASK);
	for (i = 0; i < len; i += CACHELINE_SIZE) {
		clwb(buf + i);
	}
	// if (support_clwb) {
	// 	for (i = 0; i < len; i += CACHELINE_SIZE)
	// 		_mm_clwb(buf + i);
	// } else {
	// 	for (i = 0; i < len; i += CACHELINE_SIZE)
	// 		_mm_clflush(buf + i);
	// }
	/* Do a fence only if asked. We often don't need to do a fence
	 * immediately after clflush because even if we get context switched
	 * between clflush and subsequent fence, the context switch operation
	 * provides implicit fence. */
	if (fence)
		PERSISTENT_BARRIER();
}

#endif /* _LINUX_FINEFS_DEF_H */
