/*
 * BRIEF DESCRIPTION
 *
 * Memory protection definitions for the FINEFS filesystem.
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

#ifndef __WPROTECT_H
#define __WPROTECT_H

#include <string.h>

#include "finefs/finefs_def.h"
#include "vfs/com.h"
#include "finefs/finefs.h"

#include "util/log.h"

/* finefs_memunlock_super() before calling! */
// 同步冗余的super block
static inline void finefs_sync_super(struct finefs_super_block *ps)
{
	u16 crc = 0;

	// r_error("%s should not run.\n", __func__);
	// ps->s_wtime = cpu_to_le32(get_seconds());
	ps->s_wtime = cpu_to_le32(0);
	ps->s_sum = 0;
	// crc = crc16(~0, (__u8 *)ps + sizeof(__le16),
	// 		FINEFS_SB_STATIC_SIZE(ps) - sizeof(__le16));
	ps->s_sum = cpu_to_le16(crc);
	/* Keep sync redundant super block */
	memcpy((void *)ps + FINEFS_SB_SIZE, (void *)ps,
		sizeof(struct finefs_super_block));
}

#if 0
/* finefs_memunlock_inode() before calling! */
static inline void finefs_sync_inode(struct finefs_inode *pi)
{
	u16 crc = 0;

	pi->i_sum = 0;
	crc = crc16(~0, (__u8 *)pi + sizeof(__le16), FINEFS_INODE_SIZE -
		    sizeof(__le16));
	pi->i_sum = cpu_to_le16(crc);
}
#endif

extern int finefs_writeable(void *vaddr, unsigned long size, int rw);
extern int finefs_dax_mem_protect(struct super_block *sb,
				 void *vaddr, unsigned long size, int rw);

static inline int finefs_is_protected(struct super_block *sb)
{
	struct finefs_sb_info *sbi = (struct finefs_sb_info *)sb->s_fs_info;

	return sbi->s_mount_opt & FINEFS_MOUNT_PROTECT;
}

static inline int finefs_is_wprotected(struct super_block *sb)
{
	return finefs_is_protected(sb);
}

static inline void
__finefs_memunlock_range(void *p, unsigned long len)
{
	/*
	 * NOTE: Ideally we should lock all the kernel to be memory safe
	 * and avoid to write in the protected memory,
	 * obviously it's not possible, so we only serialize
	 * the operations at fs level. We can't disable the interrupts
	 * because we could have a deadlock in this path.
	 */
	finefs_writeable(p, len, 1);
}

static inline void
__finefs_memlock_range(void *p, unsigned long len)
{
	finefs_writeable(p, len, 0);
}

static inline void finefs_memunlock_range(struct super_block *sb, void *p,
					 unsigned long len)
{
	if (finefs_is_protected(sb))
		__finefs_memunlock_range(p, len);
}

static inline void finefs_memlock_range(struct super_block *sb, void *p,
				       unsigned long len)
{
	if (finefs_is_protected(sb))
		__finefs_memlock_range(p, len);
}

static inline void finefs_memunlock_super(struct super_block *sb,
					 struct finefs_super_block *ps)
{
	if (finefs_is_protected(sb))
		__finefs_memunlock_range(ps, FINEFS_SB_SIZE);
}

static inline void finefs_memlock_super(struct super_block *sb,
				       struct finefs_super_block *ps)
{
	finefs_sync_super(ps);
	if (finefs_is_protected(sb))
		__finefs_memlock_range(ps, FINEFS_SB_SIZE);
}

static inline void finefs_memunlock_inode(struct super_block *sb,
					 struct finefs_inode *pi)
{
	if (finefs_is_protected(sb))
		__finefs_memunlock_range(pi, FINEFS_SB_SIZE);
}

static inline void finefs_memlock_inode(struct super_block *sb,
				       struct finefs_inode *pi)
{
	/* finefs_sync_inode(pi); */
	if (finefs_is_protected(sb))
		__finefs_memlock_range(pi, FINEFS_SB_SIZE);
}

static inline void finefs_memunlock_block(struct super_block *sb, void *bp)
{
	if (finefs_is_protected(sb))
		__finefs_memunlock_range(bp, sb->s_blocksize);
}

static inline void finefs_memlock_block(struct super_block *sb, void *bp)
{
	if (finefs_is_protected(sb))
		__finefs_memlock_range(bp, sb->s_blocksize);
}

#endif
