/*
 * BRIEF DESCRIPTION
 *
 * Symlink operations
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

#include "finefs/finefs.h"
#include "finefs/wprotect.h"

// int finefs_block_symlink(struct super_block *sb, struct finefs_inode *pi,
// 	struct inode *inode, u64 log_block,
// 	unsigned long name_blocknr, const char *symname, int len)
// {
// 	struct finefs_file_write_entry *entry;
// 	struct finefs_inode_info *si = FINEFS_I(inode);
// 	struct finefs_inode_info_header *sih = &si->header;
// 	u64 block;
// 	u32 time;
// 	char *blockp;

// 	/* First copy name to name block */
// 	block = finefs_get_block_off(sb, name_blocknr, FINEFS_BLOCK_TYPE_4K);
// 	blockp = (char *)finefs_get_block(sb, block);

// 	finefs_memunlock_block(sb, blockp);
// 	memcpy_to_pmem_nocache(blockp, symname, len);
// 	blockp[len] = '\0';
// 	finefs_memlock_block(sb, blockp);

// 	/* Apply a write entry to the start of log page */
// 	block = log_block;
// 	entry = (struct finefs_file_write_entry *)finefs_get_block(sb, block);

// 	entry->pgoff = 0;
// 	entry->num_pages = cpu_to_le32(1);
// 	entry->invalid_pages = 0;
// 	entry->block = cpu_to_le64(finefs_get_block_off(sb, name_blocknr,
// 							FINEFS_BLOCK_TYPE_4K));
// 	time = CURRENT_TIME_SEC.tv_sec;
// 	entry->mtime = cpu_to_le32(time);
// 	/* Set entry type after set block */
// 	finefs_set_entry_type(entry, FILE_WRITE);
// 	entry->size = cpu_to_le64(len + 1);
// 	finefs_flush_buffer(entry, CACHELINE_SIZE, 0);

// 	sih->log_pages = 1;
// 	pi->log_head = block;
// 	finefs_update_tail(pi, block + sizeof(struct finefs_file_write_entry));

// 	return 0;
// }

// static int finefs_readlink(struct dentry *dentry, char *buffer, int buflen)
// {
// 	struct finefs_file_write_entry *entry;
// 	struct inode *inode = dentry->d_inode;
// 	struct super_block *sb = inode->i_sb;
// 	struct finefs_inode *pi = finefs_get_inode(sb, inode);
// 	char *blockp;

// 	entry = (struct finefs_file_write_entry *)finefs_get_block(sb,
// 							pi->log_head);
// 	blockp = (char *)finefs_get_block(sb, FINEFS_BLOCK_OFF(entry->block));

// 	return readlink_copy(buffer, buflen, blockp);
// }

// static char *finefs_get_link(struct dentry *dentry, struct inode *inode, void **cookie)
// {
// 	struct finefs_file_write_entry *entry;
// 	struct super_block *sb = inode->i_sb;
// 	struct finefs_inode *pi = finefs_get_inode(sb, inode);
// 	char *blockp;

// 	entry = (struct finefs_file_write_entry *)finefs_get_block(sb,
// 							pi->log_head);
// 	blockp = (char *)finefs_get_block(sb, FINEFS_BLOCK_OFF(entry->block));

// 	return blockp;
// }

// #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
// static void *finefs_follow_link(struct dentry *dentry, void **cookie)
// {
// 	struct inode *inode = dentry->d_inode;
// 	return finefs_get_link(dentry, inode, cookie);
// }
// #endif

const struct inode_operations finefs_symlink_inode_operations = {
	// .readlink	= finefs_readlink,
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
// 	.get_link	= finefs_get_link,
// #else
	// .follow_link	= finefs_follow_link,
// #endif
	.setattr	= finefs_notify_change,
};
