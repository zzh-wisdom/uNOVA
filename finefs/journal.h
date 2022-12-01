/*
 * FINEFS journal header
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __FINEFS_JOURNAL_H__
#define __FINEFS_JOURNAL_H__

#include "vfs/com.h"

/* Lite journal */
// 刚好一个cacheline
struct finefs_lite_journal_entry {
	/* The highest byte of addr is type */
	// 比如高位是8表示修改的是8字节
	u64 addrs[4];  // 最大存储4个地址
	u64 values[4];
};

int finefs_lite_journal_soft_init(struct super_block *sb);
int finefs_lite_journal_hard_init(struct super_block *sb);
u64 finefs_create_lite_transaction(struct super_block *sb,
	struct finefs_lite_journal_entry *dram_entry1,
	struct finefs_lite_journal_entry *dram_entry2,
	int entries, int cpu);
void finefs_commit_lite_transaction(struct super_block *sb, u64 tail, int cpu);
#endif    /* __FINEFS_JOURNAL_H__ */
