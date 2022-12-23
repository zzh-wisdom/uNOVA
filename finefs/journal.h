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
#include "util/lock.h"

#define FINEFS_JOURNAL_SIZE (2048)
#define FINEFS_JOURNAL_BLK_TYPE FINEFS_BLOCK_TYPE_4K

#define FINEFS_JOURNAL_COMMIT_ENTRY_TYPE ((1<<8)-1)

struct journal_header {
    __le64 j_head;
    __le64 j_tail;
    __le32 j_version;
};

struct journal_desc
{
    spinlock_t  lock;
	u64 p_head;
	u64 p_tail;
	u32 version;
    journal_header* header;
};

/* Lite journal */
// 刚好一个cacheline
// struct finefs_lite_journal_entry {
// 	/* The highest byte of addr is type */
// 	// 比如高位是8表示修改的是8字节
// 	u64 addrs[4];  // 最大存储4个地址
// 	u64 values[4];
// };

struct finefs_lite_journal_entry {
	/* The highest byte of addr is type */
	u64 values[4];
	union {
		u64 addrs[3];  // 最大存储4个地址，每个地址48bit
		struct {
			u64 addr0: 48;
			u64 addr1: 48;
			u64 addr2: 48;
			u64 addr3: 48;
		}__attribute((__packed__));
	};
	u8 type[4];
	u32 entry_version;
}__attribute((__packed__));

// const int size = sizeof(finefs_lite_journal_entry);

int finefs_lite_journal_soft_init(struct super_block *sb);
int finefs_lite_journal_hard_init(struct super_block *sb);
u64 finefs_create_lite_transaction(struct super_block *sb,
	struct finefs_lite_journal_entry *dram_entry1,
	struct finefs_lite_journal_entry *dram_entry2,
	int entries, int cpu);
void finefs_commit_lite_transaction(struct super_block *sb, u64 tail, int cpu);
#endif    /* __FINEFS_JOURNAL_H__ */
