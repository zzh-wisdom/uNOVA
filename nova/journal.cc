/*
 * NOVA journaling facility.
 *
 * This file contains journaling code to guarantee the atomicity of directory
 * operations that span multiple inodes (unlink, rename, etc).
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

#include <errno.h>

#include "nova/nova.h"
#include "nova/journal.h"
#include "util/log.h"

/**************************** Lite journal ******************************/

static u64 next_lite_journal(u64 curr_p)
{
	size_t size = sizeof(struct nova_lite_journal_entry);

	/* One page holds 64 entries with cacheline size */
	if ((curr_p & (PAGE_SIZE - 1)) + size >= PAGE_SIZE)  // 回环
		return (curr_p & PAGE_MASK);

	return curr_p + size;
}

static void nova_recover_lite_journal_entry(struct super_block *sb,
	u64 addr, u64 value, u8 type)
{
	switch (type) {
		case 1:
			*(u8 *)nova_get_block(sb, addr) = (u8)value;
			break;
		case 2:
			*(u16 *)nova_get_block(sb, addr) = (u16)value;
			break;
		case 4:
			*(u32 *)nova_get_block(sb, addr) = (u32)value;
			break;
		case 8:
			*(u64 *)nova_get_block(sb, addr) = (u64)value;
			break;
		default:
			rd_info("%s: unknown data type %u",
					__func__, type);
			break;
	}

	nova_flush_buffer((void *)nova_get_block(sb, addr), CACHELINE_SIZE, 0);
}

void nova_print_lite_transaction(struct nova_lite_journal_entry *entry)
{
	int i;

	for (i = 0; i < 4; i++)
		rdv_proc("Entry %d: addr 0x%lx, value 0x%lx",
				i, entry->addrs[i], entry->values[i]);
}

u64 nova_create_lite_transaction(struct super_block *sb,
	struct nova_lite_journal_entry *dram_entry1,
	struct nova_lite_journal_entry *dram_entry2,
	int entries, int cpu)
{
	struct ptr_pair *pair;
	struct nova_lite_journal_entry *entry;
	size_t size = sizeof(struct nova_lite_journal_entry);
	u64 new_tail, temp;;

	pair = nova_get_journal_pointers(sb, cpu);
	if (!pair || pair->journal_head == 0 ||
			pair->journal_head != pair->journal_tail)
		BUG();

	temp = pair->journal_head;
	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);

//	nova_print_lite_transaction(dram_entry1);
	memcpy_to_pmem_nocache(entry, dram_entry1, size);

	if (entries == 2) {
		temp = next_lite_journal(temp);
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);
//		nova_print_lite_transaction(dram_entry2);
		memcpy_to_pmem_nocache(entry, dram_entry2, size); // 这里的每一次拷贝都有fence
	}

	new_tail = next_lite_journal(temp);
	pair->journal_tail = new_tail;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1); //所以至少两个fence，最多三个fence

	return new_tail;
}

void nova_commit_lite_transaction(struct super_block *sb, u64 tail, int cpu)
{
	struct ptr_pair *pair;

	pair = nova_get_journal_pointers(sb, cpu);
	if (!pair || pair->journal_tail != tail)
		BUG();

	pair->journal_head = tail;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);
}

static void nova_undo_lite_journal_entry(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	int i;
	u8 type;

	for (i = 0; i < 4; i++) {
		type = entry->addrs[i] >> 56;
		if (entry->addrs[i] && type) {
			rd_info("%s: recover entry %d", __func__, i);
			nova_recover_lite_journal_entry(sb, entry->addrs[i],
					entry->values[i], type);
		}
	}
}

// 恢复存活的journal
// undo log，恢复完成后，head = tail
static int nova_recover_lite_journal(struct super_block *sb,
	struct ptr_pair *pair, int recover)
{
	struct nova_lite_journal_entry *entry;
	u64 temp;

	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							pair->journal_head);
	nova_undo_lite_journal_entry(sb, entry);

	if (recover == 2) {
		temp = next_lite_journal(pair->journal_head);
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);
		nova_undo_lite_journal_entry(sb, entry);
	}

	pair->journal_tail = pair->journal_head;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	return 0;
}

// 初始化跟journal相关的一些dram结构
// 并进行journal的undo恢复
int nova_lite_journal_soft_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct ptr_pair *pair;
	int i;
	u64 temp;

	sbi->journal_locks = (spinlock_t *)ZALLOC(sbi->cpus * sizeof(spinlock_t));
	if (!sbi->journal_locks)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++)
		spin_lock_init(&sbi->journal_locks[i]);

	for (i = 0; i < sbi->cpus; i++) {
		pair = nova_get_journal_pointers(sb, i);
		if (pair->journal_head == pair->journal_tail)
			continue;

		/* We only allow up to two uncommited entries */
		temp = next_lite_journal(pair->journal_head);
		if (pair->journal_tail == temp) {
			nova_recover_lite_journal(sb, pair, 1);
			continue;
		}

		temp = next_lite_journal(temp);
		if (pair->journal_tail == temp) {
			nova_recover_lite_journal(sb, pair, 2);
			continue;
		}

		/* We are in trouble if we get here*/
		r_error("%s: lite journal %d error: head 0x%lx, "
				"tail 0x%lx", __func__, i,
				pair->journal_head, pair->journal_tail);
		return -EINVAL;
	}

	return 0;
}

// durable初始化 journal，即会修改对应的NVM区域
// 里面会调用soft init，即初始化dram中的易失结构部分
int nova_lite_journal_hard_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode fake_pi;
	struct ptr_pair *pair;
	unsigned long blocknr = 0;
	int allocated;
	int i;
	u64 block;

	fake_pi.nova_ino = NOVA_LITEJOURNAL_INO;
	fake_pi.i_blk_type = NOVA_BLOCK_TYPE_4K;

	for (i = 0; i < sbi->cpus; i++) {
		pair = nova_get_journal_pointers(sb, i);
		if (!pair)
			return -EINVAL;

		allocated = nova_new_log_blocks(sb, &fake_pi, &blocknr, 1, 1, i);
		rdv_proc("%s: allocate log @ 0x%lx", __func__, blocknr);

		// 检查
		if (allocated != 1 || blocknr == 0)
			return -ENOSPC;

		block = nova_get_block_off(sb, blocknr, NOVA_BLOCK_TYPE_4K);
		pair->journal_head = pair->journal_tail = block;
		nova_flush_buffer(pair, CACHELINE_SIZE, 0);
	}

	PERSISTENT_BARRIER();
	return nova_lite_journal_soft_init(sb);
}
