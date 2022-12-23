/*
 * FINEFS journaling facility.
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

#include "finefs/finefs.h"
#include "finefs/journal.h"
#include "util/log.h"

/**************************** Lite journal ******************************/

static u64 next_lite_journal(u64 curr_p)
{
	size_t size = sizeof(struct finefs_lite_journal_entry);

	/* One page holds 64 entries with cacheline size */
	if ((curr_p & (FINEFS_BLOCK_SIZE - 1)) + size >= FINEFS_BLOCK_SIZE)  // 回环
		return (curr_p & FINEFS_BLOCK_MASK);

	return curr_p + size;
}

static void finefs_recover_lite_journal_entry(struct super_block *sb,
	u64 addr, u64 value, u8 type)
{
	switch (type) {
		case 1:
			*(u8 *)finefs_get_block(sb, addr) = (u8)value;
			break;
		case 2:
			*(u16 *)finefs_get_block(sb, addr) = (u16)value;
			break;
		case 4:
			*(u32 *)finefs_get_block(sb, addr) = (u32)value;
			break;
		case 8:
			*(u64 *)finefs_get_block(sb, addr) = (u64)value;
			break;
		default:
			rd_info("%s: unknown data type %u",
					__func__, type);
			break;
	}

	finefs_flush_buffer((void *)finefs_get_block(sb, addr), CACHELINE_SIZE, 0);
}

void finefs_print_lite_transaction(struct finefs_lite_journal_entry *entry)
{
	int i;

	for (i = 0; i < 4; i++)
		rdv_proc("Entry %d: addr 0x%lx, value 0x%lx",
				i, entry->addrs[i], entry->values[i]);
}

static force_inline void finefs_check_reset_journal(struct super_block *sb, journal_desc *jour_desc,
											size_t need_size) {
	struct finefs_lite_journal_entry *jour_entry;
	journal_header* jour_header = jour_desc->header;
	size_t remain = jour_desc->p_tail - jour_desc->p_head;
	if(remain >= need_size) return;
	u64 curr = jour_desc->p_tail;
	while(curr < jour_desc->p_head + FINEFS_JOURNAL_SIZE) {
		jour_entry = (finefs_lite_journal_entry*)finefs_get_block(sb, curr);
		jour_entry->entry_version = jour_desc->version;
		finefs_flush_cacheline(jour_entry, 0);
		curr += CACHELINE_SIZE;
	}
	++jour_header->j_version;
	finefs_flush_cacheline(jour_header, 1);
	++jour_desc->version;
	jour_desc->p_tail = jour_desc->p_head;
}

u64 finefs_create_lite_transaction(struct super_block *sb,
	struct finefs_lite_journal_entry *dram_entry1,
	struct finefs_lite_journal_entry *dram_entry2,
	int entries, int cpu)
{
	struct journal_header *jour_header;
	journal_desc *jour_desc;
	struct finefs_lite_journal_entry *entry;
	size_t size = sizeof(struct finefs_lite_journal_entry);
	size_t need_size;
	u64 new_tail, temp;

	jour_desc = finefs_get_journal_desc(sb, cpu);
	jour_header = jour_desc->header;
	if (!jour_header || jour_header->j_head == 0)
		// || pair->journal_head != pair->journal_tail
		BUG();

	need_size = (entries == 1 ? size : size << 1) + size;
	finefs_check_reset_journal(sb, jour_desc, need_size);

	temp = jour_desc->p_tail;
	entry = (struct finefs_lite_journal_entry *)finefs_get_block(sb,
							temp);

	pmem_memcpy_noflush(entry, dram_entry1,
		sizeof(finefs_lite_journal_entry) - sizeof(finefs_lite_journal_entry::entry_version));
	barrier();
	entry->entry_version = jour_desc->version;
	finefs_flush_cacheline(entry, 0);
//	finefs_print_lite_transaction(dram_entry1);
	// memcpy_to_pmem_nocache(entry, dram_entry1, size);

	if (entries == 2) {
		// temp = next_lite_journal(temp);
		temp += sizeof(finefs_lite_journal_entry);
		entry = (struct finefs_lite_journal_entry *)finefs_get_block(sb,
							temp);
//		finefs_print_lite_transaction(dram_entry2);
		// memcpy_to_pmem_nocache(entry, dram_entry2, size); // 这里的每一次拷贝都有fence
		pmem_memcpy_noflush(entry, dram_entry2,
		sizeof(finefs_lite_journal_entry) - sizeof(finefs_lite_journal_entry::entry_version));
		barrier();
		entry->entry_version = jour_desc->version;
		finefs_flush_cacheline(entry, 0);
	}

	// new_tail = next_lite_journal(temp);
	// pair->journal_tail = new_tail;
	PERSISTENT_BARRIER();
	jour_desc->p_tail += need_size - size;
	// finefs_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1); //所以至少两个fence，最多三个fence

	return new_tail;
}

void finefs_commit_lite_transaction(struct super_block *sb, u64 tail, int cpu)
{
	journal_desc *jour_desc;
    struct finefs_lite_journal_entry *entry;

	jour_desc = finefs_get_journal_desc(sb, cpu);
	entry = (struct finefs_lite_journal_entry *)finefs_get_block(sb,
							jour_desc->p_tail);
	entry->type[0] = FINEFS_JOURNAL_COMMIT_ENTRY_TYPE;
	barrier();
	entry->entry_version = jour_desc->version;
	finefs_flush_cacheline(entry, 1);

	// pair = finefs_get_journal_pointers(sb, cpu);
	// if (!pair || pair->journal_tail != tail)
	// 	BUG();

	// pair->journal_head = tail;
	// finefs_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);
}

// static void finefs_undo_lite_journal_entry(struct super_block *sb,
// 	struct finefs_lite_journal_entry *entry)
// {
// 	int i;
// 	u8 type;

// 	for (i = 0; i < 4; i++) {
// 		type = entry->addrs[i] >> 56;
// 		if (entry->addrs[i] && type) {
// 			rd_info("%s: recover entry %d", __func__, i);
// 			finefs_recover_lite_journal_entry(sb, entry->addrs[i],
// 					entry->values[i], type);
// 		}
// 	}
// }

// 恢复存活的journal
// undo log，恢复完成后，head = tail
// static int finefs_recover_lite_journal(struct super_block *sb,
// 	struct journal_header *pair, int recover)
// {
// 	struct finefs_lite_journal_entry *entry;
// 	u64 temp;

// 	entry = (struct finefs_lite_journal_entry *)finefs_get_block(sb,
// 							pair->journal_head);
// 	finefs_undo_lite_journal_entry(sb, entry);

// 	if (recover == 2) {
// 		temp = next_lite_journal(pair->journal_head);
// 		entry = (struct finefs_lite_journal_entry *)finefs_get_block(sb,
// 							temp);
// 		finefs_undo_lite_journal_entry(sb, entry);
// 	}

// 	pair->journal_tail = pair->journal_head;
// 	finefs_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

// 	return 0;
// }

// 初始化跟journal相关的一些dram结构
// 并进行journal的undo恢复
int finefs_lite_journal_soft_init(struct super_block *sb)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);
	struct journal_header *jour_header;
	int i;
	u64 temp;

	sbi->journal_descs = (journal_desc *)ZALLOC(sbi->cpus * sizeof(journal_desc));
	if (!sbi->journal_descs)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++) {
		jour_header = finefs_get_journal_header(sb, i);
		spin_lock_init(&sbi->journal_descs[i].lock);
		sbi->journal_descs[i].header = jour_header;
		sbi->journal_descs[i].p_head = le64_to_cpu(jour_header->j_head);
		sbi->journal_descs[i].p_tail = sbi->journal_descs[i].p_head;
		sbi->journal_descs[i].version = le32_to_cpu(jour_header->j_version);
	}


	// TODO: journal recovery
	// for (i = 0; i < sbi->cpus; i++) {
	// 	pair = finefs_get_journal_pointers(sb, i);
	// 	if (pair->journal_head == pair->journal_tail)
	// 		continue;

	// 	/* We only allow up to two uncommited entries */
	// 	temp = next_lite_journal(pair->journal_head);
	// 	if (pair->journal_tail == temp) {
	// 		finefs_recover_lite_journal(sb, pair, 1);
	// 		continue;
	// 	}

	// 	temp = next_lite_journal(temp);
	// 	if (pair->journal_tail == temp) {
	// 		finefs_recover_lite_journal(sb, pair, 2);
	// 		continue;
	// 	}

	// 	/* We are in trouble if we get here*/
	// 	r_error("%s: lite journal %d error: head 0x%lx, "
	// 			"tail 0x%lx", __func__, i,
	// 			pair->journal_head, pair->journal_tail);
	// 	return -EINVAL;
	// }

	return 0;
}

// durable初始化 journal，即会修改对应的NVM区域
// 里面会调用soft init，即初始化dram中的易失结构部分
int finefs_lite_journal_hard_init(struct super_block *sb)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);
	struct finefs_inode fake_pi;
	struct journal_header *jour_header;
	unsigned long blocknr = 0;
	int allocated;
	int i;
	u64 block;

	fake_pi.finefs_ino = FINEFS_LITEJOURNAL_INO;
	fake_pi.i_blk_type = FINEFS_JOURNAL_BLK_TYPE;

	for (i = 0; i < sbi->cpus; i++) {
		jour_header = finefs_get_journal_header(sb, i);
		if (!jour_header)
			return -EINVAL;

		allocated = finefs_new_data_blocks(sb, &fake_pi, &blocknr, 1, 0, 1, 0, i);
		rdv_proc("%s: allocate log @ 0x%lx, block num: %d", __func__, blocknr, allocated);

		// 检查
		if (allocated != 1 || blocknr == 0)
			return -ENOSPC;

		block = finefs_get_block_off(sb, blocknr, FINEFS_BLOCK_TYPE_4K);
		jour_header->j_head = jour_header->j_tail = block;
		jour_header->j_version = 0;
		finefs_flush_buffer(jour_header, CACHELINE_SIZE, 0);
	}

	PERSISTENT_BARRIER();
	return finefs_lite_journal_soft_init(sb);
}
