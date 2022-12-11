/*
 * FINEFS File System statistics
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
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

#include "finefs/finefs.h"

const char *finefs_Timingstring[TIMING_NUM] =
{
	"init",
	"mount",
	"ioremap",
	"new_init",
	"recovery",

	"create",
	"lookup",
	"link",
	"unlink",
	"symlink",
	"mkdir",
	"rmdir",
	"mknod",
	"rename",
	"readdir",
	"add_dentry",
	"remove_dentry",
	"setattr",

	"dax_read",
	"cow_write",
	"copy_to_nvmm",
	"dax_get_block",

	"memcpy_read_nvmm",
	"memcpy_write_nvmm",
	"memcpy_write_back_to_nvmm",
	"handle_partial_block",

	"new_data_blocks",
	"new_log_blocks",
	"free_data_blocks",
	"free_log_blocks",

	"transaction_new_inode",
	"transaction_link_change",
	"update_tail",

	"append_dir_entry",
	"append_file_entry",
	"append_link_change",
	"append_setattr",
	"log_fast_gc",
	"log_thorough_gc",
	"check_invalid_log",

	"find_cache_page",
	"assign_blocks",
	"fsync",
	"direct_IO",
	"delete_file_tree",
	"delete_dir_tree",
	"new_vfs_inode",
	"new_finefs_inode",
	"free_inode",
	"free_inode_log",
	"evict_inode",
	"mmap_page_fault",

	"rebuild_dir",
	"rebuild_file",
};

// u64 Timingstats[TIMING_NUM];
// DEFINE_PER_CPU(u64[TIMING_NUM], Timingstats_percpu);
// u64 Countstats[TIMING_NUM];
// DEFINE_PER_CPU(u64[TIMING_NUM], Countstats_percpu);
// u64 IOstats[STATS_NUM];
// DEFINE_PER_CPU(u64[STATS_NUM], IOstats_percpu);

// static void finefs_print_alloc_stats(struct super_block *sb)
// {
// 	struct finefs_sb_info *sbi = FINEFS_SB(sb);
// 	struct free_list *free_list;
// 	unsigned long alloc_log_count = 0;
// 	unsigned long alloc_log_pages = 0;
// 	unsigned long alloc_data_count = 0;
// 	unsigned long alloc_data_pages = 0;
// 	unsigned long free_log_count = 0;
// 	unsigned long freed_log_pages = 0;
// 	unsigned long free_data_count = 0;
// 	unsigned long freed_data_pages = 0;
// 	int i;

// 	printk("=========== FINEFS allocation stats ===========\n");
// 	printk("Alloc %lu, alloc steps %lu, average %lu\n",
// 		Countstats[new_data_blocks_t], IOstats[alloc_steps],
// 		Countstats[new_data_blocks_t] ?
// 			IOstats[alloc_steps] / Countstats[new_data_blocks_t] : 0);
// 	printk("Free %lu\n", Countstats[free_data_t]);
// 	printk("Fast GC %lu, check pages %lu, free pages %lu, average %lu\n",
// 		Countstats[fast_gc_t], IOstats[fast_checked_pages],
// 		IOstats[fast_gc_pages], Countstats[fast_gc_t] ?
// 			IOstats[fast_gc_pages] / Countstats[fast_gc_t] : 0);
// 	printk("Thorough GC %lu, checked pages %lu, free pages %lu, "
// 		"average %lu\n", Countstats[thorough_gc_t],
// 		IOstats[thorough_checked_pages], IOstats[thorough_gc_pages],
// 		Countstats[thorough_gc_t] ?
// 			IOstats[thorough_gc_pages] / Countstats[thorough_gc_t] : 0);

// 	for (i = 0; i < sbi->cpus; i++) {
// 		free_list = finefs_get_free_list(sb, i);

// 		alloc_log_count += free_list->alloc_log_count;
// 		alloc_log_pages += free_list->alloc_log_pages;
// 		alloc_data_count += free_list->alloc_data_count;
// 		alloc_data_pages += free_list->alloc_data_pages;
// 		free_log_count += free_list->free_log_count;
// 		freed_log_pages += free_list->freed_log_pages;
// 		free_data_count += free_list->free_data_count;
// 		freed_data_pages += free_list->freed_data_pages;
// 	}

// 	printk("alloc log count %lu, allocated log pages %lu, "
// 		"alloc data count %lu, allocated data pages %lu, "
// 		"free log count %lu, freed log pages %lu, "
// 		"free data count %lu, freed data pages %lu\n",
// 		alloc_log_count, alloc_log_pages,
// 		alloc_data_count, alloc_data_pages,
// 		free_log_count, freed_log_pages,
// 		free_data_count, freed_data_pages);
// }

// static void finefs_print_IO_stats(struct super_block *sb)
// {
// 	printk("=========== FINEFS I/O stats ===========\n");
// 	printk("Read %lu, bytes %lu, average %lu\n",
// 		Countstats[dax_read_t], IOstats[read_bytes],
// 		Countstats[dax_read_t] ?
// 			IOstats[read_bytes] / Countstats[dax_read_t] : 0);
// 	printk("COW write %lu, bytes %lu, average %lu, "
// 		"write breaks %lu, average %lu\n",
// 		Countstats[cow_write_t], IOstats[cow_write_bytes],
// 		Countstats[cow_write_t] ?
// 			IOstats[cow_write_bytes] / Countstats[cow_write_t] : 0,
// 		IOstats[write_breaks], Countstats[cow_write_t] ?
// 			IOstats[write_breaks] / Countstats[cow_write_t] : 0);
// }

// void finefs_get_timing_stats(void)
// {
// 	int i;
// 	int cpu;

// 	for (i = 0; i < TIMING_NUM; i++) {
// 		Timingstats[i] = 0;
// 		Countstats[i] = 0;
// 		for_each_possible_cpu(cpu) {
// 			Timingstats[i] += per_cpu(Timingstats_percpu[i], cpu);
// 			Countstats[i] += per_cpu(Countstats_percpu[i], cpu);
// 		}
// 	}
// }

// void finefs_get_IO_stats(void)
// {
// 	int i;
// 	int cpu;

// 	for (i = 0; i < STATS_NUM; i++) {
// 		IOstats[i] = 0;
// 		for_each_possible_cpu(cpu)
// 			IOstats[i] += per_cpu(IOstats_percpu[i], cpu);
// 	}
// }

// void finefs_print_timing_stats(struct super_block *sb)
// {
// 	int i;

// 	finefs_get_timing_stats();
// 	finefs_get_IO_stats();

// 	printk("======== FINEFS kernel timing stats ========\n");
// 	for (i = 0; i < TIMING_NUM; i++) {
// 		if (measure_timing || Timingstats[i]) {
// 			printk("%s: count %lu, timing %lu, average %lu\n",
// 				finefs_Timingstring[i],
// 				Countstats[i],
// 				Timingstats[i],
// 				Countstats[i] ?
// 				Timingstats[i] / Countstats[i] : 0);
// 		} else {
// 			printk("%s: count %lu\n",
// 				finefs_Timingstring[i],
// 				Countstats[i]);
// 		}
// 	}

// 	finefs_print_alloc_stats(sb);
// 	finefs_print_IO_stats(sb);
// }

// static void finefs_clear_timing_stats(void)
// {
// 	int i;
// 	int cpu;

// 	for (i = 0; i < TIMING_NUM; i++) {
// 		Countstats[i] = 0;
// 		Timingstats[i] = 0;
// 		for_each_possible_cpu(cpu) {
// 			per_cpu(Timingstats_percpu[i], cpu) = 0;
// 			per_cpu(Countstats_percpu[i], cpu) = 0;
// 		}
// 	}
// }

// static void finefs_clear_IO_stats(void)
// {
// 	int i;
// 	int cpu;

// 	for (i = 0; i < STATS_NUM; i++) {
// 		IOstats[i] = 0;
// 		for_each_possible_cpu(cpu)
// 			per_cpu(IOstats_percpu[i], cpu) = 0;
// 	}
// }

// void finefs_clear_stats(void)
// {
// 	finefs_clear_timing_stats();
// 	finefs_clear_IO_stats();
// }

static inline void finefs_print_file_write_entry(struct super_block *sb,
	u64 curr, struct finefs_file_pages_write_entry *entry)
{
	rd_info("file write entry @ 0x%lx: paoff %lu, pages %u, "
			"blocknr %lu, invalid count %u, size %lu\n",
			curr, entry->pgoff, entry->num_pages,
			entry->block >> FINEFS_BLOCK_SHIFT,
			entry->invalid_pages, entry->size);
}

static inline void finefs_print_set_attr_entry(struct super_block *sb,
	u64 curr, struct finefs_setattr_logentry *entry)
{
	rd_info("set attr entry @ 0x%lx: mode %u, size %lu\n",
			curr, entry->mode, entry->size);
}

static inline void finefs_print_link_change_entry(struct super_block *sb,
	u64 curr, struct finefs_link_change_entry *entry)
{
	rd_info("link change entry @ 0x%lx: links %u, flags %u\n",
			curr, entry->links, entry->flags);
}

static inline size_t finefs_print_dentry(struct super_block *sb,
	u64 curr, struct finefs_dentry *entry)
{
	rd_info("dir logentry @ 0x%lx: inode %lu, "
			"namelen %u, rec len %u\n", curr,
			le64_to_cpu(entry->ino),
			entry->name_len, le16_to_cpu(entry->de_len));

	return le16_to_cpu(entry->de_len);
}

static u64 finefs_print_log_entry(struct super_block *sb, u64 curr)
{
	void *addr;
	size_t size;
	u8 type;

	addr = (void *)finefs_get_block(sb, curr);
	type = finefs_get_entry_type(addr);
	switch (type) {
		case SET_ATTR:
			finefs_print_set_attr_entry(sb, curr, (struct finefs_setattr_logentry *)addr);
			curr += sizeof(struct finefs_setattr_logentry);
			break;
		case LINK_CHANGE:
			finefs_print_link_change_entry(sb, curr, (struct finefs_link_change_entry *)addr);
			curr += sizeof(struct finefs_link_change_entry);
			break;
		case FILE_PAGES_WRITE:
			finefs_print_file_write_entry(sb, curr, (struct finefs_file_pages_write_entry *)addr);
			curr += sizeof(struct finefs_file_pages_write_entry);
			break;
		case DIR_LOG:
			size = finefs_print_dentry(sb, curr, (struct finefs_dentry *)addr);
			curr += size;
			if (size == 0) {
				rd_info("%s: dentry with size 0 @ 0x%lx\n",
						__func__, curr);
				curr += sizeof(struct finefs_file_pages_write_entry);
				log_assert(0);
			}
			break;
		case NEXT_PAGE:
			rd_info("%s: next page sign @ 0x%lx\n",
						__func__, curr);
			curr = FINEFS_LOG_TAIL(curr);
			break;
		default:
			rd_info("%s: unknown type %d, 0x%lx\n",
						__func__, type, curr);
			curr += sizeof(struct finefs_file_pages_write_entry);
			log_assert(0);
			break;
	}

	return curr;
}

// void finefs_print_curr_log_page(struct super_block *sb, u64 curr)
// {
// 	struct finefs_inode_page_tail *tail;
// 	u64 start, end;

// 	start = curr & FINEFS_LOG_MASK;
// 	end = FINEFS_LOG_TAIL(curr);

// 	while (start < end) {
// 		start = finefs_print_log_entry(sb, start);
// 	}

// 	tail = finefs_get_block(sb, end);
// 	finefs_dbg("Page tail. curr 0x%lx, next page 0x%lx\n",
// 			start, tail->next_page);
// }

void finefs_print_finefs_log(struct super_block *sb,
	struct finefs_inode_info_header *sih, struct finefs_inode *pi)
{
	u64 curr;

	if (sih->i_log_tail == 0)
		return;

	curr = pi->log_head.next_page_;
	rd_info("Pi %lu: log head 0x%lx, tail 0x%lx\n",
			sih->ino, curr, sih->i_log_tail);
	while (curr != sih->i_log_tail) {
		if ((curr & FINEFS_LOG_UMASK) == FINEFS_LOG_LAST_ENTRY) {
			struct finefs_inode_page_tail *tail =
					(struct finefs_inode_page_tail *)finefs_get_block(sb, curr);
			rd_info("Log tail, curr 0x%lx, next page 0x%lx\n",
					curr, tail->page_link.next_page_ - FINEFS_LOG_LINK_PAGE_OFF);
			curr = tail->page_link.next_page_ - FINEFS_LOG_LINK_PAGE_OFF;
		} else {
			curr = finefs_print_log_entry(sb, curr);
		}
	}
}

// void finefs_print_inode_log(struct super_block *sb, struct inode *inode)
// {
// 	struct finefs_inode_info *si = FINEFS_I(inode);
// 	struct finefs_inode_info_header *sih = &si->header;
// 	struct finefs_inode *pi;

// 	pi = finefs_get_inode(sb, inode);
// 	finefs_print_finefs_log(sb, sih, pi);
// }

// int finefs_get_finefs_log_pages(struct super_block *sb,
// 	struct finefs_inode_info_header *sih, struct finefs_inode *pi)
// {
// 	struct finefs_inode_log_page *curr_page;
// 	u64 curr, next;
// 	int count = 1;

// 	if (pi->log_head == 0 || pi->log_tail == 0) {
// 		finefs_dbg("Pi %lu has no log\n", sih->ino);
// 		return 0;
// 	}

// 	curr = pi->log_head;
// 	curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr);
// 	while ((next = curr_page->page_tail.next_page) != 0) {
// 		curr = next;
// 		curr_page = (struct finefs_inode_log_page *)
// 			finefs_get_block(sb, curr);
// 		count++;
// 	}

// 	return count;
// }

void finefs_print_finefs_log_pages(struct super_block *sb,
	struct finefs_inode_info_header *sih, struct finefs_inode *pi)
{
	struct finefs_inode_log_page *curr_page;
	u64 curr, next;
	int count = 1;
	int used = count;
	if (pi->log_head.next_page_ == 0 || sih->i_log_tail == 0) {
		rd_info("Pi %lu has no log\n", sih->ino);
		return;
	}

	curr = pi->log_head.next_page_;
	rd_info("Pi %lu: log head @ 0x%lx, tail @ 0x%lx\n",
			sih->ino, curr, sih->i_log_tail);
	curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr);
	while ((next = FINEFS_LOG_NEXT_PAGE(curr_page)) != 0) {
		rd_info("Current page 0x%lx, next page 0x%lx\n",
			curr >> FINEFS_LOG_SHIFT, next >> FINEFS_LOG_SHIFT);
		if (sih->i_log_tail >> FINEFS_LOG_SHIFT == curr >> FINEFS_LOG_SHIFT)
			used = count;
		curr = next;
		curr_page = (struct finefs_inode_log_page *)
			finefs_get_block(sb, curr);
		count++;
	}
	if (sih->i_log_tail >> FINEFS_LOG_SHIFT == curr >> FINEFS_LOG_SHIFT)
		used = count;
	rd_info("Pi %lu: log used %d pages, has %d pages, "
		"si reports %lu pages\n", sih->ino, used, count,
		sih->log_pages);
}

// void finefs_print_inode_log_pages(struct super_block *sb, struct inode *inode)
// {
// 	struct finefs_inode *pi;
// 	struct finefs_inode_info *si = FINEFS_I(inode);
// 	struct finefs_inode_info_header *sih = &si->header;

// 	pi = finefs_get_inode(sb, inode);
// 	finefs_print_finefs_log_pages(sb, sih, pi);
// }

// void finefs_print_free_lists(struct super_block *sb)
// {
// 	struct finefs_sb_info *sbi = FINEFS_SB(sb);
// 	struct free_list *free_list;
// 	int i;

// 	finefs_dbg("======== FINEFS per-CPU free list allocation stats ========\n");
// 	for (i = 0; i < sbi->cpus; i++) {
// 		free_list = finefs_get_free_list(sb, i);
// 		finefs_dbg("Free list %d: block start %lu, block end %lu, "
// 			"num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
// 			i, free_list->block_start, free_list->block_end,
// 			free_list->block_end - free_list->block_start + 1,
// 			free_list->num_free_blocks, free_list->num_blocknode);

// 		finefs_dbg("Free list %d: alloc log count %lu, "
// 			"allocated log pages %lu, alloc data count %lu, "
// 			"allocated data pages %lu, free log count %lu, "
// 			"freed log pages %lu, free data count %lu, "
// 			"freed data pages %lu\n", i,
// 			free_list->alloc_log_count,
// 			free_list->alloc_log_pages,
// 			free_list->alloc_data_count,
// 			free_list->alloc_data_pages,
// 			free_list->free_log_count,
// 			free_list->freed_log_pages,
// 			free_list->free_data_count,
// 			free_list->freed_data_pages);
// 	}

// 	i = SHARED_CPU;
// 	free_list = finefs_get_free_list(sb, i);
// 	finefs_dbg("Free list %d: block start %lu, block end %lu, "
// 		"num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
// 		i, free_list->block_start, free_list->block_end,
// 		free_list->block_end - free_list->block_start + 1,
// 		free_list->num_free_blocks, free_list->num_blocknode);

// 	finefs_dbg("Free list %d: alloc log count %lu, "
// 		"allocated log pages %lu, alloc data count %lu, "
// 		"allocated data pages %lu, free log count %lu, "
// 		"freed log pages %lu, free data count %lu, "
// 		"freed data pages %lu\n", i,
// 		free_list->alloc_log_count, free_list->alloc_log_pages,
// 		free_list->alloc_data_count, free_list->alloc_data_pages,
// 		free_list->free_log_count, free_list->freed_log_pages,
// 		free_list->free_data_count, free_list->freed_data_pages);
// }

