/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
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

#include "finefs/finefs.h"
#include "finefs/wprotect.h"
#include "util/cpu.h"
#include "util/log.h"

unsigned int finefs_blk_type_to_shift[FINEFS_BLOCK_TYPE_MAX] = {
    12 + FINEFS_4K_BLK_NUM_BITS,   12 + FINEFS_8K_BLK_NUM_BITS,   12 + FINEFS_16K_BLK_NUM_BITS,
    12 + FINEFS_32K_BLK_NUM_BITS,  12 + FINEFS_64K_BLK_NUM_BITS,  12 + FINEFS_128K_BLK_NUM_BITS,
    12 + FINEFS_256K_BLK_NUM_BITS, 12 + FINEFS_512K_BLK_NUM_BITS, 12 + FINEFS_1M_BLK_NUM_BITS,
    12 + FINEFS_2M_BLK_NUM,        12 + FINEFS_1G_BLK_NUM,
};
unsigned int finefs_blk_type_to_size[FINEFS_BLOCK_TYPE_MAX] = {
    1u << (12 + FINEFS_4K_BLK_NUM_BITS),   1u << (12 + FINEFS_8K_BLK_NUM_BITS),
    1u << (12 + FINEFS_16K_BLK_NUM_BITS),  1u << (12 + FINEFS_32K_BLK_NUM_BITS),
    1u << (12 + FINEFS_64K_BLK_NUM_BITS),  1u << (12 + FINEFS_128K_BLK_NUM_BITS),
    1u << (12 + FINEFS_256K_BLK_NUM_BITS), 1u << (12 + FINEFS_512K_BLK_NUM_BITS),
    1u << (12 + FINEFS_1M_BLK_NUM_BITS),   1u << (12 + FINEFS_2M_BLK_NUM),
    1u << (12 + FINEFS_1G_BLK_NUM),
};
unsigned int finefs_blk_type_to_blk_num[FINEFS_BLOCK_TYPE_MAX] = {
    1u << (12 + FINEFS_4K_BLK_NUM_BITS - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_8K_BLK_NUM_BITS - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_16K_BLK_NUM_BITS - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_32K_BLK_NUM_BITS - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_64K_BLK_NUM_BITS - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_128K_BLK_NUM_BITS - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_256K_BLK_NUM_BITS - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_512K_BLK_NUM_BITS - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_1M_BLK_NUM_BITS - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_2M_BLK_NUM - FINEFS_BLOCK_SHIFT) ?: 1,
    1u << (12 + FINEFS_1G_BLK_NUM - FINEFS_BLOCK_SHIFT) ?: 1,
};

int finefs_init_inode_inuse_list(struct super_block *sb) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct finefs_range_node *range_node;
    struct inode_map *inode_map;
    unsigned long range_high;
    int i;
    int ret;

    // 优先把预留的inode，设置为已经使用
    sbi->s_inodes_used_count = FINEFS_NORMAL_INODE_START;

    range_high = (FINEFS_NORMAL_INODE_START - 1) / sbi->cpus;
    if (FINEFS_NORMAL_INODE_START % sbi->cpus) range_high++;

    for (i = 0; i < sbi->cpus; i++) {
        inode_map = &sbi->inode_maps[i];
        range_node = finefs_alloc_inode_node(sb);
        if (range_node == NULL) /* FIXME: free allocated memories */
            return -ENOMEM;

        range_node->range_low = 0;
        range_node->range_high = range_high;
        ret = finefs_insert_inodetree(sbi, range_node, i);
        if (ret) {
            r_error("%s failed", __func__);
            finefs_free_inode_node(sb, range_node);
            return ret;
        }
        inode_map->num_range_node_inode = 1;
        inode_map->first_inode_range = range_node;
    }

    return 0;
}

int finefs_init_inode_table(struct super_block *sb) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct inode_table *inode_table;
    struct finefs_inode *pi = finefs_get_inode_by_ino(sb, FINEFS_INODETABLE_INO);
    unsigned long blocknr;
    u64 block;
    int allocated;
    int i;

    pi->i_mode = 0;
    pi->i_uid = 0;
    pi->i_gid = 0;
    pi->i_links_count = cpu_to_le16(1);
    pi->i_flags = 0;
    pi->finefs_ino = FINEFS_INODETABLE_INO;

    pi->i_blk_type = FINEFS_BLOCK_TYPE_2M;

    for (i = 0; i < sbi->cpus; i++) {
        inode_table = finefs_get_inode_table(sb, i);
        if (!inode_table) return -EINVAL;

        allocated = finefs_new_data_blocks(sb, pi, &blocknr, 1, 0, 1, 0, i);
        rdv_proc("%s: allocate log @ 0x%lx", __func__, blocknr);
        if (allocated != 1 || blocknr == 0) return -ENOSPC;

        block = finefs_get_block_off(sb, blocknr, FINEFS_BLOCK_TYPE_2M);
        inode_table->log_head = block;
        finefs_flush_buffer(inode_table, CACHELINE_SIZE, 0);
    }

    PERSISTENT_BARRIER();
    return 0;
}

int finefs_init_slab_page_inode(struct super_block *sb) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct finefs_inode *pi = finefs_get_inode_by_ino(sb, FINEFS_SLAB_PAGE_INO);

    pi->i_links_count = cpu_to_le16(1);
    pi->finefs_ino = FINEFS_INODETABLE_INO;
    pi->i_blk_type = FINEFS_DEFAULT_DATA_BLOCK_TYPE;
    pi->log_tail = 0;

    finefs_flush_buffer(pi, sizeof(finefs_inode), 1);
    return 0;
}

// 需要读取nvm中的结构索引来找到对应inode在nvm中的资质
// 索引信息能否搬迁到dram
// extendable 为1时表示，当查到超过最后一个block返回时，是否分配新的block进行扩展
// pi_addr 带回inode的NVM地址
int finefs_get_inode_address(struct super_block *sb, u64 ino, u64 *pi_addr, int extendable) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct finefs_inode *pi;
    struct inode_table *inode_table;
    unsigned int data_bits;
    unsigned int num_inodes_bits;
    u64 curr;
    unsigned int superpage_count;
    u64 internal_ino;
    int cpuid;
    unsigned int index;
    unsigned int i = 0;
    unsigned long blocknr;
    unsigned long curr_addr;
    int allocated;

    pi = finefs_get_inode_by_ino(sb, FINEFS_INODETABLE_INO);
    data_bits = finefs_blk_type_to_shift[pi->i_blk_type];
    num_inodes_bits = data_bits - FINEFS_INODE_BITS;  // 一个block可以容纳的inode个数的bit

    cpuid = ino % sbi->cpus;
    internal_ino = ino / sbi->cpus;

    inode_table = finefs_get_inode_table(sb, cpuid);
    superpage_count = internal_ino >> num_inodes_bits;    // block的个数，即2MB的跳转次数
    index = internal_ino & ((1 << num_inodes_bits) - 1);  // 所在block的内部index

    curr = inode_table->log_head;
    if (curr == 0) return -EINVAL;

    for (i = 0; i < superpage_count; i++) {
        if (curr == 0) return -EINVAL;

        curr_addr = (unsigned long)finefs_get_block(sb, curr);
        /* Next page pointer in the last 8 bytes of the superpage */
        curr_addr += 2097152 - 8;
        curr = *(u64 *)(curr_addr);

        if (curr == 0) {
            if (extendable == 0) return -EINVAL;

            allocated = finefs_new_data_blocks(sb, pi, &blocknr, 1, 0, 1, 0);

            if (allocated != 1) {
                // return allocated;
                return -ENOMEM;
            }

            curr = finefs_get_block_off(sb, blocknr, FINEFS_BLOCK_TYPE_2M);
            *(u64 *)(curr_addr) = curr;
            finefs_flush_buffer((void *)curr_addr, FINEFS_INODE_SIZE, 1);
        }
    }

    *pi_addr = curr + index * FINEFS_INODE_SIZE;

    return 0;
}

// 释放连续的数据块
// 返回实质释放的page个数
// TODO: 这里还可以优化
static inline int finefs_free_contiguous_data_blocks(
    struct super_block *sb, struct finefs_inode_info_header *sih, struct finefs_inode *pi,
    struct finefs_file_pages_write_entry *entry, unsigned long pgoff, unsigned long num_pages,
    unsigned long *start_blocknr, unsigned long *num_free) {
    int freed = 0;
    unsigned long nvmm;

    if(entry == nullptr) return 0;

    if (entry->num_pages < entry->invalid_pages + num_pages) {
        r_error(
            "%s: inode %lu, entry pgoff %lu, %lu pages, "
            "invalid %lu, try to free %lu, pgoff %lu",
            __func__, sih->ino, entry->pgoff, entry->num_pages, entry->invalid_pages, num_pages,
            pgoff);
        return freed;  // 这是有可能发生的
    }

    // TODO: 这个又是NVM本地写，随机性很严重
    entry->invalid_pages += num_pages;
    if(entry->invalid_pages == entry->num_pages) {
        log_entry_set_invalid(sb, sih, entry, true);
    }

    nvmm = get_nvmm(sb, sih, entry, pgoff);

    if (*start_blocknr == 0) {
        *start_blocknr = nvmm;
        *num_free = num_pages;
    } else {
        if (nvmm == *start_blocknr + *num_free) {  // 这里是连续的
            (*num_free) += num_pages;
        } else {
            /* A new start */
            finefs_free_data_blocks(sb, pi, *start_blocknr,
                                    *num_free);  // 把之前的合并一起释放
            freed = *num_free;
            *start_blocknr = nvmm;
            *num_free = num_pages;
        }
    }

    return freed;
}

// 释放一个用链表连接起来的log page
// 返回实质释放的page个数
// sih == null，则no checkout
static int finefs_free_contiguous_log_blocks(struct super_block *sb, struct finefs_inode *pi,
                                             struct finefs_inode_info_header *sih, u64 head, u64 end) {
    struct finefs_inode_log_page *curr_page;
    unsigned long blocknr, start_blocknr = 0;
    u64 curr_block = head;
    u32 btype = pi->i_blk_type;
    int num_free = 0;
    int freed = 0;
    bool check = sih != nullptr;
    u64 tail = sih ? sih->h_log_tail : 0;

    while (curr_block != end) {
        if (curr_block & FINEFS_LOG_UMASK) {
            r_error("%s: ERROR: invalid block %lu", __func__, curr_block);
            break;
        }
        curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr_block);
#ifndef NDEBUG
        if(check) {
            // 不存在混合负载，因此，一遇到非unlink log便停止检查
            if((tail & FINEFS_LOG_MASK) == curr_block) {
                int nr = FINEFS_LOG_ENTRY_NR(tail);
                int entry_nr;
                int num = 0;
                for_each_set_bit(entry_nr, (const unsigned long *)&curr_page->page_tail.bitmap, nr) {
                    void* entry = finefs_get_block(sb, (tail & FINEFS_LOG_MASK) + entry_nr*CACHELINE_SIZE);
                    u8 entry_type = finefs_get_entry_type(entry);
                    dlog_assert(entry_type != FILE_PAGES_WRITE);
                    ++num;
                }
                dlog_assert(curr_page->page_tail.valid_num == num + BITS_PER_TYPE(curr_page->page_tail.bitmap) - nr - 1);
                // void* entry = finefs_get_block(sb, tail-CACHELINE_SIZE);
                // u8 entry_type = finefs_get_entry_type(entry);
                // dlog_assert(entry_type == LINK_CHANGE);
                // dlog_assert(entry_nr);
                // if(entry_nr == 1) {
                //     dlog_assert(curr_page->page_tail.bitmap == FINEFS_LOG_BITMAP_INIT);
                //     dlog_assert(curr_page->page_tail.valid_num == FINEFS_LOG_ENTRY_VALID_NUM_INIT);
                // } else {
                //     dlog_assert((curr_page->page_tail.bitmap <<
                //         (BITS_PER_TYPE(curr_page->page_tail.bitmap) - entry_nr + 1)) == 0);
                //     dlog_assert(curr_page->page_tail.valid_num =
                //         (BITS_PER_TYPE(curr_page->page_tail.bitmap) - entry_nr + 1));
                // }
                check = false;
            } else {
                if(curr_page->page_tail.bitmap != 0) {
                    int entry_nr = __ffs(curr_page->page_tail.bitmap);
                    void* entry = finefs_get_block(sb, curr_block+entry_nr*CACHELINE_SIZE);
                    u8 entry_type = finefs_get_entry_type(entry);
                    dlog_assert(entry_type != LINK_CHANGE && entry_type != FILE_PAGES_WRITE);
                    check = false;
                } else {
                    dlog_assert(curr_page->page_tail.valid_num == 0);
                }
            }
        }
#endif
        blocknr = finefs_get_blocknr(sb, le64_to_cpu(curr_block), btype);
        rdv_proc("%s: free page %lu", __func__, curr_block);
        curr_block = FINEFS_LOG_NEXT_PAGE(curr_page);

        if (start_blocknr == 0) {
            start_blocknr = blocknr;
            num_free = 1;
        } else {
            if (blocknr == start_blocknr + num_free) {
                num_free++;
            } else {
                /* A new start */
                finefs_free_log_blocks(sb, pi, start_blocknr, num_free);
                freed += num_free;
                start_blocknr = blocknr;
                num_free = 1;
            }
        }
    }
    if (start_blocknr) {
        finefs_free_log_blocks(sb, pi, start_blocknr, num_free);
        freed += num_free;
    }

    return freed;
}

// 优化前： 3512.64 kops
// 优化后:  3739.36 kops
static inline int finefs_gc_free_log_page(struct super_block *sb,
                                            struct finefs_inode_info_header *sih)
{
    if(sih->log_pages_to_free.empty()) return 0;
    rd_info("%s log_pages_to_gc=%u, log_pages_to_gc=%u", __func__,
        sih->log_pages_to_free.size(), sih->log_pages_to_gc.size());

    // finefs_inode_log_page* tail_page = finefs_log_page_addr(sb,
    //     sih->h_log_tail & FINEFS_LOG_MASK);
    log_assert(sih->log_pages_to_free.count(sih->h_log_tail & FINEFS_LOG_MASK) == 0);

    std::unordered_set<u64> log_pages_had_gc;
    std::unordered_map<u64, std::pair<u64, int> > pages_to_del;

    for(auto page_p: sih->log_pages_to_free) {
        if(log_pages_had_gc.count(page_p)) continue;
        log_pages_had_gc.insert(page_p);
        u64 start_p = page_p;
        finefs_inode_log_page *first_page =
            (finefs_inode_log_page*)finefs_get_block(sb, page_p);
        finefs_inode_log_page *cur_page = first_page;
        int num = 1;
        u64 cur_page_p = page_p;
        u64 next_page_p = cur_page->page_tail.page_link.next_page_;
        while(1) {
            if(sih->log_pages_to_free.count(next_page_p)) {
                if(log_pages_had_gc.count(next_page_p)) { // 后一个已经处理
                    auto iter = pages_to_del.find(next_page_p);
                    log_assert(iter != pages_to_del.end());
                    std::pair<u64, int> p = iter->second;
                    u64 last_start = iter->first;
                    p.second += num;
                    pages_to_del[start_p] = p;
                    pages_to_del.erase(last_start);
                    break;
                } else {
                    log_pages_had_gc.insert(next_page_p);
                    ++num;
                    cur_page_p = next_page_p;
                    cur_page = (finefs_inode_log_page*)finefs_get_block(sb, next_page_p);
                    next_page_p = cur_page->page_tail.page_link.next_page_;
                }
            } else {
                std::pair<u64, int> p = std::make_pair(cur_page_p, num);
                pages_to_del[start_p] = p;
                break;
            }
        }
    }

    finefs_inode *pi = (finefs_inode *)finefs_get_block(sb, sih->pi_addr);
    int free_pages = 0;
    for(auto p: pages_to_del) {
        u64 start_p = p.first;
        u64 end_p = p.second.first;
        int free_num = p.second.second;
        rd_info("range delete log pages: %d, from %lu to %lu", free_num, start_p, end_p);
        finefs_inode_log_page *start_page =
            (finefs_inode_log_page*)finefs_get_block(sb, start_p);
        finefs_inode_log_page *end_page =
            (finefs_inode_log_page*)finefs_get_block(sb, end_p);
        finefs_log_range_delete(sb, start_page, end_page);
        sih->log_pages -= free_num;
        sih->h_blocks -= free_num;
        free_pages += free_num;

        u64 d_head = start_p;
        u64 d_end = end_page->page_tail.page_link.next_page_;
        int freed = finefs_free_contiguous_log_blocks(sb, pi, sih, start_p, d_end);
        log_assert(freed == free_num);
    }

    log_assert(log_pages_had_gc.size() == sih->log_pages_to_free.size());
    log_assert(free_pages == sih->log_pages_to_free.size());
    sih->log_pages_to_free.clear();
    return free_pages;
}

// static int finefs_delete_cache_tree(struct super_block *sb,
// 	struct finefs_inode *pi, struct finefs_inode_info_header *sih,
// 	unsigned long start_blocknr, unsigned long last_blocknr)
// {
// 	unsigned long addr;
// 	unsigned long i;
// 	int deleted = 0;
// 	void *ret;

// 	finefs_dbgv("%s: inode %lu, mmap pages %lu, start %lu, last %lu",
// 			__func__, sih->ino, sih->mmap_pages,
// 			start_blocknr, last_blocknr);

// 	for (i = start_blocknr; i <= last_blocknr; i++) {
// 		addr = (unsigned long)radix_tree_lookup(&sih->cache_tree, i);
// 		if (addr) {
// 			ret = radix_tree_delete(&sih->cache_tree, i);
// 			finefs_free_data_blocks(sb, pi, addr >> PAGE_SHIFT, 1);
// 			sih->mmap_pages--;
// 			deleted++;
// 		}
// 	}

// 	finefs_dbgv("%s: inode %lu, deleted mmap pages %d",
// 			__func__, sih->ino, deleted);

// 	if (sih->mmap_pages == 0) {
// 		sih->low_dirty = ULONG_MAX;
// 		sih->high_dirty = 0;
// 	}

// 	return 0;
// }

// static int finefs_zero_cache_tree(struct super_block *sb,
// 	struct finefs_inode *pi, struct finefs_inode_info_header *sih,
// 	unsigned long start_blocknr)
// {
// 	unsigned long block;
// 	unsigned long i;
// 	void *addr;

// 	finefs_dbgv("%s: inode %lu, mmap pages %lu, start %lu, last %lu, "
// 			"size %lu", __func__, sih->ino, sih->mmap_pages,
// 			start_blocknr, sih->high_dirty, sih->i_size);

// 	for (i = start_blocknr; i <= sih->high_dirty; i++) {
// 		block = (unsigned long)radix_tree_lookup(&sih->cache_tree, i);
// 		if (block) {
// 			addr = finefs_get_block(sb, block);
// 			memset(addr, 0, PAGE_SIZE);
// 		}
// 	}

// 	return 0;
// }
// 删除 small entry 的 NVM 结构
static force_inline void finefs_small_entry_remove(super_block* sb,
        struct finefs_inode *pi,
		struct finefs_inode_info_header *sih,
		finefs_file_small_entry* small_entry) {
	finefs_file_small_write_entry *small_write_entry = small_entry->nvm_entry_p;
	if(small_write_entry == nullptr) return;
    dlog_assert(small_write_entry);
    u64 slab_off = small_write_entry->slab_off;
    size_t slab_size = 1 << small_write_entry->slab_bits;
    // 释放 nvm slab 空间
    finefs_less_page_free(sb, pi, slab_off, slab_size);
    log_entry_set_invalid(sb, sih, small_write_entry, true);

    sih->h_slabs--;
    sih->h_slab_bytes -= slab_size;
}

static void finefs_file_page_entry_clear(struct super_block *sb,
    struct finefs_inode *pi, struct finefs_inode_info_header *sih,
    finefs_file_page_entry* dram_page_entry, bool just_del_small, bool nvm_delete)
{
    finefs_file_small_entry *cur, *next;
#ifdef FINEFS_SMALL_ENTRY_USE_LIST
    list_for_each_entry_safe(cur, next, &dram_page_entry->small_write_head, entry) {
        dlog_assert(cur->nvm_data);
        // dlog_assert(cur->nvm_entry_p);
        if(nvm_delete) {
            finefs_small_entry_remove(sb, pi, sih, cur);
        }
        list_del(&cur->entry);
        finefs_free_small_entry(cur);
        dram_page_entry->num_small_write--;
    }
#else
    for(auto p: dram_page_entry->file_off_2_small) {
        cur = p.second;
        dlog_assert(cur->nvm_data);
        dlog_assert(cur->nvm_entry_p);
        if(nvm_delete) {
            finefs_small_entry_remove(sb, pi, sih, cur);
        }
        finefs_free_small_entry(cur);
        dram_page_entry->num_small_write--;
    }
    dram_page_entry->file_off_2_small.clear();
#endif

    dlog_assert(dram_page_entry->num_small_write == 0);
    if(just_del_small) return; // for file delete

    if(nvm_delete && dram_page_entry->nvm_entry_p) {
        dlog_assert(dram_page_entry->nvm_block_p);
        finefs_file_pages_write_entry  *old_nvm_entry = dram_page_entry->nvm_entry_p;
        // old_nvm_entry->invalid_pages++;
        if(old_nvm_entry->invalid_pages + 1 == old_nvm_entry->num_pages) {
            log_entry_set_invalid(sb, sih, old_nvm_entry, true);
        } else {
            old_nvm_entry->invalid_pages++;
        }
        // 立即释放特定的block
        u64 old_nvmm = get_blocknr_from_page_entry(sb, sih, dram_page_entry, dram_page_entry->file_pgoff);
        finefs_free_data_blocks(sb, pi, old_nvmm, 1);
        sih->h_blocks--;
    }
    // finefs_page_write_entry_init(dram_page_entry);
}

// 删除[start_blocknr, last_blocknr]的数据块
int finefs_delete_file_tree(struct super_block *sb, struct finefs_inode_info_header *sih,
                            unsigned long start_blocknr, unsigned long last_blocknr,
                            bool delete_nvmm, bool delete_mmap) {
    struct finefs_file_pages_write_entry *entry;
    struct finefs_file_page_entry *page_entry_dram;
    struct finefs_inode *pi;
    unsigned long free_blocknr = 0, num_free = 0;
    unsigned long pgoff = start_blocknr;
    timing_t delete_time;
    int freed = 0;
    void *ret;

    pi = (struct finefs_inode *)finefs_get_block(sb, sih->pi_addr);

    FINEFS_START_TIMING(delete_file_tree_t, delete_time);

    // if (delete_mmap && sih->mmap_pages) {
    //     r_error("un support mmap");
    //     // finefs_delete_cache_tree(sb, pi, sih, start_blocknr,
    //     // 				last_blocknr);
    // }

    // if (sih->mmap_pages && start_blocknr <= sih->high_dirty)
    // 	finefs_zero_cache_tree(sb, pi, sih, start_blocknr);

    pgoff = start_blocknr;
    while (pgoff <= last_blocknr) {
        page_entry_dram = (struct finefs_file_page_entry *)radix_tree_lookup(&sih->tree, pgoff);
        if (page_entry_dram) {
            ret = radix_tree_delete(&sih->tree, pgoff);
            BUG_ON(!ret || ret != page_entry_dram);
            if (delete_nvmm) {
                // 删除slab
                finefs_file_page_entry_clear(sb, pi, sih, page_entry_dram, true, delete_nvmm);
                entry = page_entry_dram->nvm_entry_p;
                freed += finefs_free_contiguous_data_blocks(sb, sih, pi, entry, pgoff, 1,
                                                            &free_blocknr, &num_free);
            } else {
                // 删除小写的内存结构
                finefs_file_page_entry_clear(sb, pi, sih, page_entry_dram, true, false);
            }
            pgoff++;
            // 删除内存
            finefs_free_page_entry(page_entry_dram);
        } else {
            /* We are finding a hole. Jump to the next entry. */
            page_entry_dram = finefs_find_next_page_entry(sb, sih, pgoff);
            if (!page_entry_dram) break;
            entry = page_entry_dram->nvm_entry_p;
            pgoff++;
            pgoff = pgoff > entry->pgoff ? pgoff : entry->pgoff;
        }
    }

    if (free_blocknr) {
        finefs_free_data_blocks(sb, pi, free_blocknr, num_free);
        freed += num_free;
    }

    FINEFS_END_TIMING(delete_file_tree_t, delete_time);
    rd_info(
        "Inode %lu: delete file tree from pgoff %lu to %lu, "
        "%d blocks freed",
        pi->finefs_ino, start_blocknr, last_blocknr, freed);

    return freed;
}

static int finefs_free_dram_resource(struct super_block *sb, struct finefs_inode_info_header *sih) {
    unsigned long last_blocknr;
    int freed = 0;

    if (!(S_ISREG(sih->i_mode)) && !(S_ISDIR(sih->i_mode))) return 0;

    if (S_ISREG(sih->i_mode)) {
        last_blocknr = finefs_get_last_blocknr(sb, sih);
        freed = finefs_delete_file_tree(sb, sih, 0, last_blocknr, false, true);
        finefs_delete_dir_tree(sb, sih, false);
        return freed;
    } else {
        finefs_delete_dir_tree(sb, sih, false);
        freed = 1;
    }

    return freed;
}

/*
 * Free data blocks from inode in the range start <=> end
 */
static void finefs_truncate_file_blocks(struct inode *inode, loff_t start, loff_t end) {
    struct super_block *sb = inode->i_sb;
    struct finefs_inode *pi = finefs_get_inode(sb, inode);
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;
    unsigned int data_bits = finefs_blk_type_to_shift[pi->i_blk_type];
    unsigned long first_blocknr, last_blocknr;
    int freed = 0;

    inode->i_mtime = inode->i_ctime = get_cur_time_spec();

    rd_info("truncate: pi %p iblocks %llx %llx %llx %llx", pi, pi->i_blocks, start, end,
            pi->i_size);

    first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

    if (end == 0) return;
    last_blocknr = (end - 1) >> data_bits;

    if (first_blocknr > last_blocknr) return;

    log_assert(0);

    freed = finefs_delete_file_tree(sb, sih, first_blocknr, last_blocknr, 1, 0);

    inode->i_blocks -= (freed * (1 << (data_bits - sb->s_blocksize_bits)));

    dlog_assert(inode->i_blocks == sih->h_blocks);
    // sih->h_blocks = cpu_to_le64(inode->i_blocks);
    /* Check for the flag EOFBLOCKS is still valid after the set size */
    check_eof_blocks(sb, sih, pi, inode->i_size);

    return;
}

// struct finefs_file_pages_write_entry *finefs_find_next_entry(struct super_block *sb,
//                                                        struct finefs_inode_info_header *sih,
//                                                        pgoff_t pgoff) {
//     struct finefs_file_pages_write_entry *entry = NULL;
//     struct finefs_file_pages_write_entry *entries[1];
//     int nr_entries;

//     nr_entries = radix_tree_gang_lookup(&sih->tree, (void **)entries, pgoff, 1);
//     if (nr_entries == 1) entry = entries[0];

//     return entry;
// }

struct finefs_file_page_entry *finefs_find_next_page_entry(struct super_block *sb,
	struct finefs_inode_info_header *sih, pgoff_t pgoff) {
    struct finefs_file_page_entry *entry = NULL;
    struct finefs_file_page_entry *entries[1];
    int nr_entries;

    nr_entries = radix_tree_gang_lookup(&sih->tree, (void **)entries, pgoff, 1);
    if (nr_entries == 1) entry = entries[0];

    return entry;
}

/* search the radix tree to find hole or data
 * in the specified range
 * Input:
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * @data_found: indicates whether data blocks were found
 * @hole_found: indicates whether a hole was found
 * hole: whether we are looking for a hole or data
 */
// static int finefs_lookup_hole_in_range(struct super_block *sb,
// 	struct finefs_inode_info_header *sih,
// 	unsigned long first_blocknr, unsigned long last_blocknr,
// 	int *data_found, int *hole_found, int hole)
// {
// 	struct finefs_file_pages_write_entry *entry;
// 	unsigned long blocks = 0;
// 	unsigned long pgoff, old_pgoff;

// 	pgoff = first_blocknr;
// 	while (pgoff <= last_blocknr) {
// 		old_pgoff = pgoff;
// 		entry = radix_tree_lookup(&sih->tree, pgoff);
// 		if (entry) {
// 			*data_found = 1;
// 			if (!hole)
// 				goto done;
// 			pgoff++;
// 		} else {
// 			*hole_found = 1;
// 			entry = finefs_find_next_entry(sb, sih, pgoff);
// 			pgoff++;
// 			if (entry) {
// 				pgoff = pgoff > entry->pgoff ?
// 					pgoff : entry->pgoff;
// 				if (pgoff > last_blocknr)
// 					pgoff = last_blocknr + 1;
// 			}
// 		}

// 		if (!*hole_found || !hole)
// 			blocks += pgoff - old_pgoff;
// 	}
// done:
// 	return blocks;
// }

void finefs_page_write_entry_set(finefs_file_page_entry* entry,
	finefs_file_pages_write_entry* nvm_entry_p, u64 file_pgoff, void* nvm_block_p) {
    entry->nvm_entry_p = nvm_entry_p;
    entry->file_pgoff = file_pgoff;
    entry->nvm_block_p = nvm_block_p;

    entry->num_small_write = 0;
#ifdef FINEFS_SMALL_ENTRY_USE_LIST
    INIT_LIST_HEAD(&entry->small_write_head);
#else
    new (&entry->file_off_2_small) std::map<u64, finefs_file_small_entry*>();
#endif
}

bool finefs_page_entry_is_right(super_block* sb, finefs_file_page_entry* page_entry) {
    finefs_file_pages_write_entry* write_entry = page_entry->nvm_entry_p;
    u64 pgoff = page_entry->file_pgoff;

	dlog_assert(write_entry->pgoff <= pgoff &&
		write_entry->pgoff + write_entry->num_pages > pgoff);
	u64 block_off = (unsigned long)((uintptr_t)(page_entry->nvm_block_p) -
		(uintptr_t)finefs_get_super(sb));
	u64 write_entry_block = write_entry->block & FINEFS_BLOCK_MASK;
	dlog_assert(write_entry_block <= block_off &&
		write_entry_block + write_entry->num_pages > block_off);

    return true;
}

// 听过东西可以写的
int finefs_file_page_entry_flush_slab(struct super_block *sb,
    struct finefs_inode *pi, struct finefs_inode_info_header *sih,
    finefs_file_page_entry* dram_page_entry, u64 *tail)
{
    int ret = 0;
    u64 blocknr = 0;
    void* page_data = nullptr;
    bool is_new_page;
    finefs_file_small_entry *cur, *next;
    finefs_file_pages_write_entry* pages_write_entry = dram_page_entry->nvm_entry_p;

    if(pages_write_entry) {
        is_new_page = false;
        page_data = dram_page_entry->nvm_block_p;
        u64 start_blocknr = finefs_get_blocknr(sb, pages_write_entry->block, pi->i_blk_type);
        blocknr = start_blocknr + dram_page_entry->file_pgoff - pages_write_entry->pgoff;
    } else {
        is_new_page = true;
        int allocated = finefs_new_data_blocks(sb, pi, &blocknr, 1, 0, 0, 0);
        if(allocated <= 0) {
            r_error("%s: new block fail. ENOSPC", __func__);
            return -ENOSPC;
        }
        rd_info("%s: new block %lu", __func__ ,blocknr);
        u64 block_off = finefs_get_block_off(sb, blocknr, pi->i_blk_type);
        page_data = finefs_get_block(sb, block_off);

    }
    rd_info("%s: num_small_write %d, file_pgoff %lu, nvm_entry_p %p", __func__, dram_page_entry->num_small_write,
        dram_page_entry->file_pgoff, dram_page_entry->nvm_entry_p);

    // 先拷贝数据
    u64 last_pos = dram_page_entry->file_pgoff << FINEFS_BLOCK_SHIFT;
    char* cur_ptr = (char*)page_data;
    u32 mtime = 0;
    u32 file_size = 0;

    dlog_assert(dram_page_entry->num_small_write);
    u64 bytes;

#ifdef FINEFS_SMALL_ENTRY_USE_LIST
    list_for_each_entry_safe(cur, next, &dram_page_entry->small_write_head, entry) {
        dlog_assert(cur->nvm_data);
        // dlog_assert(cur->nvm_entry_p);
        bytes = cur->file_off - last_pos;
        if(is_new_page && bytes) {
            pmem_memset(cur_ptr, 0, bytes, false);
        }
        cur_ptr += bytes;
        last_pos += bytes;
        dlog_assert(last_pos == cur->file_off);
        finefs_copy_to_nvm(sb, cur_ptr, cur->nvm_data, cur->bytes, false);
        cur_ptr += cur->bytes;
        last_pos += cur->bytes;

        if(cur->nvm_entry_p) {
            mtime = cur->nvm_entry_p->mtime > mtime  ? cur->nvm_entry_p->mtime : mtime;
            file_size = cur->nvm_entry_p->size > file_size ? cur->nvm_entry_p->size : file_size;
        }
    }
#else
    for(auto p : dram_page_entry->file_off_2_small) {
        cur = p.second;
        bytes = cur->file_off - last_pos;
        if(is_new_page && bytes) {
            pmem_memset(cur_ptr, 0, bytes, false);
            cur_ptr += bytes;
            last_pos += bytes;
        }
        dlog_assert(last_pos == cur->file_off);
        pmem_memcpy(cur_ptr, cur->nvm_data, cur->bytes, false);
        cur_ptr += cur->bytes;
        last_pos += cur->bytes;

        mtime = cur->nvm_entry_p->mtime > mtime  ? cur->nvm_entry_p->mtime : mtime;
        file_size = cur->nvm_entry_p->size > file_size ? cur->nvm_entry_p->size : file_size;
    }
#endif

    u64 end_pos = ((dram_page_entry->file_pgoff + 1) << FINEFS_BLOCK_SHIFT);
    if(last_pos != end_pos && is_new_page) {
        dlog_assert(last_pos < end_pos);
        pmem_memset(cur_ptr, 0, end_pos - last_pos, false);
    }

    u64 cur_tail = *tail;
    finefs_file_pages_write_entry page_entry_data;

    // 提交log
    page_entry_data.is_old = 0;
    page_entry_data.pgoff = cpu_to_le64(dram_page_entry->file_pgoff);
	page_entry_data.num_pages = cpu_to_le32(1);
	page_entry_data.invalid_pages = 0;
	page_entry_data.block = cpu_to_le64(finefs_get_block_off(sb, blocknr,
							pi->i_blk_type));
	page_entry_data.mtime = cpu_to_le32(mtime);
	finefs_set_entry_type((void *)&page_entry_data, TX_ATOMIC_FILE_PAGES_WRITE);
	page_entry_data.size = cpu_to_le64(file_size);
    PERSISTENT_BARRIER();
    inode* inode = finefs_get_vfs_inode_from_header(sih);
    // dlog_assert(cur_tail != 0);
	u64 curr_entry = finefs_append_file_write_entry(sb, pi, inode,
							&page_entry_data, cur_tail);
	if (curr_entry == 0) {
		rd_warning("%s: append inode entry failed", __func__);
		ret = -ENOSPC;
		goto out;
	}
    // dlog_assert(curr_entry == cur_tail);
    cur_tail = curr_entry + sizeof(struct finefs_file_pages_write_entry);
    *tail = cur_tail;
    PERSISTENT_BARRIER();  // 确保落盘

    // 删除旧的small_write entry
    finefs_file_page_entry_clear(sb, pi, sih, dram_page_entry, true, true);
    // 删除 page write entry
    if(pages_write_entry) {
        if(pages_write_entry->invalid_pages + 1 == pages_write_entry->num_pages) {
            log_entry_set_invalid(sb, sih, pages_write_entry, true);
        } else {
            pages_write_entry->invalid_pages++;
        }
    }

    dram_page_entry->nvm_entry_p = (finefs_file_pages_write_entry*)finefs_get_block(sb, curr_entry);
    dram_page_entry->nvm_block_p = finefs_get_block(sb,
        finefs_get_block_off(sb, blocknr, pi->i_blk_type));

    if(!is_new_page)
        sih->h_blocks--;

out:
    if(ret < 0) {
        if(is_new_page) {
            int err = finefs_free_data_blocks(sb, pi, blocknr, 1);
            dlog_assert(ret == 0);
        }
    }
    return ret;
}

// 我们不会将无用的log重复应用，因此总是能 nvm_delete=true
// FIXME: 但对于崩溃恢复来说，可能会出现的现象是：
// 当遍历一个log，将它索引的slab/block标志为有效，即从free head中删除相关的数据
// 这时可能会出现删除失败的现象，需要特殊处理，
// 因为我们无法完全按照之前的全局执行顺序来replay
static inline int finefs_file_page_entry_apply_slab(struct super_block *sb,
    struct finefs_inode *pi, struct finefs_inode_info_header *sih,
    finefs_file_page_entry* dram_page_entry,
    finefs_file_small_write_entry *small_write_entry, u64 *tail, bool nvm_delete)
{
    int ret = 0;
    if(dram_page_entry->num_small_write > SMALL_ENTRY_FLUSH_THRESHOLD_FOR_WRITE) {
        ret = finefs_file_page_entry_flush_slab(sb, pi, sih, dram_page_entry, tail);
        log_assert(ret == 0);
        if(ret) return ret;
    }
    finefs_file_small_entry *last = nullptr;
    finefs_file_small_entry *cur, *next;
    u64 start = small_write_entry->file_off;
    u64 end = small_write_entry->file_off + small_write_entry->bytes;

#ifdef FINEFS_SMALL_ENTRY_USE_LIST
    list_for_each_entry_safe(cur, next, &dram_page_entry->small_write_head, entry) {
        // 不覆盖，大于
        if(start >= cur->file_off + cur->bytes) {
            last = cur;
            continue;
        }
        // 不覆盖，小于
        if(end <= cur->file_off) {
            break;
        }
        // 覆盖前半部分
        if(start <= cur->file_off && end < cur->file_off + cur->bytes) {
            cur->bytes -= end - cur->file_off;
            cur->nvm_data += end - cur->file_off;
            cur->file_off = end;
            break;
        }
        // 完整覆盖
        if(start <= cur->file_off && end >= cur->file_off + cur->bytes) {
            // 删除旧的log
            finefs_small_entry_remove(sb, pi, sih, cur);
            list_del(&cur->entry);
            finefs_free_small_entry(cur);
            dram_page_entry->num_small_write--;
            continue;
        }
        // 覆盖后半部分
        if(start > cur->file_off && end >= cur->file_off + cur->bytes) {
            cur->bytes = start - cur->file_off;
            last = cur;
            continue;
        }
        // 中间覆盖
        if(start > cur->file_off && end < cur->file_off + cur->bytes) {
            // 处理后半部分
            finefs_file_small_entry* new_cur = finefs_alloc_small_entry(sb);
            new_cur->bytes = cur->file_off + cur->bytes - end;
            new_cur->file_off = end;
            new_cur->nvm_data = cur->nvm_data + (end - cur->file_off);
            // 由于所有的小写entry是同时flush的，所以这里将nvm_entry_p=0没有问题
            // 不会造成nvm entry泄漏或者重复释放
            new_cur->nvm_entry_p = 0;
            // new_cur->slab_bits = 0;

            // 处理前半部分
            cur->bytes = start - cur->file_off;
            list_add(&new_cur->entry, &cur->entry);
            break;
        }
    }
    cur = finefs_alloc_small_entry(sb);
    finefs_file_small_entry_set(sb, cur, small_write_entry);
    if(last == nullptr) {
        list_add(&cur->entry, &dram_page_entry->small_write_head);
        ++dram_page_entry->num_small_write;
    } else {
        list_add(&cur->entry, &last->entry);
        ++dram_page_entry->num_small_write;
    }
#else
    auto it = dram_page_entry->file_off_2_small.lower_bound(start);
    if(it == dram_page_entry->file_off_2_small.end()) {
        cur = finefs_alloc_small_entry(sb);
        finefs_file_small_entry_set(sb, cur, small_write_entry);
        dram_page_entry->file_off_2_small[start] = cur;
        dram_page_entry->num_small_write++;
    } else if (it->second->file_off <= end) {
        cur = it->second;
        // 其他部分覆盖的情况暂不处理
        log_assert(cur->file_off == start &&
            cur->file_off + cur->bytes == end);
        finefs_small_entry_remove(sb, pi, sih, cur);
        finefs_file_small_entry_set(sb, cur, small_write_entry);
    } else {
        cur = finefs_alloc_small_entry(sb);
        finefs_file_small_entry_set(sb, cur, small_write_entry);
        dram_page_entry->file_off_2_small[start] = cur;
        dram_page_entry->num_small_write++;
    }
#endif

    if(dram_page_entry->nvm_entry_p) {
        dram_page_entry->nvm_entry_p->is_old = 1;
    }
    return 0;
}

// nvm_delete = false，可能为了给文件系统关闭时使用的
static inline int finefs_apply_for_one_page(struct super_block *sb, struct finefs_inode *pi,
    struct finefs_inode_info_header *sih, finefs_file_page_entry* dram_page_entry,
    void *entry, u64 curr_pgoff, char* curr_block_p, u64 *tail, bool nvm_delete)
{
    u8 entry_type = finefs_get_entry_type(entry) & LOG_ENTRY_TYPE_MASK;
    if(entry_type == FILE_PAGES_WRITE) {
        // 释放旧的结构
        finefs_file_page_entry_clear(sb, pi, sih, dram_page_entry, false, nvm_delete);
        // 应用新的page
        finefs_file_pages_write_entry *pages_write_entry = (finefs_file_pages_write_entry*)entry;
        finefs_page_write_entry_set(dram_page_entry, pages_write_entry, curr_pgoff, curr_block_p);
        return 0;
    } else {
        // 小写
        finefs_file_small_write_entry *small_write_entry = (finefs_file_small_write_entry*)entry;
        int ret = finefs_file_page_entry_apply_slab(sb, pi, sih, dram_page_entry, small_write_entry, tail, nvm_delete);
        return ret;
        return 0;
    }
}

// file 写操作时，更新radix tree
int finefs_assign_write_entry(struct super_block *sb, struct finefs_inode *pi,
                              struct finefs_inode_info_header *sih,
                              void *entry, u64 *tail, bool free) {
    finefs_file_pages_write_entry* pages_write_entry = (finefs_file_pages_write_entry*)entry;
    finefs_file_small_write_entry* pages_small_entry = (finefs_file_small_write_entry*)entry;
    unsigned long curr_pgoff;
    unsigned long start_block = 0;  // for page write
    unsigned long slab_off = 0;     // for small write
    unsigned int num;

    u8 entry_type = finefs_get_entry_type(entry) & LOG_ENTRY_TYPE_MASK;
    if(entry_type == FILE_PAGES_WRITE) {
        curr_pgoff = pages_write_entry->pgoff;
        start_block = pages_write_entry->block;
        num = pages_write_entry->num_pages;
    } else {
        curr_pgoff = pages_small_entry->file_off >> FINEFS_BLOCK_SHIFT;
        slab_off = pages_small_entry->slab_off;
        num = 1;
    }

    void **pentry;
    char* curr_block_p = (char*)finefs_get_block(sb, start_block & FINEFS_BLOCK_MASK);
    int i;
    int ret = 0;
    timing_t assign_time;
    finefs_file_page_entry* dram_entry = nullptr;

    FINEFS_START_TIMING(assign_t, assign_time);
    for (i = 0; i < num; i++) {  // 插入也只能一个一个page插入
        pentry = radix_tree_lookup_slot(&sih->tree, curr_pgoff);
        if(!pentry) {
            dram_entry = finefs_alloc_page_entry(sb);
            log_assert(dram_entry);
            finefs_page_write_entry_init(dram_entry, curr_pgoff);
            ret = radix_tree_insert(&sih->tree, curr_pgoff, dram_entry);
            if (ret) {
                rd_info("%s: ERROR %d", __func__, ret);
                finefs_free_page_entry(dram_entry);
                goto out;
            }
        } else {
            dram_entry = (struct finefs_file_page_entry *)radix_tree_deref_slot(pentry);
        }
        ret = finefs_apply_for_one_page(sb, pi, sih, dram_entry, entry, curr_pgoff,
            curr_block_p, tail, free);
        if (ret) {
            rd_info("%s: ERROR %d", __func__, ret);
            goto out;
        }

        // if (pentry) {
        //     old_dram_entry = (struct finefs_file_page_entry *)radix_tree_deref_slot(pentry);
        //     old_nvmm = get_blocknr_from_page_entry(sb, sih, old_dram_entry, curr_pgoff);
        //     // old_nvmm = get_nvmm(sb, sih, old_entry, curr_pgoff);
        //     old_nvm_entry = old_dram_entry->nvm_entry_p;
        //     if (free) {
        //         old_nvm_entry->invalid_pages++;
        //         if(old_nvm_entry->invalid_pages == old_nvm_entry->num_pages) {
        //             log_entry_set_invalid(sb, sih, old_nvm_entry);
        //         }
        //         // 立即释放特定的block
        //         finefs_free_data_blocks(sb, pi, old_nvmm, 1);
        //         pi->i_blocks--;
        //     }
        //     finefs_page_write_entry_set(old_dram_entry, entry, curr_pgoff, curr_block_p);
        //     // radix_tree_replace_slot(pentry, entry);
        // } else {
        //     // 之前是hole/初始化
        //     dram_entry = finefs_alloc_page_entry(sb);
        //     log_assert(dram_entry);
        //     finefs_page_write_entry_set(dram_entry, entry, curr_pgoff, curr_block_p);
        //     ret = radix_tree_insert(&sih->tree, curr_pgoff, dram_entry);
        //     if (ret) {
        //         rd_info("%s: ERROR %d", __func__, ret);
        //         finefs_free_page_entry(dram_entry);
        //         goto out;
        //     }
        // }
        ++curr_pgoff;
        curr_block_p += FINEFS_BLOCK_SIZE;
    }

out:
    FINEFS_END_TIMING(assign_t, assign_time);

    return ret;
}

// 根据NVM的信息，初始化内存inode
// 只用于root inode 的初始化
static int finefs_read_inode(struct super_block *sb, struct inode *inode, u64 pi_addr) {
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode *pi;
    struct finefs_inode_info_header *sih = &si->header;
    int ret = -EIO;
    unsigned long ino;

    pi = (struct finefs_inode *)finefs_get_block(sb, pi_addr);
    inode->i_mode = sih->i_mode;
    // i_uid_write(inode, le32_to_cpu(pi->i_uid));
    // i_gid_write(inode, le32_to_cpu(pi->i_gid));
    set_nlink(inode, le16_to_cpu(pi->i_links_count));
    inode->i_generation = le32_to_cpu(pi->i_generation);
    finefs_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
    ino = inode->i_ino;

    /* check if the inode is active. */
    if (inode->i_mode == 0 || pi->valid == 0) {
        /* this inode is deleted */
        rd_warning("inode %lu, already delete， inode->i_mode=%d, pi->valid=%d", inode->i_mode,
                   pi->valid);
        ret = -ESTALE;
        goto bad_inode;
    }

    // inode->i_blocks = le64_to_cpu(pi->i_blocks);
    inode->i_blocks = sih->h_blocks;
    // inode->i_mapping->a_ops = &finefs_aops_dax;

    switch (inode->i_mode & S_IFMT) {
        case S_IFREG:
            inode->i_op = &finefs_file_inode_operations;
            inode->i_fop = &finefs_dax_file_operations;
            break;
        case S_IFDIR:
            inode->i_op = &finefs_dir_inode_operations;
            inode->i_fop = &finefs_dir_operations;
            break;
        case S_IFLNK:
            r_error("un support S_IFLNK");
            inode->i_op = &finefs_symlink_inode_operations;
            break;
        default:
            r_error("un support special_inode");
            inode->i_op = &finefs_special_inode_operations;
            // init_special_inode(inode, inode->i_mode,
            // 		   le32_to_cpu(pi->dev.rdev));
            break;
    }

    /* Update size and time after rebuild the tree */
    inode->i_size = le64_to_cpu(sih->i_size);
    inode->i_atime.tv_sec = le32_to_cpu(pi->i_atime);
    inode->i_ctime.tv_sec = le32_to_cpu(pi->i_ctime);
    inode->i_mtime.tv_sec = le32_to_cpu(pi->i_mtime);
    inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;
    set_nlink(inode, le16_to_cpu(pi->i_links_count));
    return 0;

bad_inode:
    // make_bad_inode(inode);
    return ret;
}

static void finefs_get_inode_flags(struct inode *inode, struct finefs_inode *pi) {
    unsigned int flags = inode->i_flags;
    unsigned int finefs_flags = le32_to_cpu(pi->i_flags);

    finefs_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL | FS_NOATIME_FL | FS_DIRSYNC_FL);
    if (flags & S_SYNC) finefs_flags |= FS_SYNC_FL;
    if (flags & S_APPEND) finefs_flags |= FS_APPEND_FL;
    if (flags & S_IMMUTABLE) finefs_flags |= FS_IMMUTABLE_FL;
    if (flags & S_NOATIME) finefs_flags |= FS_NOATIME_FL;
    if (flags & S_DIRSYNC) finefs_flags |= FS_DIRSYNC_FL;

    pi->i_flags = cpu_to_le32(finefs_flags);
}

static void finefs_update_inode(struct inode *inode, struct finefs_inode *pi) {
    finefs_memunlock_inode(inode->i_sb, pi);
    pi->i_mode = cpu_to_le16(inode->i_mode);
    // pi->i_uid = cpu_to_le32(i_uid_read(inode));
    // pi->i_gid = cpu_to_le32(i_gid_read(inode));
    pi->i_links_count = cpu_to_le16(inode->i_nlink);
    pi->i_size = cpu_to_le64(inode->i_size);
    pi->i_blocks = cpu_to_le64(inode->i_blocks);
    pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
    pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
    pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
    pi->i_generation = cpu_to_le32(inode->i_generation);
    finefs_get_inode_flags(inode, pi);

    // if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
    // 	pi->dev.rdev = cpu_to_le32(inode->i_rdev);

    finefs_memlock_inode(inode->i_sb, pi);
}

static int finefs_alloc_unused_inode(struct super_block *sb, int cpuid, unsigned long *ino) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct inode_map *inode_map;
    struct finefs_range_node *i, *next_i;
    struct rb_node *temp, *next;
    unsigned long next_range_low;
    unsigned long new_ino;
    unsigned long MAX_INODE = 1UL << 31;

    inode_map = &sbi->inode_maps[cpuid];
    i = inode_map->first_inode_range;
    dlog_assert(i);
    temp = &i->node;
    next = rb_next(temp);

    if (!next) {
        next_i = NULL;
        next_range_low = MAX_INODE;
    } else {
        next_i = container_of(next, struct finefs_range_node, node);
        next_range_low = next_i->range_low;
    }

    new_ino = i->range_high + 1;

    if (next_i && new_ino == (next_range_low - 1)) {
        /* Fill the gap completely */
        i->range_high = next_i->range_high;
        rb_erase(&next_i->node, &inode_map->inode_inuse_tree);
        finefs_free_inode_node(sb, next_i);
        inode_map->num_range_node_inode--;
    } else if (new_ino < (next_range_low - 1)) {
        /* Aligns to left */
        i->range_high = new_ino;
    } else {
        r_error("%s: ERROR: new ino %lu, next low %lu", __func__, new_ino, next_range_low);
        return -ENOSPC;
    }

    *ino = new_ino * sbi->cpus + cpuid;
    sbi->s_inodes_used_count++;
    inode_map->allocated++;

    rdv_proc("Alloc ino %lu", *ino);
    return 0;
}

static int finefs_free_inuse_inode(struct super_block *sb, unsigned long ino) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct inode_map *inode_map;
    struct finefs_range_node *i = NULL;
    struct finefs_range_node *curr_node;
    int found = 0;
    int cpuid = ino % sbi->cpus;
    unsigned long internal_ino = ino / sbi->cpus;
    int ret = 0;

    rdv_proc("Free inuse ino: %lu", ino);
    inode_map = &sbi->inode_maps[cpuid];

    mutex_lock(&inode_map->inode_table_mutex);
    found = finefs_search_inodetree(sbi, ino, &i);
    if (!found) {
        r_error("%s ERROR: ino %lu not found", __func__, ino);
        mutex_unlock(&inode_map->inode_table_mutex);
        return -EINVAL;
    }

    if ((internal_ino == i->range_low) && (internal_ino == i->range_high)) {
        /* fits entire node */
        rb_erase(&i->node, &inode_map->inode_inuse_tree);
        finefs_free_inode_node(sb, i);
        inode_map->num_range_node_inode--;
        goto block_found;
    }
    if ((internal_ino == i->range_low) && (internal_ino < i->range_high)) {
        /* Aligns left */
        i->range_low = internal_ino + 1;
        goto block_found;
    }
    if ((internal_ino > i->range_low) && (internal_ino == i->range_high)) {
        /* Aligns right */
        i->range_high = internal_ino - 1;
        goto block_found;
    }
    if ((internal_ino > i->range_low) && (internal_ino < i->range_high)) {
        /* Aligns somewhere in the middle */
        curr_node = finefs_alloc_inode_node(sb);
        log_assert(curr_node);
        if (curr_node == NULL) {
            /* returning without freeing the block */
            goto block_found;
        }
        curr_node->range_low = internal_ino + 1;
        curr_node->range_high = i->range_high;
        i->range_high = internal_ino - 1;
        ret = finefs_insert_inodetree(sbi, curr_node, cpuid);
        if (ret) {
            finefs_free_inode_node(sb, curr_node);
            goto err;
        }
        inode_map->num_range_node_inode++;
        goto block_found;
    }

err:
    r_error("Unable to free inode %lu", ino);
    r_error("Found inuse block %lu - %lu", i->range_low, i->range_high);
    mutex_unlock(&inode_map->inode_table_mutex);
    return ret;

block_found:
    sbi->s_inodes_used_count--;
    inode_map->freed++;
    mutex_unlock(&inode_map->inode_table_mutex);
    return ret;
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 */
static int finefs_free_inode(struct inode *inode, struct finefs_inode_info_header *sih) {
    struct super_block *sb = inode->i_sb;
    struct finefs_inode *pi;
    int err = 0;
    timing_t free_time;

    FINEFS_START_TIMING(free_inode_t, free_time);

    pi = finefs_get_inode(sb, inode);

    if (pi->valid) {
        rd_info("%s: inode %lu still valid", __func__, inode->i_ino);
        pi->valid = 0;
    }

    if (pi->finefs_ino != inode->i_ino) {
        r_error("%s: inode %lu ino does not match: %lu", __func__, inode->i_ino, pi->finefs_ino);
        rd_info(
            "inode size %lu, pi addr 0x%lx, pi head 0x%lx, "
            "tail 0x%lx, mode %u",
            inode->i_size, sih->pi_addr, pi->log_head, pi->log_tail, pi->i_mode);
        rd_info(
            "sih: ino %lu, inode size %lu, mode %u, "
            "inode mode %u",
            sih->ino, sih->i_size, sih->i_mode, inode->i_mode);
        // finefs_print_inode_log(sb, inode);
    }

    rd_info("%s ino: %lu, log_pages: %lu", __func__, sih->ino, sih->log_pages);
    finefs_free_inode_log(sb, pi, sih);

    err = finefs_free_inuse_inode(sb, pi->finefs_ino);

    FINEFS_END_TIMING(free_inode_t, free_time);
    return err;
}

// 获取指定ino的内存结构，如果不存在，则分配空间返回
// 返回的inode已经存储在sb的哈希map中
struct inode *finefs_iget(struct super_block *sb, unsigned long ino) {
    struct finefs_inode_info *si;
    struct inode *inode;
    u64 pi_addr;
    int err;

    inode = iget_or_alloc(sb, ino);
    if (unlikely(!inode)) return nullptr;

    if (inode->i_state) return inode;

    // 新分配的，需要初始化
    si = FINEFS_I(inode);

    rd_info("%s: init inode %lu", __func__, ino);

    if (ino == FINEFS_ROOT_INO) {
        pi_addr = FINEFS_ROOT_INO_START;
    } else {
        err = finefs_get_inode_address(sb, ino, &pi_addr, 0);
        if (err) {
            r_error("%s: get inode %lu address failed %d", __func__, ino, err);
            goto fail;
        }
    }

    if (pi_addr == 0) {
        r_error("%s: get inode %lu address failed, pi_addr = 0", __func__, ino);
        goto fail;
    }

    // 主要初始化finefs_inode_info_header
    err = finefs_rebuild_inode(sb, si, pi_addr);
    if (err) {
        r_error("%s: finefs_rebuild_inode fail, inode = %lu, err = %d", __func__, ino, err);
        goto fail;
    }

    // 初始化内存inode
    err = finefs_read_inode(sb, inode, pi_addr);
    if (unlikely(err)) goto fail;
    inode->i_ino = ino;

    inode_set_valid(inode);
    // unlock_new_inode(inode);
    return inode;
fail:
    inode_unref(inode);
    inode_delete(sb, inode);
    return nullptr;
}

unsigned long finefs_get_last_blocknr(struct super_block *sb,
                                      struct finefs_inode_info_header *sih) {
    struct finefs_inode *pi;
    unsigned long last_blocknr;
    unsigned int btype;
    unsigned int data_bits;

    pi = (struct finefs_inode *)finefs_get_block(sb, sih->pi_addr);
    btype = pi->i_blk_type;
    data_bits = finefs_blk_type_to_shift[btype];

    if (sih->i_size == 0)
        last_blocknr = 0;
    else
        last_blocknr = (sih->i_size - 1) >> data_bits;

    return last_blocknr;
}

static force_inline void finefs_inode_statistic_dump(struct finefs_inode *pi,
    struct finefs_inode_info_header *sih)
{
    pi->i_blocks = cpu_to_le64(sih->h_blocks);
    pi->i_slabs =  cpu_to_le32(sih->h_slabs);
    pi->i_slab_bytes = cpu_to_le32(sih->h_slab_bytes);
    pi->i_ts = cpu_to_le64(sih->h_ts);

    finefs_flush_buffer(pi, sizeof(finefs_inode), 1);
}

// TODO: 将删除inode的过程放到后台执行
void finefs_evict_inode(struct inode *inode) {
    struct super_block *sb = inode->i_sb;
    struct finefs_inode *pi = finefs_get_inode(sb, inode);
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;
    unsigned long last_blocknr;
    timing_t evict_time;
    int err = 0;
    int freed = 0;
    int destroy = 0;

    if (!sih) {
        r_error("%s: ino %lu sih is NULL!", __func__, inode->i_ino);
        log_assert(0);
        goto out;
    }

    FINEFS_START_TIMING(evict_inode_t, evict_time);
    rdv_proc("%s: %lu", __func__, inode->i_ino);
    // FIXME: 目前保证删除时，link数为0
    log_assert(!inode->i_nlink);
    if (!inode->i_nlink) {  // !is_bad_inode(inode)
        // if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
        // 	goto out;

        destroy = 1;
        /* We need the log to free the blocks from the b-tree */
        switch (inode->i_mode & S_IFMT) {
            case S_IFREG:
                last_blocknr = finefs_get_last_blocknr(sb, sih);
                rd_info("%s: file ino %lu, size: %lu", __func__, inode->i_ino, inode->i_size);
                freed = finefs_delete_file_tree(sb, sih, 0, last_blocknr, true, true);
                finefs_delete_dir_tree(sb, sih, false); // 删除内存的radix tree
                break;
            case S_IFDIR:
                rd_info("%s: dir ino %lu", __func__, inode->i_ino);
                finefs_delete_dir_tree(sb, sih, true);
                break;
            case S_IFLNK:
                log_assert(0);
                /* Log will be freed later */
                rd_info("%s: symlink ino %lu", __func__, inode->i_ino);
                freed = finefs_delete_file_tree(sb, sih, 0, 0, true, true);
                finefs_delete_dir_tree(sb, sih, false); // 删除内存的radix tree
                break;
            default:
                rd_info("%s: special ino %lu", __func__, inode->i_ino);
                log_assert(0);
                break;
        }
        rd_info("%s: Freed %d, %0.2lf MB", __func__, freed, ((u64)freed << FINEFS_BLOCK_SHIFT >> 10) / 1024.0);
        dlog_assert(freed == sih->h_blocks - sih->log_pages);

        finefs_sih_flush_setattr_entry(sb, sih, true);
        finefs_sih_flush_link_change_entry(sb,sih);
        finefs_sih_bitmap_cache_flush(sih, true);

        dlog_assert(sih->h_slabs == 0);
        dlog_assert(sih->h_slab_bytes == 0);
        dlog_assert(sih->log_valid_bytes == 0);
        rd_info("%s: valid entrys: %lu", __func__, sih->log_valid_bytes/CACHELINE_SIZE);
        /* Then we can free the inode log*/
        err = finefs_free_inode(inode, sih);
        if (err) {
            r_error("%s: free inode %lu failed", __func__, inode->i_ino);
            goto out;
        }
        pi = NULL; /* we no longer own the finefs_inode */

        inode->i_mtime = inode->i_ctime = get_cur_time_spec();
        inode->i_size = 0;
    }
out:
    if (destroy == 0) {
        r_fatal("TODO");
        finefs_inode_statistic_dump(pi, sih);
        finefs_free_dram_resource(sb, sih); // 如果是文件删除，这个不会执行
    }

    /* TODO: Since we don't use page-cache, do we really need the following
     * call? */
    // truncate_inode_pages(&inode->i_data, 0);

    clear_inode(inode);
    FINEFS_END_TIMING(evict_inode_t, evict_time);
}

/* Returns 0 on failure */
// pi_addr: inode在NVM中的地址
// 返回分配的inumber
u64 finefs_new_finefs_inode(struct super_block *sb, u64 *pi_addr) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct inode_map *inode_map;
    unsigned long free_ino = 0;
    int map_id;
    u64 ino = 0;
    int ret;
    timing_t new_inode_time;

    FINEFS_START_TIMING(new_finefs_inode_t, new_inode_time);
    map_id = atomic_fetch_add(&sbi->map_id, 1);
    map_id = (map_id + 1) % sbi->cpus;

    inode_map = &sbi->inode_maps[map_id];

    mutex_lock(&inode_map->inode_table_mutex);
    ret = finefs_alloc_unused_inode(sb, map_id, &free_ino);
    if (ret) {
        rd_info("%s: alloc inode number failed %d", __func__, ret);
        mutex_unlock(&inode_map->inode_table_mutex);
        return 0;
    }

    ret = finefs_get_inode_address(sb, free_ino, pi_addr, 1);
    if (ret) {
        rd_info("%s: get inode address failed %d", __func__, ret);
        mutex_unlock(&inode_map->inode_table_mutex);
        return 0;
    }

    mutex_unlock(&inode_map->inode_table_mutex);

    ino = free_ino;

    FINEFS_END_TIMING(new_finefs_inode_t, new_inode_time);
    return ino;
}

// 新建一个内存inode, 并引用
// 初始化NVM中inode
struct inode *finefs_new_vfs_inode(enum finefs_new_inode_type type, struct inode *dir, u64 pi_addr,
                                   u64 ino, umode_t mode, size_t size, dev_t rdev,
                                   const struct qstr *qstr) {
    struct super_block *sb;
    struct finefs_sb_info *sbi;
    struct inode *inode;
    struct finefs_inode *diri = NULL;
    struct finefs_inode_info *si;
    struct finefs_inode_info_header *sih = NULL;
    struct finefs_inode *pi;
    int errval;
    timing_t new_inode_time;

    FINEFS_START_TIMING(new_vfs_inode_t, new_inode_time);
    sb = dir->i_sb;
    sbi = (struct finefs_sb_info *)sb->s_fs_info;
    inode = alloc_inode(sb);
    if (!inode) {
        errval = -ENOMEM;
        goto fail2;
    }

    inode_init_owner(inode, dir, mode);
    inode->i_blocks = inode->i_size = 0;
    inode->i_mtime = inode->i_atime = inode->i_ctime = get_cur_time_spec();

    inode->i_generation = atomic_add_fetch(&sbi->next_generation, 1);
    inode->i_size = size;  // 初始化是0

    /* chosen inode is in ino */
    inode->i_ino = ino;
    inode_insert(sb, inode);

    diri = finefs_get_inode(sb, dir);
    if (!diri) {
        r_error("unexpected finefs_get_inode fail!");
        errval = -EACCES;
        goto fail1;
    }

    pi = (struct finefs_inode *)finefs_get_block(sb, pi_addr);
    rdv_proc("%s: allocating inode %lu @ 0x%lx", __func__, ino, pi_addr);

    switch (type) {
        case TYPE_CREATE:
            inode->i_op = &finefs_file_inode_operations;
            // inode->i_mapping->a_ops = &finefs_aops_dax;
            inode->i_fop = &finefs_dax_file_operations;
            break;
        case TYPE_MKNOD:
            r_error("Un support TYPE_MKNOD");
            // init_special_inode(inode, mode, rdev);
            // inode->i_op = &finefs_special_inode_operations;
            break;
        case TYPE_SYMLINK:  // 符号链接
            r_error("Un support TYPE_SYMLINK");
            inode->i_op = &finefs_symlink_inode_operations;
            // inode->i_mapping->a_ops = &finefs_aops_dax;
            break;
        case TYPE_MKDIR:
            inode->i_op = &finefs_dir_inode_operations;
            inode->i_fop = &finefs_dir_operations;
            // inode->i_mapping->a_ops = &finefs_aops_dax;
            set_nlink(inode, 2);
            break;
        default:
            r_warning("Unknown new inode type %d", type);
            break;
    }

    /*
     * Pi is part of the dir log so no transaction is needed,
     * but we need to flush to NVMM.
     */
    finefs_memunlock_inode(sb, pi);
    pi->i_blk_type = FINEFS_LOG_BLOCK_TYPE;
    pi->i_flags = finefs_mask_flags(mode, diri->i_flags);

    pi->i_blocks = 0;
    pi->i_slabs = 0;
    pi->i_slab_bytes = 0;
    pi->i_ts = cpu_to_le64(1);

    finefs_log_link_init(&pi->log_head);
    finefs_log_link_init(&pi->log_head_gc);
    pi->log_tail = 0;
    pi->finefs_ino = ino;
    finefs_memlock_inode(sb, pi);

    si = FINEFS_I(inode);
    sih = &si->header;
    finefs_init_header(sb, sih, pi, inode->i_mode);
    sih->ino = ino;
    sih->pi_addr = pi_addr;

    finefs_update_inode(inode, pi);

    finefs_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));

    // if (insert_inode_locked(inode) < 0) {
    // 	r_error(sb, "finefs_new_inode failed ino %lx", inode->i_ino);
    // 	errval = -EINVAL;
    // 	goto fail1;
    // }

    finefs_flush_buffer(&pi, FINEFS_INODE_SIZE, 0);
    inode_set_valid(inode);
    FINEFS_END_TIMING(new_vfs_inode_t, new_inode_time);
    return inode;
fail1:
    // 	make_bad_inode(inode);
    // 	iput(inode);
    inode_unref(inode);
    inode_delete(sb, inode);
fail2:
    FINEFS_END_TIMING(new_vfs_inode_t, new_inode_time);
    // return ERR_PTR(errval);
    return nullptr;
}

int finefs_write_inode(struct inode *inode, struct writeback_control *wbc) {
    /* write_inode should never be called because we always keep our inodes
     * clean. So let us know if write_inode ever gets called. */
    //	BUG();
    return 0;
}

/*
 * dirty_inode() is called from mark_inode_dirty_sync()
 * usually dirty_inode should not be called because FINEFS always keeps its inodes
 * clean. Only exception is touch_atime which calls dirty_inode to update the
 * i_atime field.
 */
void finefs_dirty_inode(struct inode *inode, int flags) {
    struct super_block *sb = inode->i_sb;
    struct finefs_inode *pi = finefs_get_inode(sb, inode);

    /* only i_atime should have changed if at all.
     * we can do in-place atomic update */
    // finefs_memunlock_inode(sb, pi);
    // pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
    // finefs_memlock_inode(sb, pi);
    // /* Relax atime persistency */
    // finefs_flush_buffer(&pi->i_atime, sizeof(pi->i_atime), 0);
}

/*
 * Zero the tail page. Used in resize request
 * to avoid to keep data in case the file grows again.
 */
static void finefs_clear_last_page_tail(struct super_block *sb, struct inode *inode,
                                        loff_t newsize) {
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;
    unsigned long offset = newsize & (sb->s_blocksize - 1);
    unsigned long pgoff, length;
    u64 nvmm;
    char *nvmm_addr;

    if (offset == 0 || newsize > inode->i_size) return;

    log_assert(0);

    length = sb->s_blocksize - offset;
    pgoff = newsize >> sb->s_blocksize_bits;

    nvmm = finefs_find_nvmm_block(sb, si, NULL, pgoff);
    if (nvmm == 0) return;

    nvmm_addr = (char *)finefs_get_block(sb, nvmm);
    memset(nvmm_addr + offset, 0, length);
    finefs_flush_buffer(nvmm_addr + offset, length, 0);

    /* Clear mmap page */
    // if (sih->mmap_pages && pgoff <= sih->high_dirty &&
    // 		pgoff >= sih->low_dirty) {
    // 	nvmm = (unsigned long)radix_tree_lookup(&sih->cache_tree,
    // 						pgoff);
    // 	if (nvmm) {
    // 		nvmm_addr = finefs_get_block(sb, nvmm);
    // 		memset(nvmm_addr + offset, 0, length);
    // 	}
    // }
}

static void finefs_setsize(struct inode *inode, loff_t oldsize, loff_t newsize) {
    struct super_block *sb = inode->i_sb;
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;

    /* We only support truncate regular file */
    if (!(S_ISREG(inode->i_mode))) {
        r_error("%s:wrong file mode %x", inode->i_mode);
        return;
    }

    // inode_dio_wait(inode);

    rd_info("%s: inode %lu, old size %lu, new size %lu", __func__, inode->i_ino, oldsize, newsize);

    if (newsize != oldsize) {
        finefs_clear_last_page_tail(sb, inode, newsize);
        i_size_write(inode, newsize);
        sih->i_size = newsize;
    }

    /* FIXME: we should make sure that there is nobody reading the inode
     * before truncating it. Also we need to munmap the truncated range
     * from application address space, if mmapped. */
    /* synchronize_rcu(); */

    /* FIXME: Do we need to clear truncated DAX pages? */
    //	dax_truncate_page(inode, newsize, finefs_dax_get_block);

    // truncate_pagecache(inode, newsize);
    finefs_truncate_file_blocks(inode, newsize, oldsize);  // 回收移除的block
}

int finefs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat) {
    struct inode *inode;

    inode = dentry->d_inode;
    generic_fillattr(inode, stat);
    /* stat->blocks should be the number of 512B blocks */
    stat->blocks = (inode->i_blocks << inode->i_sb->s_blocksize_bits) >> 9;
    return 0;
}

static void finefs_update_setattr_entry(struct inode *inode,
                                        struct finefs_setattr_logentry *p_entry,
                                        struct iattr *attr) {
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;
    unsigned int ia_valid = attr->ia_valid, attr_mask;
    struct finefs_setattr_logentry *entry = p_entry;
    /* These files are in the lowest byte */
    attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE | ATTR_ATIME | ATTR_MTIME | ATTR_CTIME;

    entry->entry_type = TX_ATOMIC_SET_ATTR;
    entry->attr = ia_valid & attr_mask;
    entry->mode = cpu_to_le16(inode->i_mode);
    // entry->uid	= cpu_to_le32(i_uid_read(inode));
    // entry->gid	= cpu_to_le32(i_gid_read(inode));
    entry->atime = cpu_to_le32(inode->i_atime.tv_sec);
    entry->ctime = cpu_to_le32(inode->i_ctime.tv_sec);
    entry->mtime = cpu_to_le32(inode->i_mtime.tv_sec);
    if (ia_valid & ATTR_SIZE)
        entry->size = cpu_to_le64(attr->ia_size);
    else
        entry->size = cpu_to_le64(inode->i_size);
    entry->finefs_ino = cpu_to_le64(sih->ino);
    entry->entry_ts = cpu_to_le64(sih->h_ts++);
    barrier();
    // sfence();
    entry->entry_version = finefs_log_page_version(inode->i_sb,
        finefs_get_addr_off(inode->i_sb, entry));

    finefs_flush_buffer(p_entry, sizeof(struct finefs_setattr_logentry), 0);
}

// 属性还包括文件大小（截断/扩展）
void finefs_apply_setattr_entry(struct super_block *sb, struct finefs_inode *pi,
                                struct finefs_inode_info_header *sih,
                                struct finefs_setattr_logentry *entry) {
    unsigned int data_bits = finefs_blk_type_to_shift[pi->i_blk_type];
    unsigned long first_blocknr, last_blocknr;
    loff_t start, end;
    int freed = 0;

    dlog_assert((entry->entry_type & LOG_ENTRY_TYPE_MASK) == SET_ATTR);

    pi->i_mode = entry->mode;
    pi->i_uid = entry->uid;
    pi->i_gid = entry->gid;
    pi->i_atime = entry->atime;
    pi->i_ctime = entry->ctime;
    pi->i_mtime = entry->mtime;

    if (pi->i_size > entry->size && S_ISREG(pi->i_mode)) {
        log_assert(0);
        start = entry->size;
        end = pi->i_size;

        first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

        if (end > 0)
            last_blocknr = (end - 1) >> data_bits;
        else
            last_blocknr = 0;

        if (first_blocknr > last_blocknr) goto out;
        // 说明大小被截断了
        freed = finefs_delete_file_tree(sb, sih, first_blocknr, last_blocknr, 0, 0);
    }
out:
    pi->i_size = entry->size;
    sih->i_size = le64_to_cpu(pi->i_size);
    /* Do not flush now */
}

/* Returns new tail after append */
static u64 finefs_append_setattr_entry(struct super_block *sb, struct finefs_inode *pi,
                                       struct inode *inode, struct iattr *attr, u64 tail) {
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;
    struct finefs_setattr_logentry *entry;
    u64 curr_p, new_tail = 0;
    int extended = 0;
    size_t size = sizeof(struct finefs_setattr_logentry);
    timing_t append_time;

    FINEFS_START_TIMING(append_setattr_t, append_time);
    rd_info("%s: inode %lu attr change", __func__, inode->i_ino);

    curr_p = finefs_get_append_head(sb, pi, sih, tail, size, &extended, false);
    if (curr_p == 0) BUG();

    rd_info("%s curr_p: 0x%lx", __func__, curr_p);
    entry = (struct finefs_setattr_logentry *)finefs_get_block(sb, curr_p);
    /* inode is already updated with attr */
    finefs_update_setattr_entry(inode, entry, attr);
    new_tail = curr_p + size;
    sih->log_valid_bytes += size;

    FINEFS_END_TIMING(append_setattr_t, append_time);
    return new_tail;
}

static void finefs_sih_add_attr_entry(super_block* sb, finefs_inode_info_header *sih, u64 entry_p, bool is_shrink) {
    log_assert(!is_shrink);
    // spin_lock(&sih->h_entry_lock);
    if(sih->cur_setattr_idx == 0) {
        sih->h_setattr_entry_p[0] = entry_p;
        ++sih->cur_setattr_idx;
        sih->h_can_just_drop = !is_shrink;
    } else if(!is_shrink && sih->h_can_just_drop) {
        int last_idx = sih->cur_setattr_idx - 1;
        rd_info("%s: new entry: 0x%lx, invalid entry: 0x%lx", __func__,
            entry_p, sih->h_setattr_entry_p[last_idx]);
        void *entry = finefs_get_block(sb, sih->h_setattr_entry_p[last_idx]);
        log_entry_set_invalid(sb, sih, entry, false);
        sih->h_setattr_entry_p[last_idx] = entry_p;
    } else {
        sih->h_setattr_entry_p[sih->cur_setattr_idx++] = entry_p;
        sih->h_can_just_drop = false;
        if(sih->cur_setattr_idx == FINEFS_INODE_META_FLUSH_BATCH) {
            finefs_sih_setattr_entry_gc(sb, sih);
        }
    }
    // spin_unlock(&sih->h_entry_lock);
}

int finefs_notify_change(struct dentry *dentry, struct iattr *attr) {
    struct inode *inode = dentry->d_inode;
    struct super_block *sb = inode->i_sb;
    struct finefs_inode *pi = finefs_get_inode(sb, inode);
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;
    int ret = 0;
    unsigned int ia_valid = attr->ia_valid, attr_mask;
    loff_t oldsize = inode->i_size;
    u64 new_tail;
    timing_t setattr_time;

    FINEFS_START_TIMING(setattr_t, setattr_time);
    if (!pi) return -EACCES;

    // ret = inode_change_ok(inode, attr);
    // if (ret)
    // 	return ret;

    /* Update inode with attr except for size */
    setattr_copy(inode, attr);

    if (ia_valid & ATTR_MODE) sih->i_mode = inode->i_mode;

    attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE | ATTR_ATIME | ATTR_MTIME | ATTR_CTIME;

    ia_valid = ia_valid & attr_mask;

    if (ia_valid == 0) return ret;

    // 单纯的pm顺序写，也只是IOPS=2384k, BW=145MiB/s
    // static u64 offset = 1024 << FINEFS_BLOCK_SHIFT;
    // // printf("offset=%llu\n", offset);
    // finefs_setattr_logentry* entry = (struct finefs_setattr_logentry *)finefs_get_block(sb,
    // offset); finefs_update_setattr_entry(inode, entry, attr); offset += 64; PERSISTENT_BARRIER();

    /* We are holding i_mutex so OK to append the log */
    new_tail = finefs_append_setattr_entry(sb, pi, inode, attr, 0);
    finefs_update_volatile_tail(sih, new_tail);

    bool is_shrink = false;
    /* Only after log entry is committed, we can truncate size */
    if ((ia_valid & ATTR_SIZE) &&
        (attr->ia_size != oldsize || pi->i_flags & cpu_to_le32(FINEFS_EOFBLOCKS_FL))) {
        // finefs_set_blocksize_hint(sb, inode, pi, attr->ia_size);
        /* now we can freely truncate the inode */
        is_shrink = attr->ia_size < oldsize;
        finefs_setsize(inode, oldsize, attr->ia_size);
    }
    finefs_sih_add_attr_entry(sb, sih,
        new_tail-sizeof(finefs_setattr_logentry), is_shrink);

    FINEFS_END_TIMING(setattr_t, setattr_time);
    return ret;
}

void finefs_set_inode_flags(struct inode *inode, struct finefs_inode *pi, unsigned int flags) {
    inode->i_flags &= ~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
    if (flags & FS_SYNC_FL) inode->i_flags |= S_SYNC;
    if (flags & FS_APPEND_FL) inode->i_flags |= S_APPEND;
    if (flags & FS_IMMUTABLE_FL) inode->i_flags |= S_IMMUTABLE;
    if (flags & FS_NOATIME_FL) inode->i_flags |= S_NOATIME;
    if (flags & FS_DIRSYNC_FL) inode->i_flags |= S_DIRSYNC;
    // if (!pi->i_xattr)
    // 	inode_has_no_xattr(inode);
    inode->i_flags |= S_DAX;
}

#if 0
static ssize_t finefs_direct_IO(struct kiocb *iocb,
	struct iov_iter *iter, loff_t offset)
{
	struct file *filp = iocb->ki_filp;
	loff_t end = offset;
	size_t count = iov_iter_count(iter);
	ssize_t ret = -EINVAL;
	ssize_t written = 0;
	unsigned long seg;
	unsigned long nr_segs = iter->nr_segs;
	const struct iovec *iv = iter->iov;
	timing_t dio_time;

	FINEFS_START_TIMING(direct_IO_t, dio_time);
	end = offset + count;

	finefs_dbgv("%s: %lu segs", __func__, nr_segs);
	iv = iter->iov;
	for (seg = 0; seg < nr_segs; seg++) {
		if (iov_iter_rw(iter) == READ) {
			ret = finefs_dax_file_read(filp, iv->iov_base,
					iv->iov_len, &offset);
		} else if (iov_iter_rw(iter) == WRITE) {
			ret = finefs_cow_file_write(filp, iv->iov_base,
					iv->iov_len, &offset, false);
		}
		if (ret < 0)
			goto err;

		if (iter->count > iv->iov_len)
			iter->count -= iv->iov_len;
		else
			iter->count = 0;

		written += ret;
		iter->nr_segs--;
		iv++;
	}
	if (offset != end)
		printk(KERN_ERR "finefs: direct_IO: end = %lld"
			"but offset = %lld", end, offset);
	ret = written;
err:
	FINEFS_END_TIMING(direct_IO_t, dio_time);
	return ret;
}
#endif

// static ssize_t finefs_direct_IO(struct kiocb *iocb, struct iov_iter *iter,
// 	loff_t offset)
// {
// 	struct file *filp = iocb->ki_filp;
// 	struct address_space *mapping = filp->f_mapping;
// 	struct inode *inode = mapping->host;
// 	ssize_t ret;
// 	timing_t dio_time;

// 	FINEFS_START_TIMING(direct_IO_t, dio_time);

// 	ret = dax_do_io(iocb, inode, iter, offset, finefs_dax_get_block,
// 				NULL, DIO_LOCKING);
// 	FINEFS_END_TIMING(direct_IO_t, dio_time);
// 	return ret;
// }

// 将prev_blocknr和first_blocknr对应的log page连接在一起
// prev_blocknr为0表示first_blocknr是链表的首个节点
// num_pages 需要链接的page个数
// 最后一个page的tail设置为0，fence落盘
static int finefs_coalesce_log_pages(struct super_block *sb, unsigned long prev_blocknr,
                                     unsigned long first_blocknr, unsigned long num_pages, bool for_gc) {
    unsigned long next_blocknr;
    u64 curr_block, next_page;
    struct finefs_inode_log_page *curr_page;
    int i;

    if (prev_blocknr) {
        /* Link prev block and newly allocated head block */
        curr_block = finefs_get_block_off(sb, prev_blocknr, FINEFS_BLOCK_TYPE_4K);
        curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr_block);
        next_page = finefs_get_block_off(sb, first_blocknr, FINEFS_BLOCK_TYPE_4K);
        finefs_log_set_next_page(sb, curr_page, next_page, 0);
    }

    next_blocknr = first_blocknr + 1;
    curr_block = finefs_get_block_off(sb, first_blocknr, FINEFS_BLOCK_TYPE_4K);
    curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr_block);
    for (i = 0; i < num_pages - 1; i++) {
        next_page = finefs_get_block_off(sb, next_blocknr, FINEFS_BLOCK_TYPE_4K);
        finefs_log_page_tail_init(sb, curr_page, next_page, for_gc, 0);
        curr_page++;
        next_blocknr++;
    }

    /* Last page */
    finefs_log_page_tail_init(sb, curr_page, 0, for_gc, 0);
    return 0;
}

static int finefs_inode_log_page_num(struct super_block *sb, u64 curr) {
    int num = 0;
    struct finefs_inode_log_page *curr_page = NULL;
    while (curr) {
        ++num;
        curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr);
        curr = FINEFS_LOG_NEXT_PAGE(curr_page);
    }
    return num;
}


// #define LOG_ZERO

/* Log block resides in NVMM */
// 循环的方式分配,尽量分配连续的空间，共分配num_pages个页
// new_block 返回分配的第一个page的nvm偏移
// 返回值是实际分配的page个数，分配好的page已经用链表连接好
int finefs_allocate_inode_log_pages(struct super_block *sb, struct finefs_inode *pi,
                                    unsigned long num_pages, u64 *new_block, bool for_gc, int cpuid) {
    unsigned long new_inode_blocknr;
    unsigned long first_blocknr;
    unsigned long prev_blocknr;
    int allocated;
    int ret_pages = 0;

#ifdef LOG_ZERO
    // r_info("finefs_new_log_blocks ZERO=1");
    allocated = finefs_new_log_blocks(sb, pi, &new_inode_blocknr, num_pages, 1, cpuid);
#else
    // r_info("finefs_new_log_blocks ZERO=0");
    // TODO: log block alloc support not successive
    allocated = finefs_new_log_blocks(sb, pi, &new_inode_blocknr, num_pages, 0, cpuid);
#endif
    if (allocated <= 0) {
        r_error("ERROR: no inode log page available: %ld %d", num_pages, allocated);
        return allocated;
    }
    ret_pages += allocated;
    num_pages -= allocated;
    rdv_proc("Pi %lu: Alloc %d log blocks @ 0x%lx", pi->finefs_ino, allocated, new_inode_blocknr);

    /* Coalesce the pages */
    finefs_coalesce_log_pages(sb, 0, new_inode_blocknr, allocated, for_gc);
    first_blocknr = new_inode_blocknr;
    prev_blocknr = new_inode_blocknr + allocated - 1;
    *new_block = finefs_get_block_off(sb, first_blocknr, FINEFS_BLOCK_TYPE_4K);
    if(num_pages == 0) {
        PERSISTENT_BARRIER();
        return ret_pages;
    }

    /* Allocate remaining pages */
    while (num_pages) {
        log_assert(0);
        allocated = finefs_new_log_blocks(sb, pi, &new_inode_blocknr, num_pages, 0, cpuid);

        r_info("Alloc %d log blocks @ 0x%lx", allocated, new_inode_blocknr);
        if (allocated <= 0) {
            r_error(
                "%s: no inode log page available: "
                "%lu %d",
                __func__, num_pages, allocated);
            /* Return whatever we have */
            break;
        }
        ret_pages += allocated;
        num_pages -= allocated;
        finefs_coalesce_log_pages(sb, prev_blocknr, new_inode_blocknr, allocated, for_gc);
        prev_blocknr = new_inode_blocknr + allocated - 1;
    }

    // int log_page_num = finefs_inode_log_page_num(sb, *new_block);
    // log_assert(log_page_num == ret_pages && num_pages == 0);
    PERSISTENT_BARRIER();
    return ret_pages;
}

// curr_p位置的entry是不是无效
// length 带回entry的长度
// TODO: 关注该函数
static bool curr_log_entry_invalid(struct super_block *sb, struct finefs_inode *pi,
                                   struct finefs_inode_info_header *sih, u64 curr_p,
                                   size_t *length) {
    struct finefs_setattr_logentry *setattr_entry;
    struct finefs_file_pages_write_entry *entry;
    struct finefs_dentry *dentry;
    void *addr;
    u8 type;
    bool ret = true;

    addr = (void *)finefs_get_block(sb, curr_p);
    type = finefs_get_entry_type(addr);
    switch (type & LOG_ENTRY_TYPE_MASK) {
        case SET_ATTR:
            // if (sih->last_setattr == curr_p) ret = false;

            /* Do not invalidate setsize entries */
            setattr_entry = (struct finefs_setattr_logentry *)addr;
            if (setattr_entry->attr & ATTR_SIZE) ret = false;
            *length = sizeof(struct finefs_setattr_logentry);
            break;
        case LINK_CHANGE:
            if (sih->last_link_change == curr_p) ret = false;
            *length = sizeof(struct finefs_link_change_entry);
            break;
        case FILE_PAGES_WRITE:
            entry = (struct finefs_file_pages_write_entry *)addr;
            if (entry->num_pages != entry->invalid_pages) ret = false;
            *length = sizeof(struct finefs_file_pages_write_entry);
            break;
        case DIR_LOG:
            dentry = (struct finefs_dentry *)addr;
            if (dentry->ino && log_entry_is_set_valid(dentry)) ret = false;
            *length = sizeof(finefs_dentry);
            break;
        case NEXT_PAGE:
            log_assert(0);
            /* No more entries in this page */
            *length = FINEFS_BLOCK_SIZE - FINEFS_LOG_ENTRY_LOC(curr_p);
            break;
        default:
            rd_error("%s: unknown type %d, 0x%lx", __func__, type, curr_p);
            log_assert(0);
            *length = FINEFS_BLOCK_SIZE - FINEFS_LOG_ENTRY_LOC(curr_p);
            ;
            break;
    }

    return ret;
}

// 判断一个log page是不是全部无效
// 同时统计当前有效的entry的总字节数
// static force_inline bool curr_page_invalid(struct super_block *sb, struct finefs_inode *pi,
//                               struct finefs_inode_info_header *sih, u64 page_head) {
//     // u64 curr_p = page_head;
//     // bool ret = true;
//     // size_t length;
//     // timing_t check_time;

//     // FINEFS_START_TIMING(check_invalid_t, check_time);
//     // while (curr_p < page_head + FINEFS_LOG_LAST_ENTRY) {
//     //     if (curr_p == 0) {
//     //         r_error("File inode %lu log is NULL!", sih->ino);
//     //         BUG();
//     //     }

//     //     length = 0;
//     //     if (!curr_log_entry_invalid(sb, pi, sih, curr_p, &length)) {
//     //         sih->log_valid_bytes += length;
//     //         ret = false;
//     //     }

//     //     curr_p += length;
//     // }

//     // FINEFS_END_TIMING(check_invalid_t, check_time);
//     // return ret;

//     dlog_assert(page_head);
//     finefs_inode_log_page* cur_page = (finefs_inode_log_page*)finefs_get_block(sb, page_head);
//     sih->log_valid_bytes += cur_page->page_tail.valid_num * CACHELINE_SIZE;
//     return cur_page->page_tail.valid_num == 0;
// }

// 指示当前log已经结束，最后设置一个flag（一个字节）
static void finefs_set_next_page_flag(struct super_block *sb, u64 curr_p) {
    void *p;

    if (FINEFS_LOG_ENTRY_LOC(curr_p) >= FINEFS_LOG_LAST_ENTRY) return;

    p = finefs_get_block(sb, curr_p);
    finefs_set_entry_type(p, NEXT_PAGE);
    finefs_flush_buffer(p, CACHELINE_SIZE, 1);
}

// 释放一个log page 链表
static void free_curr_page(struct super_block *sb, struct finefs_inode *pi,
                           struct finefs_inode_log_page *last_page,
                           struct finefs_inode_log_page *prev_page) {
    unsigned short btype = pi->i_blk_type;
    u64 curr = last_page->page_tail.page_link.next_page_;
    u64 end = prev_page->page_tail.page_link.next_page_;
    dlog_assert(curr != end);
    finefs_log_set_next_page(sb, last_page, end, 1);
    while(curr != end) {
        finefs_free_log_blocks(sb, pi, finefs_get_blocknr(sb, curr, btype), 1);
        curr = finefs_log_get_next_page(sb, curr);
    }
}

int finefs_gc_assign_file_entry(struct super_block *sb, struct finefs_inode_info_header *sih,
                                struct finefs_file_pages_write_entry *old_entry,
                                struct finefs_file_pages_write_entry *new_entry) {
    struct finefs_file_page_entry *temp;
    void **pentry;
    unsigned long start_pgoff = old_entry->pgoff;
    unsigned int num = old_entry->num_pages;
    unsigned long curr_pgoff;
    int i;
    int ret = 0;

    for (i = 0; i < num; i++) {
        curr_pgoff = start_pgoff + i;

        pentry = radix_tree_lookup_slot(&sih->tree, curr_pgoff);
        if (pentry) {
            temp = (struct finefs_file_page_entry *)radix_tree_deref_slot(pentry);
            log_assert(temp->nvm_entry_p == old_entry);
            if (temp->nvm_entry_p == old_entry) {
                temp->nvm_entry_p = new_entry;
                dlog_assert(finefs_page_entry_is_right(sb, temp));
                // radix_tree_replace_slot(pentry, new_entry);
            }
        }
    }

    return ret;
}

static int finefs_gc_assign_dentry(struct super_block *sb, struct finefs_inode_info_header *sih,
                                   struct finefs_dentry *old_dentry,
                                   struct finefs_dentry *new_dentry) {
    struct finefs_dentry *temp;
    void **pentry;
    unsigned long hash;
    int ret = 0;

    hash = BKDRHash(old_dentry->name, old_dentry->name_len);
    rdv_proc("%s: assign %s hash %lu", __func__, old_dentry->name, hash);

    /* FIXME: hash collision ignored here */
    pentry = radix_tree_lookup_slot(&sih->tree, hash);
    if (pentry) {
        temp = (struct finefs_dentry *)radix_tree_deref_slot(pentry);
        if (temp == old_dentry) radix_tree_replace_slot(pentry, new_dentry);
    }

    return ret;
}

static int finefs_gc_assign_new_entry(struct super_block *sb, struct finefs_inode *pi,
                                      struct finefs_inode_info_header *sih, u64 curr_p,
                                      u64 new_curr) {
    struct finefs_file_pages_write_entry *old_entry, *new_entry;
    struct finefs_dentry *old_dentry, *new_dentry;
    void *addr, *new_addr;
    u8 type;
    int ret = 0;

    addr = (void *)finefs_get_block(sb, curr_p);
    type = finefs_get_entry_type(addr);
    switch (type & LOG_ENTRY_TYPE_MASK) {
        case SET_ATTR:
            log_assert(sih->cur_setattr_idx == 1 &&
                sih->h_setattr_entry_p[0] == curr_p);
            sih->h_setattr_entry_p[0] = new_curr;
            break;
        case LINK_CHANGE:
            log_assert(sih->last_link_change == curr_p);
            sih->last_link_change = new_curr;
            break;
        case FILE_PAGES_WRITE:
            new_addr = (void *)finefs_get_block(sb, new_curr);
            old_entry = (struct finefs_file_pages_write_entry *)addr;
            new_entry = (struct finefs_file_pages_write_entry *)new_addr;
            // 修改文件数据的dram radix tree 索引
            ret = finefs_gc_assign_file_entry(sb, sih, old_entry, new_entry);
            break;
        case FILE_SMALL_WRITE:
            r_fatal("TODO: gc FILE_SMALL_WRITE entry");
            break;
        case DIR_LOG:
            // 修改目录的dram radix tree 索引
            new_addr = (void *)finefs_get_block(sb, new_curr);
            old_dentry = (struct finefs_dentry *)addr;
            new_dentry = (struct finefs_dentry *)new_addr;
            ret = finefs_gc_assign_dentry(sb, sih, old_dentry, new_dentry);
            break;
        default:
            rdv_proc("%s: unknown type %d, 0x%lx", __func__, type, curr_p);
            log_assert(0);
            break;
    }

    return ret;
}

static int need_thorough_gc(struct super_block *sb, struct finefs_inode_info_header *sih,
    unsigned long blocks, unsigned long checked_pages) {
    if (blocks && (u64)(checked_pages * FINEFS_LOG_EFFECTIVE_RATIO_TRIGGER_GC) >= blocks)
        return 1;
    return 0;
}

// 返回 new_curr
static u64 finefs_log_page_entry_move(super_block *sb, finefs_inode *pi,
    struct finefs_inode_info_header *sih, u64 new_curr, u64 moved_page_p) {
    int extended = 0;
    const size_t entry_size = CACHELINE_SIZE;
    const unsigned int entry_bits = CACHELINE_SHIFT;
    finefs_inode_log_page *log_page = finefs_log_page_addr(sb, moved_page_p);
    void *moved_entry_addr = nullptr;
    int num_entry_gc = 0;
    int entry_idx = 0;
    u64 curr_p;
    for_each_set_bit(entry_idx, (unsigned long*)&log_page->page_tail.bitmap, FINEFS_LOG_PAGE_NUM_ENTRY) {
        moved_entry_addr = (char*)log_page + (entry_idx << entry_bits);
        new_curr = finefs_get_append_head(sb, pi, NULL, new_curr, entry_size, &extended, true);
        log_assert(extended == 0 && new_curr);

        /* Copy entry to the new log */
        memcpy_to_pmem_nocache(finefs_get_block(sb, new_curr), moved_entry_addr, entry_size);

        // 搬迁log后，需要修改内存中对应的索引
        curr_p = finefs_get_addr_off(sb, moved_entry_addr);
        finefs_gc_assign_new_entry(sb, pi, sih, curr_p, new_curr);

        new_curr += entry_size;
        ++num_entry_gc;
    }
    log_assert(num_entry_gc == log_page->page_tail.valid_num);
    return new_curr;
}

/* Copy alive log entries to the new log and atomically replace the old log */
static int finefs_inode_log_thorough_gc(struct super_block *sb, struct finefs_inode *pi,
                                        struct finefs_inode_info_header *sih, unsigned long blocks,
                                        unsigned long checked_pages) {
    // log_assert(0);
    // finefs_gc_free_log_page(sb, sih);

    struct finefs_inode_log_page *curr_page = NULL;
    size_t length;
    u64 ino = pi->finefs_ino;
    u64 curr_p, new_curr, tail_page_p, gc_tail_page_p;
    u64 new_head = 0;
    u64 next;
    unsigned long new_blocks, gc_entry_num = 0;
    int allocated;
    int extended = 0;
    bool include_tail_page = false;
    int free_pages = 0;
    timing_t gc_time;

    std::unordered_set<u64> log_pages_had_gc;
    std::unordered_map<u64, std::pair<u64, int> > pages_to_del;

    FINEFS_START_TIMING(thorough_gc_t, gc_time);

    log_assert(sih->h_log_tail);
    tail_page_p = sih->h_log_tail & FINEFS_LOG_MASK;
    if(sih->log_pages_to_gc.count(tail_page_p)) {
        include_tail_page = true;
        sih->log_pages_to_gc.erase(tail_page_p);
    }

    if(sih->log_pages_to_gc.size() <= 1) {
        r_fatal("%s: log_pages_to_gc num %lu", __func__, sih->log_pages_to_gc.size());
        goto out;
    }

    // 统计gc需要blocks
    for(auto page_p: sih->log_pages_to_gc) {
        curr_page = (finefs_inode_log_page*)finefs_get_block(sb, page_p);
        gc_entry_num += curr_page->page_tail.valid_num;
    }
    new_blocks = (gc_entry_num + FINEFS_LOG_PAGE_NUM_ENTRY - 1) / FINEFS_LOG_PAGE_NUM_ENTRY;

    allocated = finefs_allocate_inode_log_pages(sb, pi, new_blocks, &new_head, true);
    if (allocated != new_blocks) {
        r_fatal(
            "%s: ERROR: no inode log page "
            "available, new blocks: %lu",
            __func__, new_blocks);
        goto out;
    }

    r_info("%s num_pages_to_gc=%u, new alloc pages=%d", __func__,
        sih->log_pages_to_gc.size(), allocated);

    // 先将setattr entry gc
    finefs_sih_setattr_entry_gc(sb, sih);

    // 把有效率低于阈值的log page中有效的entry进行搬迁
    new_curr = new_head;
    for(auto page_p: sih->log_pages_to_gc) {
        if(log_pages_had_gc.count(page_p)) continue;
        log_pages_had_gc.insert(page_p);
        u64 start_p = page_p;
        finefs_inode_log_page *first_page =
            (finefs_inode_log_page*)finefs_get_block(sb, page_p);
        finefs_inode_log_page *cur_page = first_page;
        int num = 1;
        u64 cur_page_p = page_p;
        new_curr = finefs_log_page_entry_move(sb, pi, sih, new_curr, cur_page_p);
        u64 next_page_p = cur_page->page_tail.page_link.next_page_;
        while(1) {
            if(sih->log_pages_to_gc.count(next_page_p)) {
                if(log_pages_had_gc.count(next_page_p)) { // 后一个已经处理
                    auto iter = pages_to_del.find(next_page_p);
                    log_assert(iter != pages_to_del.end());
                    std::pair<u64, int> p = iter->second;
                    u64 last_start = iter->first;
                    p.second += num;
                    pages_to_del[start_p] = p;
                    pages_to_del.erase(last_start);
                    break;
                } else {
                    log_pages_had_gc.insert(next_page_p);
                    ++num;
                    cur_page_p = next_page_p;
                    new_curr = finefs_log_page_entry_move(sb, pi, sih, new_curr, cur_page_p);
                    cur_page = (finefs_inode_log_page*)finefs_get_block(sb, next_page_p);
                    next_page_p = cur_page->page_tail.page_link.next_page_;
                }
            } else {
                std::pair<u64, int> p = std::make_pair(cur_page_p, num);
                pages_to_del[start_p] = p;
                break;
            }
        }
    }

    /* Step 1: Link new log to the gc_head tail */

    // FIXME: 目前只实现双向链表，但不循环，无法尾插，暂时采用头插
    gc_tail_page_p = new_curr & FINEFS_LOG_MASK;
    curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, gc_tail_page_p);
    next = FINEFS_LOG_NEXT_PAGE(curr_page);
    if (next)  {
        // 多分配的空间进行释放
        log_assert(0);
        finefs_free_contiguous_log_blocks(sb, pi, nullptr ,next, 0);
    }
    // 将多余空间的entry对应的bitmap设置为0
    for(int entry_nr = FINEFS_LOG_ENTRY_NR(new_curr);
        entry_nr < FINEFS_LOG_PAGE_NUM_ENTRY; ++entry_nr) {
        bitmap_clear_bit(entry_nr, (unsigned long *)&(curr_page->page_tail.bitmap));
    }
    if(FINEFS_LOG_ENTRY_NR(new_curr) < FINEFS_LOG_PAGE_NUM_ENTRY) {
        finefs_flush_cacheline(&curr_page->page_tail, false);
    }
    finefs_log_set_next_page(sb, curr_page, pi->log_head_gc.next_page_, 0);
    finefs_set_next_page_flag(sb, new_curr); // fence

    /* Step 2: Atomically switch to the new log */
    finefs_link_set_next_page(sb, &pi->log_head_gc, new_head, 1);
    sih->log_pages += new_blocks;
    sih->h_blocks += new_blocks;

    /* Step 3: Unlink the old log 这步多余*/

    /* Step 4: Free the old log */
    for(auto p: pages_to_del) {
        u64 start_p = p.first;
        u64 end_p = p.second.first;
        int free_num = p.second.second;
        r_info("%s: range delete log pages: %d, from %lu to %lu",
            __func__, free_num, start_p, end_p);
        finefs_inode_log_page *start_page =
            (finefs_inode_log_page*)finefs_get_block(sb, start_p);
        finefs_inode_log_page *end_page =
            (finefs_inode_log_page*)finefs_get_block(sb, end_p);
        finefs_log_range_delete(sb, start_page, end_page);
        sih->log_pages -= free_num;
        sih->h_blocks -= free_num;
        free_pages += free_num;

        u64 d_head = start_p;
        u64 d_end = end_page->page_tail.page_link.next_page_;
        int freed = finefs_free_contiguous_log_blocks(sb, pi, sih, start_p, d_end);
        log_assert(freed == free_num);
    }
    log_assert(log_pages_had_gc.size() == sih->log_pages_to_gc.size());
    log_assert(free_pages == sih->log_pages_to_gc.size());
    sih->log_pages_to_gc.clear();

    // while (curr_p != sih->h_log_tail) {
    //     old_curr_p = curr_p;  // 保存被回收log 链表中的最后一个page
    //     if (goto_next_page(sb, curr_p)) curr_p = finefs_log_next_page(sb, curr_p);

    //     if (curr_p >> FINEFS_BLOCK_SHIFT == sih->h_log_tail >> FINEFS_BLOCK_SHIFT) {
    //         /* Don't recycle tail page */
    //         break;
    //     }

    //     if (curr_p == 0) {
    //         r_error("File inode %lu log is NULL!", ino);
    //         BUG();
    //     }

    //     length = 0;
    //     ret = curr_log_entry_invalid(sb, pi, sih, curr_p, &length);
    //     if (!ret) {
    //         // 有效，进行搬迁
    //         extended = 0;
    //         new_curr = finefs_get_append_head(sb, pi, NULL, new_curr, length, &extended, true);
    //         if (extended) {
    //             rd_warning("%s extent gc log! blocks: %lu", __func__, blocks);
    //             blocks++;
    //         }

    //         /* Copy entry to the new log */
    //         memcpy_to_pmem_nocache(finefs_get_block(sb, new_curr), finefs_get_block(sb, curr_p),
    //                                length);
    //         // 搬迁log后，需要修改内存中对应的索引
    //         finefs_gc_assign_new_entry(sb, pi, sih, curr_p, new_curr);
    //         new_curr += length;
    //     }

    //     curr_p += length;
    // }

    // /* Step 1: Link new log to the tail block */
    // tail_block = FINEFS_LOG_BLOCK_OFF(sih->h_log_tail);
    // curr_page =
    //     (struct finefs_inode_log_page *)finefs_get_block(sb, FINEFS_LOG_BLOCK_OFF(new_curr));
    // next = FINEFS_LOG_NEXT_PAGE(curr_page);
    // if (next)  // 多分配的空间进行释放
    //     finefs_free_contiguous_log_blocks(sb, pi, nullptr ,next);
    // finefs_set_next_page_flag(sb, new_curr);
    // finefs_log_set_next_page(sb, curr_page, tail_block, 0);
    // // TODO: 这里需要flush这么多？entry是通过ntstore的，flag也flush了，
    // // 这里感觉不需要flush了
    // finefs_flush_buffer(curr_page, FINEFS_BLOCK_SIZE, 0);

    // /* Step 2: Atomically switch to the new log */
    // pi->log_head = new_head;
    // finefs_flush_buffer(pi, sizeof(struct finefs_inode), 1);

    // /* Step 3: Unlink the old log */
    // // 将旧log从链表中断开
    // curr_page =
    //     (struct finefs_inode_log_page *)finefs_get_block(sb, FINEFS_LOG_BLOCK_OFF(old_curr_p));
    // next = FINEFS_LOG_NEXT_PAGE(curr_page);
    // if (next != tail_block) {
    //     r_error("Old log error: old curr_p 0x%lx, next 0x%lx curr_p 0x%lx, tail block 0x%lx",
    //             old_curr_p, next, curr_p, tail_block);
    //     BUG();
    // }
    // finefs_log_set_next_page(sb, curr_page, 0, 1);

    // /* Step 4: Free the old log */
    // finefs_free_contiguous_log_blocks(sb, pi, nullptr, old_head);

    // // blocks是新分配的，checked_pages是释放的
    // sih->log_pages = sih->log_pages + blocks - checked_pages;
    FINEFS_STATS_ADD(thorough_gc_pages, free_pages - new_blocks);
    FINEFS_STATS_ADD(thorough_checked_pages, free_pages);

    // 处理 gc_tail_page_p, 若低于阈值，需要加入gc set
    curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, gc_tail_page_p);
    log_assert(curr_page->page_tail.valid_num != 0);
    if(curr_page->page_tail.valid_num <= FINEFS_LOG_PAGE_NUM_EFFECTIVE_ENTRY) {
        sih->log_pages_to_gc.insert(gc_tail_page_p);
    }
out:
    if(include_tail_page) {
        sih->log_pages_to_gc.insert(tail_page_p);
    }
    FINEFS_END_TIMING(thorough_gc_t, gc_time);
    return 0;
}

// #define FINEFS_LOG_TEST

// new_block：新分配log page的第一个page的偏移
// num_pages: 新分配page的个数
// TODO: 修改fast gc的方式，不在需要遍历整个log链表
static int finefs_inode_log_fast_gc(struct super_block *sb, struct finefs_inode *pi,
                                    struct finefs_inode_info_header *sih, u64 curr_tail,
                                    u64 new_block, int num_pages) {
    u64 old_head, curr, next, possible_head = 0;
    int found_head = 0;
    struct finefs_inode_log_page *last_page = NULL;
    struct finefs_inode_log_page *prev_page = NULL;
    struct finefs_inode_log_page *curr_page = NULL;
    int first_need_free = 0;
    unsigned short btype = pi->i_blk_type;
    unsigned long blocks;
    unsigned long checked_pages;
    int to_free_pages = 0;
    int freed_pages = 0;
    timing_t gc_time;

    // curr = pi->log_head;
    // old_head = curr;
    // sih->log_valid_bytes = 0;

#ifdef FINEFS_LOG_TEST
    sih->log_pages += num_pages;
    curr = FINEFS_LOG_BLOCK_OFF(curr_tail);
    curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr);
    finefs_log_set_next_page(sb, curr_page, new_block, 1);
    return 0;
#endif

    rd_info("%s: log head 0x%lx, tail 0x%lx, new pages: %d", __func__, curr, curr_tail, num_pages);
    // FINEFS_START_TIMING(fast_gc_t, gc_time);
    // while (1) {
    //     if (curr >> FINEFS_BLOCK_SHIFT == sih->h_log_tail >> FINEFS_BLOCK_SHIFT) {
    //         /* Don't recycle tail page 不回收最后一个page，避免即修改head又修改tail，不能原子*/
    //         if (found_head == 0) possible_head = cpu_to_le64(curr);
    //         break;
    //     }
    //     prev_page = curr_page;
    //     curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr);
    //     next = FINEFS_LOG_NEXT_PAGE(curr_page);
    //     rdv_proc("curr 0x%lx, next 0x%lx", curr, next);
    //     if (curr_page_invalid(sb, pi, sih, curr)) {
    //         rdv_proc("curr page %p invalid", curr_page);
    //         if (curr == old_head) {
    //             /* Free first page later */
    //             first_need_free = 1;
    //             last_page = curr_page;
    //             ++freed_pages;
    //         } else {
    //             // TODO: 不释放第一个log page只是为了后面便于删除中间page的处理(通过原子交换的方式，删除中间page)
    //             // 这里可以优化，减少不必要的多次flush+fence
    //             // 方法，记录从个有效page当前page之间无效的page个数，如果不为0，才进行next指针改变
    //             ++to_free_pages;
    //             rdv_proc("to_free_pages: %d, cur block 0x%lx", to_free_pages, curr >> FINEFS_BLOCK_SHIFT);
    //         }
    //         FINEFS_STATS_ADD(fast_gc_pages, 1);
    //     } else {
    //         sih->log_valid_bytes += FINEFS_LOG_LAST_ENTRY;
    //         if(to_free_pages) {
    //             freed_pages += to_free_pages;
    //             rd_info("%s: to_free_pages: %d\n", __func__, to_free_pages);
    //             dlog_assert(last_page != prev_page);
    //             free_curr_page(sb, pi, last_page, prev_page);
    //             to_free_pages = 0;
    //         }

    //         if (found_head == 0) {
    //             possible_head = cpu_to_le64(curr);
    //             found_head = 1;
    //         }
    //         last_page = curr_page;
    //     }

    //     curr = next;
    //     checked_pages++;
    //     if (curr == 0) break;
    // }

    // FINEFS_STATS_ADD(fast_checked_pages, checked_pages);
    // checked_pages -= freed_pages;

    // 需要维护的状态
    // sih->log_valid_bytes;
    // sih->log_pages;
    // sih->h_log_tail;
    // pi->log_head;
    // pi->i_blocks;
    // finefs_gc_free_log_page(sb, sih);
    checked_pages = sih->log_pages;

    curr = FINEFS_LOG_BLOCK_OFF(curr_tail);
    curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr);
    log_assert(curr_page->page_tail.page_link.next_page_ == 0);
    finefs_log_set_next_page(sb, curr_page, new_block, 1);
    sih->log_pages += num_pages - freed_pages;
    // pi->i_blocks += num_pages - freed_pages;
    sih->h_blocks += num_pages - freed_pages;

    rdv_proc("%s: log_pages: %lu", __func__, sih->log_pages);

    // rdv_proc("%s: found_head:%d, old head 0x%llx, new head 0x%llx", __func__, found_head, old_head, possible_head);
    // rdv_proc("Num pages %d, freed %d", num_pages, freed_pages);
    // /* Don't update log tail pointer here */
    // if (first_need_free) {
    //     curr = pi->log_head;
    //     pi->log_head = possible_head;
    //     finefs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);
    //     rdv_proc("Free log head block 0x%lx", curr >> FINEFS_BLOCK_SHIFT);
    //     finefs_free_log_blocks(sb, pi, finefs_get_blocknr(sb, curr, btype), 1);
    // }

    blocks = sih->log_valid_bytes / FINEFS_LOG_LAST_ENTRY;
    if (sih->log_valid_bytes % FINEFS_LOG_LAST_ENTRY) blocks++;

    // FINEFS_END_TIMING(fast_gc_t, gc_time);
    dlog_assert(finefs_inode_log_page_num(sb, pi->log_head.next_page_) == sih->log_pages);

    // 有效率低于50%，开启彻底gc
    if (need_thorough_gc(sb, sih, blocks, checked_pages)) {
        r_info(
            "Thorough GC for inode %lu: checked pages %lu, "
            "valid pages %lu, log_valid_bytes %lu",
            sih->ino, checked_pages, blocks, sih->log_valid_bytes);
        finefs_inode_log_thorough_gc(sb, pi, sih, blocks, checked_pages);
        // int log_page_num = finefs_inode_log_page_num(sb, pi->log_head);
        // log_assert(log_page_num == sih->log_pages);
    }

    return 0;
}

// 分配新的log page
// 返回新分配log page的偏移地址
// curr_p = 0 表示为inode分配第一个log page
static u64 finefs_extend_inode_log(struct super_block *sb, struct finefs_inode *pi,
                                   struct finefs_inode_info_header *sih, u64 curr_p, bool for_gc) {
    u64 new_block;
    int allocated;
    unsigned long num_pages;

    if (curr_p == 0) {  // 第一个分配1个
        allocated = finefs_allocate_inode_log_pages(sb, pi, 1, &new_block, for_gc);
        if (allocated != 1) {
            r_error(
                "%s ERROR: no inode log page "
                "available",
                __func__);
            return 0;
        }
        // pi->log_tail = new_block;
        // finefs_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 0);
        sih->h_log_tail = new_block;
        sih->log_pages = 1;
        sih->h_blocks++;
        // pi->i_blocks++;
        finefs_link_set_next_page(sb, &pi->log_head, new_block, 1);
        // pi->log_head = new_block;
        // finefs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);
    } else {  // 按倍数分配新page，直到256后，每次只256个log page
        num_pages = sih->log_pages >= LOG_EXTEND_THRESHOLD ? LOG_EXTEND_THRESHOLD : sih->log_pages;
        //		finefs_dbg("Before append log pages:");
        //		finefs_print_inode_log_page(sb, inode);
        allocated = finefs_allocate_inode_log_pages(sb, pi, num_pages, &new_block, for_gc);
        rdv_proc("Link block %lu to block %lu", curr_p >> FINEFS_BLOCK_SHIFT,
                 new_block >> FINEFS_BLOCK_SHIFT);
        if (allocated <= 0) {
            r_error(
                "%s ERROR: no inode log page "
                "available",
                __func__);
            rd_info("curr_p 0x%lx, %lu pages", curr_p, sih->log_pages);
            return 0;
        }

        finefs_inode_log_fast_gc(sb, pi, sih, curr_p, new_block, allocated);

        //		finefs_dbg("After append log pages:");
        //		finefs_print_inode_log_page(sb, inode);
        /* Atomic switch to new log */
        //		finefs_switch_to_new_log(sb, pi, new_block, num_pages);
    }
    return new_block;
}

/* For thorough GC, simply append one more page */
static u64 finefs_append_one_log_page(struct super_block *sb, struct finefs_inode *pi, u64 curr_p) {
    struct finefs_inode_log_page *curr_page;
    u64 new_block;
    u64 curr_block;
    int allocated;

    allocated = finefs_allocate_inode_log_pages(sb, pi, 1, &new_block, true);
    if (allocated != 1) {
        r_error("%s: ERROR: no inode log page available", __func__);
        return 0;
    }

    if (curr_p == 0) {
        curr_p = new_block;
    } else {
        /* Link prev block and newly allocated head block */
        curr_block = FINEFS_LOG_BLOCK_OFF(curr_p);
        curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr_block);
        finefs_log_set_next_page(sb, curr_page, new_block, 1);
    }

    return curr_p;
}

// 传入tail=0,表示使用inode当前的log tail，否则判断tail位置能够放入size大小的log entry
// extended指示是否扩展了
// size 要append的log entry大小
u64 finefs_get_append_head(struct super_block *sb, struct finefs_inode *pi,
                           struct finefs_inode_info_header *sih, u64 tail, size_t size,
                           int *extended, bool for_gc) {
    u64 curr_p;

    if (tail)
        curr_p = tail;
    else
        // curr_p = pi->log_tail;
        curr_p = sih->h_log_tail;

    if (curr_p == 0 || (is_last_entry(curr_p, size) && finefs_log_next_page(sb, curr_p) == 0)) {
        if (is_last_entry(curr_p, size)) finefs_set_next_page_flag(sb, curr_p);

        // 当前log的空间不足，需要分配新的log page
        if (sih) {
            // curr_p已经指向新的block
            curr_p = finefs_extend_inode_log(sb, pi, sih, curr_p, for_gc);
        } else {
            r_fatal("unexpected: GC");
            // 用于GC时的append log，GC应该到不了这里吧，因为一次就分配足够的page了
            // 不不不，之前分配的空间只是预判而已，可能预测少了
            curr_p = finefs_append_one_log_page(sb, pi, curr_p);
            /* For thorough GC */
            *extended = 1;
        }

        if (curr_p == 0) {
            log_assert(0);
            return 0;
        }
    }

    if (is_last_entry(curr_p, size)) {  // 感觉这才是给gc用的，预留多个page后，也会经过这里
        // r_info("%s curr_p 0x%lx", __func__, curr_p);
        finefs_set_next_page_flag(sb, curr_p);
        curr_p = finefs_log_next_page(sb, curr_p);
        // r_info("%s curr_p 0x%lx", __func__, curr_p);
    }

    return curr_p;
}

/*
 * Append a finefs_file_pages_write_entry to the current finefs_inode_log_page.
 * blocknr and start_blk are pgoff.
 * We cannot update pi->log_tail here because a transaction may contain
 * multiple entries.
 * 返回当前entry写入的地址
 */
u64 finefs_append_file_write_entry(struct super_block *sb, struct finefs_inode *pi,
                                   struct inode *inode, struct finefs_file_pages_write_entry *dram_entry,
                                   u64 tail) {
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;
    struct finefs_file_pages_write_entry *entry;
    u64 curr_p;
    int extended = 0;
    size_t size = sizeof(struct finefs_file_pages_write_entry);
    timing_t append_time;

    FINEFS_START_TIMING(append_file_entry_t, append_time);

    curr_p = finefs_get_append_head(sb, pi, sih, tail, size, &extended, false);
    if (curr_p == 0) return curr_p;

    entry = (struct finefs_file_pages_write_entry *)finefs_get_block(sb, curr_p);
    dram_entry->finefs_ino = cpu_to_le64(sih->ino);
	dram_entry->entry_ts = cpu_to_le64(sih->h_ts++);
    memcpy(entry, dram_entry, sizeof(finefs_file_pages_write_entry) - sizeof(entry->entry_version));
    barrier();
    entry->entry_version = finefs_log_page_version(sb, curr_p);
    finefs_flush_buffer(entry, sizeof(struct finefs_file_pages_write_entry), 0);
    rdv_proc(
        "file %lu entry @ 0x%lx: pgoff %lu, num %u, "
        "block %lu, size %lu",
        inode->i_ino, curr_p, entry->pgoff, entry->num_pages, entry->block >> FINEFS_BLOCK_SHIFT,
        entry->size);
    /* entry->invalid is set to 0 */

    FINEFS_END_TIMING(append_file_entry_t, append_time);

    sih->log_valid_bytes += size;
    sih->h_blocks += dram_entry->num_pages;
    return curr_p;
}

int finefs_free_inode_log(struct super_block *sb, struct finefs_inode *pi, struct finefs_inode_info_header *sih) {
    u64 curr_block;
    int freed = 0;
    timing_t free_time;

    if (finefs_log_link_is_end(pi->log_head.next_page_)) return 0;

    FINEFS_START_TIMING(free_inode_log_t, free_time);

    curr_block = pi->log_head.next_page_;

    /* The inode is invalid now, no need to call PCOMMIT */
    finefs_log_link_init(&pi->log_head);
    finefs_flush_cacheline(&pi->log_head, 0);

    freed = finefs_free_contiguous_log_blocks(sb, pi, sih, curr_block, 0);

    rd_info("ino: %lu free inode %d log", pi->finefs_ino, freed);
    dlog_assert(freed == sih->log_pages);

    FINEFS_END_TIMING(free_inode_log_t, free_time);

    return freed;
}

static inline void finefs_rebuild_file_time_and_size(struct super_block *sb,
                                                     struct finefs_inode *pi,
                                                     struct finefs_file_pages_write_entry *entry) {
    if (!entry || !pi) return;

    pi->i_ctime = cpu_to_le32(entry->mtime);
    pi->i_mtime = cpu_to_le32(entry->mtime);
    pi->i_size = cpu_to_le64(entry->size);
}

int finefs_rebuild_file_inode_tree(struct super_block *sb, struct finefs_inode *pi, u64 pi_addr,
                                   struct finefs_inode_info_header *sih) {
    struct finefs_file_pages_write_entry *entry = NULL;
    struct finefs_setattr_logentry *attr_entry = NULL;
    struct finefs_link_change_entry *link_change_entry = NULL;
    struct finefs_inode_log_page *curr_page;
    unsigned int data_bits = finefs_blk_type_to_shift[pi->i_blk_type];
    u64 ino = pi->finefs_ino;
    timing_t rebuild_time;
    void *addr;
    u64 curr_p;
    u64 next;
    u8 type;

    FINEFS_START_TIMING(rebuild_file_t, rebuild_time);
    rdv_proc("Rebuild file inode %lu tree", ino);

    sih->pi_addr = pi_addr;

    curr_p = pi->log_head.next_page_;
    rdv_proc("Log head 0x%lx, tail 0x%llx", curr_p, pi->log_tail);
    if (curr_p == 0) return 0;

    log_assert(0);
    sih->log_pages = 1;

    // TODO: log_tail
    log_assert(0);
    while (curr_p != pi->log_tail) {
        if (goto_next_page(sb, curr_p)) {
            sih->log_pages++;
            curr_p = finefs_log_next_page(sb, curr_p);
        }

        if (curr_p == 0) {
            r_error("File inode %lu log is NULL!", ino);
            BUG();
        }

        addr = (void *)finefs_get_block(sb, curr_p);
        type = finefs_get_entry_type(addr);
        switch (type) {
            case SET_ATTR:
                attr_entry = (struct finefs_setattr_logentry *)addr;
                finefs_apply_setattr_entry(sb, pi, sih, attr_entry);
                // sih->last_setattr = curr_p;
                curr_p += sizeof(struct finefs_setattr_logentry);
                continue;
            case LINK_CHANGE:
                link_change_entry = (struct finefs_link_change_entry *)addr;
                finefs_apply_link_change_entry(pi, link_change_entry);
                sih->last_link_change = curr_p;
                curr_p += sizeof(struct finefs_link_change_entry);
                continue;
            case FILE_PAGES_WRITE:
                break;
            default:
                r_error("unknown type %d, 0x%lx", type, curr_p);
                log_assert(0);
                curr_p += sizeof(struct finefs_file_pages_write_entry);
                continue;
        }

        entry = (struct finefs_file_pages_write_entry *)addr;
        if (entry->num_pages != entry->invalid_pages) {
            dlog_assert(log_entry_is_set_valid(entry));
            /*
             * The overlaped blocks are already freed.
             * Don't double free them, just re-assign the pointers.
             */
            // FIXME
            finefs_assign_write_entry(sb, pi, sih, entry, nullptr, false);
        }

        finefs_rebuild_file_time_and_size(sb, pi, entry);
        /* Update sih->i_size for setattr apply operations */
        // sih->i_size = le64_to_cpu(pi->i_size);
        curr_p += sizeof(struct finefs_file_pages_write_entry);
    }

    sih->i_size = le64_to_cpu(pi->i_size);
    sih->i_mode = le16_to_cpu(pi->i_mode);
    finefs_flush_buffer(pi, sizeof(struct finefs_inode), 0);

    /* Keep traversing until log ends */
    curr_p &= FINEFS_LOG_MASK;
    curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr_p);
    while ((next = FINEFS_LOG_NEXT_PAGE(curr_page)) != 0) {
        sih->log_pages++;
        curr_p = next;
        curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr_p);
    }

    // pi->i_blocks = sih->log_pages + (sih->i_size >> data_bits);

    //	finefs_print_inode_log_page(sb, inode);
    FINEFS_END_TIMING(rebuild_file_t, rebuild_time);
    return 0;
}

// /*
//  * find the file offset for SEEK_DATA/SEEK_HOLE
//  */
// unsigned long finefs_find_region(struct inode *inode, loff_t *offset, int hole)
// {
// 	struct super_block *sb = inode->i_sb;
// 	struct finefs_inode *pi = finefs_get_inode(sb, inode);
// 	struct finefs_inode_info *si = FINEFS_I(inode);
// 	struct finefs_inode_info_header *sih = &si->header;
// 	unsigned int data_bits = finefs_blk_type_to_shift[pi->i_blk_type];
// 	unsigned long first_blocknr, last_blocknr;
// 	unsigned long blocks = 0, offset_in_block;
// 	int data_found = 0, hole_found = 0;

// 	if (*offset >= inode->i_size)
// 		return -ENXIO;

// 	if (!inode->i_blocks || !sih->i_size) {
// 		if (hole)
// 			return inode->i_size;
// 		else
// 			return -ENXIO;
// 	}

// 	offset_in_block = *offset & ((1UL << data_bits) - 1);

// 	first_blocknr = *offset >> data_bits;
// 	last_blocknr = inode->i_size >> data_bits;

// 	finefs_dbg_verbose("find_region offset %llx, first_blocknr %lx,"
// 		" last_blocknr %lx hole %d",
// 		  *offset, first_blocknr, last_blocknr, hole);

// 	blocks = finefs_lookup_hole_in_range(inode->i_sb, sih,
// 		first_blocknr, last_blocknr, &data_found, &hole_found, hole);

// 	/* Searching data but only hole found till the end */
// 	if (!hole && !data_found && hole_found)
// 		return -ENXIO;

// 	if (data_found && !hole_found) {
// 		/* Searching data but we are already into them */
// 		if (hole)
// 			/* Searching hole but only data found, go to the end */
// 			*offset = inode->i_size;
// 		return 0;
// 	}

// 	/* Searching for hole, hole found and starting inside an hole */
// 	if (hole && hole_found && !blocks) {
// 		/* we found data after it */
// 		if (!data_found)
// 			/* last hole */
// 			*offset = inode->i_size;
// 		return 0;
// 	}

// 	if (offset_in_block) {
// 		blocks--;
// 		*offset += (blocks << data_bits) +
// 			   ((1 << data_bits) - offset_in_block);
// 	} else {
// 		*offset += blocks << data_bits;
// 	}

// 	return 0;
// }

// const struct address_space_operations finefs_aops_dax = {
// 	.direct_IO		= finefs_direct_IO,
// 	/*.dax_mem_protect	= finefs_dax_mem_protect,*/
// };
