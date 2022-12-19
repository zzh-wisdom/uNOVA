#include "finefs/finefs.h"

// void finefs_init_slab_heap(struct slab_heap *slab_heap) {
//     slab_free_list* slab_list = nullptr;
//     spin_lock_init(&slab_heap->slab_lock);
//     for(int i = 0; i < SLAB_LEVELS; ++i) {
//         slab_list = &slab_heap->slab_lists[i];
//         slab_list->page_num = 0;
//         slab_list->next_slab_idx = 0;
//         slab_list->next_alloc_pages = 1;
//         slab_list->cur_page = nullptr;
//         INIT_LIST_HEAD(&slab_list->page_head);
//     }
// }

// void finefs_free_slab_heap(struct slab_heap *slab_heap) {
//     slab_free_list *slab_list = nullptr;
//     slab_page *cur, *next;
//     for(int i = 0; i < SLAB_LEVELS; ++i) {
//         slab_list = &slab_heap->slab_lists[i];
//         log_assert(slab_list->page_num && slab_list->cur_page ||
//             !slab_list->page_num && !slab_list->cur_page);
//         list_for_each_entry_safe(cur, next, &(slab_list->page_head), entry) {
//             list_del(&cur->entry);
//             finefs_free_slab_page(cur);
//             --slab_list->page_num;
//         }
//         log_assert(slab_list->page_num == 0);
//     }
// }

int finefs_alloc_slab_heaps(struct super_block *sb)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);
	// struct slab_heap *slab_heap;
	// int i;

    // (struct slab_heap*)ZALLOC(sbi->cpus * sizeof(struct slab_heap));
	sbi->slab_heaps = new slab_heap[sbi->cpus];
	if (!sbi->slab_heaps)
		return -ENOMEM;

	// for (i = 0; i < sbi->cpus; i++) {
	// 	slab_heap = finefs_get_slab_heap(sb, i);
	// 	finefs_init_slab_heap(slab_heap);
	// }
	return 0;
}

void finefs_delete_slab_heaps(struct super_block *sb)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);
    // struct slab_heap *slab_heap;
    // int i;

    // for (i = 0; i < sbi->cpus; i++) {
	// 	slab_heap = finefs_get_slab_heap(sb, i);
	// 	finefs_free_slab_heap(slab_heap);
	// }

	/* Each slab_page_list is freed in save_blocknode_mappings ? */
	// FREE(sbi->slab_heaps);
    delete []sbi->slab_heaps;
	sbi->slab_heaps = NULL;
}

static force_inline slab_page* finefs_find_slab_page(slab_free_list* slab_list, u64 page_off) {
    auto it = slab_list->page_off_2_slab_page.find(page_off);
    if(it == slab_list->page_off_2_slab_page.end()) return nullptr;
    return it->second;
    // list_for_each_entry(cur, &slab_list->page_head, entry) {
    //     if(cur == )
    // }
}

static force_inline void finefs_insert_slab_page(slab_free_list* slab_list, u64 page_off, slab_page* page) {
    auto it = slab_list->page_off_2_slab_page.find(page_off);
    dlog_assert(it == slab_list->page_off_2_slab_page.end());
    slab_list->page_off_2_slab_page[page_off] = page;
}

static force_inline slab_page* finefs_delete_slab_page(slab_free_list* slab_list, u64 page_off) {
    slab_page *ret = nullptr;
    auto it = slab_list->page_off_2_slab_page.find(page_off);
    if(it != slab_list->page_off_2_slab_page.end()) {
        ret = it->second;
        slab_list->page_off_2_slab_page.erase(it);
    }
    return ret;
}

// 返回实际分配的block个数
static inline int finefs_batch_extend_slab_page(super_block* sb, slab_free_list* slab_list) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct finefs_inode *pi = finefs_get_inode_by_ino(sb, FINEFS_SLAB_PAGE_INO);
    unsigned long blocknr;
    int cur_allocated;
    int allocated = 0;
    slab_page* page;
    int extend_pages;

    dlog_assert(pi->i_blk_type == FINEFS_DEFAULT_DATA_BLOCK_TYPE);
    extend_pages = slab_list->next_alloc_pages;
    while(extend_pages) {
        cur_allocated = finefs_new_data_blocks(sb, pi, &blocknr, extend_pages, 0, 0, 0);
        if(!cur_allocated) break;

        for(int i = 0; i < cur_allocated; ++i) {
            dlog_assert(get_cpuid(sbi, blocknr+i) == get_processor_id());
            u64 block_off = finefs_get_block_off(sb, blocknr+i, pi->i_blk_type);
            page = finefs_alloc_slab_page(sb);
            log_assert(page);
            finefs_slab_page_init_empty(page, block_off, slab_list->slab_bits);
            if(slab_list->cur_page == nullptr) {
                slab_list->cur_page = page;
                slab_list->next_slab_idx = 0;
                rd_info("%s: cur_page block_off: %lu, next_slab_idx: %u",
                    __func__, block_off, slab_list->next_slab_idx);
            }
            finefs_insert_slab_page(slab_list, block_off, page);
        }

        allocated += cur_allocated;
        extend_pages -= cur_allocated;
    }

    slab_list->page_num += allocated;
    slab_list->next_alloc_pages <<= 1;
    if(slab_list->next_alloc_pages > SLAB_PAGE_BATCH_EXTEND_THRESHOLD) {
        slab_list->next_alloc_pages = SLAB_PAGE_BATCH_EXTEND_THRESHOLD;
    }
    rd_info("%s: allocated page: %d, now page_num: %u, next_alloc_pages: %u",
        __func__, allocated, slab_list->page_num, slab_list->next_alloc_pages);

    return allocated;
}

static inline void finefs_free_or_goto_next_page(slab_free_list* slab_list, slab_page* page, bool is_free) {
    dlog_assert(slab_list->cur_page);
    auto it = slab_list->page_off_2_slab_page.find(page->block_off);
    dlog_assert(it != slab_list->page_off_2_slab_page.end());
    auto it_next = std::next(it);
    dlog_assert(it->second == page);
    dlog_assert(is_free &&
        (page->num_free_slab == 0 || finefs_get_num_slab_for_page(page) == page->num_free_slab) ||
        (!is_free && page->num_free_slab != 0));

    if(is_free) {
        rd_info("%s: free page_off %lu, slab_bits: %u, num_free_slab: %u", __func__,
        page->block_off, page->slab_bits, page->num_free_slab);
        slab_list->page_off_2_slab_page.erase(it);
        finefs_free_slab_page(page);
        slab_list->page_num--;
    }
    if(slab_list->cur_page && slab_list->cur_page != page) return;

    if(it_next == slab_list->page_off_2_slab_page.end()) {
        it_next = slab_list->page_off_2_slab_page.begin();
    }
    if(it_next != slab_list->page_off_2_slab_page.end()) {
        slab_list->cur_page = it_next->second;
        dlog_assert(slab_list->cur_page->bitmap);
        slab_list->next_slab_idx = __ffs(slab_list->cur_page->bitmap);
    } else {
        dlog_assert(slab_list->page_num == 0);
        slab_list->cur_page = nullptr;
        // r_error("slab_list->cur_page set null, slab_list->page_num = %u", slab_list->page_num);
        slab_list->next_slab_idx = 0;
    }
    rd_info("%s: page_num: %u, cur_page_off: %lu, next_slab_idx:%u", __func__, slab_list->page_num,
        slab_list->cur_page ? slab_list->cur_page->block_off : 0,
        slab_list->next_slab_idx);
}

static force_inline void finefs_goto_next_slab(slab_free_list* slab_list) {
    slab_page* cur_page = slab_list->cur_page;
    u32 cur_idx = slab_list->next_slab_idx;
    dlog_assert(cur_page);
    dlog_assert(cur_page->num_free_slab != 0);
    unsigned long tmp = cur_page->bitmap & (~((2ul << cur_idx) - 1));
    if(tmp == 0) {
        finefs_free_or_goto_next_page(slab_list, cur_page, false);
    } else {
        cur_idx = __ffs(tmp);
        dlog_assert(cur_idx > slab_list->next_slab_idx);
        slab_list->next_slab_idx = cur_idx;
    }
    rd_info("%s: next_slab_idx: %u", __func__, slab_list->next_slab_idx);
}

u64 finefs_slab_alloc(super_block* sb, size_t size, int *s_bits) {
	dlog_assert(size);
    int cpuid = get_processor_id();
    struct slab_heap *slab_heap = finefs_get_slab_heap(sb, cpuid);
	int size_bits = finefs_get_slab_size(size);
    *s_bits = size_bits;
    dlog_assert(size_bits <= SLAB_MAX_BITS);
    slab_free_list *slab_list = &slab_heap->slab_lists[size_bits - SLAB_MIN_BITS];
    slab_page* cur_page = nullptr;
    u64 slab_off = 0;
    bool is_full;

    spin_lock(&slab_heap->slab_lock);
    if(slab_list->cur_page == nullptr) {
        dlog_assert(slab_list->page_num == 0);
        int nr = finefs_batch_extend_slab_page(sb, slab_list);
        if(nr == 0) {
            r_error("%s: not free block.", __func__);
            log_assert(0);
        }
    }
    cur_page = slab_list->cur_page;
    dlog_assert(cur_page);
    slab_off = cur_page->block_off + (slab_list->next_slab_idx << slab_list->slab_bits);
    rd_info("%s: slab_off: %lu, slab_idx: %u", __func__, slab_off, slab_list->next_slab_idx);
    is_full = finefs_slab_page_set_alloc(cur_page, slab_list->next_slab_idx);
    if(is_full) {
        finefs_free_or_goto_next_page(slab_list, cur_page, is_full);
    } else {
        finefs_goto_next_slab(slab_list);
    }
    spin_unlock(&slab_heap->slab_lock);

    return slab_off;
}

void finefs_slab_free(super_block* sb, u64 nvm_off, size_t size) {
	dlog_assert((size & (size - 1)) == 0 && size >= SLAB_MIN_SIZE);
	u64 blocknr = finefs_get_blocknr(sb, nvm_off, FINEFS_DEFAULT_DATA_BLOCK_TYPE);
    u64 block_off = finefs_get_block_off(sb, blocknr, FINEFS_DEFAULT_DATA_BLOCK_TYPE);
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    int cpuid = get_cpuid(sbi, blocknr);
    dlog_assert(finefs_is_log_area(sbi, blocknr) == false);
    struct slab_heap *slab_heap = finefs_get_slab_heap(sb, cpuid);
    int size_bits = fls(size) - 1;
    dlog_assert((1 << size_bits) == size);
    slab_free_list *slab_list = &slab_heap->slab_lists[size_bits - SLAB_MIN_BITS];
    slab_page* page = nullptr;
    u32 slab_idx = (nvm_off & FINEFS_BLOCK_UMASK) >> size_bits;
    bool ret;

    spin_lock(&slab_heap->slab_lock);
    page = finefs_find_slab_page(slab_list, block_off);
    if(page == nullptr) {
        page = finefs_alloc_slab_page(sb);
        log_assert(page);
        finefs_slab_page_init_full(page, block_off, size_bits);
        finefs_insert_slab_page(slab_list, block_off, page);
        ++slab_list->page_num;
        rd_info("%s: new page_off: %lu, page_num:%u", __func__, block_off, slab_list->page_num);
    }
    dlog_assert(page);
    rd_info("%s: free page_off %lu, slab_idx: %u", __func__, block_off, slab_idx);
    ret = finefs_slab_page_set_free(page, slab_idx);
    if(ret && slab_list->page_num > SLAB_PAGE_KEEP_THRESHOLD) {
        rd_info("%s: page_num: %u > %u, free page_off: %lu", __func__,
            slab_list->page_num, SLAB_PAGE_KEEP_THRESHOLD, page->block_off);
        finefs_free_or_goto_next_page(slab_list, page, true);
    }
    spin_unlock(&slab_heap->slab_lock);
}
