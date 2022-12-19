#include "finefs/finefs.h"

int finefs_init_log_page_inode(struct super_block *sb) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct finefs_inode *pi = finefs_get_inode_by_ino(sb, FINEFS_LOG_PAGE_INO);

    pi->i_links_count = cpu_to_le16(1);
    pi->finefs_ino = FINEFS_LOG_PAGE_INO;
    pi->i_blk_type = FINEFS_DEFAULT_DATA_BLOCK_TYPE;
    pi->log_tail = 0;

    finefs_flush_buffer(pi, sizeof(finefs_inode), 1);
    return 0;
}

int finefs_log_soft_init(struct super_block *sb) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
	finefs_log *fine_log;
	finefs_log_info *log_info;
	int i;
	u64 temp;

	sbi->file_logs = (finefs_log_info *)ZALLOC(sbi->cpus * sizeof(finefs_log_info));
	if (!sbi->file_logs)
		return -ENOMEM;
    sbi->dir_logs = (finefs_log_info *)ZALLOC(sbi->cpus * sizeof(finefs_log_info));
	if (!sbi->dir_logs)
		return -ENOMEM;

	// 如果是崩溃恢复，需要先
	for (i = 0; i < sbi->cpus; i++) {
		spin_lock_init(&sbi->file_logs[i].log_lock);
		spin_lock_init(&sbi->file_logs[i].info_lock);
		sbi->file_logs[i].next_alloc_pages = 1;
		sbi->file_logs[i].cpuid = i;
		sbi->file_logs[i].fine_log = finefs_get_file_log(sb, i);
		new (&sbi->file_logs[i].free_logs) std::vector<u64>();
		new (&sbi->file_logs[i].sparse_logs) std::unordered_set<u64>();
		fine_log = finefs_get_file_log(sb, i);
		sbi->file_logs[i].cur_tail = fine_log->log_tail;
		sbi->file_logs[i].gc_tail = fine_log->log_gc_tail;

		spin_lock_init(&sbi->dir_logs[i].log_lock);
		spin_lock_init(&sbi->dir_logs[i].info_lock);
		sbi->dir_logs[i].next_alloc_pages = 1;
		sbi->dir_logs[i].cpuid = i;
		sbi->dir_logs[i].fine_log = finefs_get_dir_log(sb, i);
		new (&sbi->dir_logs[i].free_logs) std::vector<u64>();
		new (&sbi->dir_logs[i].sparse_logs) std::unordered_set<u64>();
		fine_log = finefs_get_dir_log(sb, i);
		sbi->dir_logs[i].cur_tail = fine_log->log_tail;
		sbi->dir_logs[i].gc_tail = fine_log->log_gc_tail;
    }

	return 0;
}

int finefs_log_hard_init(struct super_block *sb) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
	struct finefs_inode *pi = finefs_get_inode_by_ino(sb, FINEFS_LOG_PAGE_INO);
	struct finefs_log *fine_log;
	unsigned long blocknr = 0;
	int allocated;
	int i;
	u64 block;

	log_assert(pi->finefs_ino == FINEFS_LOG_PAGE_INO);
	log_assert(pi->i_blk_type == FINEFS_DEFAULT_DATA_BLOCK_TYPE);

	for (i = 0; i < sbi->cpus; i++) {
		fine_log = finefs_get_file_log(sb, i);
		if (!fine_log)
			return -EINVAL;
        pmem_memset(fine_log, 0, CACHELINE_SIZE, 0);

        fine_log = finefs_get_dir_log(sb, i);
		if (!fine_log)
			return -EINVAL;
        pmem_memset(fine_log, 0, CACHELINE_SIZE, 0);
	}

	PERSISTENT_BARRIER();
	return finefs_log_soft_init(sb);
}

finefs_log_info* finefs_log_tx_begin(super_block* sb, log_type_t log_type) {
	int	cpuid = get_processor_id();
	finefs_log_info* log_info = nullptr;
	switch (log_type)
	{
	case FINEFS_FILE_LOG:
		log_info = finefs_get_file_log_info(sb, cpuid);
		break;
	case FINEFS_DIR_LOG:
		log_info = finefs_get_dir_log_info(sb, cpuid);
	default:
		break;
	}
	spin_lock(&log_info->log_lock);
	return log_info;
}

finefs_log_info* finefs_log_tx_begin(super_block* sb, log_type_t log_type, int cpuid) {
	finefs_log_info* log_info = nullptr;
	switch (log_type)
	{
	case FINEFS_FILE_LOG:
		log_info = finefs_get_file_log_info(sb, cpuid);
		break;
	case FINEFS_DIR_LOG:
		log_info = finefs_get_dir_log_info(sb, cpuid);
		break;
	default:
		break;
	}
	spin_lock(&log_info->log_lock);
	return log_info;
}

void finefs_log_tx_end(super_block* sb, finefs_log_info* log_info, u64 new_tail) {
	PERSISTENT_BARRIER();
	u64 old_tail = log_info->cur_tail;
	if(old_tail == 0) {
		old_tail = log_info->fine_log->log_head.next_page_;
	}
	log_info->cur_tail = new_tail;

	u64 curr = old_tail & FINEFS_LOG_MASK;
	u64 end = new_tail & FINEFS_LOG_MASK;
	u64 next;
	finefs_inode_log_page* curr_page;
	while (curr != end) {
        curr_page = (finefs_inode_log_page *)finefs_get_block(sb, curr);
        curr = curr_page->page_tail.page_link.next_page_;
		curr_page->page_tail.can_delete = 1;
    }
#ifndef NDEBUG
	u64 curr_p = old_tail;
	bool is_tx_begin = false, is_tx_end = false;
	void *entry;
	u8 entry_type;
	while (curr_p != new_tail) {
		if (is_last_entry(curr_p, CACHELINE_SIZE))
			curr_p = finefs_log_next_page(sb, curr_p);

		entry = finefs_get_block(sb, curr_p);
		entry_type = finefs_get_entry_type(entry);

		if(entry_type & TX_BEGIN) {
			is_tx_begin = true;
		}
		if(entry_type & TX_END) {
			is_tx_end = true;
			log_assert(is_tx_begin);
		}
		curr_p += CACHELINE_SIZE;
	}
	log_assert(is_tx_begin && is_tx_end);
#endif

	spin_unlock(&log_info->log_lock);
}
