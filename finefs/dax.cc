/*
 * BRIEF DESCRIPTION
 *
 * DAX file operations.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "finefs/finefs.h"
#include "finefs/wprotect.h"

#include "util/cpu.h"

// ppos带回实际拷贝到的偏移
// 返回实际读取的字节数
static ssize_t
do_dax_mapping_read(struct file *filp, char *buf,
	size_t len, loff_t *ppos)
{
	// struct inode *inode = filp->f_mapping->host;
	struct inode *inode = filp->f_inode;
	struct super_block *sb = inode->i_sb;
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;
	struct finefs_file_write_entry *entry;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	// 已拷贝的字节数
	size_t copied = 0, err = 0;
	timing_t memcpy_time;

	pos = *ppos;
	// page index
	index = pos >> FINEFS_BLOCK_SHIFT;
	// page内偏移
	offset = pos & FINEFS_BLOCK_UMASK;

	// if (!access_ok(VERIFY_WRITE, buf, len)) {
	// 	err = -EFAULT;
	// 	goto out;
	// }

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	rdv_proc("%s: inode %lu, offset %lld, count %lu, size %lld",
		__func__, inode->i_ino,	pos, len, isize);

	if (len > isize - pos)
		len = isize - pos;

	if (len <= 0)
		goto out;

	end_index = (isize - 1) >> FINEFS_BLOCK_SHIFT;
	do {
		unsigned long nr, left;
		unsigned long nvmm;
		void *dax_mem = NULL;
		int zero = 0;

		/* nr is the maximum number of bytes to copy from this page */
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & FINEFS_BLOCK_UMASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}

		entry = finefs_get_write_entry(sb, si, index);
		if (unlikely(entry == NULL)) {
			// 一个空洞的页
			rdv_proc("Required extent not found: pgoff %lu, "
				"inode size %lld", index, isize);
			nr = FINEFS_BLOCK_SIZE;
			zero = 1;
			goto memcpy;
		}

		/* Find contiguous blocks */
		if (index < entry->pgoff ||
			index - entry->pgoff >= entry->num_pages) { // 超出范围了
			r_error("%s ERROR: %lu, entry pgoff %lu, num %u, "
				"blocknr %lu", __func__, index, entry->pgoff,
				entry->num_pages, entry->block >> FINEFS_BLOCK_SHIFT);
			return -EINVAL;
		}
		if (entry->invalid_pages == 0) {
			nr = (entry->num_pages - (index - entry->pgoff))
				* FINEFS_BLOCK_SIZE;
		} else {  // 如果有无效的page，一个一个page的拷贝。防止下一个page就是无效的
			nr = FINEFS_BLOCK_SIZE;
		}

		nvmm = get_nvmm(sb, sih, entry, index);
		dax_mem = finefs_get_block(sb, (nvmm << FINEFS_BLOCK_SHIFT));

memcpy:
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		FINEFS_START_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (!zero)
			left = __copy_to_user(buf + copied,
						dax_mem + offset, nr);
		else
			left = __clear_user(buf + copied, nr);

		FINEFS_END_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (left) {
			r_error("%s ERROR!: bytes %lu, left %lu",
				__func__, nr, left);
			err = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> FINEFS_BLOCK_SHIFT;
		offset &= FINEFS_BLOCK_UMASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	// if (filp)
	// 	file_accessed(filp);

	FINEFS_STATS_ADD(read_bytes, copied);

	rd_info("%s returned %zu", __func__, copied);
	return (copied ? copied : err);
}

/*
 * Wrappers. We need to use the rcu read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * i_mutex.
 */
ssize_t finefs_dax_file_read(struct file *filp, char *buf,
			    size_t len, loff_t *ppos)
{
	ssize_t res;
	timing_t dax_read_time;

	FINEFS_START_TIMING(dax_read_t, dax_read_time);
//	rcu_read_lock();
	res = do_dax_mapping_read(filp, buf, len, ppos);
//	rcu_read_unlock();
	FINEFS_END_TIMING(dax_read_t, dax_read_time);
	return res;
}

// block index
// kmem 新nvm block的地址
// 拷贝未覆盖的block内容
// is_end_blk为true，表示覆盖的是尾部，则就要拷贝头部数据
static inline int finefs_copy_partial_block(struct super_block *sb,
	struct finefs_inode_info_header *sih,
	struct finefs_file_write_entry *entry, unsigned long index,
	size_t offset, void* kmem, bool is_end_blk)
{
	void *ptr;
	unsigned long nvmm;

	nvmm = get_nvmm(sb, sih, entry, index);
	ptr = finefs_get_block(sb, (nvmm << FINEFS_BLOCK_SHIFT));
	if (ptr != NULL) {
		if (is_end_blk)
			memcpy(kmem + offset, ptr + offset,
				sb->s_blocksize - offset);
		else
			memcpy(kmem, ptr, offset);
	}

	return 0;
}

/*
 * Fill the new start/end block from original blocks.
 * Do nothing if fully covered; copy if original blocks present;
 * Fill zero otherwise.
 */
static void finefs_handle_head_tail_blocks(struct super_block *sb,
	struct finefs_inode *pi, struct inode *inode, loff_t pos, size_t count,
	void *kmem)
{
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;
	size_t offset, eblk_offset;
	unsigned long start_blk, end_blk, num_blocks;
	struct finefs_file_write_entry *entry;
	timing_t partial_time;

	FINEFS_START_TIMING(partial_block_t, partial_time);
	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	/* offset in the actual block size block */
	offset = pos & (finefs_inode_blk_size(pi) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	rdv_proc("%s: %lu blocks", __func__, num_blocks);
	/* We avoid zeroing the alloc'd range, which is going to be overwritten
	 * by this system call anyway */
	rdv_proc("%s: start offset %lu start blk %lu %p", __func__,
				offset, start_blk, kmem);
	if (offset != 0) {
		entry = finefs_get_write_entry(sb, si, start_blk);
		if (entry == NULL) {
			/* Fill zero */
		    	memset(kmem, 0, offset);
		} else {
			/* Copy from original block */
			// 处理第一个非对齐的块
			finefs_copy_partial_block(sb, sih, entry, start_blk,
					offset, kmem, false);
		}
		finefs_flush_buffer(kmem, offset, 0);
	}

	kmem = (void *)((char *)kmem +
			((num_blocks - 1) << sb->s_blocksize_bits));
	// 处理尾部部分块
	eblk_offset = (pos + count) & (finefs_inode_blk_size(pi) - 1);
	rdv_proc("%s: end offset %lu, end blk %lu %p", __func__,
				eblk_offset, end_blk, kmem);
	if (eblk_offset != 0) {
		entry = finefs_get_write_entry(sb, si, end_blk);
		if (entry == NULL) {
			/* Fill zero */
		    	memset(kmem + eblk_offset, 0,
					sb->s_blocksize - eblk_offset);
		} else {
			/* Copy from original block */
			finefs_copy_partial_block(sb, sih, entry, end_blk,
					eblk_offset, kmem, true);
		}
		finefs_flush_buffer(kmem + eblk_offset,
					sb->s_blocksize - eblk_offset, 0);
	}

	FINEFS_END_TIMING(partial_block_t, partial_time);
}

int finefs_reassign_file_tree(struct super_block *sb,
	struct finefs_inode *pi, struct finefs_inode_info_header *sih,
	u64 begin_tail)
{
	struct finefs_file_write_entry *entry_data;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct finefs_file_write_entry);

	while (curr_p != sih->i_log_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			r_error("%s: File inode %lu log is NULL!",
				__func__, pi->finefs_ino);
			return -EINVAL;
		}

		entry_data = (struct finefs_file_write_entry *)
					finefs_get_block(sb, curr_p);

		if (finefs_get_entry_type(entry_data) != FILE_WRITE) {
			r_error("%s: entry type is not write? %d",
				__func__, finefs_get_entry_type(entry_data));
			curr_p += entry_size;
			continue;
		}

		finefs_assign_write_entry(sb, pi, sih, entry_data, true);
		curr_p += entry_size;
	}

	return 0;
}

static int finefs_cleanup_incomplete_write(struct super_block *sb,
	struct finefs_inode *pi, struct finefs_inode_info_header *sih,
	unsigned long blocknr, int allocated, u64 begin_tail, u64 end_tail)
{
	struct finefs_file_write_entry *entry;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct finefs_file_write_entry);

	if (blocknr > 0 && allocated > 0)
		finefs_free_data_blocks(sb, pi, blocknr, allocated);

	if (begin_tail == 0 || end_tail == 0)
		return 0;

	while (curr_p != end_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			r_error("%s: File inode %lu log is NULL!",
				__func__, pi->finefs_ino);
			return -EINVAL;
		}

		entry = (struct finefs_file_write_entry *)
					finefs_get_block(sb, curr_p);

		if (finefs_get_entry_type(entry) != FILE_WRITE) {
			r_error("%s: entry type is not write? %d",
				__func__, finefs_get_entry_type(entry));
			curr_p += entry_size;
			continue;
		}

		blocknr = entry->block >> FINEFS_BLOCK_SHIFT;
		finefs_free_data_blocks(sb, pi, blocknr, entry->num_pages);
		curr_p += entry_size;
	}

	return 0;
}

ssize_t finefs_cow_file_write(struct file *filp,
	const char *buf, size_t len, loff_t *ppos, bool need_mutex)
{
	// struct address_space *mapping = filp->f_mapping;
	// struct inode    *inode = mapping->host;
	struct inode    *inode = filp->f_inode;
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct finefs_inode *pi;
	struct finefs_file_write_entry entry_data;
	ssize_t     written = 0;  // 已经拷贝的用户数据
	loff_t pos;
	size_t count, offset, copied, ret;
	unsigned long start_blk, num_blocks;
	unsigned long total_blocks;
	unsigned long blocknr = 0;
	unsigned int data_bits;
	int allocated = 0;
	void* kmem;
	u64 curr_entry;
	size_t bytes;
	long status = 0;
	timing_t cow_write_time, memcpy_time;
	unsigned long step = 0;
	// begin_tail第一个write entry的起始地址
	u64 temp_tail = 0, begin_tail = 0;
	u32 time;

	if (len == 0)
		return 0;

	/*
	 * We disallow writing to a mmaped file,
	 * since write is copy-on-write while mmap is DAX (in-place).
	 */
	// if (mapping_mapped(mapping))
	// 	return -EACCES;

	FINEFS_START_TIMING(cow_write_t, cow_write_time);

	// 一些加锁同步的操作
	// sb_start_write(inode->i_sb);
	if (need_mutex)
		mutex_lock(&inode->i_mutex);

	// if (!access_ok(VERIFY_READ, buf, len)) {
	// 	ret = -EFAULT;
	// 	goto out;
	// }
	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;

	pi = finefs_get_inode(sb, inode);

	// 块内偏移
	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;
	/* offset in the actual block size block */

	// ret = file_remove_privs(filp);
	// if (ret) {
	// 	goto out;
	// }
	struct timespec cur_time = get_cur_time_spec();
	inode->i_ctime = inode->i_mtime = cur_time;
	time = cur_time.tv_sec;

	rd_info("%s: inode %lu, offset %lld, count %lu",
			__func__, inode->i_ino,	pos, count);
	// temp_tail = pi->log_tail;
	temp_tail = sih->i_log_tail;
	while (num_blocks > 0) {
		offset = pos & (finefs_inode_blk_size(pi) - 1);
		start_blk = pos >> sb->s_blocksize_bits;

		/* don't zero-out the allocated blocks */
		allocated = finefs_new_data_blocks(sb, pi, &blocknr, num_blocks,
						start_blk, 0, 1);
		rdv_proc("%s: alloc %d blocks @ %lu", __func__,
						allocated, blocknr);

		if (allocated <= 0) {
			r_warning("%s alloc blocks failed %d", __func__,
								allocated);
			ret = allocated;
			goto out;
		}

		step++;
		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		// 新配备区域的nvm虚拟地址
		kmem = finefs_get_block(inode->i_sb,
			finefs_get_block_off(sb, blocknr,	pi->i_blk_type));

		if (offset || ((offset + bytes) & (FINEFS_BLOCK_SIZE - 1)) != 0)
			finefs_handle_head_tail_blocks(sb, pi, inode, pos, bytes,
								kmem);

		/* Now copy from user buf */
//		finefs_dbg("Write: %p", kmem);
		FINEFS_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
						buf, bytes);
		FINEFS_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

		entry_data.pgoff = cpu_to_le64(start_blk);
		entry_data.num_pages = cpu_to_le32(allocated);
		entry_data.invalid_pages = 0;
		entry_data.block = cpu_to_le64(finefs_get_block_off(sb, blocknr,
							pi->i_blk_type));
		entry_data.mtime = cpu_to_le32(time);
		/* Set entry type after set block */
		finefs_set_entry_type((void *)&entry_data, FILE_WRITE);

		if (pos + copied > inode->i_size)
			entry_data.size = cpu_to_le64(pos + copied);
		else
			entry_data.size = cpu_to_le64(inode->i_size);

		curr_entry = finefs_append_file_write_entry(sb, pi, inode,
							&entry_data, temp_tail);
		if (curr_entry == 0) {
			rd_warning("%s: append inode entry failed", __func__);
			ret = -ENOSPC;
			goto out;
		}

		rd_info("Write: %p, %lu", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			buf += copied;
			count -= copied;
			num_blocks -= allocated;
		}
		if (unlikely(copied != bytes)) {
			r_error("%s ERROR!: %p, bytes %lu, copied %lu",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0)
			break;

		if (begin_tail == 0)
			begin_tail = curr_entry;
		temp_tail = curr_entry + sizeof(struct finefs_file_write_entry);
	}

	finefs_memunlock_inode(sb, pi);
	data_bits = finefs_blk_type_to_shift[pi->i_blk_type];
	le64_add_cpu(&pi->i_blocks,
			(total_blocks << (data_bits - sb->s_blocksize_bits)));
	finefs_memlock_inode(sb, pi);

	// 提交写操作
	// finefs_update_tail(pi, temp_tail);
	finefs_update_volatile_tail(sih, temp_tail);

	/* Free the overlap blocks after the write is committed */
	// 更改内存中的索引
	ret = finefs_reassign_file_tree(sb, pi, sih, begin_tail);
	if (ret)
		goto out;

	inode->i_blocks = le64_to_cpu(pi->i_blocks);

	ret = written;
	FINEFS_STATS_ADD(write_breaks, step);
	rd_info("blocks: %lu, %lu", inode->i_blocks, pi->i_blocks);

	*ppos = pos;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		sih->i_size = pos;
	}

out:
	if (ret < 0) {
		r_error("Unexpected!!");
		finefs_cleanup_incomplete_write(sb, pi, sih, blocknr, allocated,
						begin_tail, temp_tail);
	}


	if (need_mutex)
		mutex_unlock(&inode->i_mutex);
	// sb_end_write(inode->i_sb);
	FINEFS_END_TIMING(cow_write_t, cow_write_time);
	FINEFS_STATS_ADD(cow_write_bytes, written);
	return ret;
}

ssize_t finefs_dax_file_write(struct file *filp, const char *buf,
	size_t len, loff_t *ppos)
{
	return finefs_cow_file_write(filp, buf, len, ppos, true);
}

#if 0

/*
 * return > 0, # of blocks mapped or allocated.
 * return = 0, if plain lookup failed.
 * return < 0, error case.
 */
static int finefs_dax_get_blocks(struct inode *inode, sector_t iblock,
	unsigned long max_blocks, struct buffer_head *bh, int create)
{
	struct super_block *sb = inode->i_sb;
	struct finefs_inode *pi;
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;
	struct finefs_file_write_entry *entry = NULL;
	struct finefs_file_write_entry entry_data;
	u64 temp_tail = 0;
	u64 curr_entry;
	u32 time;
	unsigned int data_bits;
	unsigned long nvmm = 0;
	unsigned long next_pgoff;
	unsigned long blocknr = 0;
	int num_blocks = 0;
	int allocated = 0;
	int ret = 0;

	if (max_blocks == 0)
		return 0;

	finefs_dbgv("%s: pgoff %lu, num %lu, create %d",
				__func__, iblock, max_blocks, create);

	entry = finefs_get_write_entry(sb, si, iblock);
	if (entry) {
		/* Find contiguous blocks */
		if (entry->invalid_pages == 0)
			num_blocks = entry->num_pages - (iblock - entry->pgoff);
		else
			num_blocks = 1;

		if (num_blocks > max_blocks)
			num_blocks = max_blocks;

		nvmm = get_nvmm(sb, sih, entry, iblock);
		clear_buffer_new(bh);
		finefs_dbgv("%s: pgoff %lu, block %lu", __func__, iblock, nvmm);
		goto out;
	}

	if (create == 0)
		return 0;

	pi = finefs_get_inode(sb, inode);
	num_blocks = max_blocks;
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;

	/* Fill the hole */
	entry = finefs_find_next_entry(sb, sih, iblock);
	if (entry) {
		next_pgoff = entry->pgoff;
		if (next_pgoff <= iblock) {
			BUG();
			ret = -EINVAL;
			goto out;
		}

		num_blocks = next_pgoff - iblock;
		if (num_blocks > max_blocks)
			num_blocks = max_blocks;
	}

	/* Return initialized blocks to the user */
	allocated = finefs_new_data_blocks(sb, pi, &blocknr, num_blocks,
						iblock, 1, 1);
	if (allocated <= 0) {
		finefs_dbg("%s alloc blocks failed %d", __func__,
							allocated);
		ret = allocated;
		goto out;
	}

	num_blocks = allocated;
	entry_data.pgoff = cpu_to_le64(iblock);
	entry_data.num_pages = cpu_to_le32(num_blocks);
	entry_data.invalid_pages = 0;
	entry_data.block = cpu_to_le64(finefs_get_block_off(sb, blocknr,
							pi->i_blk_type));
	/* Set entry type after set block */
	finefs_set_entry_type((void *)&entry_data, FILE_WRITE);
	entry_data.mtime = cpu_to_le32(time);

	/* Do not extend file size */
	entry_data.size = cpu_to_le64(inode->i_size);

	curr_entry = finefs_append_file_write_entry(sb, pi, inode,
						&entry_data, pi->log_tail);
	if (curr_entry == 0) {
		finefs_dbg("%s: append inode entry failed", __func__);
		ret = -ENOSPC;
		goto out;
	}

	nvmm = blocknr;
	data_bits = finefs_blk_type_to_shift[pi->i_blk_type];
	le64_add_cpu(&pi->i_blocks,
			(num_blocks << (data_bits - sb->s_blocksize_bits)));

	temp_tail = curr_entry + sizeof(struct finefs_file_write_entry);
	finefs_update_tail(pi, temp_tail);

	ret = finefs_reassign_file_tree(sb, pi, sih, curr_entry);
	if (ret)
		goto out;

	inode->i_blocks = le64_to_cpu(pi->i_blocks);

//	set_buffer_new(bh);

out:
	if (ret < 0) {
		finefs_cleanup_incomplete_write(sb, pi, sih, blocknr, allocated,
						0, temp_tail);
		return ret;
	}

	map_bh(bh, inode->i_sb, nvmm);
	if (num_blocks > 1)
		bh->b_size = sb->s_blocksize * num_blocks;

	return num_blocks;
}

int finefs_dax_get_block(struct inode *inode, sector_t iblock,
	struct buffer_head *bh, int create)
{
	unsigned long max_blocks = bh->b_size >> inode->i_blkbits;
	int ret;
	timing_t gb_time;

	FINEFS_START_TIMING(dax_get_block_t, gb_time);

	ret = finefs_dax_get_blocks(inode, iblock, max_blocks, bh, create);
	if (ret > 0) {
		bh->b_size = ret << inode->i_blkbits;
		ret = 0;
	}
	FINEFS_END_TIMING(dax_get_block_t, gb_time);
	return ret;
}

#endif

#if 0
static ssize_t finefs_flush_mmap_to_nvmm(struct super_block *sb,
	struct inode *inode, struct finefs_inode *pi, loff_t pos,
	size_t count, void *kmem)
{
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;
	unsigned long start_blk;
	unsigned long cache_addr;
	u64 nvmm_block;
	void *nvmm_addr;
	loff_t offset;
	size_t bytes, copied;
	ssize_t written = 0;
	int status = 0;
	ssize_t ret;

	while (count) {
		start_blk = pos >> sb->s_blocksize_bits;
		offset = pos & (sb->s_blocksize - 1);
		bytes = sb->s_blocksize - offset;
		if (bytes > count)
			bytes = count;

		cache_addr = finefs_get_cache_addr(sb, si, start_blk);
		if (cache_addr == 0) {
			finefs_dbg("%s: ino %lu %lu mmap page %lu not found!",
					__func__, inode->i_ino, sih->ino, start_blk);
			finefs_dbg("mmap pages %lu", sih->mmap_pages);
			ret = -EINVAL;
			goto out;
		}

		nvmm_block = MMAP_ADDR(cache_addr);
		nvmm_addr = finefs_get_block(sb, nvmm_block);
		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
				nvmm_addr + offset, bytes);

		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			count -= copied;
			kmem += offset + copied;
		}
		if (unlikely(copied != bytes)) {
			finefs_dbg("%s ERROR!: %p, bytes %lu, copied %lu",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0) {
			ret = status;
			goto out;
		}
	}
	ret = written;
out:
	return ret;
}

ssize_t finefs_copy_to_nvmm(struct super_block *sb, struct inode *inode,
	struct finefs_inode *pi, loff_t pos, size_t count, u64 *begin,
	u64 *end)
{
	struct finefs_file_write_entry entry_data;
	unsigned long start_blk, num_blocks;
	unsigned long blocknr = 0;
	unsigned long total_blocks;
	unsigned int data_bits;
	int allocated = 0;
	u64 curr_entry;
	ssize_t written = 0;
	int ret;
	void *kmem;
	size_t bytes, copied;
	loff_t offset;
	int status = 0;
	u64 temp_tail = 0, begin_tail = 0;
	u32 time;
	timing_t memcpy_time, copy_to_nvmm_time;

	FINEFS_START_TIMING(copy_to_nvmm_t, copy_to_nvmm_time);
	sb_start_write(inode->i_sb);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;

	finefs_dbgv("%s: ino %lu, block %lu, offset %lu, count %lu",
		__func__, inode->i_ino, pos >> sb->s_blocksize_bits,
		(unsigned long)offset, count);

	temp_tail = *end;
	while (num_blocks > 0) {
		offset = pos & (finefs_inode_blk_size(pi) - 1);
		start_blk = pos >> sb->s_blocksize_bits;
		allocated = finefs_new_data_blocks(sb, pi, &blocknr, num_blocks,
						start_blk, 0, 0);
		if (allocated <= 0) {
			finefs_dbg("%s alloc blocks failed %d", __func__,
								allocated);
			ret = allocated;
			goto out;
		}

		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		kmem = finefs_get_block(inode->i_sb,
			finefs_get_block_off(sb, blocknr,	pi->i_blk_type));

		if (offset || ((offset + bytes) & (FINEFS_BLOCK_SIZE - 1)))
			finefs_handle_head_tail_blocks(sb, pi, inode, pos,
							bytes, kmem);

		FINEFS_START_TIMING(memcpy_w_wb_t, memcpy_time);
		copied = finefs_flush_mmap_to_nvmm(sb, inode, pi, pos, bytes,
							kmem);
		FINEFS_END_TIMING(memcpy_w_wb_t, memcpy_time);

		entry_data.pgoff = cpu_to_le64(start_blk);
		entry_data.num_pages = cpu_to_le32(allocated);
		entry_data.invalid_pages = 0;
		entry_data.block = cpu_to_le64(finefs_get_block_off(sb, blocknr,
							pi->i_blk_type));
		/* FIXME: should we use the page cache write time? */
		entry_data.mtime = cpu_to_le32(time);
		/* Set entry type after set block */
		finefs_set_entry_type((void *)&entry_data, FILE_WRITE);

		entry_data.size = cpu_to_le64(inode->i_size);

		curr_entry = finefs_append_file_write_entry(sb, pi, inode,
						&entry_data, temp_tail);
		if (curr_entry == 0) {
			finefs_dbg("%s: append inode entry failed", __func__);
			ret = -ENOSPC;
			goto out;
		}

		finefs_dbgv("Write: %p, %ld", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			count -= copied;
			num_blocks -= allocated;
		}
		if (unlikely(copied != bytes)) {
			finefs_dbg("%s ERROR!: %p, bytes %lu, copied %lu",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0) {
			ret = status;
			goto out;
		}

		if (begin_tail == 0)
			begin_tail = curr_entry;
		temp_tail = curr_entry + sizeof(struct finefs_file_write_entry);
	}

	finefs_memunlock_inode(sb, pi);
	data_bits = finefs_blk_type_to_shift[pi->i_blk_type];
	le64_add_cpu(&pi->i_blocks,
			(total_blocks << (data_bits - sb->s_blocksize_bits)));
	finefs_memlock_inode(sb, pi);
	inode->i_blocks = le64_to_cpu(pi->i_blocks);

	*begin = begin_tail;
	*end = temp_tail;

	ret = written;
out:
	if (ret < 0)
		finefs_cleanup_incomplete_write(sb, pi, sih, blocknr, allocated,
						begin_tail, temp_tail);

	sb_end_write(inode->i_sb);
	FINEFS_END_TIMING(copy_to_nvmm_t, copy_to_nvmm_time);
	return ret;
}

static int finefs_get_nvmm_pfn(struct super_block *sb, struct finefs_inode *pi,
	struct finefs_inode_info *si, u64 nvmm, pgoff_t pgoff,
	vm_flags_t vm_flags, void **kmem, unsigned long *pfn)
{
	struct finefs_inode_info_header *sih = &si->header;
	u64 mmap_block;
	unsigned long cache_addr = 0;
	unsigned long blocknr = 0;
	void *mmap_addr;
	void *nvmm_addr;
	int ret;

	cache_addr = finefs_get_cache_addr(sb, si, pgoff);

	if (cache_addr) {
		mmap_block = MMAP_ADDR(cache_addr);
		mmap_addr = finefs_get_block(sb, mmap_block);
	} else {
		ret = finefs_new_data_blocks(sb, pi, &blocknr, 1,
						pgoff, 0, 1);

		if (ret <= 0) {
			finefs_dbg("%s alloc blocks failed %d",
					__func__, ret);
			return ret;
		}

		mmap_block = blocknr << FINEFS_BLOCK_SHIFT;
		mmap_addr = finefs_get_block(sb, mmap_block);

		if (vm_flags & VM_WRITE)
			mmap_block |= MMAP_WRITE_BIT;

		finefs_dbgv("%s: inode %lu, pgoff %lu, mmap block 0x%lx",
			__func__, sih->ino, pgoff, mmap_block);

		ret = radix_tree_insert(&sih->cache_tree, pgoff,
					(void *)mmap_block);
		if (ret) {
			finefs_dbg("%s: ERROR %d", __func__, ret);
			return ret;
		}

		sih->mmap_pages++;
		if (nvmm) {
			/* Copy from NVMM to dram */
			nvmm_addr = finefs_get_block(sb, nvmm);
			memcpy(mmap_addr, nvmm_addr, FINEFS_BLOCK_SIZE);
		} else {
			memset(mmap_addr, 0, FINEFS_BLOCK_SIZE);
		}
	}

	*kmem = mmap_addr;
	*pfn = finefs_get_pfn(sb, mmap_block);

	return 0;
}

static int finefs_get_mmap_addr(struct inode *inode, struct vm_area_struct *vma,
	pgoff_t pgoff, int create, void **kmem, unsigned long *pfn)
{
	struct super_block *sb = inode->i_sb;
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;
	struct finefs_inode *pi;
	u64 nvmm;
	vm_flags_t vm_flags = vma->vm_flags;
	int ret;

	pi = finefs_get_inode(sb, inode);

	nvmm = finefs_find_nvmm_block(sb, si, NULL, pgoff);

	ret = finefs_get_nvmm_pfn(sb, pi, si, nvmm, pgoff, vm_flags,
						kmem, pfn);

	if (vm_flags & VM_WRITE) {
		if (pgoff < sih->low_dirty)
			sih->low_dirty = pgoff;
		if (pgoff > sih->high_dirty)
			sih->high_dirty = pgoff;
	}

	return ret;
}

/* OOM err return with dax file fault handlers doesn't mean anything.
 * It would just cause the OS to go an unnecessary killing spree !
 */
static int __finefs_dax_file_fault(struct vm_area_struct *vma,
				  struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	pgoff_t size;
	void *dax_mem;
	unsigned long dax_pfn = 0;
	int err;
	int ret = VM_FAULT_SIGBUS;

	mutex_lock(&inode->i_mutex);
	size = (i_size_read(inode) + FINEFS_BLOCK_SIZE - 1) >> FINEFS_BLOCK_SHIFT;
	if (vmf->pgoff >= size) {
		finefs_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx), size 0x%lx",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->virtual_address, size);
		goto out;
	}

	err = finefs_get_mmap_addr(inode, vma, vmf->pgoff, 1,
						&dax_mem, &dax_pfn);
	if (unlikely(err)) {
		finefs_dbg("[%s:%d] get_mmap_addr failed. vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx)",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->virtual_address);
		goto out;
	}

	finefs_dbgv("%s flags: vma 0x%lx, vmf 0x%x",
			__func__, vma->vm_flags, vmf->flags);

	finefs_dbgv("DAX mmap: inode %lu, vm_start(0x%lx), vm_end(0x%lx), "
			"pgoff(0x%lx), vma pgoff(0x%lx), "
			"VA(0x%lx)->PA(0x%lx)",
			inode->i_ino, vma->vm_start, vma->vm_end, vmf->pgoff,
			vma->vm_pgoff, (unsigned long)vmf->virtual_address,
			(unsigned long)dax_pfn << FINEFS_BLOCK_SHIFT);

	if (dax_pfn == 0)
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	err = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address,
		__pfn_to_pfn_t(dax_pfn, PFN_DEV));
#else
	err = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address, dax_pfn);
#endif

	if (err == -ENOMEM)
		goto out;
	/*
	 * err == -EBUSY is fine, we've raced against another thread
	 * that faulted-in the same page
	 */
	if (err != -EBUSY)
		BUG_ON(err);

	ret = VM_FAULT_NOPAGE;

out:
	mutex_unlock(&inode->i_mutex);
	return ret;
}

static int finefs_dax_file_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int ret = 0;
	timing_t fault_time;

	FINEFS_START_TIMING(mmap_fault_t, fault_time);
	ret = __finefs_dax_file_fault(vma, vmf);
	FINEFS_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}
#endif

#if 0

static int finefs_dax_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vma->vm_file);
	int ret = 0;
	timing_t fault_time;

	FINEFS_START_TIMING(mmap_fault_t, fault_time);

	mutex_lock(&inode->i_mutex);
	ret = dax_fault(vma, vmf, finefs_dax_get_block, NULL);
	mutex_unlock(&inode->i_mutex);

	FINEFS_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static int finefs_dax_pmd_fault(struct vm_area_struct *vma, unsigned long addr,
	pmd_t *pmd, unsigned int flags)
{
	struct inode *inode = file_inode(vma->vm_file);
	int ret = 0;
	timing_t fault_time;

	FINEFS_START_TIMING(mmap_fault_t, fault_time);

	mutex_lock(&inode->i_mutex);
	ret = dax_pmd_fault(vma, addr, pmd, flags, finefs_dax_get_block, NULL);
	mutex_unlock(&inode->i_mutex);

	FINEFS_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static int finefs_dax_pfn_mkwrite(struct vm_area_struct *vma,
	struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vma->vm_file);
	loff_t size;
	int ret = 0;
	timing_t fault_time;

	FINEFS_START_TIMING(mmap_fault_t, fault_time);

	mutex_lock(&inode->i_mutex);
	size = (i_size_read(inode) + FINEFS_BLOCK_SIZE - 1) >> FINEFS_BLOCK_SHIFT;
	if (vmf->pgoff >= size)
		ret = VM_FAULT_SIGBUS;
	else
		ret = dax_pfn_mkwrite(vma, vmf);
	mutex_unlock(&inode->i_mutex);

	FINEFS_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static const struct vm_operations_struct finefs_dax_vm_ops = {
	.fault	= finefs_dax_fault,
	.pmd_fault = finefs_dax_pmd_fault,
	.page_mkwrite = finefs_dax_fault,
	.pfn_mkwrite = finefs_dax_pfn_mkwrite,
};

int finefs_dax_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;

	vma->vm_ops = &finefs_dax_vm_ops;
	finefs_dbg_mmap4k("[%s:%d] MMAP 4KPAGE vm_start(0x%lx),"
			" vm_end(0x%lx), vm_flags(0x%lx), "
			"vm_page_prot(0x%lx)", __func__,
			__LINE__, vma->vm_start, vma->vm_end,
			vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}

#endif