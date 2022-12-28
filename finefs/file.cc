/*
 * BRIEF DESCRIPTION
 *
 * File operations for files.
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

// static inline int finefs_can_set_blocksize_hint(struct inode *inode,
// 	struct finefs_inode *pi, loff_t new_size)
// {
// 	struct finefs_inode_info *si = FINEFS_I(inode);
// 	struct finefs_inode_info_header *sih = &si->header;

// 	/* Currently, we don't deallocate data blocks till the file is deleted.
// 	 * So no changing blocksize hints once allocation is done. */
// 	if (sih->i_size > 0)
// 		return 0;
// 	return 1;
// }

// int finefs_set_blocksize_hint(struct super_block *sb, struct inode *inode,
// 	struct finefs_inode *pi, loff_t new_size)
// {
// 	unsigned short block_type;

// 	if (!finefs_can_set_blocksize_hint(inode, pi, new_size))
// 		return 0;

// 	if (new_size >= 0x40000000) {   /* 1G */
// 		block_type = FINEFS_BLOCK_TYPE_1G;
// 		goto hint_set;
// 	}

// 	if (new_size >= 0x200000) {     /* 2M */
// 		block_type = FINEFS_BLOCK_TYPE_2M;
// 		goto hint_set;
// 	}

// 	/* defaulting to 4K */
// 	block_type = FINEFS_DEFAULT_DATA_BLOCK_TYPE;

// hint_set:
// 	finefs_dbg_verbose(
// 		"Hint: new_size 0x%lx, i_size 0x%lx",
// 		new_size, pi->i_size);
// 	finefs_dbg_verbose("Setting the hint to 0x%x", block_type);
// 	finefs_memunlock_inode(sb, pi);
// 	pi->i_blk_type = block_type;
// 	finefs_memlock_inode(sb, pi);
// 	return 0;
// }

static loff_t finefs_llseek(struct file *file, loff_t offset, int origin)
{
	// struct inode *inode = file->f_path.dentry->d_inode;
	struct inode *inode = file->f_inode;
	int retval;

	if (origin != SEEK_DATA && origin != SEEK_HOLE)
		return generic_file_llseek(file, offset, origin);

	r_fatal("NOT SUPPORT! SEEK_DATA and SEEK_HOLE");
	// mutex_lock(&inode->i_mutex);
	// switch (origin) {
	// case SEEK_DATA:
	// 	retval = finefs_find_region(inode, &offset, 0);
	// 	if (retval) {
	// 		mutex_unlock(&inode->i_mutex);
	// 		return retval;
	// 	}
	// 	break;
	// case SEEK_HOLE:
	// 	retval = finefs_find_region(inode, &offset, 1);
	// 	if (retval) {
	// 		mutex_unlock(&inode->i_mutex);
	// 		return retval;
	// 	}
	// 	break;
	// }

	// if ((offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET)) ||
	//     offset > inode->i_sb->s_maxbytes) {
	// 	mutex_unlock(&inode->i_mutex);
	// 	return -EINVAL;
	// }

	// if (offset != file->f_pos) {
	// 	file->f_pos = offset;
	// 	// file->f_version = 0;
	// }

	// mutex_unlock(&inode->i_mutex);
	return offset;
}

#if 0
static inline int finefs_check_page_dirty(struct super_block *sb,
	unsigned long addr)
{
	return IS_MAP_WRITE(addr);
}

static unsigned long finefs_get_dirty_range(struct super_block *sb,
	struct finefs_inode *pi, struct finefs_inode_info *si, loff_t *start,
	loff_t end)
{
	unsigned long flush_bytes = 0;
	unsigned long bytes;
	unsigned long cache_addr = 0;
	pgoff_t pgoff;
	loff_t offset;
	loff_t dirty_start;
	loff_t temp = *start;

	finefs_dbgv("%s: inode %lu, start %lu, end %lu",
			__func__, pi->finefs_ino, *start, end);

	dirty_start = temp;
	while (temp < end) {
		pgoff = temp >> PAGE_SHIFT;
		offset = temp & ~PAGE_MASK;
		bytes = sb->s_blocksize - offset;
		if (bytes > (end - temp))
			bytes = end - temp;

		cache_addr = finefs_get_cache_addr(sb, si, pgoff);
		if (cache_addr && finefs_check_page_dirty(sb, cache_addr)) {
			if (flush_bytes == 0)
				dirty_start = temp;
			flush_bytes += bytes;
		} else {
			if (flush_bytes)
				break;
		}
		temp += bytes;
	}

	if (flush_bytes == 0)
		*start = end;
	else
		*start = dirty_start;

	return flush_bytes;
}

static void finefs_get_sync_range(struct finefs_inode_info_header *sih,
	loff_t *start, loff_t *end)
{
	unsigned long start_blk, end_blk;
	unsigned long low_blk, high_blk;

	start_blk = *start >> PAGE_SHIFT;
	end_blk = *end >> PAGE_SHIFT;

	low_blk = sih->low_dirty;
	high_blk = sih->high_dirty;

	if (start_blk < low_blk)
		*start = low_blk << PAGE_SHIFT;
	if (end_blk > high_blk)
		*end = (high_blk + 1) << PAGE_SHIFT;
}

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling finefs_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * finefs_flush_buffer() on fsync() */
int finefs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	/* Sync from start to end[inclusive] */
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct finefs_inode *pi;
	unsigned long start_blk, end_blk;
	u64 end_tail = 0, begin_tail = 0;
	u64 begin_temp = 0, end_temp = 0;
	int ret = 0;
	loff_t sync_start, sync_end;
	loff_t isize;
	timing_t fsync_time;

	FINEFS_START_TIMING(fsync_t, fsync_time);
	if (!mapping_mapped(mapping))
		goto out;

	mutex_lock(&inode->i_mutex);

	/* Check the dirty range */
	pi = finefs_get_inode(sb, inode);

	end += 1; /* end is inclusive. We like our indices normal please! */

	isize = i_size_read(inode);

	if ((unsigned long)end > (unsigned long)isize)
		end = isize;
	if (!isize || (start >= end))
	{
		finefs_dbg_verbose("[%s:%d] : (ERR) isize(%llx), start(%llx),"
			" end(%llx)", __func__, __LINE__, isize, start, end);
		FINEFS_END_TIMING(fsync_t, fsync_time);
		mutex_unlock(&inode->i_mutex);
		return 0;
	}

	finefs_get_sync_range(sih, &start, &end);
	start_blk = start >> PAGE_SHIFT;
	end_blk = end >> PAGE_SHIFT;

	finefs_dbgv("%s: start %lu, end %lu, size %lu, "
			" start_blk %lu, end_blk %lu",
			__func__, start, end, isize, start_blk,
			end_blk);

	sync_start = start;
	sync_end = end;
	end_temp = pi->log_tail;

	do {
		unsigned long nr_flush_bytes = 0;

		nr_flush_bytes = finefs_get_dirty_range(sb, pi, si, &start, end);

		finefs_dbgv("start %lu, flush bytes %lu",
				start, nr_flush_bytes);
		if (nr_flush_bytes) {
			finefs_copy_to_nvmm(sb, inode, pi, start,
				nr_flush_bytes, &begin_temp, &end_temp);
			if (begin_tail == 0)
				begin_tail = begin_temp;
		}

		start += nr_flush_bytes;
	} while (start < end);

	end_tail = end_temp;
	if (begin_tail && end_tail && end_tail != pi->log_tail) {
		finefs_update_tail(pi, end_tail);

		/* Free the overlap blocks after the write is committed */
		ret = finefs_reassign_file_tree(sb, pi, sih, begin_tail);

		inode->i_blocks = le64_to_cpu(pi->i_blocks);
	}

	mutex_unlock(&inode->i_mutex);

out:
	FINEFS_END_TIMING(fsync_t, fsync_time);

	return ret;
}
#endif

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling finefs_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * finefs_flush_buffer() on fsync() */
int finefs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	/* Sync from start to end[inclusive] */
	// struct address_space *mapping = file->f_mapping;
	// struct inode *inode = mapping->host;
	// struct super_block *sb = inode->i_sb;
	// struct finefs_inode_info *si = FINEFS_I(inode);
	// struct finefs_inode_info_header *sih = &si->header;
	// struct finefs_file_pages_write_entry *entry;
	int ret = 0;
	// loff_t isize;
	// timing_t fsync_time;

	FINEFS_START_TIMING(fsync_t, fsync_time);

	/* No need to flush if the file is not mmaped */
	// if (!mapping_mapped(mapping))
	// 	goto persist;

	// end += 1; /* end is inclusive. We like our indices normal please! */

	// isize = i_size_read(inode);

	// if ((unsigned long)end > (unsigned long)isize)
	// 	end = isize;
	// if (!isize || (start >= end))
	// {
	// 	finefs_dbgv("[%s:%d] : (ERR) isize(%llx), start(%llx),"
	// 		" end(%llx)", __func__, __LINE__, isize, start, end);
	// 	FINEFS_END_TIMING(fsync_t, fsync_time);
	// 	return -ENODATA;
	// }

	// /* Align start and end to cacheline boundaries */
	// start = start & CACHELINE_MASK;
	// end = CACHELINE_ALIGN(end);
	// do {
	// 	unsigned long nvmm;
	// 	unsigned long nr_flush_bytes = 0;
	// 	unsigned long avail_bytes = 0;
	// 	void *dax_mem;
	// 	pgoff_t pgoff;
	// 	loff_t offset;

	// 	pgoff = start >> PAGE_SHIFT;
	// 	offset = start & ~PAGE_MASK;

	// 	entry = finefs_get_write_entry(sb, si, pgoff);
	// 	if (unlikely(entry == NULL)) {
	// 		finefs_dbgv("Found hole: pgoff %lu, inode size %lld",
	// 				pgoff, isize);

	// 		/* Jump the hole */
	// 		entry = finefs_find_next_entry(sb, sih, pgoff);
	// 		if (!entry)
	// 			goto persist;

	// 		pgoff = entry->pgoff;
	// 		start = pgoff << PAGE_SHIFT;
	// 		offset = 0;

	// 		if (start >= end)
	// 			goto persist;
	// 	}

	// 	nr_flush_bytes = end - start;

	// 	if (pgoff < entry->pgoff ||
	// 			pgoff - entry->pgoff >= entry->num_pages) {
	// 		finefs_err(sb, "%s ERROR: %lu, entry pgoff %lu, num %u, "
	// 			"blocknr %lu", __func__, pgoff, entry->pgoff,
	// 			entry->num_pages, entry->block >> PAGE_SHIFT);
	// 		FINEFS_END_TIMING(fsync_t, fsync_time);
	// 		return -EINVAL;
	// 	}

	// 	/* Find contiguous blocks */
	// 	if (entry->invalid_pages == 0)
	// 		avail_bytes = (entry->num_pages - (pgoff - entry->pgoff))
	// 			* PAGE_SIZE - offset;
	// 	else
	// 		avail_bytes = PAGE_SIZE - offset;

	// 	if (nr_flush_bytes > avail_bytes)
	// 		nr_flush_bytes = avail_bytes;

	// 	nvmm = get_nvmm(sb, sih, entry, pgoff);
	// 	dax_mem = finefs_get_block(sb, (nvmm << PAGE_SHIFT));

	// 	finefs_dbgv("start %lu, flush bytes %lu",
	// 			start, nr_flush_bytes);
	// 	if (nr_flush_bytes)
	// 		finefs_flush_buffer(dax_mem + offset, nr_flush_bytes, 0);

	// 	start += nr_flush_bytes;
	// } while (start < end);

persist:
	// PERSISTENT_BARRIER();
	FINEFS_END_TIMING(fsync_t, fsync_time);

	return ret;
}

/* This callback is called when a file is closed */
static int finefs_flush(struct file *file, fl_owner_t id)
{
	PERSISTENT_BARRIER();
	return 0;
}

// static int finefs_open(struct inode *inode, struct file *filp)
// {
// 	return generic_file_open(inode, filp);
// }

const struct file_operations finefs_dax_file_operations = {
// #ifndef FINEFS_CUT_OUT
	.llseek			= finefs_llseek,
// #endif
	.read			= finefs_dax_file_read,
	.write			= finefs_dax_file_write,
	// .read_iter		= generic_file_read_iter,
	// .write_iter		= generic_file_write_iter,
	// .mmap			= finefs_dax_file_mmap,
	// .open			= finefs_open,
	.flush			= finefs_flush,
	.fsync			= finefs_fsync,  // 主要对mmap有用，不过我们目前已经将mmap去掉了
	// .unlocked_ioctl		= finefs_ioctl,
// #ifdef CONFIG_COMPAT
// 	.compat_ioctl		= finefs_compat_ioctl,
// #endif
};

const struct inode_operations finefs_file_inode_operations = {
	.setattr	= finefs_notify_change,
	.getattr	= finefs_getattr,
	// .get_acl	= NULL,
};
