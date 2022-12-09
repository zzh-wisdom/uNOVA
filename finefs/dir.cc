/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
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
#include "util/log.h"
#include "util/cpu.h"
#include "util/util.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

// 在目录的radix中查找对应的孩子
struct finefs_dentry *finefs_find_dentry(struct super_block *sb,
	struct finefs_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len)
{
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;
	struct finefs_dentry *direntry;
	unsigned long hash;

	hash = BKDRHash(name, name_len);
	direntry = (struct finefs_dentry *)radix_tree_lookup(&sih->tree, hash);

	return direntry;
}

static int finefs_insert_dir_radix_tree(struct super_block *sb,
	struct finefs_inode_info_header *sih, const char *name,
	int namelen, struct finefs_dentry *direntry)
{
	unsigned long hash;
	int ret;

	hash = BKDRHash(name, namelen);
	rd_info("%s: insert %s hash %lu", __func__, name, hash);

	/* FIXME: hash collision ignored here */
	ret = radix_tree_insert(&sih->tree, hash, direntry);
	if (ret) {
		r_error("%s ERROR %d: %s", __func__, ret, name);
		log_assert(0);
	}

	return ret;
}

// 检查文件名是否匹配
// 返回0表示匹配
static int finefs_check_dentry_match(struct super_block *sb,
	struct finefs_dentry *dentry, const char *name, int namelen)
{
	if (dentry->name_len != namelen)
		return -EINVAL;

	return strncmp(dentry->name, name, namelen);
}

// 将一个dir entry从 dir中删除，并将entry的无效标志位设置为1
static int finefs_remove_dir_radix_tree(struct super_block *sb,
	struct finefs_inode_info_header *sih, const char *name, int namelen,
	int replay)
{
	struct finefs_dentry *entry;
	unsigned long hash;

	hash = BKDRHash(name, namelen);
	entry = (struct finefs_dentry *)radix_tree_delete(&sih->tree, hash);

	if (replay == 0) {  // 不是replay，则必然会替换成功
		if (!entry) {
			r_error("%s ERROR: %s, length %d, hash %lu",
					__func__, name, namelen, hash);
			return -EINVAL;
		}
		rd_info("%s: %s", __func__, entry->name);

		if (entry->ino == 0 ||
		    finefs_check_dentry_match(sb, entry, name, namelen)) {  // entry->invalid
			r_error("%s dentry not match: %s, length %d, "
					"hash %lu", __func__, name,
					namelen, hash);
			r_error("dentry: type %d, inode %lu, name %s, "
					"namelen %u, rec len %u",
					entry->entry_type,
					le64_to_cpu(entry->ino),
					entry->name, entry->name_len,
					le16_to_cpu(entry->de_len));
			return -EINVAL;
		}

		// /* No need to flush */
		// entry->invalid = 1;  // 把旧的entry标记为无效，只是为了方便垃圾回收，不作用与原子性
		// 不flush是因为恢复时可以根据后面的log得知该entry是否有效
		log_entry_set_invalid(entry);
	}

	return 0;
}

// 删除内存radix tree
void finefs_delete_dir_tree(struct super_block *sb,
	struct finefs_inode_info_header *sih)
{
	struct finefs_dentry *direntry;
	unsigned long pos = 0;
	struct finefs_dentry *entries[FREE_BATCH];
	timing_t delete_time;
	int nr_entries;
	int i;
	void *ret;

	FINEFS_START_TIMING(delete_dir_tree_t, delete_time);

	do {
		nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, FREE_BATCH);
		for (i = 0; i < nr_entries; i++) {
			direntry = entries[i];
			BUG_ON(!direntry);
			pos = BKDRHash(direntry->name, direntry->name_len);
			ret = radix_tree_delete(&sih->tree, pos);
			if (!ret || ret != direntry) {
				r_error("dentry: type %d, inode %lu, "
					"name %s, namelen %u, rec len %u",
					direntry->entry_type,
					le64_to_cpu(direntry->ino),
					direntry->name, direntry->name_len,
					le16_to_cpu(direntry->de_len));
				if (!ret)
					rd_info("ret is NULL");
			}
		}
		pos++;
	} while (nr_entries == FREE_BATCH);

	FINEFS_END_TIMING(delete_dir_tree_t, delete_time);
	return;
}

/* ========================= Entry operations ============================= */

/*
 * Append a finefs_dentry to the current finefs_inode_log_page.
 * Note unlike append_file_write_entry(), this method returns the tail pointer
 * after append.
 * 在父目录中append entry log
 * pidir父目录在finefs中的地址
 * dir 父目录的内存inode
 * ino 孩子inode 号
 */
static u64 finefs_append_dir_inode_entry(struct super_block *sb,
	struct finefs_inode *pidir, struct inode *dir,
	u64 ino, struct dentry *dentry, unsigned short de_len, u64 tail,
	int link_change, u64 *curr_tail)
{
	struct finefs_inode_info *si = FINEFS_I(dir);
	struct finefs_inode_info_header *sih = &si->header;
	struct finefs_dentry *entry;
	u64 curr_p;
	size_t size = de_len; // log len, 文件名
	int extended = 0;
	unsigned short links_count;
	timing_t append_time;

	FINEFS_START_TIMING(append_dir_entry_t, append_time);

	// 获取这次写log的位置
	curr_p = finefs_get_append_head(sb, pidir, sih, tail, size, &extended, false);
	if (curr_p == 0)
		BUG();

	entry = (struct finefs_dentry *)finefs_get_block(sb, curr_p);
	entry->entry_type = DIR_LOG;
	entry->ino = cpu_to_le64(ino);
	entry->name_len = dentry->d_name.len;
	// memcpy_to_pmem_nocache(entry->name, dentry->d_name.name,
	// 			dentry->d_name.len);
	memcpy(entry->name, dentry->d_name.name, dentry->d_name.len);
	entry->name[dentry->d_name.len] = '\0';
	entry->file_type = 0;
	// entry->invalid = 0;
	entry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	entry->size = cpu_to_le64(dir->i_size);

	links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	entry->links_count = cpu_to_le16(links_count);

	/* Update actual de_len */
	entry->de_len = cpu_to_le16(de_len);
	rdv_proc("dir entry @ 0x%lx: ino %lu, entry len %u, "
			"name len %u, file type %u",
			curr_p, entry->ino, entry->de_len,
			entry->name_len, entry->file_type);
	entry->entry_version = 0x1234;
	finefs_flush_buffer(entry, de_len, 0);

	dlog_assert(log_entry_is_set_valid(entry));
	*curr_tail = curr_p + de_len;

	dir->i_blocks = pidir->i_blocks;
	FINEFS_END_TIMING(append_dir_entry_t, append_time);
	return curr_p;
}

// 只用与root dir
int finefs_append_root_init_entries(struct super_block *sb,
	struct finefs_inode *pi, u64 self_ino, u64 parent_ino, u64 *log_tail, int cpuid)
{
	int allocated;
	u64 new_block;
	u64 curr_p;
	struct finefs_dentry *de_entry;

	if (!finefs_log_link_is_end(pi->log_head.next_page_)) {
		r_error("%s: log head exists @ 0x%lx!",
				__func__, pi->log_head.next_page_);
		return -EINVAL;
	}

	allocated = finefs_allocate_inode_log_pages(sb, pi, 1, &new_block, cpuid, false);
	if (allocated != 1) {
		r_error("ERROR: no inode log page available");
		return -ENOMEM;
	}
	// pi->log_tail = new_block;
	pi->i_blocks = 1;
	finefs_link_set_next_page(sb, &pi->log_head, new_block, 0);
	// pi->log_head = new_block;
	// finefs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
	dlog_assert(finefs_log_page_tail_remain_init(sb, finefs_log_page_addr(sb, pi->log_head.next_page_)));

	de_entry = (struct finefs_dentry *)finefs_get_block(sb, new_block);
	de_entry->entry_type = DIR_LOG;
	de_entry->name_len = 1;
	// de_entry->invalid = 0;
	de_entry->de_len = cpu_to_le16(FINEFS_DIR_LOG_REC_LEN(1));
	de_entry->links_count = 1;
	de_entry->mtime = GetTsSec();
	de_entry->ino = cpu_to_le64(self_ino);
	de_entry->size = sb->s_blocksize;
	strncpy(de_entry->name, ".\0", 2);
	finefs_flush_buffer(de_entry, FINEFS_DIR_LOG_REC_LEN(1), 0);
	dlog_assert(log_entry_is_set_valid(de_entry));

	curr_p = new_block + FINEFS_DIR_LOG_REC_LEN(1);

	de_entry = (struct finefs_dentry *)((char *)de_entry +
					le16_to_cpu(de_entry->de_len));
	de_entry->entry_type = DIR_LOG;
	de_entry->name_len = 2;
	// de_entry->invalid = 0;
	de_entry->de_len = cpu_to_le16(FINEFS_DIR_LOG_REC_LEN(2));
	de_entry->links_count = 2;
	de_entry->mtime = GetTsSec();
	de_entry->ino = cpu_to_le64(parent_ino);
	de_entry->size = sb->s_blocksize;
	strncpy(de_entry->name, "..\0", 3);
	finefs_flush_buffer(de_entry, FINEFS_DIR_LOG_REC_LEN(2), 0);
	dlog_assert(log_entry_is_set_valid(de_entry));

	curr_p += FINEFS_DIR_LOG_REC_LEN(2);
	// finefs_update_tail(pi, curr_p);
	// finefs_update_volatile_tail(sih, curr_p);
	*log_tail = curr_p;

	return 0;
}

/* Append . and .. entries */
// 为新创建的目录分配1个log page
// 并写入两个log entry（. 和 ..）
// 更新tail 并fence
int finefs_append_dir_init_entries(struct super_block *sb,
	struct finefs_inode *pi, struct inode* inode, u64 parent_ino, int cpuid)
{
	int allocated;
	u64 new_block;
	u64 curr_p;
	struct finefs_dentry *de_entry;
	struct finefs_inode_info_header *sih = &FINEFS_I(inode)->header;
	u64 self_ino = inode->i_ino;

	if (!finefs_log_link_is_end(pi->log_head.next_page_)) {
		r_error("%s: log head exists @ 0x%lx!",
				__func__, pi->log_head.next_page_);
		return -EINVAL;
	}

	allocated = finefs_allocate_inode_log_pages(sb, pi, 1, &new_block, cpuid, false);
	if (allocated != 1) {
		r_error("ERROR: no inode log page available");
		return -ENOMEM;
	}
	// pi->log_tail = new_block;
	pi->i_blocks = 1;
	finefs_link_set_next_page(sb, &pi->log_head, new_block, 0);
	// pi->log_head = new_block;
	// finefs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
	dlog_assert(finefs_log_page_tail_remain_init(sb, finefs_log_page_addr(sb, pi->log_head.next_page_)));

	de_entry = (struct finefs_dentry *)finefs_get_block(sb, new_block);
	de_entry->entry_type = DIR_LOG;
	de_entry->name_len = 1;
	// de_entry->invalid = 0;
	de_entry->de_len = cpu_to_le16(FINEFS_DIR_LOG_REC_LEN(1));
	de_entry->links_count = 1;
	de_entry->mtime = GetTsSec();
	de_entry->ino = cpu_to_le64(self_ino);
	de_entry->size = sb->s_blocksize;
	strncpy(de_entry->name, ".\0", 2);
	finefs_flush_buffer(de_entry, FINEFS_DIR_LOG_REC_LEN(1), 0);
	dlog_assert(log_entry_is_set_valid(de_entry));

	curr_p = new_block + FINEFS_DIR_LOG_REC_LEN(1);

	de_entry = (struct finefs_dentry *)((char *)de_entry +
					le16_to_cpu(de_entry->de_len));
	de_entry->entry_type = DIR_LOG;
	de_entry->name_len = 2;
	// de_entry->invalid = 0;
	de_entry->de_len = cpu_to_le16(FINEFS_DIR_LOG_REC_LEN(2));
	de_entry->links_count = 2;
	de_entry->mtime = GetTsSec();
	de_entry->ino = cpu_to_le64(parent_ino);
	de_entry->size = sb->s_blocksize;
	strncpy(de_entry->name, "..\0", 3);
	finefs_flush_buffer(de_entry, FINEFS_DIR_LOG_REC_LEN(2), 0);
	dlog_assert(log_entry_is_set_valid(de_entry));

	curr_p += FINEFS_DIR_LOG_REC_LEN(2);
	// finefs_update_tail(pi, curr_p);
	finefs_update_volatile_tail(sih, curr_p);

	return 0;
}

/* adds a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
// new_tail 返回修改后的tail
// 父母写log
int finefs_add_dentry(struct dentry *dentry, u64 ino, int inc_link,
	u64 tail, u64 *new_tail)
{
	// 父目录的inode
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct finefs_inode_info *si = FINEFS_I(dir);
	struct finefs_inode_info_header *sih = &si->header;
	struct finefs_inode *pidir;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct finefs_dentry *direntry;
	unsigned short loglen;
	int ret;
	u64 curr_entry, curr_tail;
	timing_t add_dentry_time;

	rdv_proc("%s: dir %lu new inode %lu",
				__func__, dir->i_ino, ino);
	rdv_proc("%s: %s %d", __func__, name, namelen);
	FINEFS_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;

	// 父目录在NVM中的
	pidir = finefs_get_inode(sb, dir);

	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 */
	// dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	dir->i_mtime = dir->i_ctime = get_cur_time_spec();

	loglen = FINEFS_DIR_LOG_REC_LEN(namelen);
	// curr_tail指向下一个entry的起始，
	// 返回值是，当前append log entry的地址
	curr_entry = finefs_append_dir_inode_entry(sb, pidir, dir, ino,
				dentry,	loglen, tail, inc_link,
				&curr_tail);

	direntry = (struct finefs_dentry *)finefs_get_block(sb, curr_entry);
	// 将新的dentry插入到目录的radix-tree索引中
	ret = finefs_insert_dir_radix_tree(sb, sih, name, namelen, direntry);
	*new_tail = curr_tail;
	FINEFS_END_TIMING(add_dentry_t, add_dentry_time);
	return ret;
}

/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 * 返回dentry父母inode的新log tail
 * 并从内存radix tree中删除
 */
int finefs_remove_dentry(struct dentry *dentry, int dec_link, u64 tail,
	u64 *new_tail)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct finefs_inode_info *si = FINEFS_I(dir);
	struct finefs_inode_info_header *sih = &si->header;
	struct finefs_inode *pidir;
	struct qstr *entry = &dentry->d_name;
	unsigned short loglen;
	u64 curr_tail, curr_entry;
	timing_t remove_dentry_time;

	FINEFS_START_TIMING(remove_dentry_t, remove_dentry_time);

	if (!dentry->d_name.len)
		return -EINVAL;

	pidir = finefs_get_inode(sb, dir);

	dir->i_mtime = dir->i_ctime = get_cur_time_spec();

	loglen = FINEFS_DIR_LOG_REC_LEN(entry->len);
	// 在父母inode中写删除entry的log
	// ino为0，表示删除
	curr_entry = finefs_append_dir_inode_entry(sb, pidir, dir, 0,
				dentry, loglen, tail, dec_link, &curr_tail);
	*new_tail = curr_tail;

	finefs_remove_dir_radix_tree(sb, sih, entry->name, entry->len, 0);
	FINEFS_END_TIMING(remove_dentry_t, remove_dentry_time);
	return 0;
}

// 向radix-tree添加新目录项
inline int finefs_replay_add_dentry(struct super_block *sb,
	struct finefs_inode_info_header *sih, struct finefs_dentry *entry)
{
	if (!entry->name_len)
		return -EINVAL;

	rdv_proc("%s: add %s", __func__, entry->name);
	return finefs_insert_dir_radix_tree(sb, sih,
			entry->name, entry->name_len, entry);
}

inline int finefs_replay_remove_dentry(struct super_block *sb,
	struct finefs_inode_info_header *sih,
	struct finefs_dentry *entry)
{
	rdv_proc("%s: remove %s", __func__, entry->name);
	finefs_remove_dir_radix_tree(sb, sih, entry->name,
					entry->name_len, 1);
	return 0;
}

static inline void finefs_rebuild_dir_time_and_size(struct super_block *sb,
	struct finefs_inode *pi, struct finefs_dentry *entry)
{
	if (!entry || !pi)
		return;

	pi->i_ctime = entry->mtime;
	pi->i_mtime = entry->mtime;
	pi->i_size = entry->size;
	pi->i_links_count = entry->links_count;
}

int finefs_rebuild_dir_inode_tree(struct super_block *sb,
	struct finefs_inode *pi, u64 pi_addr,
	struct finefs_inode_info_header *sih)
{
	struct finefs_dentry *entry = NULL;
	struct finefs_setattr_logentry *attr_entry = NULL;
	struct finefs_link_change_entry *link_change_entry = NULL;
	struct finefs_inode_log_page *curr_page;
	u64 ino = pi->finefs_ino;
	unsigned short de_len;
	timing_t rebuild_time;
	void *addr;
	u64 curr_p;
	u64 next;
	u8 type;
	int ret;

	FINEFS_START_TIMING(rebuild_dir_t, rebuild_time);
	rdv_proc("Rebuild dir %lu tree", ino);

	sih->pi_addr = pi_addr;

	curr_p = pi->log_head.next_page_;
	if (curr_p == 0) {
		r_error("Dir %lu log is NULL!", ino);
		BUG();
	}

	rdv_proc("Log head 0x%lx, tail 0x%lx",
				curr_p, pi->log_tail);

	sih->log_pages = 1;
	// TODO: log_tail
	// 临时解决方法，未考虑恢复
	int times = 0;
	while (curr_p != pi->log_tail) {
		++times;
		if(times == 3) break;
		if (goto_next_page(sb, curr_p)) {
			sih->log_pages++;
			curr_p = finefs_log_next_page(sb, curr_p);
		}

		if (curr_p == 0) {
			r_error("Dir %lu log is NULL!", ino);
			BUG();
		}

		addr = (void *)finefs_get_block(sb, curr_p);
		type = finefs_get_entry_type(addr);
		switch (type) {
			case SET_ATTR:
				log_assert(0);
				attr_entry =
					(struct finefs_setattr_logentry *)addr;
				finefs_apply_setattr_entry(sb, pi, sih,
								attr_entry);
				sih->last_setattr = curr_p;
				curr_p += sizeof(struct finefs_setattr_logentry);
				continue;
			case LINK_CHANGE:
				link_change_entry =
					(struct finefs_link_change_entry *)addr;
				finefs_apply_link_change_entry(pi,
							link_change_entry);
				sih->last_link_change = curr_p;
				curr_p += sizeof(struct finefs_link_change_entry);
				continue;
			case DIR_LOG:
				break;
			default:
				rd_error("%s: unknown type %d, 0x%lx",
							__func__, type, curr_p);
				log_assert(0);
		}

		entry = (struct finefs_dentry *)finefs_get_block(sb, curr_p);
		rdv_proc("curr_p: 0x%lx, type %d, ino %lu, "
			"name %s, namelen %u, rec len %u", curr_p,
			entry->entry_type, le64_to_cpu(entry->ino),
			entry->name, entry->name_len,
			le16_to_cpu(entry->de_len));

		if (entry->ino > 0) {
			if (log_entry_is_set_valid(entry)) {
				/* A valid entry to add */
				ret = finefs_replay_add_dentry(sb, sih, entry);
			}
		} else {
			/* Delete the entry */
			ret = finefs_replay_remove_dentry(sb, sih, entry);
		}

		if (ret) {
			r_error("%s ERROR %d", __func__, ret);
			break;
		}

		finefs_rebuild_dir_time_and_size(sb, pi, entry);

		de_len = le16_to_cpu(entry->de_len);
		curr_p += de_len;
	}

	sih->i_size = le64_to_cpu(pi->i_size);
	sih->i_mode = le64_to_cpu(pi->i_mode);
	finefs_flush_buffer(pi, sizeof(struct finefs_inode), 0);

	/* Keep traversing until log ends */
	curr_p &= FINEFS_LOG_MASK;
	curr_page = (struct finefs_inode_log_page *)finefs_get_block(sb, curr_p);
	while ((next = FINEFS_LOG_NEXT_PAGE(curr_page)) != 0) {
		sih->log_pages++;
		curr_p = next;
		curr_page = (struct finefs_inode_log_page *)
			finefs_get_block(sb, curr_p);
	}

	pi->i_blocks = sih->log_pages;

//	finefs_print_dir_tree(sb, sih, ino);
	FINEFS_END_TIMING(rebuild_dir_t, rebuild_time);
	return 0;
}

#if 0
static int finefs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct finefs_inode *pidir;
	struct finefs_inode_info *si = FINEFS_I(inode);
	struct finefs_inode_info_header *sih = &si->header;
	struct finefs_inode *child_pi;
	struct finefs_dentry *entry;
	struct finefs_dentry *entries[FREE_BATCH];
	int nr_entries;
	u64 pi_addr;
	unsigned long pos = 0;
	ino_t ino;
	int i;
	int ret;
	timing_t readdir_time;

	FINEFS_START_TIMING(readdir_t, readdir_time);
	pidir = finefs_get_inode(sb, inode);
	finefs_dbgv("%s: ino %lu, size %lu, pos %lu",
			__func__, (u64)inode->i_ino,
			pidir->i_size, ctx->pos);

	if (!sih) {
		finefs_dbg("%s: inode %lu sih does not exist!",
				__func__, inode->i_ino);
		ctx->pos = READDIR_END;
		return 0;
	}

	pos = ctx->pos;
	if (pos == READDIR_END)
		goto out;

	do {
		nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, FREE_BATCH);
		for (i = 0; i < nr_entries; i++) {
			entry = entries[i];
			pos = BKDRHash(entry->name, entry->name_len);
			ino = __le64_to_cpu(entry->ino);
			if (ino == 0)
				continue;

			ret = finefs_get_inode_address(sb, ino, &pi_addr, 0);
			if (ret) {
				finefs_dbg("%s: get child inode %lu address "
					"failed %d", __func__, ino, ret);
				ctx->pos = READDIR_END;
				return ret;
			}

			child_pi = finefs_get_block(sb, pi_addr);
			finefs_dbgv("ctx: ino %lu, name %s, "
				"name_len %u, de_len %u",
				(u64)ino, entry->name, entry->name_len,
				entry->de_len);
			if (!dir_emit(ctx, entry->name, entry->name_len,
				ino, IF2DT(le16_to_cpu(child_pi->i_mode)))) {
				finefs_dbgv("Here: pos %lu", ctx->pos);
				return 0;
			}
			ctx->pos = pos + 1;
		}
		pos++;
	} while (nr_entries == FREE_BATCH);

out:
	FINEFS_END_TIMING(readdir_t, readdir_time);
	return 0;
}
#endif

static u64 finefs_find_next_dentry_addr(struct super_block *sb,
	struct finefs_inode_info_header *sih, u64 pos)
{
	struct finefs_sb_info *sbi = FINEFS_SB(sb);
	struct finefs_file_write_entry *entry = NULL;
	struct finefs_file_write_entry *entries[1];
	int nr_entries;
	u64 addr = 0;

	nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, 1);
	if (nr_entries == 1) {
		entry = entries[0];
		addr = finefs_get_addr_off(sbi, entry);
	}

	return addr;
}

// static int finefs_readdir(struct file *file, struct dir_context *ctx)
// {
// 	struct inode *inode = file_inode(file);
// 	struct super_block *sb = inode->i_sb;
// 	struct finefs_inode *pidir;
// 	struct finefs_inode_info *si = FINEFS_I(inode);
// 	struct finefs_inode_info_header *sih = &si->header;
// 	struct finefs_inode *child_pi;
// 	struct finefs_inode *prev_child_pi = NULL;
// 	struct finefs_dentry *entry = NULL;
// 	struct finefs_dentry *prev_entry = NULL;
// 	unsigned short de_len;
// 	u64 pi_addr;
// 	unsigned long pos = 0;
// 	ino_t ino;
// 	void *addr;
// 	u64 curr_p;
// 	u8 type;
// 	int ret;
// 	timing_t readdir_time;

// 	FINEFS_START_TIMING(readdir_t, readdir_time);
// 	pidir = finefs_get_inode(sb, inode);
// 	finefs_dbgv("%s: ino %lu, size %lu, pos 0x%lx",
// 			__func__, (u64)inode->i_ino,
// 			pidir->i_size, ctx->pos);

// 	if (pidir->log_head == 0) {
// 		finefs_err(sb, "Dir %lu log is NULL!", inode->i_ino);
// 		BUG();
// 		return -EINVAL;
// 	}

// 	pos = ctx->pos;

// 	if (pos == 0) {
// 		curr_p = pidir->log_head;
// 	} else if (pos == READDIR_END) {
// 		goto out;
// 	} else {
// 		curr_p = finefs_find_next_dentry_addr(sb, sih, pos);
// 		if (curr_p == 0)
// 			goto out;
// 	}

// 	while (curr_p != pidir->log_tail) {
// 		if (goto_next_page(sb, curr_p)) {
// 			curr_p = finefs_log_next_page(sb, curr_p);
// 		}

// 		if (curr_p == 0) {
// 			finefs_err(sb, "Dir %lu log is NULL!", inode->i_ino);
// 			BUG();
// 			return -EINVAL;
// 		}

// 		addr = (void *)finefs_get_block(sb, curr_p);
// 		type = finefs_get_entry_type(addr);
// 		switch (type) {
// 			case SET_ATTR:
// 				curr_p += sizeof(struct finefs_setattr_logentry);
// 				continue;
// 			case LINK_CHANGE:
// 				curr_p += sizeof(struct finefs_link_change_entry);
// 				continue;
// 			case DIR_LOG:
// 				break;
// 			default:
// 				finefs_dbg("%s: unknown type %d, 0x%lx",
// 							__func__, type, curr_p);
// 			BUG();
// 			return -EINVAL;
// 		}

// 		entry = (struct finefs_dentry *)finefs_get_block(sb, curr_p);
// 		finefs_dbgv("curr_p: 0x%lx, type %d, ino %lu, "
// 			"name %s, namelen %u, rec len %u", curr_p,
// 			entry->entry_type, le64_to_cpu(entry->ino),
// 			entry->name, entry->name_len,
// 			le16_to_cpu(entry->de_len));

// 		de_len = le16_to_cpu(entry->de_len);
// 		if (entry->ino > 0 && entry->invalid == 0) {
// 			ino = __le64_to_cpu(entry->ino);
// 			pos = BKDRHash(entry->name, entry->name_len);

// 			ret = finefs_get_inode_address(sb, ino, &pi_addr, 0);
// 			if (ret) {
// 				finefs_dbg("%s: get child inode %lu address "
// 					"failed %d", __func__, ino, ret);
// 				ctx->pos = READDIR_END;
// 				return ret;
// 			}

// 			child_pi = finefs_get_block(sb, pi_addr);
// 			finefs_dbgv("ctx: ino %lu, name %s, "
// 				"name_len %u, de_len %u",
// 				(u64)ino, entry->name, entry->name_len,
// 				entry->de_len);
// 			if (prev_entry && !dir_emit(ctx, prev_entry->name,
// 				prev_entry->name_len, ino,
// 				IF2DT(le16_to_cpu(prev_child_pi->i_mode)))) {
// 				finefs_dbgv("Here: pos %lu", ctx->pos);
// 				return 0;
// 			}
// 			prev_entry = entry;
// 			prev_child_pi = child_pi;
// 		}
// 		ctx->pos = pos;
// 		curr_p += de_len;
// 	}

// 	if (prev_entry && !dir_emit(ctx, prev_entry->name,
// 			prev_entry->name_len, ino,
// 			IF2DT(le16_to_cpu(prev_child_pi->i_mode))))
// 		return 0;

// 	ctx->pos = READDIR_END;
// out:
// 	FINEFS_END_TIMING(readdir_t, readdir_time);
// 	finefs_dbgv("%s return", __func__);
// 	return 0;
// }

int finefs_noop_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int ret = 0;
	FINEFS_START_TIMING(fsync_t, fsync_time);
	PERSISTENT_BARRIER();
	FINEFS_END_TIMING(fsync_t, fsync_time);
	return ret;
}

const struct file_operations finefs_dir_operations = {
// 	.llseek		= generic_file_llseek,
// 	.read		= generic_read_dir,
// 	.iterate	= finefs_readdir,
	.fsync		= finefs_noop_fsync,
// 	.unlocked_ioctl = finefs_ioctl,
// #ifdef CONFIG_COMPAT
// 	.compat_ioctl	= finefs_compat_ioctl,
// #endif
};
