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

#include "nova/nova.h"
#include "util/log.h"
#include "util/cpu.h"
#include "util/util.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

// 在目录的radix中查找对应的孩子
struct nova_dentry *nova_find_dentry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_dentry *direntry;
	unsigned long hash;

	hash = BKDRHash(name, name_len);
	direntry = (struct nova_dentry *)radix_tree_lookup(&sih->tree, hash);

	return direntry;
}

static int nova_insert_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name,
	int namelen, struct nova_dentry *direntry)
{
	unsigned long hash;
	int ret;

	hash = BKDRHash(name, namelen);
	rd_info("%s: insert %s hash %lu", __func__, name, hash);

	/* FIXME: hash collision ignored here */
	ret = radix_tree_insert(&sih->tree, hash, direntry);
	if (ret)
		r_error("%s ERROR %d: %s", __func__, ret, name);

	return ret;
}

// 检查文件名是否匹配
// 返回0表示匹配
static int nova_check_dentry_match(struct super_block *sb,
	struct nova_dentry *dentry, const char *name, int namelen)
{
	if (dentry->name_len != namelen)
		return -EINVAL;

	return strncmp(dentry->name, name, namelen);
}

// 将一个dir entry从 dir中删除，并将entry的无效标志位设置为1
static int nova_remove_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name, int namelen,
	int replay)
{
	struct nova_dentry *entry;
	unsigned long hash;

	hash = BKDRHash(name, namelen);
	entry = (struct nova_dentry *)radix_tree_delete(&sih->tree, hash);

	if (replay == 0) {  // 不是replay，则必然会替换成功
		if (!entry) {
			rd_error("%s ERROR: %s, length %d, hash %lu",
					__func__, name, namelen, hash);
			return -EINVAL;
		}

		if (entry->ino == 0 || entry->invalid ||
		    nova_check_dentry_match(sb, entry, name, namelen)) {
			rd_info("%s dentry not match: %s, length %d, "
					"hash %lu", __func__, name,
					namelen, hash);
			rd_info("dentry: type %d, inode %lu, name %s, "
					"namelen %u, rec len %u",
					entry->entry_type,
					le64_to_cpu(entry->ino),
					entry->name, entry->name_len,
					le16_to_cpu(entry->de_len));
			return -EINVAL;
		}

		/* No need to flush */
		entry->invalid = 1;  // TODO: 为啥呢
	}

	return 0;
}

void nova_delete_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	struct nova_dentry *direntry;
	unsigned long pos = 0;
	struct nova_dentry *entries[FREE_BATCH];
	timing_t delete_time;
	int nr_entries;
	int i;
	void *ret;

	NOVA_START_TIMING(delete_dir_tree_t, delete_time);

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

	NOVA_END_TIMING(delete_dir_tree_t, delete_time);
	return;
}

/* ========================= Entry operations ============================= */

/*
 * Append a nova_dentry to the current nova_inode_log_page.
 * Note unlike append_file_write_entry(), this method returns the tail pointer
 * after append.
 * 在父目录中append entry log
 * pidir父目录在nova中的地址
 * dir 父目录的内存inode
 * ino 孩子inode 号
 */
static u64 nova_append_dir_inode_entry(struct super_block *sb,
	struct nova_inode *pidir, struct inode *dir,
	u64 ino, struct dentry *dentry, unsigned short de_len, u64 tail,
	int link_change, u64 *curr_tail)
{
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_dentry *entry;
	u64 curr_p;
	size_t size = de_len; // log len, 文件名
	int extended = 0;
	unsigned short links_count;
	timing_t append_time;

	NOVA_START_TIMING(append_dir_entry_t, append_time);

	// 获取这次写log的位置
	curr_p = nova_get_append_head(sb, pidir, sih, tail, size, &extended);
	if (curr_p == 0)
		BUG();

	entry = (struct nova_dentry *)nova_get_block(sb, curr_p);
	entry->entry_type = DIR_LOG;
	entry->ino = cpu_to_le64(ino);
	entry->name_len = dentry->d_name.len;
	memcpy_to_pmem_nocache(entry->name, dentry->d_name.name,
				dentry->d_name.len);
	entry->name[dentry->d_name.len] = '\0';
	entry->file_type = 0;
	entry->invalid = 0;
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

	nova_flush_buffer(entry, de_len, 0);

	*curr_tail = curr_p + de_len;

	dir->i_blocks = pidir->i_blocks;
	NOVA_END_TIMING(append_dir_entry_t, append_time);
	return curr_p;
}

/* Append . and .. entries */
// 为新创建的目录分配1个log page
// 并写入两个log entry（. 和 ..）
// 更新tail 并fence
int nova_append_dir_init_entries(struct super_block *sb,
	struct nova_inode *pi, u64 self_ino, u64 parent_ino, int cpuid)
{
	int allocated;
	u64 new_block;
	u64 curr_p;
	struct nova_dentry *de_entry;

	if (pi->log_head) {
		r_error("%s: log head exists @ 0x%lx!",
				__func__, pi->log_head);
		return -EINVAL;
	}

	allocated = nova_allocate_inode_log_pages(sb, pi, 1, &new_block, cpuid);
	if (allocated != 1) {
		r_error("ERROR: no inode log page available");
		return -ENOMEM;
	}
	pi->log_tail = pi->log_head = new_block;
	pi->i_blocks = 1;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	de_entry = (struct nova_dentry *)nova_get_block(sb, new_block);
	de_entry->entry_type = DIR_LOG;
	de_entry->name_len = 1;
	de_entry->invalid = 0;
	de_entry->de_len = cpu_to_le16(NOVA_DIR_LOG_REC_LEN(1));
	de_entry->links_count = 1;
	de_entry->mtime = GetTsSec();
	de_entry->ino = cpu_to_le64(self_ino);
	de_entry->size = sb->s_blocksize;
	strncpy(de_entry->name, ".\0", 2);
	nova_flush_buffer(de_entry, NOVA_DIR_LOG_REC_LEN(1), 0);

	curr_p = new_block + NOVA_DIR_LOG_REC_LEN(1);

	de_entry = (struct nova_dentry *)((char *)de_entry +
					le16_to_cpu(de_entry->de_len));
	de_entry->entry_type = DIR_LOG;
	de_entry->name_len = 2;
	de_entry->invalid = 0;
	de_entry->de_len = cpu_to_le16(NOVA_DIR_LOG_REC_LEN(2));
	de_entry->links_count = 2;
	de_entry->mtime = GetTsSec();
	de_entry->ino = cpu_to_le64(parent_ino);
	de_entry->size = sb->s_blocksize;
	strncpy(de_entry->name, "..\0", 3);
	nova_flush_buffer(de_entry, NOVA_DIR_LOG_REC_LEN(2), 0);

	curr_p += NOVA_DIR_LOG_REC_LEN(2);
	nova_update_tail(pi, curr_p);

	return 0;
}

/* adds a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
// new_tail 返回修改后的tail
int nova_add_dentry(struct dentry *dentry, u64 ino, int inc_link,
	u64 tail, u64 *new_tail)
{
	// 父目录的inode
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pidir;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct nova_dentry *direntry;
	unsigned short loglen;
	int ret;
	u64 curr_entry, curr_tail;
	timing_t add_dentry_time;

	rdv_proc("%s: dir %lu new inode %lu",
				__func__, dir->i_ino, ino);
	rdv_proc("%s: %s %d", __func__, name, namelen);
	NOVA_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;

	// 父目录在NVM中的
	pidir = nova_get_inode(sb, dir);

	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 */
	// dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	dir->i_mtime = dir->i_ctime = get_cur_time_spec();

	loglen = NOVA_DIR_LOG_REC_LEN(namelen);
	// curr_tail指向下一个entry的起始，
	// 返回值是，当前append log entry的地址
	curr_entry = nova_append_dir_inode_entry(sb, pidir, dir, ino,
				dentry,	loglen, tail, inc_link,
				&curr_tail);

	direntry = (struct nova_dentry *)nova_get_block(sb, curr_entry);
	// 将新的dentry插入到目录的radix-tree索引中
	ret = nova_insert_dir_radix_tree(sb, sih, name, namelen, direntry);
	*new_tail = curr_tail;
	NOVA_END_TIMING(add_dentry_t, add_dentry_time);
	return ret;
}

/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 * 返回dentry父母inode的新log tail
 * 并从内存radix tree中删除
 */
int nova_remove_dentry(struct dentry *dentry, int dec_link, u64 tail,
	u64 *new_tail)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pidir;
	struct qstr *entry = &dentry->d_name;
	unsigned short loglen;
	u64 curr_tail, curr_entry;
	timing_t remove_dentry_time;

	NOVA_START_TIMING(remove_dentry_t, remove_dentry_time);

	if (!dentry->d_name.len)
		return -EINVAL;

	pidir = nova_get_inode(sb, dir);

	dir->i_mtime = dir->i_ctime = get_cur_time_spec();

	loglen = NOVA_DIR_LOG_REC_LEN(entry->len);
	// 在父母inode中写删除entry的log
	curr_entry = nova_append_dir_inode_entry(sb, pidir, dir, 0,
				dentry, loglen, tail, dec_link, &curr_tail);
	*new_tail = curr_tail;

	nova_remove_dir_radix_tree(sb, sih, entry->name, entry->len, 0);
	NOVA_END_TIMING(remove_dentry_t, remove_dentry_time);
	return 0;
}

// 向radix-tree添加新目录项
inline int nova_replay_add_dentry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_dentry *entry)
{
	if (!entry->name_len)
		return -EINVAL;

	rdv_proc("%s: add %s", __func__, entry->name);
	return nova_insert_dir_radix_tree(sb, sih,
			entry->name, entry->name_len, entry);
}

inline int nova_replay_remove_dentry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_dentry *entry)
{
	rdv_proc("%s: remove %s", __func__, entry->name);
	nova_remove_dir_radix_tree(sb, sih, entry->name,
					entry->name_len, 1);
	return 0;
}

static inline void nova_rebuild_dir_time_and_size(struct super_block *sb,
	struct nova_inode *pi, struct nova_dentry *entry)
{
	if (!entry || !pi)
		return;

	pi->i_ctime = entry->mtime;
	pi->i_mtime = entry->mtime;
	pi->i_size = entry->size;
	pi->i_links_count = entry->links_count;
}

int nova_rebuild_dir_inode_tree(struct super_block *sb,
	struct nova_inode *pi, u64 pi_addr,
	struct nova_inode_info_header *sih)
{
	struct nova_dentry *entry = NULL;
	struct nova_setattr_logentry *attr_entry = NULL;
	struct nova_link_change_entry *link_change_entry = NULL;
	struct nova_inode_log_page *curr_page;
	u64 ino = pi->nova_ino;
	unsigned short de_len;
	timing_t rebuild_time;
	void *addr;
	u64 curr_p;
	u64 next;
	u8 type;
	int ret;

	NOVA_START_TIMING(rebuild_dir_t, rebuild_time);
	rdv_proc("Rebuild dir %lu tree", ino);

	sih->pi_addr = pi_addr;

	curr_p = pi->log_head;
	if (curr_p == 0) {
		r_error("Dir %lu log is NULL!", ino);
		BUG();
	}

	rdv_proc("Log head 0x%lx, tail 0x%lx",
				curr_p, pi->log_tail);

	sih->log_pages = 1;
	while (curr_p != pi->log_tail) {
		if (goto_next_page(sb, curr_p)) {
			sih->log_pages++;
			curr_p = finefs_log_next_page(sb, curr_p);
		}

		if (curr_p == 0) {
			r_error("Dir %lu log is NULL!", ino);
			BUG();
		}

		addr = (void *)nova_get_block(sb, curr_p);
		type = nova_get_entry_type(addr);
		switch (type) {
			case SET_ATTR:
				attr_entry =
					(struct nova_setattr_logentry *)addr;
				nova_apply_setattr_entry(sb, pi, sih,
								attr_entry);
				sih->last_setattr = curr_p;
				curr_p += sizeof(struct nova_setattr_logentry);
				continue;
			case LINK_CHANGE:
				link_change_entry =
					(struct nova_link_change_entry *)addr;
				nova_apply_link_change_entry(pi,
							link_change_entry);
				sih->last_link_change = curr_p;
				curr_p += sizeof(struct nova_link_change_entry);
				continue;
			case DIR_LOG:
				break;
			default:
				rd_error("%s: unknown type %d, 0x%lx",
							__func__, type, curr_p);
				log_assert(0);
		}

		entry = (struct nova_dentry *)nova_get_block(sb, curr_p);
		rdv_proc("curr_p: 0x%lx, type %d, ino %lu, "
			"name %s, namelen %u, rec len %u", curr_p,
			entry->entry_type, le64_to_cpu(entry->ino),
			entry->name, entry->name_len,
			le16_to_cpu(entry->de_len));

		if (entry->ino > 0) {
			if (entry->invalid == 0) {
				/* A valid entry to add */
				ret = nova_replay_add_dentry(sb, sih, entry);
			}
		} else {
			/* Delete the entry */
			ret = nova_replay_remove_dentry(sb, sih, entry);
		}

		if (ret) {
			r_error("%s ERROR %d", __func__, ret);
			break;
		}

		nova_rebuild_dir_time_and_size(sb, pi, entry);

		de_len = le16_to_cpu(entry->de_len);
		curr_p += de_len;
	}

	sih->i_size = le64_to_cpu(pi->i_size);
	sih->i_mode = le64_to_cpu(pi->i_mode);
	nova_flush_buffer(pi, sizeof(struct nova_inode), 0);

	/* Keep traversing until log ends */
	curr_p &= PAGE_MASK;
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr_p);
	while ((next = curr_page->page_tail.next_page) != 0) {
		sih->log_pages++;
		curr_p = next;
		curr_page = (struct nova_inode_log_page *)
			nova_get_block(sb, curr_p);
	}

	pi->i_blocks = sih->log_pages;

//	nova_print_dir_tree(sb, sih, ino);
	NOVA_END_TIMING(rebuild_dir_t, rebuild_time);
	return 0;
}

#if 0
static int nova_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pidir;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *child_pi;
	struct nova_dentry *entry;
	struct nova_dentry *entries[FREE_BATCH];
	int nr_entries;
	u64 pi_addr;
	unsigned long pos = 0;
	ino_t ino;
	int i;
	int ret;
	timing_t readdir_time;

	NOVA_START_TIMING(readdir_t, readdir_time);
	pidir = nova_get_inode(sb, inode);
	nova_dbgv("%s: ino %lu, size %lu, pos %lu",
			__func__, (u64)inode->i_ino,
			pidir->i_size, ctx->pos);

	if (!sih) {
		nova_dbg("%s: inode %lu sih does not exist!",
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

			ret = nova_get_inode_address(sb, ino, &pi_addr, 0);
			if (ret) {
				nova_dbg("%s: get child inode %lu address "
					"failed %d", __func__, ino, ret);
				ctx->pos = READDIR_END;
				return ret;
			}

			child_pi = nova_get_block(sb, pi_addr);
			nova_dbgv("ctx: ino %lu, name %s, "
				"name_len %u, de_len %u",
				(u64)ino, entry->name, entry->name_len,
				entry->de_len);
			if (!dir_emit(ctx, entry->name, entry->name_len,
				ino, IF2DT(le16_to_cpu(child_pi->i_mode)))) {
				nova_dbgv("Here: pos %lu", ctx->pos);
				return 0;
			}
			ctx->pos = pos + 1;
		}
		pos++;
	} while (nr_entries == FREE_BATCH);

out:
	NOVA_END_TIMING(readdir_t, readdir_time);
	return 0;
}
#endif

static u64 nova_find_next_dentry_addr(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 pos)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_file_write_entry *entry = NULL;
	struct nova_file_write_entry *entries[1];
	int nr_entries;
	u64 addr = 0;

	nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, 1);
	if (nr_entries == 1) {
		entry = entries[0];
		addr = nova_get_addr_off(sbi, entry);
	}

	return addr;
}

// static int nova_readdir(struct file *file, struct dir_context *ctx)
// {
// 	struct inode *inode = file_inode(file);
// 	struct super_block *sb = inode->i_sb;
// 	struct nova_inode *pidir;
// 	struct nova_inode_info *si = NOVA_I(inode);
// 	struct nova_inode_info_header *sih = &si->header;
// 	struct nova_inode *child_pi;
// 	struct nova_inode *prev_child_pi = NULL;
// 	struct nova_dentry *entry = NULL;
// 	struct nova_dentry *prev_entry = NULL;
// 	unsigned short de_len;
// 	u64 pi_addr;
// 	unsigned long pos = 0;
// 	ino_t ino;
// 	void *addr;
// 	u64 curr_p;
// 	u8 type;
// 	int ret;
// 	timing_t readdir_time;

// 	NOVA_START_TIMING(readdir_t, readdir_time);
// 	pidir = nova_get_inode(sb, inode);
// 	nova_dbgv("%s: ino %lu, size %lu, pos 0x%lx",
// 			__func__, (u64)inode->i_ino,
// 			pidir->i_size, ctx->pos);

// 	if (pidir->log_head == 0) {
// 		nova_err(sb, "Dir %lu log is NULL!", inode->i_ino);
// 		BUG();
// 		return -EINVAL;
// 	}

// 	pos = ctx->pos;

// 	if (pos == 0) {
// 		curr_p = pidir->log_head;
// 	} else if (pos == READDIR_END) {
// 		goto out;
// 	} else {
// 		curr_p = nova_find_next_dentry_addr(sb, sih, pos);
// 		if (curr_p == 0)
// 			goto out;
// 	}

// 	while (curr_p != pidir->log_tail) {
// 		if (goto_next_page(sb, curr_p)) {
// 			curr_p = finefs_log_next_page(sb, curr_p);
// 		}

// 		if (curr_p == 0) {
// 			nova_err(sb, "Dir %lu log is NULL!", inode->i_ino);
// 			BUG();
// 			return -EINVAL;
// 		}

// 		addr = (void *)nova_get_block(sb, curr_p);
// 		type = nova_get_entry_type(addr);
// 		switch (type) {
// 			case SET_ATTR:
// 				curr_p += sizeof(struct nova_setattr_logentry);
// 				continue;
// 			case LINK_CHANGE:
// 				curr_p += sizeof(struct nova_link_change_entry);
// 				continue;
// 			case DIR_LOG:
// 				break;
// 			default:
// 				nova_dbg("%s: unknown type %d, 0x%lx",
// 							__func__, type, curr_p);
// 			BUG();
// 			return -EINVAL;
// 		}

// 		entry = (struct nova_dentry *)nova_get_block(sb, curr_p);
// 		nova_dbgv("curr_p: 0x%lx, type %d, ino %lu, "
// 			"name %s, namelen %u, rec len %u", curr_p,
// 			entry->entry_type, le64_to_cpu(entry->ino),
// 			entry->name, entry->name_len,
// 			le16_to_cpu(entry->de_len));

// 		de_len = le16_to_cpu(entry->de_len);
// 		if (entry->ino > 0 && entry->invalid == 0) {
// 			ino = __le64_to_cpu(entry->ino);
// 			pos = BKDRHash(entry->name, entry->name_len);

// 			ret = nova_get_inode_address(sb, ino, &pi_addr, 0);
// 			if (ret) {
// 				nova_dbg("%s: get child inode %lu address "
// 					"failed %d", __func__, ino, ret);
// 				ctx->pos = READDIR_END;
// 				return ret;
// 			}

// 			child_pi = nova_get_block(sb, pi_addr);
// 			nova_dbgv("ctx: ino %lu, name %s, "
// 				"name_len %u, de_len %u",
// 				(u64)ino, entry->name, entry->name_len,
// 				entry->de_len);
// 			if (prev_entry && !dir_emit(ctx, prev_entry->name,
// 				prev_entry->name_len, ino,
// 				IF2DT(le16_to_cpu(prev_child_pi->i_mode)))) {
// 				nova_dbgv("Here: pos %lu", ctx->pos);
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
// 	NOVA_END_TIMING(readdir_t, readdir_time);
// 	nova_dbgv("%s return", __func__);
// 	return 0;
// }

int noop_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int ret = 0;
	NOVA_START_TIMING(fsync_t, fsync_time);
	PERSISTENT_BARRIER();
	NOVA_END_TIMING(fsync_t, fsync_time);
	return ret;
}

const struct file_operations nova_dir_operations = {
// 	.llseek		= generic_file_llseek,
// 	.read		= generic_read_dir,
// 	.iterate	= nova_readdir,
	.fsync		= noop_fsync,
// 	.unlocked_ioctl = nova_ioctl,
// #ifdef CONFIG_COMPAT
// 	.compat_ioctl	= nova_compat_ioctl,
// #endif
};
