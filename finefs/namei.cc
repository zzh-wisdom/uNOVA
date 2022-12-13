/*
 * BRIEF DESCRIPTION
 *
 * Inode operations for directories.
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
#include "util/cpu.h"

// 返回inode
static ino_t finefs_inode_by_name(struct inode *dir, struct qstr *entry,
                                  struct finefs_dentry **res_entry) {
    struct super_block *sb = dir->i_sb;
    struct finefs_dentry *direntry;

    direntry = finefs_find_dentry(sb, NULL, dir, entry->name, entry->len);
    if (direntry == NULL) return 0;

    *res_entry = direntry;
    return direntry->ino;
}

// dentry 是新分配的dentry
static struct dentry *finefs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags) {
    struct inode *inode = NULL;
    struct finefs_dentry *de;
    ino_t ino;
    timing_t lookup_time;

    FINEFS_START_TIMING(lookup_t, lookup_time);
    if (dentry->d_name.len > FINEFS_NAME_LEN) {
        rd_error("%s: namelen %u exceeds limit", __func__, dentry->d_name.len);
        return nullptr;
    }

    rdv_proc("%s: %s", __func__, dentry->d_name.name);
    ino = finefs_inode_by_name(dir, &dentry->d_name, &de);
    rdv_proc("%s: ino %lu", __func__, ino);
    if (ino) {
        log_assert(0);
        // 从NVM重建该inode
        inode = finefs_iget(dir->i_sb, ino);
        DLOG_ASSERT(inode);
        // if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM)
        // 		|| inode == ERR_PTR(-EACCES)) {
        // 	finefs_err(dir->i_sb,
        // 		  "%s: get inode failed: %lu",
        // 		  __func__, (unsigned long)ino);
        // 	return ERR_PTR(-EIO);
        // }
        inode_unref(inode);
    }
    FINEFS_END_TIMING(lookup_t, lookup_time);
    return d_splice_alias(inode, dentry);
}

// 完成一个创建事务
// pidir是父母inode
// pidir_tail是pidir的新tail
// 同时记录父母的tail和新inode的valid标记位
static void finefs_lite_transaction_for_new_inode(struct super_block *sb, struct finefs_inode *pi,
                                                  struct finefs_inode *pidir, u64 pidir_tail) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct finefs_lite_journal_entry entry;
    int cpu;
    u64 journal_tail;
    timing_t trans_time;

    FINEFS_START_TIMING(create_trans_t, trans_time);

    /* Commit a lite transaction */
    memset(&entry, 0, sizeof(struct finefs_lite_journal_entry));
    entry.addrs[0] = (u64)finefs_get_addr_off(sbi, &pidir->log_tail);
    entry.addrs[0] |= (u64)8 << 56;
    entry.values[0] = pidir->log_tail;

    entry.addrs[1] = (u64)finefs_get_addr_off(sbi, &pi->valid);
    entry.addrs[1] |= (u64)1 << 56;
    entry.values[1] = pi->valid;

    cpu = get_processor_id();
    spin_lock(&sbi->journal_locks[cpu]);
    // 返回journal后的新tail
    journal_tail = finefs_create_lite_transaction(sb, &entry, NULL, 1, cpu);

    // 执行具体的事务
    // 更新tail
    // pidir->log_tail = pidir_tail;
    // finefs_flush_buffer(&pidir->log_tail, CACHELINE_SIZE, 0);
    pi->valid = 1;
    finefs_flush_buffer(&pi->valid, CACHELINE_SIZE, 0);
    PERSISTENT_BARRIER();

    // 提交事务
    finefs_commit_lite_transaction(sb, journal_tail, cpu);
    spin_unlock(&sbi->journal_locks[cpu]);
    FINEFS_END_TIMING(create_trans_t, trans_time);
}

/* Returns new tail after append */
/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 *
 * 创建新文件
 *
 * 成功返回0，否则返回-1。
 */
static int finefs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl) {
    struct inode *inode = NULL;
    // int err = PTR_ERR(inode);
    int err = 0;
    struct super_block *sb = dir->i_sb;
    struct finefs_inode *pidir, *pi;
    finefs_inode_info_header* p_sih = &FINEFS_I(dir)->header;
    u64 pi_addr = 0;  // 新分配inode的nvm地址
    u64 tail = 0;
    u64 ino;
    timing_t create_time;

    log_assert(dentry->d_name.len <= FINEFS_NAME_LEN);

    FINEFS_START_TIMING(create_t, create_time);

    // 获取nvm中对应的inode地址
    pidir = finefs_get_inode(sb, dir);
    if (!pidir) goto out_err;

    // 分配新的inode，pi_addr为nvm地址
    ino = finefs_new_finefs_inode(sb, &pi_addr);
    if (ino == 0) goto out_err;

    // 想父目录添加一个dentry（写log的形式）
    // tail带回新的tail，实际的tail没有改
    err = finefs_add_dentry(dentry, ino, 0, 0, &tail);
    if (err) goto out_err;

    rd_info("%s: %s", __func__, dentry->d_name.name);
    rd_info("%s: inode %lu, dir %lu", __func__, ino, dir->i_ino);
    inode = finefs_new_vfs_inode(TYPE_CREATE, dir, pi_addr, ino, mode, 0, 0, &dentry->d_name);
    if (inode == nullptr) goto out_err;

    d_instantiate(dentry, inode);
    // unlock_new_inode(inode);

    pi = (struct finefs_inode *)finefs_get_block(sb, pi_addr);
    finefs_lite_transaction_for_new_inode(sb, pi, pidir, tail);
    p_sih->h_log_tail = tail;
    inode_unref(inode);
    FINEFS_END_TIMING(create_t, create_time);
    return err;
out_err:
    r_error("%s return %d", __func__, err);
    FINEFS_END_TIMING(create_t, create_time);
    return err;
}

// static int finefs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
// 		       dev_t rdev)
// {
// 	struct inode *inode = NULL;
// 	int err = PTR_ERR(inode);
// 	struct super_block *sb = dir->i_sb;
// 	u64 pi_addr = 0;
// 	struct finefs_inode *pidir, *pi;
// 	u64 tail = 0;
// 	u64 ino;
// 	timing_t mknod_time;

// 	FINEFS_START_TIMING(mknod_t, mknod_time);

// 	pidir = finefs_get_inode(sb, dir);
// 	if (!pidir)
// 		goto out_err;

// 	ino = finefs_new_finefs_inode(sb, &pi_addr);
// 	if (ino == 0)
// 		goto out_err;

// 	finefs_dbgv("%s: %s", __func__, dentry->d_name.name);
// 	finefs_dbgv("%s: inode %lu, dir %lu", __func__, ino, dir->i_ino);
// 	err = finefs_add_dentry(dentry, ino, 0, 0, &tail);
// 	if (err)
// 		goto out_err;

// 	inode = finefs_new_vfs_inode(TYPE_MKNOD, dir, pi_addr, ino, mode,
// 					0, rdev, &dentry->d_name);
// 	if (IS_ERR(inode))
// 		goto out_err;

// 	d_instantiate(dentry, inode);
// 	// unlock_new_inode(inode);

// 	pi = finefs_get_block(sb, pi_addr);
// 	finefs_lite_transaction_for_new_inode(sb, pi, pidir, tail);
// 	FINEFS_END_TIMING(mknod_t, mknod_time);
// 	return err;
// out_err:
// 	finefs_err(sb, "%s return %d", __func__, err);
// 	FINEFS_END_TIMING(mknod_t, mknod_time);
// 	return err;
// }

// static int finefs_symlink(struct inode *dir, struct dentry *dentry,
// 			 const char *symname)
// {
// 	struct super_block *sb = dir->i_sb;
// 	int err = -ENAMETOOLONG;
// 	unsigned len = strlen(symname);
// 	struct inode *inode;
// 	u64 pi_addr = 0;
// 	struct finefs_inode *pidir, *pi;
// 	u64 log_block = 0;
// 	unsigned long name_blocknr = 0;
// 	int allocated;
// 	u64 tail = 0;
// 	u64 ino;
// 	timing_t symlink_time;

// 	FINEFS_START_TIMING(symlink_t, symlink_time);
// 	if (len + 1 > sb->s_blocksize)
// 		goto out;

// 	pidir = finefs_get_inode(sb, dir);
// 	if (!pidir)
// 		goto out_fail1;

// 	ino = finefs_new_finefs_inode(sb, &pi_addr);
// 	if (ino == 0)
// 		goto out_fail1;

// 	finefs_dbgv("%s: name %s, symname %s", __func__,
// 				dentry->d_name.name, symname);
// 	finefs_dbgv("%s: inode %lu, dir %lu", __func__, ino, dir->i_ino);
// 	err = finefs_add_dentry(dentry, ino, 0, 0, &tail);
// 	if (err)
// 		goto out_fail1;

// 	inode = finefs_new_vfs_inode(TYPE_SYMLINK, dir, pi_addr, ino,
// 					S_IFLNK|S_IRWXUGO, len, 0,
// 					&dentry->d_name);
// 	if (IS_ERR(inode)) {
// 		err = PTR_ERR(inode);
// 		goto out_fail1;
// 	}

// 	pi = finefs_get_inode(sb, inode);
// 	allocated = finefs_allocate_inode_log_pages(sb, pi,
// 						1, &log_block);
// 	if (allocated != 1 || log_block == 0) {
// 		err = allocated;
// 		goto out_fail1;
// 	}

// 	allocated = finefs_new_data_blocks(sb, pi, &name_blocknr,
// 					1, 0, 1, 0);
// 	if (allocated != 1 || name_blocknr == 0) {
// 		err = allocated;
// 		goto out_fail2;
// 	}

// 	pi->i_blocks = 2;
// 	finefs_block_symlink(sb, pi, inode, log_block, name_blocknr,
// 				symname, len);
// 	d_instantiate(dentry, inode);
// 	// unlock_new_inode(inode);

// 	finefs_lite_transaction_for_new_inode(sb, pi, pidir, tail);
// out:
// 	FINEFS_END_TIMING(symlink_t, symlink_time);
// 	return err;

// out_fail2:
// 	finefs_free_log_blocks(sb, pi, log_block >> PAGE_SHIFT, 1);
// out_fail1:
// 	finefs_err(sb, "%s return %d", __func__, err);
// 	goto out;
// }

static void finefs_lite_transaction_for_time_and_link(struct super_block *sb,
                                                      struct finefs_inode *pi,
                                                      struct finefs_inode *pidir, u64 pi_tail,
                                                      u64 pidir_tail, int invalidate) {
    struct finefs_sb_info *sbi = FINEFS_SB(sb);
    struct finefs_lite_journal_entry entry;
    u64 journal_tail;
    int cpu;
    timing_t trans_time;

    FINEFS_START_TIMING(link_trans_t, trans_time);

    /* Commit a lite transaction */
    memset(&entry, 0, sizeof(struct finefs_lite_journal_entry));
    entry.addrs[0] = (u64)finefs_get_addr_off(sbi, &pi->log_tail);
    entry.addrs[0] |= (u64)8 << 56;
    entry.values[0] = pi->log_tail;

    entry.addrs[1] = (u64)finefs_get_addr_off(sbi, &pidir->log_tail);
    entry.addrs[1] |= (u64)8 << 56;
    entry.values[1] = pidir->log_tail;

    if (invalidate) {
        entry.addrs[2] = (u64)finefs_get_addr_off(sbi, &pi->valid);
        entry.addrs[2] |= (u64)1 << 56;
        entry.values[2] = pi->valid;
    }

    cpu = get_processor_id();
    spin_lock(&sbi->journal_locks[cpu]);
    journal_tail = finefs_create_lite_transaction(sb, &entry, NULL, 1, cpu);

    // pi->log_tail = pi_tail;
    // finefs_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 0);
    // pidir->log_tail = pidir_tail;
    // finefs_flush_buffer(&pidir->log_tail, CACHELINE_SIZE, 0);
    if (invalidate) {
        pi->valid = 0;  // 可能需要等到垃圾回收时，才真正回收空间
        finefs_flush_buffer(&pi->valid, CACHELINE_SIZE, 0);
    }
    PERSISTENT_BARRIER();

    finefs_commit_lite_transaction(sb, journal_tail, cpu);
    spin_unlock(&sbi->journal_locks[cpu]);
    FINEFS_END_TIMING(link_trans_t, trans_time);
}

/* Returns new tail after append */
// inode中的link个数已经修改好
int finefs_append_link_change_entry(struct super_block *sb, struct finefs_inode *pi,
                                    struct inode *inode, u64 tail, u64 *new_tail) {
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;
    struct finefs_link_change_entry *entry;
    u64 curr_p;
    int extended = 0;
    size_t size = sizeof(struct finefs_link_change_entry);
    timing_t append_time;

    FINEFS_START_TIMING(append_link_change_t, append_time);
    rdv_proc("%s: inode %lu attr change", __func__, inode->i_ino);

    curr_p = finefs_get_append_head(sb, pi, sih, tail, size, &extended, false);
    inode->i_blocks = sih->h_blocks;
    if (curr_p == 0) return -ENOMEM;

    entry = (struct finefs_link_change_entry *)finefs_get_block(sb, curr_p);
    entry->entry_type = LINK_CHANGE;
    entry->links = cpu_to_le16(inode->i_nlink);
    entry->ctime = cpu_to_le32(inode->i_ctime.tv_sec);
    entry->flags = cpu_to_le32(inode->i_flags);
    entry->generation = cpu_to_le32(inode->i_generation);
    entry->entry_version = 0x1234;
    finefs_flush_buffer(entry, size, 0);
    *new_tail = curr_p + size;
    sih->log_valid_bytes += size;
    sih->last_link_change = curr_p;

    FINEFS_END_TIMING(append_link_change_t, append_time);
    return 0;
}

void finefs_apply_link_change_entry(struct finefs_inode *pi,
                                    struct finefs_link_change_entry *entry) {
    if (entry->entry_type != LINK_CHANGE) BUG();

    pi->i_links_count = entry->links;
    pi->i_ctime = entry->ctime;
    pi->i_flags = entry->flags;
    pi->i_generation = entry->generation;

    /* Do not flush now */
}

// static int finefs_link(struct dentry *dest_dentry, struct inode *dir,
// 		      struct dentry *dentry)
// {
// 	struct super_block *sb = dir->i_sb;
// 	struct inode *inode = dest_dentry->d_inode;
// 	struct finefs_inode *pi = finefs_get_inode(sb, inode);
// 	struct finefs_inode *pidir;
// 	u64 pidir_tail = 0, pi_tail = 0;
// 	int err = -ENOMEM;
// 	timing_t link_time;

// 	FINEFS_START_TIMING(link_t, link_time);
// 	if (inode->i_nlink >= FINEFS_LINK_MAX) {
// 		err = -EMLINK;
// 		goto out;
// 	}

// 	pidir = finefs_get_inode(sb, dir);
// 	if (!pidir) {
// 		err = -EINVAL;
// 		goto out;
// 	}

// 	ihold(inode);

// 	finefs_dbgv("%s: name %s, dest %s", __func__,
// 			dentry->d_name.name, dest_dentry->d_name.name);
// 	finefs_dbgv("%s: inode %lu, dir %lu", __func__,
// 			inode->i_ino, dir->i_ino);
// 	err = finefs_add_dentry(dentry, inode->i_ino, 0, 0, &pidir_tail);
// 	if (err) {
// 		iput(inode);
// 		goto out;
// 	}

// 	inode->i_ctime = CURRENT_TIME_SEC;
// 	inc_nlink(inode);

// 	err = finefs_append_link_change_entry(sb, pi, inode, 0, &pi_tail);
// 	if (err) {
// 		iput(inode);
// 		goto out;
// 	}

// 	d_instantiate(dentry, inode);
// 	finefs_lite_transaction_for_time_and_link(sb, pi, pidir,
// 						pi_tail, pidir_tail, 0);

// out:
// 	FINEFS_END_TIMING(link_t, link_time);
// 	return err;
// }

// 删除文件
static int finefs_unlink(struct inode *dir, struct dentry *dentry) {
    struct inode *inode = dentry->d_inode;
    struct super_block *sb = dir->i_sb;
    int retval = -ENOMEM;
    struct finefs_inode *pi = finefs_get_inode(sb, inode);
    struct finefs_inode *pidir;
    u64 pidir_tail = 0, pi_tail = 0;
    int invalidate = 0;
    timing_t unlink_time;

    FINEFS_START_TIMING(unlink_t, unlink_time);

    pidir = finefs_get_inode(sb, dir);
    if (!pidir) goto out;

    rd_info("%s: %s", __func__, dentry->d_name.name);
    rd_info("%s: inode %lu, dir %lu", __func__, inode->i_ino, dir->i_ino);
    retval = finefs_remove_dentry(dentry, 0, 0, &pidir_tail);
    if (retval) goto out;

    inode->i_ctime = dir->i_ctime;

    if (inode->i_nlink == 1) invalidate = 1;

    if (inode->i_nlink) {
        drop_nlink(inode);
    }

    retval = finefs_append_link_change_entry(sb, pi, inode, 0, &pi_tail);
    if (retval) goto out;

    finefs_lite_transaction_for_time_and_link(sb, pi, pidir, pi_tail, pidir_tail, invalidate);
    FINEFS_I(dir)->header.h_log_tail = pidir_tail;
    FINEFS_I(inode)->header.h_log_tail = pi_tail;

    FINEFS_END_TIMING(unlink_t, unlink_time);
    return 0;
out:
    r_error("%s return %d", __func__, retval);
    FINEFS_END_TIMING(unlink_t, unlink_time);
    return retval;
}

static int finefs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode) {
    struct super_block *sb = dir->i_sb;
    struct inode *inode;
    struct finefs_inode *pidir, *pi;
    finefs_inode_info_header* p_sih = &FINEFS_I(dir)->header;
    struct finefs_inode_info_header *child_sih = NULL;
    u64 pi_addr = 0;
    u64 tail = 0;
    u64 ino;
    int err = -EMLINK;
    timing_t mkdir_time;

    FINEFS_START_TIMING(mkdir_t, mkdir_time);
    if (dir->i_nlink >= FINEFS_LINK_MAX) {
        r_error("i_nlink(%lu) > FINEFS_LINK_MAX(%lu)", dir->i_nlink, FINEFS_LINK_MAX);
        goto out;
    }
    log_assert(dentry->d_name.len <= FINEFS_NAME_LEN);

    ino = finefs_new_finefs_inode(sb, &pi_addr);
    if (ino == 0) {
        r_error("finefs_new_finefs_inode");
        goto out_err;
    }

    rdv_proc("%s: name %s", __func__, dentry->d_name.name);
    rdv_proc("%s: inode %lu, dir %lu, link %d", __func__, ino, dir->i_ino, dir->i_nlink);
    err = finefs_add_dentry(dentry, ino, 1, 0, &tail);
    if (err) {
        r_error("failed to add dir entry");
        goto out_err;
    }

    inode = finefs_new_vfs_inode(TYPE_MKDIR, dir, pi_addr, ino, S_IFDIR | mode, sb->s_blocksize, 0,
                                 &dentry->d_name);
    if (!inode) {
        err = -1;
        r_error("finefs_new_vfs_inode fail");
        goto out_err;
    }
    child_sih = &FINEFS_I(inode)->header;

    pi = finefs_get_inode(sb, inode);
    // 为新创建的目录inode，分配log page，并附加两个entry
    finefs_append_dir_init_entries(sb, pi, inode, dir->i_ino);

    /* Build the dir tree */
    finefs_rebuild_dir_inode_tree(sb, pi, pi_addr, child_sih);

    pidir = finefs_get_inode(sb, dir);
    dir->i_blocks = p_sih->h_blocks;
    inc_nlink(dir);
    d_instantiate(dentry, inode);
    // unlock_new_inode(inode);

    finefs_lite_transaction_for_new_inode(sb, pi, pidir, tail);
    FINEFS_I(dir)->header.h_log_tail = tail;
    inode_unref(inode);
out:
    FINEFS_END_TIMING(mkdir_t, mkdir_time);
    log_assert(err == 0);
    return err;

out_err:
    //	clear_nlink(inode);
    r_error("%s return %d", __func__, err);
    goto out;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 * 确保目录为空
 * // 空则返回1
 */
static int finefs_empty_dir(struct inode *inode) {
    struct super_block *sb;
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *sih = &si->header;
    struct finefs_dentry *entry;
    unsigned long pos = 0;
    struct finefs_dentry *entries[4];
    int nr_entries;
    int i;

    sb = inode->i_sb;
    nr_entries = radix_tree_gang_lookup(&sih->tree, (void **)entries, pos, 4);
    if (nr_entries > 2) return 0;

    for (i = 0; i < nr_entries; i++) {
        entry = entries[i];
        if (!is_dir_init_entry(sb, entry)) return 0;
    }

    return 1;
}

static int finefs_rmdir(struct inode *dir, struct dentry *dentry) {
    // 删除的目录inode
    struct inode *inode = dentry->d_inode;
    struct finefs_dentry *de;
    struct super_block *sb = inode->i_sb;
    // 删除的目录finefs_inode
    struct finefs_inode *pi = finefs_get_inode(sb, inode), *pidir;
    u64 pidir_tail = 0, pi_tail = 0;
    struct finefs_inode_info *si = FINEFS_I(inode);
    struct finefs_inode_info_header *child_sih = &si->header;
    int err = -ENOTEMPTY;
    timing_t rmdir_time;

    FINEFS_START_TIMING(rmdir_t, rmdir_time);
    if (!inode) return -ENOENT;

    rdv_func("%s: name %s", __func__, dentry->d_name.name);
    // 父母inode
    pidir = finefs_get_inode(sb, dir);
    if (!pidir) return -EINVAL;

    if (finefs_inode_by_name(dir, &dentry->d_name, &de) == 0) {
        r_error("%s: %s not found.", __func__, dentry->d_name.name);
        return -ENOENT;
    }

    if (!finefs_empty_dir(inode)) {
        r_error("%s: dir %s is not empty.", __func__, dentry->d_name.name);
        return err;
    }

    rd_info("%s: inode %lu, dir %lu, link %d", __func__, inode->i_ino, dir->i_ino, dir->i_nlink);

    if (inode->i_nlink != 2)
        r_error("empty directory %lu has nlink!=2 (%d), dir %lu", inode->i_ino, inode->i_nlink,
                dir->i_ino);

    // 先从父母inode中删除孩子，并写log
    err = finefs_remove_dentry(dentry, -1, 0, &pidir_tail);
    if (err) goto end_rmdir;

    /*inode->i_version++; */
    clear_nlink(inode);
    inode->i_ctime = dir->i_ctime;

    if (dir->i_nlink) drop_nlink(dir);
    // 删除inode内存中对应的索引
    finefs_delete_dir_tree(sb, child_sih, true);
    // 孩子中添加unlink的log
    err = finefs_append_link_change_entry(sb, pi, inode, 0, &pi_tail);
    if (err) goto end_rmdir;

    finefs_lite_transaction_for_time_and_link(sb, pi, pidir, pi_tail, pidir_tail, 1);
    FINEFS_I(dir)->header.h_log_tail = pidir_tail;
    FINEFS_I(inode)->header.h_log_tail = pi_tail;

    FINEFS_END_TIMING(rmdir_t, rmdir_time);
    return err;

end_rmdir:
    r_error("%s return %d", __func__, err);
    FINEFS_END_TIMING(rmdir_t, rmdir_time);
    return err;
}

// static int finefs_rename(struct inode *old_dir,
// 			struct dentry *old_dentry,
// 			struct inode *new_dir, struct dentry *new_dentry)
// {
// 	struct inode *old_inode = old_dentry->d_inode;
// 	struct inode *new_inode = new_dentry->d_inode;
// 	struct super_block *sb = old_inode->i_sb;
// 	struct finefs_sb_info *sbi = FINEFS_SB(sb);
// 	struct finefs_inode *old_pi = NULL, *new_pi = NULL;
// 	struct finefs_inode *new_pidir = NULL, *old_pidir = NULL;
// 	struct finefs_lite_journal_entry entry, entry1;
// 	struct finefs_dentry *father_entry = NULL;
// 	char *head_addr = NULL;
// 	u64 old_tail = 0, new_tail = 0, new_pi_tail = 0, old_pi_tail = 0;
// 	int err = -ENOENT;
// 	int inc_link = 0, dec_link = 0;
// 	int entries = 0;
// 	int cpu;
// 	int change_parent = 0;
// 	u64 journal_tail;
// 	timing_t rename_time;

// 	rd_info("%s: rename %s to %s,", __func__,
// 			old_dentry->d_name.name, new_dentry->d_name.name);
// 	rd_info("%s: %s inode %lu, old dir %lu, new dir %lu, new inode %lu",
// 			__func__, S_ISDIR(old_inode->i_mode) ? "dir" : "normal",
// 			old_inode->i_ino, old_dir->i_ino, new_dir->i_ino,
// 			new_inode ? new_inode->i_ino : 0);
// 	FINEFS_START_TIMING(rename_t, rename_time);

// 	if (new_inode) {
// 		err = -ENOTEMPTY;
// 		if (S_ISDIR(old_inode->i_mode) && !finefs_empty_dir(new_inode))
// 			goto out;
// 	} else {
// 		if (S_ISDIR(old_inode->i_mode)) {
// 			err = -EMLINK;
// 			if (new_dir->i_nlink >= FINEFS_LINK_MAX)
// 				goto out;
// 		}
// 	}

// 	if (S_ISDIR(old_inode->i_mode)) {
// 		dec_link = -1;
// 		if (!new_inode)
// 			inc_link = 1;
// 	}

// 	new_pidir = finefs_get_inode(sb, new_dir);
// 	old_pidir = finefs_get_inode(sb, old_dir);

// 	old_pi = finefs_get_inode(sb, old_inode);
// 	old_inode->i_ctime = CURRENT_TIME;
// 	err = finefs_append_link_change_entry(sb, old_pi,
// 						old_inode, 0, &old_pi_tail);
// 	if (err)
// 		goto out;

// 	if (S_ISDIR(old_inode->i_mode) && old_dir != new_dir) {
// 		/* My father is changed. Update .. entry */
// 		/* For simplicity, we use in-place update and journal it */
// 		change_parent = 1;
// 		head_addr = (char *)finefs_get_block(sb, old_pi->log_head);
// 		father_entry = (struct finefs_dentry *)(head_addr +
// 					FINEFS_DIR_LOG_REC_LEN(1));
// 		if (le64_to_cpu(father_entry->ino) != old_dir->i_ino)
// 			finefs_err(sb, "%s: dir %lu parent should be %lu, "
// 				"but actually %lu", __func__,
// 				old_inode->i_ino, old_dir->i_ino,
// 				le64_to_cpu(father_entry->ino));
// 	}

// 	if (new_inode) {
// 		/* First remove the old entry in the new directory */
// 		err = finefs_remove_dentry(new_dentry, 0,  0, &new_tail);
// 		if (err)
// 			goto out;
// 	}

// 	/* link into the new directory. */
// 	err = finefs_add_dentry(new_dentry, old_inode->i_ino,
// 				inc_link, new_tail, &new_tail);
// 	if (err)
// 		goto out;

// 	if (inc_link)
// 		inc_nlink(new_dir);

// 	if (old_dir == new_dir)
// 		old_tail = new_tail;

// 	err = finefs_remove_dentry(old_dentry, dec_link, old_tail, &old_tail);
// 	if (err)
// 		goto out;

// 	if (dec_link < 0)
// 		drop_nlink(old_dir);

// 	if (new_inode) {
// 		new_pi = finefs_get_inode(sb, new_inode);
// 		new_inode->i_ctime = CURRENT_TIME;

// 		if (S_ISDIR(old_inode->i_mode)) {
// 			if (new_inode->i_nlink)
// 				drop_nlink(new_inode);
// 		}
// 		if (new_inode->i_nlink)
// 			drop_nlink(new_inode);

// 		err = finefs_append_link_change_entry(sb, new_pi,
// 						new_inode, 0, &new_pi_tail);
// 		if (err)
// 			goto out;
// 	}

// 	entries = 1;
// 	memset(&entry, 0, sizeof(struct finefs_lite_journal_entry));

// 	entry.addrs[0] = (u64)finefs_get_addr_off(sbi, &old_pi->log_tail);
// 	entry.addrs[0] |= (u64)8 << 56;
// 	entry.values[0] = old_pi->log_tail;

// 	entry.addrs[1] = (u64)finefs_get_addr_off(sbi, &old_pidir->log_tail);
// 	entry.addrs[1] |= (u64)8 << 56;
// 	entry.values[1] = old_pidir->log_tail;

// 	if (old_dir != new_dir) {
// 		entry.addrs[2] = (u64)finefs_get_addr_off(sbi,
// 						&new_pidir->log_tail);
// 		entry.addrs[2] |= (u64)8 << 56;
// 		entry.values[2] = new_pidir->log_tail;

// 		if (change_parent && father_entry) {
// 			entry.addrs[3] = (u64)finefs_get_addr_off(sbi,
// 						&father_entry->ino);
// 			entry.addrs[3] |= (u64)8 << 56;
// 			entry.values[3] = father_entry->ino;
// 		}
// 	}

// 	if (new_inode) {
// 		entries++;
// 		memset(&entry1, 0, sizeof(struct finefs_lite_journal_entry));

// 		entry1.addrs[0] = (u64)finefs_get_addr_off(sbi,
// 						&new_pi->log_tail);
// 		entry1.addrs[0] |= (u64)8 << 56;
// 		entry1.values[0] = new_pi->log_tail;

// 		if (!new_inode->i_nlink) {
// 			entry1.addrs[1] = (u64)finefs_get_addr_off(sbi,
// 							&new_pi->valid);
// 			entry1.addrs[1] |= (u64)1 << 56;
// 			entry1.values[1] = new_pi->valid;
// 		}

// 	}

// 	cpu = smp_processor_id();
// 	spin_lock(&sbi->journal_locks[cpu]);
// 	journal_tail = finefs_create_lite_transaction(sb, &entry, &entry1,
// 							entries, cpu);

// 	old_pi->log_tail = old_pi_tail;
// 	finefs_flush_buffer(&old_pi->log_tail, CACHELINE_SIZE, 0);
// 	old_pidir->log_tail = old_tail;
// 	finefs_flush_buffer(&old_pidir->log_tail, CACHELINE_SIZE, 0);

// 	if (old_pidir != new_pidir) {
// 		new_pidir->log_tail = new_tail;
// 		finefs_flush_buffer(&new_pidir->log_tail, CACHELINE_SIZE, 0);
// 	}

// 	if (change_parent && father_entry) {
// 		father_entry->ino = cpu_to_le64(new_dir->i_ino);
// 		finefs_flush_buffer(father_entry, FINEFS_DIR_LOG_REC_LEN(2), 0);
// 	}

// 	if (new_inode) {
// 		new_pi->log_tail = new_pi_tail;
// 		finefs_flush_buffer(&new_pi->log_tail, CACHELINE_SIZE, 0);
// 		if (!new_inode->i_nlink) {
// 			new_pi->valid = 0;
// 			finefs_flush_buffer(&new_pi->valid, CACHELINE_SIZE, 0);
// 		}
// 	}

// 	PERSISTENT_BARRIER();

// 	finefs_commit_lite_transaction(sb, journal_tail, cpu);
// 	spin_unlock(&sbi->journal_locks[cpu]);

// 	FINEFS_END_TIMING(rename_t, rename_time);
// 	return 0;
// out:
// 	finefs_err(sb, "%s return %d", __func__, err);
// 	FINEFS_END_TIMING(rename_t, rename_time);
// 	return err;
// }

// struct dentry *finefs_get_parent(struct dentry *child)
// {
// 	struct inode *inode;
// 	struct qstr dotdot = QSTR_INIT("..", 2);
// 	struct finefs_dentry *de = NULL;
// 	ino_t ino;

// 	finefs_inode_by_name(child->d_inode, &dotdot, &de);
// 	if (!de)
// 		return ERR_PTR(-ENOENT);
// 	ino = le64_to_cpu(de->ino);

// 	if (ino)
// 		inode = finefs_iget(child->d_inode->i_sb, ino);
// 	else
// 		return ERR_PTR(-ENOENT);

// 	return d_obtain_alias(inode);
// }

const struct inode_operations finefs_dir_inode_operations = {
    .create = finefs_create,
    .lookup = finefs_lookup,
    // .link		= finefs_link,
    .unlink = finefs_unlink,
    // .symlink	= finefs_symlink,
    .mkdir = finefs_mkdir,
    .rmdir = finefs_rmdir,
    // .mknod		= finefs_mknod,
    // .rename		= finefs_rename,
    .setattr = finefs_notify_change,
    // .get_acl	= NULL,
};

const struct inode_operations finefs_special_inode_operations = {
    .get_acl = NULL,
    .setattr = finefs_notify_change,
};
