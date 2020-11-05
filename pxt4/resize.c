// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/pxt4/resize.c
 *
 * Support for resizing an pxt4 filesystem while it is mounted.
 *
 * Copyright (C) 2001, 2002 Andreas Dilger <adilger@clusterfs.com>
 *
 * This could probably be made into a module, because it is not often in use.
 */


#define PXT4FS_DEBUG

#include <linux/errno.h>
#include <linux/slab.h>

#include "pxt4_jbd3.h"

struct pxt4_rcu_ptr {
	struct rcu_head rcu;
	void *ptr;
};

static void pxt4_rcu_ptr_callback(struct rcu_head *head)
{
	struct pxt4_rcu_ptr *ptr;

	ptr = container_of(head, struct pxt4_rcu_ptr, rcu);
	kvfree(ptr->ptr);
	kfree(ptr);
}

void pxt4_kvfree_array_rcu(void *to_free)
{
	struct pxt4_rcu_ptr *ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);

	if (ptr) {
		ptr->ptr = to_free;
		call_rcu(&ptr->rcu, pxt4_rcu_ptr_callback);
		return;
	}
	synchronize_rcu();
	kvfree(to_free);
}

int pxt4_resize_begin(struct super_block *sb)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	int ret = 0;

	if (!capable(CAP_SYS_RESOURCE))
		return -EPERM;

	/*
	 * If we are not using the primary superblock/GDT copy don't resize,
         * because the user tools have no way of handling this.  Probably a
         * bad time to do it anyways.
         */
	if (PXT4_B2C(sbi, sbi->s_sbh->b_blocknr) !=
	    le32_to_cpu(PXT4_SB(sb)->s_es->s_first_data_block)) {
		pxt4_warning(sb, "won't resize using backup superblock at %llu",
			(unsigned long long)PXT4_SB(sb)->s_sbh->b_blocknr);
		return -EPERM;
	}

	/*
	 * We are not allowed to do online-resizing on a filesystem mounted
	 * with error, because it can destroy the filesystem easily.
	 */
	if (PXT4_SB(sb)->s_mount_state & PXT4_ERROR_FS) {
		pxt4_warning(sb, "There are errors in the filesystem, "
			     "so online resizing is not allowed");
		return -EPERM;
	}

	if (test_and_set_bit_lock(PXT4_FLAGS_RESIZING,
				  &PXT4_SB(sb)->s_pxt4_flags))
		ret = -EBUSY;

	return ret;
}

void pxt4_resize_end(struct super_block *sb)
{
	clear_bit_unlock(PXT4_FLAGS_RESIZING, &PXT4_SB(sb)->s_pxt4_flags);
	smp_mb__after_atomic();
}

static pxt4_group_t pxt4_meta_bg_first_group(struct super_block *sb,
					     pxt4_group_t group) {
	return (group >> PXT4_DESC_PER_BLOCK_BITS(sb)) <<
	       PXT4_DESC_PER_BLOCK_BITS(sb);
}

static pxt4_fsblk_t pxt4_meta_bg_first_block_no(struct super_block *sb,
					     pxt4_group_t group) {
	group = pxt4_meta_bg_first_group(sb, group);
	return pxt4_group_first_block_no(sb, group);
}

static pxt4_grpblk_t pxt4_group_overhead_blocks(struct super_block *sb,
						pxt4_group_t group) {
	pxt4_grpblk_t overhead;
	overhead = pxt4_bg_num_gdb(sb, group);
	if (pxt4_bg_has_super(sb, group))
		overhead += 1 +
			  le16_to_cpu(PXT4_SB(sb)->s_es->s_reserved_gdt_blocks);
	return overhead;
}

#define outside(b, first, last)	((b) < (first) || (b) >= (last))
#define inside(b, first, last)	((b) >= (first) && (b) < (last))

static int verify_group_input(struct super_block *sb,
			      struct pxt4_new_group_data *input)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	pxt4_fsblk_t start = pxt4_blocks_count(es);
	pxt4_fsblk_t end = start + input->blocks_count;
	pxt4_group_t group = input->group;
	pxt4_fsblk_t itend = input->inode_table + sbi->s_itb_per_group;
	unsigned overhead;
	pxt4_fsblk_t metaend;
	struct buffer_head *bh = NULL;
	pxt4_grpblk_t free_blocks_count, offset;
	int err = -EINVAL;

	if (group != sbi->s_groups_count) {
		pxt4_warning(sb, "Cannot add at group %u (only %u groups)",
			     input->group, sbi->s_groups_count);
		return -EINVAL;
	}

	overhead = pxt4_group_overhead_blocks(sb, group);
	metaend = start + overhead;
	input->free_clusters_count = free_blocks_count =
		input->blocks_count - 2 - overhead - sbi->s_itb_per_group;

	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG "PXT4-fs: adding %s group %u: %u blocks "
		       "(%d free, %u reserved)\n",
		       pxt4_bg_has_super(sb, input->group) ? "normal" :
		       "no-super", input->group, input->blocks_count,
		       free_blocks_count, input->reserved_blocks);

	pxt4_get_group_no_and_offset(sb, start, NULL, &offset);
	if (offset != 0)
			pxt4_warning(sb, "Last group not full");
	else if (input->reserved_blocks > input->blocks_count / 5)
		pxt4_warning(sb, "Reserved blocks too high (%u)",
			     input->reserved_blocks);
	else if (free_blocks_count < 0)
		pxt4_warning(sb, "Bad blocks count %u",
			     input->blocks_count);
	else if (IS_ERR(bh = pxt4_sb_bread(sb, end - 1, 0))) {
		err = PTR_ERR(bh);
		bh = NULL;
		pxt4_warning(sb, "Cannot read last block (%llu)",
			     end - 1);
	} else if (outside(input->block_bitmap, start, end))
		pxt4_warning(sb, "Block bitmap not in group (block %llu)",
			     (unsigned long long)input->block_bitmap);
	else if (outside(input->inode_bitmap, start, end))
		pxt4_warning(sb, "Inode bitmap not in group (block %llu)",
			     (unsigned long long)input->inode_bitmap);
	else if (outside(input->inode_table, start, end) ||
		 outside(itend - 1, start, end))
		pxt4_warning(sb, "Inode table not in group (blocks %llu-%llu)",
			     (unsigned long long)input->inode_table, itend - 1);
	else if (input->inode_bitmap == input->block_bitmap)
		pxt4_warning(sb, "Block bitmap same as inode bitmap (%llu)",
			     (unsigned long long)input->block_bitmap);
	else if (inside(input->block_bitmap, input->inode_table, itend))
		pxt4_warning(sb, "Block bitmap (%llu) in inode table "
			     "(%llu-%llu)",
			     (unsigned long long)input->block_bitmap,
			     (unsigned long long)input->inode_table, itend - 1);
	else if (inside(input->inode_bitmap, input->inode_table, itend))
		pxt4_warning(sb, "Inode bitmap (%llu) in inode table "
			     "(%llu-%llu)",
			     (unsigned long long)input->inode_bitmap,
			     (unsigned long long)input->inode_table, itend - 1);
	else if (inside(input->block_bitmap, start, metaend))
		pxt4_warning(sb, "Block bitmap (%llu) in GDT table (%llu-%llu)",
			     (unsigned long long)input->block_bitmap,
			     start, metaend - 1);
	else if (inside(input->inode_bitmap, start, metaend))
		pxt4_warning(sb, "Inode bitmap (%llu) in GDT table (%llu-%llu)",
			     (unsigned long long)input->inode_bitmap,
			     start, metaend - 1);
	else if (inside(input->inode_table, start, metaend) ||
		 inside(itend - 1, start, metaend))
		pxt4_warning(sb, "Inode table (%llu-%llu) overlaps GDT table "
			     "(%llu-%llu)",
			     (unsigned long long)input->inode_table,
			     itend - 1, start, metaend - 1);
	else
		err = 0;
	brelse(bh);

	return err;
}

/*
 * pxt4_new_flpxt2_group_data is used by 64bit-resize interface to add a flpxt2
 * group each time.
 */
struct pxt4_new_flpxt2_group_data {
	struct pxt4_new_group_data *groups;	/* new_group_data for groups
						   in the flpxt2 group */
	__u16 *bg_flags;			/* block group flags of groups
						   in @groups */
	pxt4_group_t count;			/* number of groups in @groups
						 */
};

/*
 * alloc_flpxt2_gd() allocates a pxt4_new_flpxt2_group_data with size of
 * @flpxt2bg_size.
 *
 * Returns NULL on failure otherwise address of the allocated structure.
 */
static struct pxt4_new_flpxt2_group_data *alloc_flpxt2_gd(unsigned long flpxt2bg_size)
{
	struct pxt4_new_flpxt2_group_data *flpxt2_gd;

	flpxt2_gd = kmalloc(sizeof(*flpxt2_gd), GFP_NOFS);
	if (flpxt2_gd == NULL)
		goto out3;

	if (flpxt2bg_size >= UINT_MAX / sizeof(struct pxt4_new_group_data))
		goto out2;
	flpxt2_gd->count = flpxt2bg_size;

	flpxt2_gd->groups = kmalloc_array(flpxt2bg_size,
					sizeof(struct pxt4_new_group_data),
					GFP_NOFS);
	if (flpxt2_gd->groups == NULL)
		goto out2;

	flpxt2_gd->bg_flags = kmalloc_array(flpxt2bg_size, sizeof(__u16),
					  GFP_NOFS);
	if (flpxt2_gd->bg_flags == NULL)
		goto out1;

	return flpxt2_gd;

out1:
	kfree(flpxt2_gd->groups);
out2:
	kfree(flpxt2_gd);
out3:
	return NULL;
}

static void free_flpxt2_gd(struct pxt4_new_flpxt2_group_data *flpxt2_gd)
{
	kfree(flpxt2_gd->bg_flags);
	kfree(flpxt2_gd->groups);
	kfree(flpxt2_gd);
}

/*
 * pxt4_alloc_group_tables() allocates block bitmaps, inode bitmaps
 * and inode tables for a flpxt2 group.
 *
 * This function is used by 64bit-resize.  Note that this function allocates
 * group tables from the 1st group of groups contained by @flpxt2gd, which may
 * be a partial of a flpxt2 group.
 *
 * @sb: super block of fs to which the groups belongs
 *
 * Returns 0 on a successful allocation of the metadata blocks in the
 * block group.
 */
static int pxt4_alloc_group_tables(struct super_block *sb,
				struct pxt4_new_flpxt2_group_data *flpxt2_gd,
				int flpxt2bg_size)
{
	struct pxt4_new_group_data *group_data = flpxt2_gd->groups;
	pxt4_fsblk_t start_blk;
	pxt4_fsblk_t last_blk;
	pxt4_group_t src_group;
	pxt4_group_t bb_indpxt2 = 0;
	pxt4_group_t ib_indpxt2 = 0;
	pxt4_group_t it_indpxt2 = 0;
	pxt4_group_t group;
	pxt4_group_t last_group;
	unsigned overhead;
	__u16 uninit_mask = (flpxt2bg_size > 1) ? ~PXT4_BG_BLOCK_UNINIT : ~0;
	int i;

	BUG_ON(flpxt2_gd->count == 0 || group_data == NULL);

	src_group = group_data[0].group;
	last_group  = src_group + flpxt2_gd->count - 1;

	BUG_ON((flpxt2bg_size > 1) && ((src_group & ~(flpxt2bg_size - 1)) !=
	       (last_group & ~(flpxt2bg_size - 1))));
npxt2t_group:
	group = group_data[0].group;
	if (src_group >= group_data[0].group + flpxt2_gd->count)
		return -ENOSPC;
	start_blk = pxt4_group_first_block_no(sb, src_group);
	last_blk = start_blk + group_data[src_group - group].blocks_count;

	overhead = pxt4_group_overhead_blocks(sb, src_group);

	start_blk += overhead;

	/* We collect contiguous blocks as much as possible. */
	src_group++;
	for (; src_group <= last_group; src_group++) {
		overhead = pxt4_group_overhead_blocks(sb, src_group);
		if (overhead == 0)
			last_blk += group_data[src_group - group].blocks_count;
		else
			break;
	}

	/* Allocate block bitmaps */
	for (; bb_indpxt2 < flpxt2_gd->count; bb_indpxt2++) {
		if (start_blk >= last_blk)
			goto npxt2t_group;
		group_data[bb_indpxt2].block_bitmap = start_blk++;
		group = pxt4_get_group_number(sb, start_blk - 1);
		group -= group_data[0].group;
		group_data[group].mdata_blocks++;
		flpxt2_gd->bg_flags[group] &= uninit_mask;
	}

	/* Allocate inode bitmaps */
	for (; ib_indpxt2 < flpxt2_gd->count; ib_indpxt2++) {
		if (start_blk >= last_blk)
			goto npxt2t_group;
		group_data[ib_indpxt2].inode_bitmap = start_blk++;
		group = pxt4_get_group_number(sb, start_blk - 1);
		group -= group_data[0].group;
		group_data[group].mdata_blocks++;
		flpxt2_gd->bg_flags[group] &= uninit_mask;
	}

	/* Allocate inode tables */
	for (; it_indpxt2 < flpxt2_gd->count; it_indpxt2++) {
		unsigned int itb = PXT4_SB(sb)->s_itb_per_group;
		pxt4_fsblk_t npxt2t_group_start;

		if (start_blk + itb > last_blk)
			goto npxt2t_group;
		group_data[it_indpxt2].inode_table = start_blk;
		group = pxt4_get_group_number(sb, start_blk);
		npxt2t_group_start = pxt4_group_first_block_no(sb, group + 1);
		group -= group_data[0].group;

		if (start_blk + itb > npxt2t_group_start) {
			flpxt2_gd->bg_flags[group + 1] &= uninit_mask;
			overhead = start_blk + itb - npxt2t_group_start;
			group_data[group + 1].mdata_blocks += overhead;
			itb -= overhead;
		}

		group_data[group].mdata_blocks += itb;
		flpxt2_gd->bg_flags[group] &= uninit_mask;
		start_blk += PXT4_SB(sb)->s_itb_per_group;
	}

	/* Update free clusters count to pxt2clude metadata blocks */
	for (i = 0; i < flpxt2_gd->count; i++) {
		group_data[i].free_clusters_count -=
				PXT4_NUM_B2C(PXT4_SB(sb),
					     group_data[i].mdata_blocks);
	}

	if (test_opt(sb, DEBUG)) {
		int i;
		group = group_data[0].group;

		printk(KERN_DEBUG "PXT4-fs: adding a flpxt2 group with "
		       "%d groups, flpxt2bg size is %d:\n", flpxt2_gd->count,
		       flpxt2bg_size);

		for (i = 0; i < flpxt2_gd->count; i++) {
			pxt4_debug(
			       "adding %s group %u: %u blocks (%d free, %d mdata blocks)\n",
			       pxt4_bg_has_super(sb, group + i) ? "normal" :
			       "no-super", group + i,
			       group_data[i].blocks_count,
			       group_data[i].free_clusters_count,
			       group_data[i].mdata_blocks);
		}
	}
	return 0;
}

static struct buffer_head *bclean(handle_t *handle, struct super_block *sb,
				  pxt4_fsblk_t blk)
{
	struct buffer_head *bh;
	int err;

	bh = sb_getblk(sb, blk);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);
	BUFFER_TRACE(bh, "get_write_access");
	if ((err = pxt4_journal_get_write_access(handle, bh))) {
		brelse(bh);
		bh = ERR_PTR(err);
	} else {
		memset(bh->b_data, 0, sb->s_blocksize);
		set_buffer_uptodate(bh);
	}

	return bh;
}

/*
 * If we have fewer than thresh credits, pxt2tend by PXT4_MAX_TRANS_DATA.
 * If that fails, restart the transaction & regain write access for the
 * buffer head which is used for block_bitmap modifications.
 */
static int pxt2tend_or_restart_transaction(handle_t *handle, int thresh)
{
	int err;

	if (pxt4_handle_has_enough_credits(handle, thresh))
		return 0;

	err = pxt4_journal_pxt2tend(handle, PXT4_MAX_TRANS_DATA);
	if (err < 0)
		return err;
	if (err) {
		err = pxt4_journal_restart(handle, PXT4_MAX_TRANS_DATA);
		if (err)
			return err;
	}

	return 0;
}

/*
 * set_flpxt2bg_block_bitmap() mark clusters [@first_cluster, @last_cluster] used.
 *
 * Helper function for pxt4_setup_new_group_blocks() which set .
 *
 * @sb: super block
 * @handle: journal handle
 * @flpxt2_gd: flpxt2 group data
 */
static int set_flpxt2bg_block_bitmap(struct super_block *sb, handle_t *handle,
			struct pxt4_new_flpxt2_group_data *flpxt2_gd,
			pxt4_fsblk_t first_cluster, pxt4_fsblk_t last_cluster)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	pxt4_group_t count = last_cluster - first_cluster + 1;
	pxt4_group_t count2;

	pxt4_debug("mark clusters [%llu-%llu] used\n", first_cluster,
		   last_cluster);
	for (count2 = count; count > 0;
	     count -= count2, first_cluster += count2) {
		pxt4_fsblk_t start;
		struct buffer_head *bh;
		pxt4_group_t group;
		int err;

		group = pxt4_get_group_number(sb, PXT4_C2B(sbi, first_cluster));
		start = PXT4_B2C(sbi, pxt4_group_first_block_no(sb, group));
		group -= flpxt2_gd->groups[0].group;

		count2 = PXT4_CLUSTERS_PER_GROUP(sb) - (first_cluster - start);
		if (count2 > count)
			count2 = count;

		if (flpxt2_gd->bg_flags[group] & PXT4_BG_BLOCK_UNINIT) {
			BUG_ON(flpxt2_gd->count > 1);
			continue;
		}

		err = pxt2tend_or_restart_transaction(handle, 1);
		if (err)
			return err;

		bh = sb_getblk(sb, flpxt2_gd->groups[group].block_bitmap);
		if (unlikely(!bh))
			return -ENOMEM;

		BUFFER_TRACE(bh, "get_write_access");
		err = pxt4_journal_get_write_access(handle, bh);
		if (err) {
			brelse(bh);
			return err;
		}
		pxt4_debug("mark block bitmap %#04llx (+%llu/%u)\n",
			   first_cluster, first_cluster - start, count2);
		pxt4_set_bits(bh->b_data, first_cluster - start, count2);

		err = pxt4_handle_dirty_metadata(handle, NULL, bh);
		brelse(bh);
		if (unlikely(err))
			return err;
	}

	return 0;
}

/*
 * Set up the block and inode bitmaps, and the inode table for the new groups.
 * This doesn't need to be part of the main transaction, since we are only
 * changing blocks outside the actual filesystem.  We still do journaling to
 * ensure the recovery is correct in case of a failure just after resize.
 * If any part of this fails, we simply abort the resize.
 *
 * setup_new_flpxt2_group_blocks handles a flpxt2 group as follow:
 *  1. copy super block and GDT, and initialize group tables if necessary.
 *     In this step, we only set bits in blocks bitmaps for blocks taken by
 *     super block and GDT.
 *  2. allocate group tables in block bitmaps, that is, set bits in block
 *     bitmap for blocks taken by group tables.
 */
static int setup_new_flpxt2_group_blocks(struct super_block *sb,
				struct pxt4_new_flpxt2_group_data *flpxt2_gd)
{
	int group_table_count[] = {1, 1, PXT4_SB(sb)->s_itb_per_group};
	pxt4_fsblk_t start;
	pxt4_fsblk_t block;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	struct pxt4_new_group_data *group_data = flpxt2_gd->groups;
	__u16 *bg_flags = flpxt2_gd->bg_flags;
	handle_t *handle;
	pxt4_group_t group, count;
	struct buffer_head *bh = NULL;
	int reserved_gdb, i, j, err = 0, err2;
	int meta_bg;

	BUG_ON(!flpxt2_gd->count || !group_data ||
	       group_data[0].group != sbi->s_groups_count);

	reserved_gdb = le16_to_cpu(es->s_reserved_gdt_blocks);
	meta_bg = pxt4_has_feature_meta_bg(sb);

	/* This transaction may be pxt2tended/restarted along the way */
	handle = pxt4_journal_start_sb(sb, PXT4_HT_RESIZE, PXT4_MAX_TRANS_DATA);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	group = group_data[0].group;
	for (i = 0; i < flpxt2_gd->count; i++, group++) {
		unsigned long gdblocks;
		pxt4_grpblk_t overhead;

		gdblocks = pxt4_bg_num_gdb(sb, group);
		start = pxt4_group_first_block_no(sb, group);

		if (meta_bg == 0 && !pxt4_bg_has_super(sb, group))
			goto handle_itb;

		if (meta_bg == 1) {
			pxt4_group_t first_group;
			first_group = pxt4_meta_bg_first_group(sb, group);
			if (first_group != group + 1 &&
			    first_group != group + PXT4_DESC_PER_BLOCK(sb) - 1)
				goto handle_itb;
		}

		block = start + pxt4_bg_has_super(sb, group);
		/* Copy all of the GDT blocks into the backup in this group */
		for (j = 0; j < gdblocks; j++, block++) {
			struct buffer_head *gdb;

			pxt4_debug("update backup group %#04llx\n", block);
			err = pxt2tend_or_restart_transaction(handle, 1);
			if (err)
				goto out;

			gdb = sb_getblk(sb, block);
			if (unlikely(!gdb)) {
				err = -ENOMEM;
				goto out;
			}

			BUFFER_TRACE(gdb, "get_write_access");
			err = pxt4_journal_get_write_access(handle, gdb);
			if (err) {
				brelse(gdb);
				goto out;
			}
			memcpy(gdb->b_data, sbi_array_rcu_deref(sbi,
				s_group_desc, j)->b_data, gdb->b_size);
			set_buffer_uptodate(gdb);

			err = pxt4_handle_dirty_metadata(handle, NULL, gdb);
			if (unlikely(err)) {
				brelse(gdb);
				goto out;
			}
			brelse(gdb);
		}

		/* Zero out all of the reserved backup group descriptor
		 * table blocks
		 */
		if (pxt4_bg_has_super(sb, group)) {
			err = sb_issue_zeroout(sb, gdblocks + start + 1,
					reserved_gdb, GFP_NOFS);
			if (err)
				goto out;
		}

handle_itb:
		/* Initialize group tables of the grop @group */
		if (!(bg_flags[i] & PXT4_BG_INODE_ZEROED))
			goto handle_bb;

		/* Zero out all of the inode table blocks */
		block = group_data[i].inode_table;
		pxt4_debug("clear inode table blocks %#04llx -> %#04lx\n",
			   block, sbi->s_itb_per_group);
		err = sb_issue_zeroout(sb, block, sbi->s_itb_per_group,
				       GFP_NOFS);
		if (err)
			goto out;

handle_bb:
		if (bg_flags[i] & PXT4_BG_BLOCK_UNINIT)
			goto handle_ib;

		/* Initialize block bitmap of the @group */
		block = group_data[i].block_bitmap;
		err = pxt2tend_or_restart_transaction(handle, 1);
		if (err)
			goto out;

		bh = bclean(handle, sb, block);
		if (IS_ERR(bh)) {
			err = PTR_ERR(bh);
			goto out;
		}
		overhead = pxt4_group_overhead_blocks(sb, group);
		if (overhead != 0) {
			pxt4_debug("mark backup superblock %#04llx (+0)\n",
				   start);
			pxt4_set_bits(bh->b_data, 0,
				      PXT4_NUM_B2C(sbi, overhead));
		}
		pxt4_mark_bitmap_end(PXT4_B2C(sbi, group_data[i].blocks_count),
				     sb->s_blocksize * 8, bh->b_data);
		err = pxt4_handle_dirty_metadata(handle, NULL, bh);
		brelse(bh);
		if (err)
			goto out;

handle_ib:
		if (bg_flags[i] & PXT4_BG_INODE_UNINIT)
			continue;

		/* Initialize inode bitmap of the @group */
		block = group_data[i].inode_bitmap;
		err = pxt2tend_or_restart_transaction(handle, 1);
		if (err)
			goto out;
		/* Mark unused entries in inode bitmap used */
		bh = bclean(handle, sb, block);
		if (IS_ERR(bh)) {
			err = PTR_ERR(bh);
			goto out;
		}

		pxt4_mark_bitmap_end(PXT4_INODES_PER_GROUP(sb),
				     sb->s_blocksize * 8, bh->b_data);
		err = pxt4_handle_dirty_metadata(handle, NULL, bh);
		brelse(bh);
		if (err)
			goto out;
	}

	/* Mark group tables in block bitmap */
	for (j = 0; j < GROUP_TABLE_COUNT; j++) {
		count = group_table_count[j];
		start = (&group_data[0].block_bitmap)[j];
		block = start;
		for (i = 1; i < flpxt2_gd->count; i++) {
			block += group_table_count[j];
			if (block == (&group_data[i].block_bitmap)[j]) {
				count += group_table_count[j];
				continue;
			}
			err = set_flpxt2bg_block_bitmap(sb, handle,
						      flpxt2_gd,
						      PXT4_B2C(sbi, start),
						      PXT4_B2C(sbi,
							       start + count
							       - 1));
			if (err)
				goto out;
			count = group_table_count[j];
			start = (&group_data[i].block_bitmap)[j];
			block = start;
		}

		if (count) {
			err = set_flpxt2bg_block_bitmap(sb, handle,
						      flpxt2_gd,
						      PXT4_B2C(sbi, start),
						      PXT4_B2C(sbi,
							       start + count
							       - 1));
			if (err)
				goto out;
		}
	}

out:
	err2 = pxt4_journal_stop(handle);
	if (err2 && !err)
		err = err2;

	return err;
}

/*
 * Iterate through the groups which hold BACKUP superblock/GDT copies in an
 * pxt4 filesystem.  The counters should be initialized to 1, 5, and 7 before
 * calling this for the first time.  In a sparse filesystem it will be the
 * sequence of powers of 3, 5, and 7: 1, 3, 5, 7, 9, 25, 27, 49, 81, ...
 * For a non-sparse filesystem it will be every group: 1, 2, 3, 4, ...
 */
static unsigned pxt4_list_backups(struct super_block *sb, unsigned *three,
				  unsigned *five, unsigned *seven)
{
	unsigned *min = three;
	int mult = 3;
	unsigned ret;

	if (!pxt4_has_feature_sparse_super(sb)) {
		ret = *min;
		*min += 1;
		return ret;
	}

	if (*five < *min) {
		min = five;
		mult = 5;
	}
	if (*seven < *min) {
		min = seven;
		mult = 7;
	}

	ret = *min;
	*min *= mult;

	return ret;
}

/*
 * Check that all of the backup GDT blocks are held in the primary GDT block.
 * It is assumed that they are stored in group order.  Returns the number of
 * groups in current filesystem that have BACKUPS, or -ve error code.
 */
static int verify_reserved_gdb(struct super_block *sb,
			       pxt4_group_t end,
			       struct buffer_head *primary)
{
	const pxt4_fsblk_t blk = primary->b_blocknr;
	unsigned three = 1;
	unsigned five = 5;
	unsigned seven = 7;
	unsigned grp;
	__le32 *p = (__le32 *)primary->b_data;
	int gdbackups = 0;

	while ((grp = pxt4_list_backups(sb, &three, &five, &seven)) < end) {
		if (le32_to_cpu(*p++) !=
		    grp * PXT4_BLOCKS_PER_GROUP(sb) + blk){
			pxt4_warning(sb, "reserved GDT %llu"
				     " missing grp %d (%llu)",
				     blk, grp,
				     grp *
				     (pxt4_fsblk_t)PXT4_BLOCKS_PER_GROUP(sb) +
				     blk);
			return -EINVAL;
		}
		if (++gdbackups > PXT4_ADDR_PER_BLOCK(sb))
			return -EFBIG;
	}

	return gdbackups;
}

/*
 * Called when we need to bring a reserved group descriptor table block into
 * use from the resize inode.  The primary copy of the new GDT block currently
 * is an indirect block (under the double indirect block in the resize inode).
 * The new backup GDT blocks will be stored as leaf blocks in this indirect
 * block, in group order.  Even though we know all the block numbers we need,
 * we check to ensure that the resize inode has actually reserved these blocks.
 *
 * Don't need to update the block bitmaps because the blocks are still in use.
 *
 * We get all of the error cases out of the way, so that we are sure to not
 * fail once we start modifying the data on disk, because JBD has no rollback.
 */
static int add_new_gdb(handle_t *handle, struct inode *inode,
		       pxt4_group_t group)
{
	struct super_block *sb = inode->i_sb;
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;
	unsigned long gdb_num = group / PXT4_DESC_PER_BLOCK(sb);
	pxt4_fsblk_t gdblock = PXT4_SB(sb)->s_sbh->b_blocknr + 1 + gdb_num;
	struct buffer_head **o_group_desc, **n_group_desc = NULL;
	struct buffer_head *dind = NULL;
	struct buffer_head *gdb_bh = NULL;
	int gdbackups;
	struct pxt4_iloc iloc = { .bh = NULL };
	__le32 *data;
	int err;

	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG
		       "PXT4-fs: pxt4_add_new_gdb: adding group block %lu\n",
		       gdb_num);

	gdb_bh = pxt4_sb_bread(sb, gdblock, 0);
	if (IS_ERR(gdb_bh))
		return PTR_ERR(gdb_bh);

	gdbackups = verify_reserved_gdb(sb, group, gdb_bh);
	if (gdbackups < 0) {
		err = gdbackups;
		goto errout;
	}

	data = PXT4_I(inode)->i_data + PXT4_DIND_BLOCK;
	dind = pxt4_sb_bread(sb, le32_to_cpu(*data), 0);
	if (IS_ERR(dind)) {
		err = PTR_ERR(dind);
		dind = NULL;
		goto errout;
	}

	data = (__le32 *)dind->b_data;
	if (le32_to_cpu(data[gdb_num % PXT4_ADDR_PER_BLOCK(sb)]) != gdblock) {
		pxt4_warning(sb, "new group %u GDT block %llu not reserved",
			     group, gdblock);
		err = -EINVAL;
		goto errout;
	}

	BUFFER_TRACE(PXT4_SB(sb)->s_sbh, "get_write_access");
	err = pxt4_journal_get_write_access(handle, PXT4_SB(sb)->s_sbh);
	if (unlikely(err))
		goto errout;

	BUFFER_TRACE(gdb_bh, "get_write_access");
	err = pxt4_journal_get_write_access(handle, gdb_bh);
	if (unlikely(err))
		goto errout;

	BUFFER_TRACE(dind, "get_write_access");
	err = pxt4_journal_get_write_access(handle, dind);
	if (unlikely(err))
		pxt4_std_error(sb, err);

	/* pxt4_reserve_inode_write() gets a reference on the iloc */
	err = pxt4_reserve_inode_write(handle, inode, &iloc);
	if (unlikely(err))
		goto errout;

	n_group_desc = pxt4_kvmalloc((gdb_num + 1) *
				     sizeof(struct buffer_head *),
				     GFP_NOFS);
	if (!n_group_desc) {
		err = -ENOMEM;
		pxt4_warning(sb, "not enough memory for %lu groups",
			     gdb_num + 1);
		goto errout;
	}

	/*
	 * Finally, we have all of the possible failures behind us...
	 *
	 * Remove new GDT block from inode double-indirect block and clear out
	 * the new GDT block for use (which also "frees" the backup GDT blocks
	 * from the reserved inode).  We don't need to change the bitmaps for
	 * these blocks, because they are marked as in-use from being in the
	 * reserved inode, and will become GDT blocks (primary and backup).
	 */
	data[gdb_num % PXT4_ADDR_PER_BLOCK(sb)] = 0;
	err = pxt4_handle_dirty_metadata(handle, NULL, dind);
	if (unlikely(err)) {
		pxt4_std_error(sb, err);
		goto errout;
	}
	inode->i_blocks -= (gdbackups + 1) * sb->s_blocksize >>
			   (9 - PXT4_SB(sb)->s_cluster_bits);
	pxt4_mark_iloc_dirty(handle, inode, &iloc);
	memset(gdb_bh->b_data, 0, sb->s_blocksize);
	err = pxt4_handle_dirty_metadata(handle, NULL, gdb_bh);
	if (unlikely(err)) {
		pxt4_std_error(sb, err);
		iloc.bh = NULL;
		goto errout;
	}
	brelse(dind);

	rcu_read_lock();
	o_group_desc = rcu_dereference(PXT4_SB(sb)->s_group_desc);
	memcpy(n_group_desc, o_group_desc,
	       PXT4_SB(sb)->s_gdb_count * sizeof(struct buffer_head *));
	rcu_read_unlock();
	n_group_desc[gdb_num] = gdb_bh;
	rcu_assign_pointer(PXT4_SB(sb)->s_group_desc, n_group_desc);
	PXT4_SB(sb)->s_gdb_count++;
	pxt4_kvfree_array_rcu(o_group_desc);

	le16_add_cpu(&es->s_reserved_gdt_blocks, -1);
	err = pxt4_handle_dirty_super(handle, sb);
	if (err)
		pxt4_std_error(sb, err);
	return err;
errout:
	kvfree(n_group_desc);
	brelse(iloc.bh);
	brelse(dind);
	brelse(gdb_bh);

	pxt4_debug("leaving with error %d\n", err);
	return err;
}

/*
 * add_new_gdb_meta_bg is the sister of add_new_gdb.
 */
static int add_new_gdb_meta_bg(struct super_block *sb,
			       handle_t *handle, pxt4_group_t group) {
	pxt4_fsblk_t gdblock;
	struct buffer_head *gdb_bh;
	struct buffer_head **o_group_desc, **n_group_desc;
	unsigned long gdb_num = group / PXT4_DESC_PER_BLOCK(sb);
	int err;

	gdblock = pxt4_meta_bg_first_block_no(sb, group) +
		   pxt4_bg_has_super(sb, group);
	gdb_bh = pxt4_sb_bread(sb, gdblock, 0);
	if (IS_ERR(gdb_bh))
		return PTR_ERR(gdb_bh);
	n_group_desc = pxt4_kvmalloc((gdb_num + 1) *
				     sizeof(struct buffer_head *),
				     GFP_NOFS);
	if (!n_group_desc) {
		brelse(gdb_bh);
		err = -ENOMEM;
		pxt4_warning(sb, "not enough memory for %lu groups",
			     gdb_num + 1);
		return err;
	}

	rcu_read_lock();
	o_group_desc = rcu_dereference(PXT4_SB(sb)->s_group_desc);
	memcpy(n_group_desc, o_group_desc,
	       PXT4_SB(sb)->s_gdb_count * sizeof(struct buffer_head *));
	rcu_read_unlock();
	n_group_desc[gdb_num] = gdb_bh;

	BUFFER_TRACE(gdb_bh, "get_write_access");
	err = pxt4_journal_get_write_access(handle, gdb_bh);
	if (err) {
		kvfree(n_group_desc);
		brelse(gdb_bh);
		return err;
	}

	rcu_assign_pointer(PXT4_SB(sb)->s_group_desc, n_group_desc);
	PXT4_SB(sb)->s_gdb_count++;
	pxt4_kvfree_array_rcu(o_group_desc);
	return err;
}

/*
 * Called when we are adding a new group which has a backup copy of each of
 * the GDT blocks (i.e. sparse group) and there are reserved GDT blocks.
 * We need to add these reserved backup GDT blocks to the resize inode, so
 * that they are kept for future resizing and not allocated to files.
 *
 * Each reserved backup GDT block will go into a different indirect block.
 * The indirect blocks are actually the primary reserved GDT blocks,
 * so we know in advance what their block numbers are.  We only get the
 * double-indirect block to verify it is pointing to the primary reserved
 * GDT blocks so we don't overwrite a data block by accident.  The reserved
 * backup GDT blocks are stored in their reserved primary GDT block.
 */
static int reserve_backup_gdb(handle_t *handle, struct inode *inode,
			      pxt4_group_t group)
{
	struct super_block *sb = inode->i_sb;
	int reserved_gdb =le16_to_cpu(PXT4_SB(sb)->s_es->s_reserved_gdt_blocks);
	int cluster_bits = PXT4_SB(sb)->s_cluster_bits;
	struct buffer_head **primary;
	struct buffer_head *dind;
	struct pxt4_iloc iloc;
	pxt4_fsblk_t blk;
	__le32 *data, *end;
	int gdbackups = 0;
	int res, i;
	int err;

	primary = kmalloc_array(reserved_gdb, sizeof(*primary), GFP_NOFS);
	if (!primary)
		return -ENOMEM;

	data = PXT4_I(inode)->i_data + PXT4_DIND_BLOCK;
	dind = pxt4_sb_bread(sb, le32_to_cpu(*data), 0);
	if (IS_ERR(dind)) {
		err = PTR_ERR(dind);
		dind = NULL;
		goto pxt2it_free;
	}

	blk = PXT4_SB(sb)->s_sbh->b_blocknr + 1 + PXT4_SB(sb)->s_gdb_count;
	data = (__le32 *)dind->b_data + (PXT4_SB(sb)->s_gdb_count %
					 PXT4_ADDR_PER_BLOCK(sb));
	end = (__le32 *)dind->b_data + PXT4_ADDR_PER_BLOCK(sb);

	/* Get each reserved primary GDT block and verify it holds backups */
	for (res = 0; res < reserved_gdb; res++, blk++) {
		if (le32_to_cpu(*data) != blk) {
			pxt4_warning(sb, "reserved block %llu"
				     " not at offset %ld",
				     blk,
				     (long)(data - (__le32 *)dind->b_data));
			err = -EINVAL;
			goto pxt2it_bh;
		}
		primary[res] = pxt4_sb_bread(sb, blk, 0);
		if (IS_ERR(primary[res])) {
			err = PTR_ERR(primary[res]);
			primary[res] = NULL;
			goto pxt2it_bh;
		}
		gdbackups = verify_reserved_gdb(sb, group, primary[res]);
		if (gdbackups < 0) {
			brelse(primary[res]);
			err = gdbackups;
			goto pxt2it_bh;
		}
		if (++data >= end)
			data = (__le32 *)dind->b_data;
	}

	for (i = 0; i < reserved_gdb; i++) {
		BUFFER_TRACE(primary[i], "get_write_access");
		if ((err = pxt4_journal_get_write_access(handle, primary[i])))
			goto pxt2it_bh;
	}

	if ((err = pxt4_reserve_inode_write(handle, inode, &iloc)))
		goto pxt2it_bh;

	/*
	 * Finally we can add each of the reserved backup GDT blocks from
	 * the new group to its reserved primary GDT block.
	 */
	blk = group * PXT4_BLOCKS_PER_GROUP(sb);
	for (i = 0; i < reserved_gdb; i++) {
		int err2;
		data = (__le32 *)primary[i]->b_data;
		/* printk("reserving backup %lu[%u] = %lu\n",
		       primary[i]->b_blocknr, gdbackups,
		       blk + primary[i]->b_blocknr); */
		data[gdbackups] = cpu_to_le32(blk + primary[i]->b_blocknr);
		err2 = pxt4_handle_dirty_metadata(handle, NULL, primary[i]);
		if (!err)
			err = err2;
	}

	inode->i_blocks += reserved_gdb * sb->s_blocksize >> (9 - cluster_bits);
	pxt4_mark_iloc_dirty(handle, inode, &iloc);

pxt2it_bh:
	while (--res >= 0)
		brelse(primary[res]);
	brelse(dind);

pxt2it_free:
	kfree(primary);

	return err;
}

/*
 * Update the backup copies of the pxt4 metadata.  These don't need to be part
 * of the main resize transaction, because e2fsck will re-write them if there
 * is a problem (basically only OOM will cause a problem).  However, we
 * _should_ update the backups if possible, in case the primary gets trashed
 * for some reason and we need to run e2fsck from a backup superblock.  The
 * important part is that the new block and inode counts are in the backup
 * superblocks, and the location of the new group metadata in the GDT backups.
 *
 * We do not need take the s_resize_lock for this, because these
 * blocks are not otherwise touched by the filesystem code when it is
 * mounted.  We don't need to worry about last changing from
 * sbi->s_groups_count, because the worst that can happen is that we
 * do not copy the full number of backups at this time.  The resize
 * which changed s_groups_count will backup again.
 */
static void update_backups(struct super_block *sb, sector_t blk_off, char *data,
			   int size, int meta_bg)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	pxt4_group_t last;
	const int bpg = PXT4_BLOCKS_PER_GROUP(sb);
	unsigned three = 1;
	unsigned five = 5;
	unsigned seven = 7;
	pxt4_group_t group = 0;
	int rest = sb->s_blocksize - size;
	handle_t *handle;
	int err = 0, err2;

	handle = pxt4_journal_start_sb(sb, PXT4_HT_RESIZE, PXT4_MAX_TRANS_DATA);
	if (IS_ERR(handle)) {
		group = 1;
		err = PTR_ERR(handle);
		goto pxt2it_err;
	}

	if (meta_bg == 0) {
		group = pxt4_list_backups(sb, &three, &five, &seven);
		last = sbi->s_groups_count;
	} else {
		group = pxt4_get_group_number(sb, blk_off) + 1;
		last = (pxt4_group_t)(group + PXT4_DESC_PER_BLOCK(sb) - 2);
	}

	while (group < sbi->s_groups_count) {
		struct buffer_head *bh;
		pxt4_fsblk_t backup_block;

		/* Out of journal space, and can't get more - abort - so sad */
		if (pxt4_handle_valid(handle) &&
		    handle->h_buffer_credits == 0 &&
		    pxt4_journal_pxt2tend(handle, PXT4_MAX_TRANS_DATA) &&
		    (err = pxt4_journal_restart(handle, PXT4_MAX_TRANS_DATA)))
			break;

		if (meta_bg == 0)
			backup_block = ((pxt4_fsblk_t)group) * bpg + blk_off;
		else
			backup_block = (pxt4_group_first_block_no(sb, group) +
					pxt4_bg_has_super(sb, group));

		bh = sb_getblk(sb, backup_block);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			break;
		}
		pxt4_debug("update metadata backup %llu(+%llu)\n",
			   backup_block, backup_block -
			   pxt4_group_first_block_no(sb, group));
		BUFFER_TRACE(bh, "get_write_access");
		if ((err = pxt4_journal_get_write_access(handle, bh))) {
			brelse(bh);
			break;
		}
		lock_buffer(bh);
		memcpy(bh->b_data, data, size);
		if (rest)
			memset(bh->b_data + size, 0, rest);
		set_buffer_uptodate(bh);
		unlock_buffer(bh);
		err = pxt4_handle_dirty_metadata(handle, NULL, bh);
		if (unlikely(err))
			pxt4_std_error(sb, err);
		brelse(bh);

		if (meta_bg == 0)
			group = pxt4_list_backups(sb, &three, &five, &seven);
		else if (group == last)
			break;
		else
			group = last;
	}
	if ((err2 = pxt4_journal_stop(handle)) && !err)
		err = err2;

	/*
	 * Ugh! Need to have e2fsck write the backup copies.  It is too
	 * late to revert the resize, we shouldn't fail just because of
	 * the backup copies (they are only needed in case of corruption).
	 *
	 * However, if we got here we have a journal problem too, so we
	 * can't really start a transaction to mark the superblock.
	 * Chicken out and just set the flag on the hope it will be written
	 * to disk, and if not - we will simply wait until npxt2t fsck.
	 */
pxt2it_err:
	if (err) {
		pxt4_warning(sb, "can't update backup for group %u (err %d), "
			     "forcing fsck on npxt2t reboot", group, err);
		sbi->s_mount_state &= ~PXT4_VALID_FS;
		sbi->s_es->s_state &= cpu_to_le16(~PXT4_VALID_FS);
		mark_buffer_dirty(sbi->s_sbh);
	}
}

/*
 * pxt4_add_new_descs() adds @count group descriptor of groups
 * starting at @group
 *
 * @handle: journal handle
 * @sb: super block
 * @group: the group no. of the first group desc to be added
 * @resize_inode: the resize inode
 * @count: number of group descriptors to be added
 */
static int pxt4_add_new_descs(handle_t *handle, struct super_block *sb,
			      pxt4_group_t group, struct inode *resize_inode,
			      pxt4_group_t count)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	struct buffer_head *gdb_bh;
	int i, gdb_off, gdb_num, err = 0;
	int meta_bg;

	meta_bg = pxt4_has_feature_meta_bg(sb);
	for (i = 0; i < count; i++, group++) {
		int reserved_gdb = pxt4_bg_has_super(sb, group) ?
			le16_to_cpu(es->s_reserved_gdt_blocks) : 0;

		gdb_off = group % PXT4_DESC_PER_BLOCK(sb);
		gdb_num = group / PXT4_DESC_PER_BLOCK(sb);

		/*
		 * We will only either add reserved group blocks to a backup group
		 * or remove reserved blocks for the first group in a new group block.
		 * Doing both would be mean more complpxt2 code, and sane people don't
		 * use non-sparse filesystems anymore.  This is already checked above.
		 */
		if (gdb_off) {
			gdb_bh = sbi_array_rcu_deref(sbi, s_group_desc,
						     gdb_num);
			BUFFER_TRACE(gdb_bh, "get_write_access");
			err = pxt4_journal_get_write_access(handle, gdb_bh);

			if (!err && reserved_gdb && pxt4_bg_num_gdb(sb, group))
				err = reserve_backup_gdb(handle, resize_inode, group);
		} else if (meta_bg != 0) {
			err = add_new_gdb_meta_bg(sb, handle, group);
		} else {
			err = add_new_gdb(handle, resize_inode, group);
		}
		if (err)
			break;
	}
	return err;
}

static struct buffer_head *pxt4_get_bitmap(struct super_block *sb, __u64 block)
{
	struct buffer_head *bh = sb_getblk(sb, block);
	if (unlikely(!bh))
		return NULL;
	if (!bh_uptodate_or_lock(bh)) {
		if (bh_submit_read(bh) < 0) {
			brelse(bh);
			return NULL;
		}
	}

	return bh;
}

static int pxt4_set_bitmap_checksums(struct super_block *sb,
				     pxt4_group_t group,
				     struct pxt4_group_desc *gdp,
				     struct pxt4_new_group_data *group_data)
{
	struct buffer_head *bh;

	if (!pxt4_has_metadata_csum(sb))
		return 0;

	bh = pxt4_get_bitmap(sb, group_data->inode_bitmap);
	if (!bh)
		return -EIO;
	pxt4_inode_bitmap_csum_set(sb, group, gdp, bh,
				   PXT4_INODES_PER_GROUP(sb) / 8);
	brelse(bh);

	bh = pxt4_get_bitmap(sb, group_data->block_bitmap);
	if (!bh)
		return -EIO;
	pxt4_block_bitmap_csum_set(sb, group, gdp, bh);
	brelse(bh);

	return 0;
}

/*
 * pxt4_setup_new_descs() will set up the group descriptor descriptors of a flpxt2 bg
 */
static int pxt4_setup_new_descs(handle_t *handle, struct super_block *sb,
				struct pxt4_new_flpxt2_group_data *flpxt2_gd)
{
	struct pxt4_new_group_data	*group_data = flpxt2_gd->groups;
	struct pxt4_group_desc		*gdp;
	struct pxt4_sb_info		*sbi = PXT4_SB(sb);
	struct buffer_head		*gdb_bh;
	pxt4_group_t			group;
	__u16				*bg_flags = flpxt2_gd->bg_flags;
	int				i, gdb_off, gdb_num, err = 0;


	for (i = 0; i < flpxt2_gd->count; i++, group_data++, bg_flags++) {
		group = group_data->group;

		gdb_off = group % PXT4_DESC_PER_BLOCK(sb);
		gdb_num = group / PXT4_DESC_PER_BLOCK(sb);

		/*
		 * get_write_access() has been called on gdb_bh by pxt4_add_new_desc().
		 */
		gdb_bh = sbi_array_rcu_deref(sbi, s_group_desc, gdb_num);
		/* Update group descriptor block for new group */
		gdp = (struct pxt4_group_desc *)(gdb_bh->b_data +
						 gdb_off * PXT4_DESC_SIZE(sb));

		memset(gdp, 0, PXT4_DESC_SIZE(sb));
		pxt4_block_bitmap_set(sb, gdp, group_data->block_bitmap);
		pxt4_inode_bitmap_set(sb, gdp, group_data->inode_bitmap);
		err = pxt4_set_bitmap_checksums(sb, group, gdp, group_data);
		if (err) {
			pxt4_std_error(sb, err);
			break;
		}

		pxt4_inode_table_set(sb, gdp, group_data->inode_table);
		pxt4_free_group_clusters_set(sb, gdp,
					     group_data->free_clusters_count);
		pxt4_free_inodes_set(sb, gdp, PXT4_INODES_PER_GROUP(sb));
		if (pxt4_has_group_desc_csum(sb))
			pxt4_itable_unused_set(sb, gdp,
					       PXT4_INODES_PER_GROUP(sb));
		gdp->bg_flags = cpu_to_le16(*bg_flags);
		pxt4_group_desc_csum_set(sb, group, gdp);

		err = pxt4_handle_dirty_metadata(handle, NULL, gdb_bh);
		if (unlikely(err)) {
			pxt4_std_error(sb, err);
			break;
		}

		/*
		 * We can allocate memory for mb_alloc based on the new group
		 * descriptor
		 */
		err = pxt4_mb_add_groupinfo(sb, group, gdp);
		if (err)
			break;
	}
	return err;
}

/*
 * pxt4_update_super() updates the super block so that the newly added
 * groups can be seen by the filesystem.
 *
 * @sb: super block
 * @flpxt2_gd: new added groups
 */
static void pxt4_update_super(struct super_block *sb,
			     struct pxt4_new_flpxt2_group_data *flpxt2_gd)
{
	pxt4_fsblk_t blocks_count = 0;
	pxt4_fsblk_t free_blocks = 0;
	pxt4_fsblk_t reserved_blocks = 0;
	struct pxt4_new_group_data *group_data = flpxt2_gd->groups;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	int i;

	BUG_ON(flpxt2_gd->count == 0 || group_data == NULL);
	/*
	 * Make the new blocks and inodes valid npxt2t.  We do this before
	 * increasing the group count so that once the group is enabled,
	 * all of its blocks and inodes are already valid.
	 *
	 * We always allocate group-by-group, then block-by-block or
	 * inode-by-inode within a group, so enabling these
	 * blocks/inodes before the group is live won't actually let us
	 * allocate the new space yet.
	 */
	for (i = 0; i < flpxt2_gd->count; i++) {
		blocks_count += group_data[i].blocks_count;
		free_blocks += PXT4_C2B(sbi, group_data[i].free_clusters_count);
	}

	reserved_blocks = pxt4_r_blocks_count(es) * 100;
	reserved_blocks = div64_u64(reserved_blocks, pxt4_blocks_count(es));
	reserved_blocks *= blocks_count;
	do_div(reserved_blocks, 100);

	pxt4_blocks_count_set(es, pxt4_blocks_count(es) + blocks_count);
	pxt4_free_blocks_count_set(es, pxt4_free_blocks_count(es) + free_blocks);
	le32_add_cpu(&es->s_inodes_count, PXT4_INODES_PER_GROUP(sb) *
		     flpxt2_gd->count);
	le32_add_cpu(&es->s_free_inodes_count, PXT4_INODES_PER_GROUP(sb) *
		     flpxt2_gd->count);

	pxt4_debug("free blocks count %llu", pxt4_free_blocks_count(es));
	/*
	 * We need to protect s_groups_count against other CPUs seeing
	 * inconsistent state in the superblock.
	 *
	 * The precise rules we use are:
	 *
	 * * Writers must perform a smp_wmb() after updating all
	 *   dependent data and before modifying the groups count
	 *
	 * * Readers must perform an smp_rmb() after reading the groups
	 *   count and before reading any dependent data.
	 *
	 * NB. These rules can be relaxed when checking the group count
	 * while freeing data, as we can only allocate from a block
	 * group after serialising against the group count, and we can
	 * only then free after serialising in turn against that
	 * allocation.
	 */
	smp_wmb();

	/* Update the global fs size fields */
	sbi->s_groups_count += flpxt2_gd->count;
	sbi->s_blockfile_groups = min_t(pxt4_group_t, sbi->s_groups_count,
			(PXT4_MAX_BLOCK_FILE_PHYS / PXT4_BLOCKS_PER_GROUP(sb)));

	/* Update the reserved block counts only once the new group is
	 * active. */
	pxt4_r_blocks_count_set(es, pxt4_r_blocks_count(es) +
				reserved_blocks);

	/* Update the free space counts */
	percpu_counter_add(&sbi->s_freeclusters_counter,
			   PXT4_NUM_B2C(sbi, free_blocks));
	percpu_counter_add(&sbi->s_freeinodes_counter,
			   PXT4_INODES_PER_GROUP(sb) * flpxt2_gd->count);

	pxt4_debug("free blocks count %llu",
		   percpu_counter_read(&sbi->s_freeclusters_counter));
	if (pxt4_has_feature_flpxt2_bg(sb) && sbi->s_log_groups_per_flpxt2) {
		pxt4_group_t flpxt2_group;
		struct flpxt2_groups *fg;

		flpxt2_group = pxt4_flpxt2_group(sbi, group_data[0].group);
		fg = sbi_array_rcu_deref(sbi, s_flpxt2_groups, flpxt2_group);
		atomic64_add(PXT4_NUM_B2C(sbi, free_blocks),
			     &fg->free_clusters);
		atomic_add(PXT4_INODES_PER_GROUP(sb) * flpxt2_gd->count,
			   &fg->free_inodes);
	}

	/*
	 * Update the fs overhead information
	 */
	pxt4_calculate_overhead(sb);

	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG "PXT4-fs: added group %u:"
		       "%llu blocks(%llu free %llu reserved)\n", flpxt2_gd->count,
		       blocks_count, free_blocks, reserved_blocks);
}

/* Add a flpxt2 group to an fs. Ensure we handle all possible error conditions
 * _before_ we start modifying the filesystem, because we cannot abort the
 * transaction and not have it write the data to disk.
 */
static int pxt4_flpxt2_group_add(struct super_block *sb,
			       struct inode *resize_inode,
			       struct pxt4_new_flpxt2_group_data *flpxt2_gd)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	pxt4_fsblk_t o_blocks_count;
	pxt4_grpblk_t last;
	pxt4_group_t group;
	handle_t *handle;
	unsigned reserved_gdb;
	int err = 0, err2 = 0, credit;

	BUG_ON(!flpxt2_gd->count || !flpxt2_gd->groups || !flpxt2_gd->bg_flags);

	reserved_gdb = le16_to_cpu(es->s_reserved_gdt_blocks);
	o_blocks_count = pxt4_blocks_count(es);
	pxt4_get_group_no_and_offset(sb, o_blocks_count, &group, &last);
	BUG_ON(last);

	err = setup_new_flpxt2_group_blocks(sb, flpxt2_gd);
	if (err)
		goto pxt2it;
	/*
	 * We will always be modifying at least the superblock and  GDT
	 * blocks.  If we are adding a group past the last current GDT block,
	 * we will also modify the inode and the dindirect block.  If we
	 * are adding a group with superblock/GDT backups  we will also
	 * modify each of the reserved GDT dindirect blocks.
	 */
	credit = 3;	/* sb, resize inode, resize inode dindirect */
	/* GDT blocks */
	credit += 1 + DIV_ROUND_UP(flpxt2_gd->count, PXT4_DESC_PER_BLOCK(sb));
	credit += reserved_gdb;	/* Reserved GDT dindirect blocks */
	handle = pxt4_journal_start_sb(sb, PXT4_HT_RESIZE, credit);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto pxt2it;
	}

	BUFFER_TRACE(sbi->s_sbh, "get_write_access");
	err = pxt4_journal_get_write_access(handle, sbi->s_sbh);
	if (err)
		goto pxt2it_journal;

	group = flpxt2_gd->groups[0].group;
	BUG_ON(group != sbi->s_groups_count);
	err = pxt4_add_new_descs(handle, sb, group,
				resize_inode, flpxt2_gd->count);
	if (err)
		goto pxt2it_journal;

	err = pxt4_setup_new_descs(handle, sb, flpxt2_gd);
	if (err)
		goto pxt2it_journal;

	pxt4_update_super(sb, flpxt2_gd);

	err = pxt4_handle_dirty_super(handle, sb);

pxt2it_journal:
	err2 = pxt4_journal_stop(handle);
	if (!err)
		err = err2;

	if (!err) {
		int gdb_num = group / PXT4_DESC_PER_BLOCK(sb);
		int gdb_num_end = ((group + flpxt2_gd->count - 1) /
				   PXT4_DESC_PER_BLOCK(sb));
		int meta_bg = pxt4_has_feature_meta_bg(sb);
		sector_t old_gdb = 0;

		update_backups(sb, sbi->s_sbh->b_blocknr, (char *)es,
			       sizeof(struct pxt4_super_block), 0);
		for (; gdb_num <= gdb_num_end; gdb_num++) {
			struct buffer_head *gdb_bh;

			gdb_bh = sbi_array_rcu_deref(sbi, s_group_desc,
						     gdb_num);
			if (old_gdb == gdb_bh->b_blocknr)
				continue;
			update_backups(sb, gdb_bh->b_blocknr, gdb_bh->b_data,
				       gdb_bh->b_size, meta_bg);
			old_gdb = gdb_bh->b_blocknr;
		}
	}
pxt2it:
	return err;
}

static int pxt4_setup_npxt2t_flpxt2_gd(struct super_block *sb,
				    struct pxt4_new_flpxt2_group_data *flpxt2_gd,
				    pxt4_fsblk_t n_blocks_count,
				    unsigned long flpxt2bg_size)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	struct pxt4_new_group_data *group_data = flpxt2_gd->groups;
	pxt4_fsblk_t o_blocks_count;
	pxt4_group_t n_group;
	pxt4_group_t group;
	pxt4_group_t last_group;
	pxt4_grpblk_t last;
	pxt4_grpblk_t clusters_per_group;
	unsigned long i;

	clusters_per_group = PXT4_CLUSTERS_PER_GROUP(sb);

	o_blocks_count = pxt4_blocks_count(es);

	if (o_blocks_count == n_blocks_count)
		return 0;

	pxt4_get_group_no_and_offset(sb, o_blocks_count, &group, &last);
	BUG_ON(last);
	pxt4_get_group_no_and_offset(sb, n_blocks_count - 1, &n_group, &last);

	last_group = group | (flpxt2bg_size - 1);
	if (last_group > n_group)
		last_group = n_group;

	flpxt2_gd->count = last_group - group + 1;

	for (i = 0; i < flpxt2_gd->count; i++) {
		int overhead;

		group_data[i].group = group + i;
		group_data[i].blocks_count = PXT4_BLOCKS_PER_GROUP(sb);
		overhead = pxt4_group_overhead_blocks(sb, group + i);
		group_data[i].mdata_blocks = overhead;
		group_data[i].free_clusters_count = PXT4_CLUSTERS_PER_GROUP(sb);
		if (pxt4_has_group_desc_csum(sb)) {
			flpxt2_gd->bg_flags[i] = PXT4_BG_BLOCK_UNINIT |
					       PXT4_BG_INODE_UNINIT;
			if (!test_opt(sb, INIT_INODE_TABLE))
				flpxt2_gd->bg_flags[i] |= PXT4_BG_INODE_ZEROED;
		} else
			flpxt2_gd->bg_flags[i] = PXT4_BG_INODE_ZEROED;
	}

	if (last_group == n_group && pxt4_has_group_desc_csum(sb))
		/* We need to initialize block bitmap of last group. */
		flpxt2_gd->bg_flags[i - 1] &= ~PXT4_BG_BLOCK_UNINIT;

	if ((last_group == n_group) && (last != clusters_per_group - 1)) {
		group_data[i - 1].blocks_count = PXT4_C2B(sbi, last + 1);
		group_data[i - 1].free_clusters_count -= clusters_per_group -
						       last - 1;
	}

	return 1;
}

/* Add group descriptor data to an pxt2isting or new group descriptor block.
 * Ensure we handle all possible error conditions _before_ we start modifying
 * the filesystem, because we cannot abort the transaction and not have it
 * write the data to disk.
 *
 * If we are on a GDT block boundary, we need to get the reserved GDT block.
 * Otherwise, we may need to add backup GDT blocks for a sparse group.
 *
 * We only need to hold the superblock lock while we are actually adding
 * in the new group's counts to the superblock.  Prior to that we have
 * not really "added" the group at all.  We re-check that we are still
 * adding in the last group in case things have changed since verifying.
 */
int pxt4_group_add(struct super_block *sb, struct pxt4_new_group_data *input)
{
	struct pxt4_new_flpxt2_group_data flpxt2_gd;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	int reserved_gdb = pxt4_bg_has_super(sb, input->group) ?
		le16_to_cpu(es->s_reserved_gdt_blocks) : 0;
	struct inode *inode = NULL;
	int gdb_off;
	int err;
	__u16 bg_flags = 0;

	gdb_off = input->group % PXT4_DESC_PER_BLOCK(sb);

	if (gdb_off == 0 && !pxt4_has_feature_sparse_super(sb)) {
		pxt4_warning(sb, "Can't resize non-sparse filesystem further");
		return -EPERM;
	}

	if (pxt4_blocks_count(es) + input->blocks_count <
	    pxt4_blocks_count(es)) {
		pxt4_warning(sb, "blocks_count overflow");
		return -EINVAL;
	}

	if (le32_to_cpu(es->s_inodes_count) + PXT4_INODES_PER_GROUP(sb) <
	    le32_to_cpu(es->s_inodes_count)) {
		pxt4_warning(sb, "inodes_count overflow");
		return -EINVAL;
	}

	if (reserved_gdb || gdb_off == 0) {
		if (!pxt4_has_feature_resize_inode(sb) ||
		    !le16_to_cpu(es->s_reserved_gdt_blocks)) {
			pxt4_warning(sb,
				     "No reserved GDT blocks, can't resize");
			return -EPERM;
		}
		inode = pxt4_iget(sb, PXT4_RESIZE_INO, PXT4_IGET_SPECIAL);
		if (IS_ERR(inode)) {
			pxt4_warning(sb, "Error opening resize inode");
			return PTR_ERR(inode);
		}
	}


	err = verify_group_input(sb, input);
	if (err)
		goto out;

	err = pxt4_alloc_flpxt2_bg_array(sb, input->group + 1);
	if (err)
		goto out;

	err = pxt4_mb_alloc_groupinfo(sb, input->group + 1);
	if (err)
		goto out;

	flpxt2_gd.count = 1;
	flpxt2_gd.groups = input;
	flpxt2_gd.bg_flags = &bg_flags;
	err = pxt4_flpxt2_group_add(sb, inode, &flpxt2_gd);
out:
	iput(inode);
	return err;
} /* pxt4_group_add */

/*
 * pxt2tend a group without checking assuming that checking has been done.
 */
static int pxt4_group_pxt2tend_no_check(struct super_block *sb,
				      pxt4_fsblk_t o_blocks_count, pxt4_grpblk_t add)
{
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;
	handle_t *handle;
	int err = 0, err2;

	/* We will update the superblock, one block bitmap, and
	 * one group descriptor via pxt4_group_add_blocks().
	 */
	handle = pxt4_journal_start_sb(sb, PXT4_HT_RESIZE, 3);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		pxt4_warning(sb, "error %d on journal start", err);
		return err;
	}

	BUFFER_TRACE(PXT4_SB(sb)->s_sbh, "get_write_access");
	err = pxt4_journal_get_write_access(handle, PXT4_SB(sb)->s_sbh);
	if (err) {
		pxt4_warning(sb, "error %d on journal write access", err);
		goto errout;
	}

	pxt4_blocks_count_set(es, o_blocks_count + add);
	pxt4_free_blocks_count_set(es, pxt4_free_blocks_count(es) + add);
	pxt4_debug("freeing blocks %llu through %llu\n", o_blocks_count,
		   o_blocks_count + add);
	/* We add the blocks to the bitmap and set the group need init bit */
	err = pxt4_group_add_blocks(handle, sb, o_blocks_count, add);
	if (err)
		goto errout;
	pxt4_handle_dirty_super(handle, sb);
	pxt4_debug("freed blocks %llu through %llu\n", o_blocks_count,
		   o_blocks_count + add);
errout:
	err2 = pxt4_journal_stop(handle);
	if (err2 && !err)
		err = err2;

	if (!err) {
		if (test_opt(sb, DEBUG))
			printk(KERN_DEBUG "PXT4-fs: pxt2tended group to %llu "
			       "blocks\n", pxt4_blocks_count(es));
		update_backups(sb, PXT4_SB(sb)->s_sbh->b_blocknr,
			       (char *)es, sizeof(struct pxt4_super_block), 0);
	}
	return err;
}

/*
 * Extend the filesystem to the new number of blocks specified.  This entry
 * point is only used to pxt2tend the current filesystem to the end of the last
 * pxt2isting group.  It can be accessed via ioctl, or by "remount,resize=<size>"
 * for emergencies (because it has no dependencies on reserved blocks).
 *
 * If we _really_ wanted, we could use default values to call pxt4_group_add()
 * allow the "remount" trick to work for arbitrary resizing, assuming enough
 * GDT blocks are reserved to grow to the desired size.
 */
int pxt4_group_pxt2tend(struct super_block *sb, struct pxt4_super_block *es,
		      pxt4_fsblk_t n_blocks_count)
{
	pxt4_fsblk_t o_blocks_count;
	pxt4_grpblk_t last;
	pxt4_grpblk_t add;
	struct buffer_head *bh;
	int err;
	pxt4_group_t group;

	o_blocks_count = pxt4_blocks_count(es);

	if (test_opt(sb, DEBUG))
		pxt4_msg(sb, KERN_DEBUG,
			 "pxt2tending last group from %llu to %llu blocks",
			 o_blocks_count, n_blocks_count);

	if (n_blocks_count == 0 || n_blocks_count == o_blocks_count)
		return 0;

	if (n_blocks_count > (sector_t)(~0ULL) >> (sb->s_blocksize_bits - 9)) {
		pxt4_msg(sb, KERN_ERR,
			 "filesystem too large to resize to %llu blocks safely",
			 n_blocks_count);
		return -EINVAL;
	}

	if (n_blocks_count < o_blocks_count) {
		pxt4_warning(sb, "can't shrink FS - resize aborted");
		return -EINVAL;
	}

	/* Handle the remaining blocks in the last group only. */
	pxt4_get_group_no_and_offset(sb, o_blocks_count, &group, &last);

	if (last == 0) {
		pxt4_warning(sb, "need to use pxt2t2online to resize further");
		return -EPERM;
	}

	add = PXT4_BLOCKS_PER_GROUP(sb) - last;

	if (o_blocks_count + add < o_blocks_count) {
		pxt4_warning(sb, "blocks_count overflow");
		return -EINVAL;
	}

	if (o_blocks_count + add > n_blocks_count)
		add = n_blocks_count - o_blocks_count;

	if (o_blocks_count + add < n_blocks_count)
		pxt4_warning(sb, "will only finish group (%llu blocks, %u new)",
			     o_blocks_count + add, add);

	/* See if the device is actually as big as what was requested */
	bh = sb_bread(sb, o_blocks_count + add - 1);
	if (!bh) {
		pxt4_warning(sb, "can't read last block, resize aborted");
		return -ENOSPC;
	}
	brelse(bh);

	err = pxt4_group_pxt2tend_no_check(sb, o_blocks_count, add);
	return err;
} /* pxt4_group_pxt2tend */


static int num_desc_blocks(struct super_block *sb, pxt4_group_t groups)
{
	return (groups + PXT4_DESC_PER_BLOCK(sb) - 1) / PXT4_DESC_PER_BLOCK(sb);
}

/*
 * Release the resize inode and drop the resize_inode feature if there
 * are no more reserved gdt blocks, and then convert the file system
 * to enable meta_bg
 */
static int pxt4_convert_meta_bg(struct super_block *sb, struct inode *inode)
{
	handle_t *handle;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	struct pxt4_inode_info *ei = PXT4_I(inode);
	pxt4_fsblk_t nr;
	int i, ret, err = 0;
	int credits = 1;

	pxt4_msg(sb, KERN_INFO, "Converting file system to meta_bg");
	if (inode) {
		if (es->s_reserved_gdt_blocks) {
			pxt4_error(sb, "Unpxt2pected non-zero "
				   "s_reserved_gdt_blocks");
			return -EPERM;
		}

		/* Do a quick sanity check of the resize inode */
		if (inode->i_blocks != 1 << (inode->i_blkbits -
					     (9 - sbi->s_cluster_bits)))
			goto invalid_resize_inode;
		for (i = 0; i < PXT4_N_BLOCKS; i++) {
			if (i == PXT4_DIND_BLOCK) {
				if (ei->i_data[i])
					continue;
				else
					goto invalid_resize_inode;
			}
			if (ei->i_data[i])
				goto invalid_resize_inode;
		}
		credits += 3;	/* block bitmap, bg descriptor, resize inode */
	}

	handle = pxt4_journal_start_sb(sb, PXT4_HT_RESIZE, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	BUFFER_TRACE(sbi->s_sbh, "get_write_access");
	err = pxt4_journal_get_write_access(handle, sbi->s_sbh);
	if (err)
		goto errout;

	pxt4_clear_feature_resize_inode(sb);
	pxt4_set_feature_meta_bg(sb);
	sbi->s_es->s_first_meta_bg =
		cpu_to_le32(num_desc_blocks(sb, sbi->s_groups_count));

	err = pxt4_handle_dirty_super(handle, sb);
	if (err) {
		pxt4_std_error(sb, err);
		goto errout;
	}

	if (inode) {
		nr = le32_to_cpu(ei->i_data[PXT4_DIND_BLOCK]);
		pxt4_free_blocks(handle, inode, NULL, nr, 1,
				 PXT4_FREE_BLOCKS_METADATA |
				 PXT4_FREE_BLOCKS_FORGET);
		ei->i_data[PXT4_DIND_BLOCK] = 0;
		inode->i_blocks = 0;

		err = pxt4_mark_inode_dirty(handle, inode);
		if (err)
			pxt4_std_error(sb, err);
	}

errout:
	ret = pxt4_journal_stop(handle);
	if (!err)
		err = ret;
	return ret;

invalid_resize_inode:
	pxt4_error(sb, "corrupted/inconsistent resize inode");
	return -EINVAL;
}

/*
 * pxt4_resize_fs() resizes a fs to new size specified by @n_blocks_count
 *
 * @sb: super block of the fs to be resized
 * @n_blocks_count: the number of blocks resides in the resized fs
 */
int pxt4_resize_fs(struct super_block *sb, pxt4_fsblk_t n_blocks_count)
{
	struct pxt4_new_flpxt2_group_data *flpxt2_gd = NULL;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	struct buffer_head *bh;
	struct inode *resize_inode = NULL;
	pxt4_grpblk_t add, offset;
	unsigned long n_desc_blocks;
	unsigned long o_desc_blocks;
	pxt4_group_t o_group;
	pxt4_group_t n_group;
	pxt4_fsblk_t o_blocks_count;
	pxt4_fsblk_t n_blocks_count_retry = 0;
	unsigned long last_update_time = 0;
	int err = 0, flpxt2bg_size = 1 << sbi->s_log_groups_per_flpxt2;
	int meta_bg;

	/* See if the device is actually as big as what was requested */
	bh = sb_bread(sb, n_blocks_count - 1);
	if (!bh) {
		pxt4_warning(sb, "can't read last block, resize aborted");
		return -ENOSPC;
	}
	brelse(bh);

retry:
	o_blocks_count = pxt4_blocks_count(es);

	pxt4_msg(sb, KERN_INFO, "resizing filesystem from %llu "
		 "to %llu blocks", o_blocks_count, n_blocks_count);

	if (n_blocks_count < o_blocks_count) {
		/* On-line shrinking not supported */
		pxt4_warning(sb, "can't shrink FS - resize aborted");
		return -EINVAL;
	}

	if (n_blocks_count == o_blocks_count)
		/* Nothing need to do */
		return 0;

	n_group = pxt4_get_group_number(sb, n_blocks_count - 1);
	if (n_group >= (0xFFFFFFFFUL / PXT4_INODES_PER_GROUP(sb))) {
		pxt4_warning(sb, "resize would cause inodes_count overflow");
		return -EINVAL;
	}
	pxt4_get_group_no_and_offset(sb, o_blocks_count - 1, &o_group, &offset);

	n_desc_blocks = num_desc_blocks(sb, n_group + 1);
	o_desc_blocks = num_desc_blocks(sb, sbi->s_groups_count);

	meta_bg = pxt4_has_feature_meta_bg(sb);

	if (pxt4_has_feature_resize_inode(sb)) {
		if (meta_bg) {
			pxt4_error(sb, "resize_inode and meta_bg enabled "
				   "simultaneously");
			return -EINVAL;
		}
		if (n_desc_blocks > o_desc_blocks +
		    le16_to_cpu(es->s_reserved_gdt_blocks)) {
			n_blocks_count_retry = n_blocks_count;
			n_desc_blocks = o_desc_blocks +
				le16_to_cpu(es->s_reserved_gdt_blocks);
			n_group = n_desc_blocks * PXT4_DESC_PER_BLOCK(sb);
			n_blocks_count = (pxt4_fsblk_t)n_group *
				PXT4_BLOCKS_PER_GROUP(sb) +
				le32_to_cpu(es->s_first_data_block);
			n_group--; /* set to last group number */
		}

		if (!resize_inode)
			resize_inode = pxt4_iget(sb, PXT4_RESIZE_INO,
						 PXT4_IGET_SPECIAL);
		if (IS_ERR(resize_inode)) {
			pxt4_warning(sb, "Error opening resize inode");
			return PTR_ERR(resize_inode);
		}
	}

	if ((!resize_inode && !meta_bg) || n_blocks_count == o_blocks_count) {
		err = pxt4_convert_meta_bg(sb, resize_inode);
		if (err)
			goto out;
		if (resize_inode) {
			iput(resize_inode);
			resize_inode = NULL;
		}
		if (n_blocks_count_retry) {
			n_blocks_count = n_blocks_count_retry;
			n_blocks_count_retry = 0;
			goto retry;
		}
	}

	/*
	 * Make sure the last group has enough space so that it's
	 * guaranteed to have enough space for all metadata blocks
	 * that it might need to hold.  (We might not need to store
	 * the inode table blocks in the last block group, but there
	 * will be cases where this might be needed.)
	 */
	if ((pxt4_group_first_block_no(sb, n_group) +
	     pxt4_group_overhead_blocks(sb, n_group) + 2 +
	     sbi->s_itb_per_group + sbi->s_cluster_ratio) >= n_blocks_count) {
		n_blocks_count = pxt4_group_first_block_no(sb, n_group);
		n_group--;
		n_blocks_count_retry = 0;
		if (resize_inode) {
			iput(resize_inode);
			resize_inode = NULL;
		}
		goto retry;
	}

	/* pxt2tend the last group */
	if (n_group == o_group)
		add = n_blocks_count - o_blocks_count;
	else
		add = PXT4_C2B(sbi, PXT4_CLUSTERS_PER_GROUP(sb) - (offset + 1));
	if (add > 0) {
		err = pxt4_group_pxt2tend_no_check(sb, o_blocks_count, add);
		if (err)
			goto out;
	}

	if (pxt4_blocks_count(es) == n_blocks_count)
		goto out;

	err = pxt4_alloc_flpxt2_bg_array(sb, n_group + 1);
	if (err)
		goto out;

	err = pxt4_mb_alloc_groupinfo(sb, n_group + 1);
	if (err)
		goto out;

	flpxt2_gd = alloc_flpxt2_gd(flpxt2bg_size);
	if (flpxt2_gd == NULL) {
		err = -ENOMEM;
		goto out;
	}

	/* Add flpxt2 groups. Note that a regular group is a
	 * flpxt2 group with 1 group.
	 */
	while (pxt4_setup_npxt2t_flpxt2_gd(sb, flpxt2_gd, n_blocks_count,
					      flpxt2bg_size)) {
		if (jiffies - last_update_time > HZ * 10) {
			if (last_update_time)
				pxt4_msg(sb, KERN_INFO,
					 "resized to %llu blocks",
					 pxt4_blocks_count(es));
			last_update_time = jiffies;
		}
		if (pxt4_alloc_group_tables(sb, flpxt2_gd, flpxt2bg_size) != 0)
			break;
		err = pxt4_flpxt2_group_add(sb, resize_inode, flpxt2_gd);
		if (unlikely(err))
			break;
	}

	if (!err && n_blocks_count_retry) {
		n_blocks_count = n_blocks_count_retry;
		n_blocks_count_retry = 0;
		free_flpxt2_gd(flpxt2_gd);
		flpxt2_gd = NULL;
		if (resize_inode) {
			iput(resize_inode);
			resize_inode = NULL;
		}
		goto retry;
	}

out:
	if (flpxt2_gd)
		free_flpxt2_gd(flpxt2_gd);
	if (resize_inode != NULL)
		iput(resize_inode);
	if (err)
		pxt4_warning(sb, "error (%d) occurred during "
			     "file system resize", err);
	pxt4_msg(sb, KERN_INFO, "resized filesystem to %llu",
		 pxt4_blocks_count(es));
	return err;
}
