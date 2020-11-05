// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) 2008,2009 NEC Software Tohoku, Ltd.
 * Written by Takashi Sato <t-sato@yk.jp.nec.com>
 *            Akira Fujita <a-fujita@rs.jp.nec.com>
 */

#include <linux/fs.h>
#include <linux/quotaops.h>
#include <linux/slab.h>
#include "pxt4_jbd3.h"
#include "pxt4.h"
#include "pxt4_pxt2tents.h"

/**
 * get_pxt2t_path() - Find an pxt2tent path for designated logical block number.
 * @inode:	inode to be searched
 * @lblock:	logical block number to find an pxt2tent path
 * @ppath:	pointer to an pxt2tent path pointer (for output)
 *
 * pxt4_find_pxt2tent wrapper. Return 0 on success, or a negative error value
 * on failure.
 */
static inline int
get_pxt2t_path(struct inode *inode, pxt4_lblk_t lblock,
		struct pxt4_pxt2t_path **ppath)
{
	struct pxt4_pxt2t_path *path;

	path = pxt4_find_pxt2tent(inode, lblock, ppath, PXT4_EX_NOCACHE);
	if (IS_ERR(path))
		return PTR_ERR(path);
	if (path[pxt2t_depth(inode)].p_pxt2t == NULL) {
		pxt4_pxt2t_drop_refs(path);
		kfree(path);
		*ppath = NULL;
		return -ENODATA;
	}
	*ppath = path;
	return 0;
}

/**
 * pxt4_double_down_write_data_sem() - write lock two inodes's i_data_sem
 * @first: inode to be locked
 * @second: inode to be locked
 *
 * Acquire write lock of i_data_sem of the two inodes
 */
void
pxt4_double_down_write_data_sem(struct inode *first, struct inode *second)
{
	if (first < second) {
		down_write(&PXT4_I(first)->i_data_sem);
		down_write_nested(&PXT4_I(second)->i_data_sem, I_DATA_SEM_OTHER);
	} else {
		down_write(&PXT4_I(second)->i_data_sem);
		down_write_nested(&PXT4_I(first)->i_data_sem, I_DATA_SEM_OTHER);

	}
}

/**
 * pxt4_double_up_write_data_sem - Release two inodes' write lock of i_data_sem
 *
 * @orig_inode:		original inode structure to be released its lock first
 * @donor_inode:	donor inode structure to be released its lock second
 * Release write lock of i_data_sem of two inodes (orig and donor).
 */
void
pxt4_double_up_write_data_sem(struct inode *orig_inode,
			      struct inode *donor_inode)
{
	up_write(&PXT4_I(orig_inode)->i_data_sem);
	up_write(&PXT4_I(donor_inode)->i_data_sem);
}

/**
 * mpxt2t_check_coverage - Check that all pxt2tents in range has the same type
 *
 * @inode:		inode in question
 * @from:		block offset of inode
 * @count:		block count to be checked
 * @unwritten:		pxt2tents pxt2pected to be unwritten
 * @err:		pointer to save error value
 *
 * Return 1 if all pxt2tents in range has pxt2pected type, and zero otherwise.
 */
static int
mpxt2t_check_coverage(struct inode *inode, pxt4_lblk_t from, pxt4_lblk_t count,
		    int unwritten, int *err)
{
	struct pxt4_pxt2t_path *path = NULL;
	struct pxt4_pxt2tent *pxt2t;
	int ret = 0;
	pxt4_lblk_t last = from + count;
	while (from < last) {
		*err = get_pxt2t_path(inode, from, &path);
		if (*err)
			goto out;
		pxt2t = path[pxt2t_depth(inode)].p_pxt2t;
		if (unwritten != pxt4_pxt2t_is_unwritten(pxt2t))
			goto out;
		from += pxt4_pxt2t_get_actual_len(pxt2t);
		pxt4_pxt2t_drop_refs(path);
	}
	ret = 1;
out:
	pxt4_pxt2t_drop_refs(path);
	kfree(path);
	return ret;
}

/**
 * mpxt2t_page_double_lock - Grab and lock pages on both @inode1 and @inode2
 *
 * @inode1:	the inode structure
 * @inode2:	the inode structure
 * @indpxt21:	page indpxt2
 * @indpxt22:	page indpxt2
 * @page:	result page vector
 *
 * Grab two locked pages for inode's by inode order
 */
static int
mpxt2t_page_double_lock(struct inode *inode1, struct inode *inode2,
		      pgoff_t indpxt21, pgoff_t indpxt22, struct page *page[2])
{
	struct address_space *mapping[2];
	unsigned fl = AOP_FLAG_NOFS;

	BUG_ON(!inode1 || !inode2);
	if (inode1 < inode2) {
		mapping[0] = inode1->i_mapping;
		mapping[1] = inode2->i_mapping;
	} else {
		swap(indpxt21, indpxt22);
		mapping[0] = inode2->i_mapping;
		mapping[1] = inode1->i_mapping;
	}

	page[0] = grab_cache_page_write_begin(mapping[0], indpxt21, fl);
	if (!page[0])
		return -ENOMEM;

	page[1] = grab_cache_page_write_begin(mapping[1], indpxt22, fl);
	if (!page[1]) {
		unlock_page(page[0]);
		put_page(page[0]);
		return -ENOMEM;
	}
	/*
	 * grab_cache_page_write_begin() may not wait on page's writeback if
	 * BDI not demand that. But it is reasonable to be very conservative
	 * here and pxt2plicitly wait on page's writeback
	 */
	wait_on_page_writeback(page[0]);
	wait_on_page_writeback(page[1]);
	if (inode1 > inode2)
		swap(page[0], page[1]);

	return 0;
}

/* Force page buffers uptodate w/o dropping page's lock */
static int
mpxt2t_page_mkuptodate(struct page *page, unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	sector_t block;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize, block_start, block_end;
	int i, err,  nr = 0, partial = 0;
	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	if (PageUptodate(page))
		return 0;

	blocksize = i_blocksize(inode);
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	head = page_buffers(page);
	block = (sector_t)page->indpxt2 << (PAGE_SHIFT - inode->i_blkbits);
	for (bh = head, block_start = 0; bh != head || !block_start;
	     block++, block_start = block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
			continue;
		}
		if (buffer_uptodate(bh))
			continue;
		if (!buffer_mapped(bh)) {
			err = pxt4_get_block(inode, block, bh, 0);
			if (err) {
				SetPageError(page);
				return err;
			}
			if (!buffer_mapped(bh)) {
				zero_user(page, block_start, blocksize);
				set_buffer_uptodate(bh);
				continue;
			}
		}
		BUG_ON(nr >= MAX_BUF_PER_PAGE);
		arr[nr++] = bh;
	}
	/* No io required */
	if (!nr)
		goto out;

	for (i = 0; i < nr; i++) {
		bh = arr[i];
		if (!bh_uptodate_or_lock(bh)) {
			err = bh_submit_read(bh);
			if (err)
				return err;
		}
	}
out:
	if (!partial)
		SetPageUptodate(page);
	return 0;
}

/**
 * move_pxt2tent_per_page - Move pxt2tent data per page
 *
 * @o_filp:			file structure of original file
 * @donor_inode:		donor inode
 * @orig_page_offset:		page indpxt2 on original file
 * @donor_page_offset:		page indpxt2 on donor file
 * @data_offset_in_page:	block indpxt2 where data swapping starts
 * @block_len_in_page:		the number of blocks to be swapped
 * @unwritten:			orig pxt2tent is unwritten or not
 * @err:			pointer to save return value
 *
 * Save the data in original inode blocks and replace original inode pxt2tents
 * with donor inode pxt2tents by calling pxt4_swap_pxt2tents().
 * Finally, write out the saved data in new original inode blocks. Return
 * replaced block count.
 */
static int
move_pxt2tent_per_page(struct file *o_filp, struct inode *donor_inode,
		     pgoff_t orig_page_offset, pgoff_t donor_page_offset,
		     int data_offset_in_page,
		     int block_len_in_page, int unwritten, int *err)
{
	struct inode *orig_inode = file_inode(o_filp);
	struct page *pagep[2] = {NULL, NULL};
	handle_t *handle;
	pxt4_lblk_t orig_blk_offset, donor_blk_offset;
	unsigned long blocksize = orig_inode->i_sb->s_blocksize;
	unsigned int tmp_data_size, data_size, replaced_size;
	int i, err2, jblocks, retries = 0;
	int replaced_count = 0;
	int from = data_offset_in_page << orig_inode->i_blkbits;
	int blocks_per_page = PAGE_SIZE >> orig_inode->i_blkbits;
	struct super_block *sb = orig_inode->i_sb;
	struct buffer_head *bh = NULL;

	/*
	 * It needs twice the amount of ordinary journal buffers because
	 * inode and donor_inode may change each different metadata blocks.
	 */
again:
	*err = 0;
	jblocks = pxt4_writepage_trans_blocks(orig_inode) * 2;
	handle = pxt4_journal_start(orig_inode, PXT4_HT_MOVE_EXTENTS, jblocks);
	if (IS_ERR(handle)) {
		*err = PTR_ERR(handle);
		return 0;
	}

	orig_blk_offset = orig_page_offset * blocks_per_page +
		data_offset_in_page;

	donor_blk_offset = donor_page_offset * blocks_per_page +
		data_offset_in_page;

	/* Calculate data_size */
	if ((orig_blk_offset + block_len_in_page - 1) ==
	    ((orig_inode->i_size - 1) >> orig_inode->i_blkbits)) {
		/* Replace the last block */
		tmp_data_size = orig_inode->i_size & (blocksize - 1);
		/*
		 * If data_size equal zero, it shows data_size is multiples of
		 * blocksize. So we set appropriate value.
		 */
		if (tmp_data_size == 0)
			tmp_data_size = blocksize;

		data_size = tmp_data_size +
			((block_len_in_page - 1) << orig_inode->i_blkbits);
	} else
		data_size = block_len_in_page << orig_inode->i_blkbits;

	replaced_size = data_size;

	*err = mpxt2t_page_double_lock(orig_inode, donor_inode, orig_page_offset,
				     donor_page_offset, pagep);
	if (unlikely(*err < 0))
		goto stop_journal;
	/*
	 * If orig pxt2tent was unwritten it can become initialized
	 * at any time after i_data_sem was dropped, in order to
	 * serialize with delalloc we have recheck pxt2tent while we
	 * hold page's lock, if it is still the case data copy is not
	 * necessary, just swap data blocks between orig and donor.
	 */
	if (unwritten) {
		pxt4_double_down_write_data_sem(orig_inode, donor_inode);
		/* If any of pxt2tents in range became initialized we have to
		 * fallback to data copying */
		unwritten = mpxt2t_check_coverage(orig_inode, orig_blk_offset,
						block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		unwritten &= mpxt2t_check_coverage(donor_inode, donor_blk_offset,
						 block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		if (!unwritten) {
			pxt4_double_up_write_data_sem(orig_inode, donor_inode);
			goto data_copy;
		}
		if ((page_has_private(pagep[0]) &&
		     !try_to_release_page(pagep[0], 0)) ||
		    (page_has_private(pagep[1]) &&
		     !try_to_release_page(pagep[1], 0))) {
			*err = -EBUSY;
			goto drop_data_sem;
		}
		replaced_count = pxt4_swap_pxt2tents(handle, orig_inode,
						   donor_inode, orig_blk_offset,
						   donor_blk_offset,
						   block_len_in_page, 1, err);
	drop_data_sem:
		pxt4_double_up_write_data_sem(orig_inode, donor_inode);
		goto unlock_pages;
	}
data_copy:
	*err = mpxt2t_page_mkuptodate(pagep[0], from, from + replaced_size);
	if (*err)
		goto unlock_pages;

	/* At this point all buffers in range are uptodate, old mapping layout
	 * is no longer required, try to drop it now. */
	if ((page_has_private(pagep[0]) && !try_to_release_page(pagep[0], 0)) ||
	    (page_has_private(pagep[1]) && !try_to_release_page(pagep[1], 0))) {
		*err = -EBUSY;
		goto unlock_pages;
	}
	pxt4_double_down_write_data_sem(orig_inode, donor_inode);
	replaced_count = pxt4_swap_pxt2tents(handle, orig_inode, donor_inode,
					       orig_blk_offset, donor_blk_offset,
					   block_len_in_page, 1, err);
	pxt4_double_up_write_data_sem(orig_inode, donor_inode);
	if (*err) {
		if (replaced_count) {
			block_len_in_page = replaced_count;
			replaced_size =
				block_len_in_page << orig_inode->i_blkbits;
		} else
			goto unlock_pages;
	}
	/* Perform all necessary steps similar write_begin()/write_end()
	 * but keeping in mind that i_size will not change */
	if (!page_has_buffers(pagep[0]))
		create_empty_buffers(pagep[0], 1 << orig_inode->i_blkbits, 0);
	bh = page_buffers(pagep[0]);
	for (i = 0; i < data_offset_in_page; i++)
		bh = bh->b_this_page;
	for (i = 0; i < block_len_in_page; i++) {
		*err = pxt4_get_block(orig_inode, orig_blk_offset + i, bh, 0);
		if (*err < 0)
			break;
		bh = bh->b_this_page;
	}
	if (!*err)
		*err = block_commit_write(pagep[0], from, from + replaced_size);

	if (unlikely(*err < 0))
		goto repair_branches;

	/* Even in case of data=writeback it is reasonable to pin
	 * inode to transaction, to prevent unpxt2pected data loss */
	*err = pxt4_jbd3_inode_add_write(handle, orig_inode,
			(loff_t)orig_page_offset << PAGE_SHIFT, replaced_size);

unlock_pages:
	unlock_page(pagep[0]);
	put_page(pagep[0]);
	unlock_page(pagep[1]);
	put_page(pagep[1]);
stop_journal:
	pxt4_journal_stop(handle);
	if (*err == -ENOSPC &&
	    pxt4_should_retry_alloc(sb, &retries))
		goto again;
	/* Buffer was busy because probably is pinned to journal transaction,
	 * force transaction commit may help to free it. */
	if (*err == -EBUSY && retries++ < 4 && PXT4_SB(sb)->s_journal &&
	    jbd3_journal_force_commit_nested(PXT4_SB(sb)->s_journal))
		goto again;
	return replaced_count;

repair_branches:
	/*
	 * This should never ever happen!
	 * Extents are swapped already, but we are not able to copy data.
	 * Try to swap pxt2tents to it's original places
	 */
	pxt4_double_down_write_data_sem(orig_inode, donor_inode);
	replaced_count = pxt4_swap_pxt2tents(handle, donor_inode, orig_inode,
					       orig_blk_offset, donor_blk_offset,
					   block_len_in_page, 0, &err2);
	pxt4_double_up_write_data_sem(orig_inode, donor_inode);
	if (replaced_count != block_len_in_page) {
		PXT4_ERROR_INODE_BLOCK(orig_inode, (sector_t)(orig_blk_offset),
				       "Unable to copy data block,"
				       " data will be lost.");
		*err = -EIO;
	}
	replaced_count = 0;
	goto unlock_pages;
}

/**
 * mpxt2t_check_arguments - Check whether move pxt2tent can be done
 *
 * @orig_inode:		original inode
 * @donor_inode:	donor inode
 * @orig_start:		logical start offset in block for orig
 * @donor_start:	logical start offset in block for donor
 * @len:		the number of blocks to be moved
 *
 * Check the arguments of pxt4_move_pxt2tents() whether the files can be
 * pxt2changed with each other.
 * Return 0 on success, or a negative error value on failure.
 */
static int
mpxt2t_check_arguments(struct inode *orig_inode,
		     struct inode *donor_inode, __u64 orig_start,
		     __u64 donor_start, __u64 *len)
{
	__u64 orig_eof, donor_eof;
	unsigned int blkbits = orig_inode->i_blkbits;
	unsigned int blocksize = 1 << blkbits;

	orig_eof = (i_size_read(orig_inode) + blocksize - 1) >> blkbits;
	donor_eof = (i_size_read(donor_inode) + blocksize - 1) >> blkbits;


	if (donor_inode->i_mode & (S_ISUID|S_ISGID)) {
		pxt4_debug("pxt4 move pxt2tent: suid or sgid is set"
			   " to donor file [ino:orig %lu, donor %lu]\n",
			   orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	if (IS_IMMUTABLE(donor_inode) || IS_APPEND(donor_inode))
		return -EPERM;

	/* Ext4 move pxt2tent does not support swapfile */
	if (IS_SWAPFILE(orig_inode) || IS_SWAPFILE(donor_inode)) {
		pxt4_debug("pxt4 move pxt2tent: The argument files should "
			"not be swapfile [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EBUSY;
	}

	if (pxt4_is_quota_file(orig_inode) && pxt4_is_quota_file(donor_inode)) {
		pxt4_debug("pxt4 move pxt2tent: The argument files should "
			"not be quota files [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EBUSY;
	}

	/* Ext4 move pxt2tent supports only pxt2tent based file */
	if (!(pxt4_test_inode_flag(orig_inode, PXT4_INODE_EXTENTS))) {
		pxt4_debug("pxt4 move pxt2tent: orig file is not pxt2tents "
			"based file [ino:orig %lu]\n", orig_inode->i_ino);
		return -EOPNOTSUPP;
	} else if (!(pxt4_test_inode_flag(donor_inode, PXT4_INODE_EXTENTS))) {
		pxt4_debug("pxt4 move pxt2tent: donor file is not pxt2tents "
			"based file [ino:donor %lu]\n", donor_inode->i_ino);
		return -EOPNOTSUPP;
	}

	if ((!orig_inode->i_size) || (!donor_inode->i_size)) {
		pxt4_debug("pxt4 move pxt2tent: File size is 0 byte\n");
		return -EINVAL;
	}

	/* Start offset should be same */
	if ((orig_start & ~(PAGE_MASK >> orig_inode->i_blkbits)) !=
	    (donor_start & ~(PAGE_MASK >> orig_inode->i_blkbits))) {
		pxt4_debug("pxt4 move pxt2tent: orig and donor's start "
			"offsets are not aligned [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	if ((orig_start >= EXT_MAX_BLOCKS) ||
	    (donor_start >= EXT_MAX_BLOCKS) ||
	    (*len > EXT_MAX_BLOCKS) ||
	    (donor_start + *len >= EXT_MAX_BLOCKS) ||
	    (orig_start + *len >= EXT_MAX_BLOCKS))  {
		pxt4_debug("pxt4 move pxt2tent: Can't handle over [%u] blocks "
			"[ino:orig %lu, donor %lu]\n", EXT_MAX_BLOCKS,
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}
	if (orig_eof <= orig_start)
		*len = 0;
	else if (orig_eof < orig_start + *len - 1)
		*len = orig_eof - orig_start;
	if (donor_eof <= donor_start)
		*len = 0;
	else if (donor_eof < donor_start + *len - 1)
		*len = donor_eof - donor_start;
	if (!*len) {
		pxt4_debug("pxt4 move pxt2tent: len should not be 0 "
			"[ino:orig %lu, donor %lu]\n", orig_inode->i_ino,
			donor_inode->i_ino);
		return -EINVAL;
	}

	return 0;
}

/**
 * pxt4_move_pxt2tents - Exchange the specified range of a file
 *
 * @o_filp:		file structure of the original file
 * @d_filp:		file structure of the donor file
 * @orig_blk:		start offset in block for orig
 * @donor_blk:		start offset in block for donor
 * @len:		the number of blocks to be moved
 * @moved_len:		moved block length
 *
 * This function returns 0 and moved block length is set in moved_len
 * if succeed, otherwise returns error value.
 *
 */
int
pxt4_move_pxt2tents(struct file *o_filp, struct file *d_filp, __u64 orig_blk,
		  __u64 donor_blk, __u64 len, __u64 *moved_len)
{
	struct inode *orig_inode = file_inode(o_filp);
	struct inode *donor_inode = file_inode(d_filp);
	struct pxt4_pxt2t_path *path = NULL;
	int blocks_per_page = PAGE_SIZE >> orig_inode->i_blkbits;
	pxt4_lblk_t o_end, o_start = orig_blk;
	pxt4_lblk_t d_start = donor_blk;
	int ret;

	if (orig_inode->i_sb != donor_inode->i_sb) {
		pxt4_debug("pxt4 move pxt2tent: The argument files "
			"should be in same FS [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* orig and donor should be different inodes */
	if (orig_inode == donor_inode) {
		pxt4_debug("pxt4 move pxt2tent: The argument files should not "
			"be same inode [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* Regular file check */
	if (!S_ISREG(orig_inode->i_mode) || !S_ISREG(donor_inode->i_mode)) {
		pxt4_debug("pxt4 move pxt2tent: The argument files should be "
			"regular file [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* TODO: it's not obvious how to swap blocks for inodes with full
	   journaling enabled */
	if (pxt4_should_journal_data(orig_inode) ||
	    pxt4_should_journal_data(donor_inode)) {
		pxt4_msg(orig_inode->i_sb, KERN_ERR,
			 "Online defrag not supported with data journaling");
		return -EOPNOTSUPP;
	}

	if (IS_ENCRYPTED(orig_inode) || IS_ENCRYPTED(donor_inode)) {
		pxt4_msg(orig_inode->i_sb, KERN_ERR,
			 "Online defrag not supported for encrypted files");
		return -EOPNOTSUPP;
	}

	/* Protect orig and donor inodes against a truncate */
	lock_two_nondirectories(orig_inode, donor_inode);

	/* Wait for all pxt2isting dio workers */
	inode_dio_wait(orig_inode);
	inode_dio_wait(donor_inode);

	/* Protect pxt2tent tree against block allocations via delalloc */
	pxt4_double_down_write_data_sem(orig_inode, donor_inode);
	/* Check the filesystem environment whether move_pxt2tent can be done */
	ret = mpxt2t_check_arguments(orig_inode, donor_inode, orig_blk,
				    donor_blk, &len);
	if (ret)
		goto out;
	o_end = o_start + len;

	while (o_start < o_end) {
		struct pxt4_pxt2tent *pxt2;
		pxt4_lblk_t cur_blk, npxt2t_blk;
		pgoff_t orig_page_indpxt2, donor_page_indpxt2;
		int offset_in_page;
		int unwritten, cur_len;

		ret = get_pxt2t_path(orig_inode, o_start, &path);
		if (ret)
			goto out;
		pxt2 = path[path->p_depth].p_pxt2t;
		npxt2t_blk = pxt4_pxt2t_npxt2t_allocated_block(path);
		cur_blk = le32_to_cpu(pxt2->ee_block);
		cur_len = pxt4_pxt2t_get_actual_len(pxt2);
		/* Check hole before the start pos */
		if (cur_blk + cur_len - 1 < o_start) {
			if (npxt2t_blk == EXT_MAX_BLOCKS) {
				o_start = o_end;
				ret = -ENODATA;
				goto out;
			}
			d_start += npxt2t_blk - o_start;
			o_start = npxt2t_blk;
			continue;
		/* Check hole after the start pos */
		} else if (cur_blk > o_start) {
			/* Skip hole */
			d_start += cur_blk - o_start;
			o_start = cur_blk;
			/* Extent inside requested range ?*/
			if (cur_blk >= o_end)
				goto out;
		} else { /* in_range(o_start, o_blk, o_len) */
			cur_len += cur_blk - o_start;
		}
		unwritten = pxt4_pxt2t_is_unwritten(pxt2);
		if (o_end - o_start < cur_len)
			cur_len = o_end - o_start;

		orig_page_indpxt2 = o_start >> (PAGE_SHIFT -
					       orig_inode->i_blkbits);
		donor_page_indpxt2 = d_start >> (PAGE_SHIFT -
					       donor_inode->i_blkbits);
		offset_in_page = o_start % blocks_per_page;
		if (cur_len > blocks_per_page- offset_in_page)
			cur_len = blocks_per_page - offset_in_page;
		/*
		 * Up semaphore to avoid following problems:
		 * a. transaction deadlock among pxt4_journal_start,
		 *    ->write_begin via pagefault, and jbd3_journal_commit
		 * b. racing with ->readpage, ->write_begin, and pxt4_get_block
		 *    in move_pxt2tent_per_page
		 */
		pxt4_double_up_write_data_sem(orig_inode, donor_inode);
		/* Swap original branches with new branches */
		move_pxt2tent_per_page(o_filp, donor_inode,
				     orig_page_indpxt2, donor_page_indpxt2,
				     offset_in_page, cur_len,
				     unwritten, &ret);
		pxt4_double_down_write_data_sem(orig_inode, donor_inode);
		if (ret < 0)
			break;
		o_start += cur_len;
		d_start += cur_len;
	}
	*moved_len = o_start - orig_blk;
	if (*moved_len > len)
		*moved_len = len;

out:
	if (*moved_len) {
		pxt4_discard_preallocations(orig_inode);
		pxt4_discard_preallocations(donor_inode);
	}

	pxt4_pxt2t_drop_refs(path);
	kfree(path);
	pxt4_double_up_write_data_sem(orig_inode, donor_inode);
	unlock_two_nondirectories(orig_inode, donor_inode);

	return ret;
}
