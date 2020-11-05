// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2003-2006, Cluster File Systems, Inc, info@clusterfs.com
 * Written by Alpxt2 Tomas <alpxt2@clusterfs.com>
 *
 * Architecture independence:
 *   Copyright (c) 2005, Bull S.A.
 *   Written by Pierre Peiffer <pierre.peiffer@bull.net>
 */

/*
 * Extents support for PXT4
 *
 * TODO:
 *   - pxt4*_error() should be used in some situations
 *   - analyze all BUG()/BUG_ON(), use -EIO where appropriate
 *   - smart tree reduction
 */

#include <linux/fs.h>
#include <linux/time.h>
#include <linux/jbd3.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fiemap.h>
#include <linux/backing-dev.h>
#include "pxt4_jbd3.h"
#include "pxt4_pxt2tents.h"
#include "xattr.h"

#include <trace/events/pxt4.h>

/*
 * used by pxt2tent splitting.
 */
#define PXT4_EXT_MAY_ZEROOUT	0x1  /* safe to zeroout if split fails \
					due to ENOSPC */
#define PXT4_EXT_MARK_UNWRIT1	0x2  /* mark first half unwritten */
#define PXT4_EXT_MARK_UNWRIT2	0x4  /* mark second half unwritten */

#define PXT4_EXT_DATA_VALID1	0x8  /* first half contains valid data */
#define PXT4_EXT_DATA_VALID2	0x10 /* second half contains valid data */

static __le32 pxt4_pxt2tent_block_csum(struct inode *inode,
				     struct pxt4_pxt2tent_header *eh)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	__u32 csum;

	csum = pxt4_chksum(sbi, ei->i_csum_seed, (__u8 *)eh,
			   PXT4_EXTENT_TAIL_OFFSET(eh));
	return cpu_to_le32(csum);
}

static int pxt4_pxt2tent_block_csum_verify(struct inode *inode,
					 struct pxt4_pxt2tent_header *eh)
{
	struct pxt4_pxt2tent_tail *et;

	if (!pxt4_has_metadata_csum(inode->i_sb))
		return 1;

	et = find_pxt4_pxt2tent_tail(eh);
	if (et->et_checksum != pxt4_pxt2tent_block_csum(inode, eh))
		return 0;
	return 1;
}

static void pxt4_pxt2tent_block_csum_set(struct inode *inode,
				       struct pxt4_pxt2tent_header *eh)
{
	struct pxt4_pxt2tent_tail *et;

	if (!pxt4_has_metadata_csum(inode->i_sb))
		return;

	et = find_pxt4_pxt2tent_tail(eh);
	et->et_checksum = pxt4_pxt2tent_block_csum(inode, eh);
}

static int pxt4_split_pxt2tent(handle_t *handle,
				struct inode *inode,
				struct pxt4_pxt2t_path **ppath,
				struct pxt4_map_blocks *map,
				int split_flag,
				int flags);

static int pxt4_split_pxt2tent_at(handle_t *handle,
			     struct inode *inode,
			     struct pxt4_pxt2t_path **ppath,
			     pxt4_lblk_t split,
			     int split_flag,
			     int flags);

static int pxt4_find_delayed_pxt2tent(struct inode *inode,
				    struct pxt2tent_status *newes);

static int pxt4_pxt2t_truncate_pxt2tend_restart(handle_t *handle,
					    struct inode *inode,
					    int needed)
{
	int err;

	if (!pxt4_handle_valid(handle))
		return 0;
	if (handle->h_buffer_credits >= needed)
		return 0;
	/*
	 * If we need to pxt2tend the journal get a few pxt2tra blocks
	 * while we're at it for efficiency's sake.
	 */
	needed += 3;
	err = pxt4_journal_pxt2tend(handle, needed - handle->h_buffer_credits);
	if (err <= 0)
		return err;
	err = pxt4_truncate_restart_trans(handle, inode, needed);
	if (err == 0)
		err = -EAGAIN;

	return err;
}

/*
 * could return:
 *  - EROFS
 *  - ENOMEM
 */
static int pxt4_pxt2t_get_access(handle_t *handle, struct inode *inode,
				struct pxt4_pxt2t_path *path)
{
	if (path->p_bh) {
		/* path points to block */
		BUFFER_TRACE(path->p_bh, "get_write_access");
		return pxt4_journal_get_write_access(handle, path->p_bh);
	}
	/* path points to leaf/indpxt2 in inode body */
	/* we use in-core data, no need to protect them */
	return 0;
}

/*
 * could return:
 *  - EROFS
 *  - ENOMEM
 *  - EIO
 */
int __pxt4_pxt2t_dirty(const char *where, unsigned int line, handle_t *handle,
		     struct inode *inode, struct pxt4_pxt2t_path *path)
{
	int err;

	WARN_ON(!rwsem_is_locked(&PXT4_I(inode)->i_data_sem));
	if (path->p_bh) {
		pxt4_pxt2tent_block_csum_set(inode, pxt2t_block_hdr(path->p_bh));
		/* path points to block */
		err = __pxt4_handle_dirty_metadata(where, line, handle,
						   inode, path->p_bh);
	} else {
		/* path points to leaf/indpxt2 in inode body */
		err = pxt4_mark_inode_dirty(handle, inode);
	}
	return err;
}

static pxt4_fsblk_t pxt4_pxt2t_find_goal(struct inode *inode,
			      struct pxt4_pxt2t_path *path,
			      pxt4_lblk_t block)
{
	if (path) {
		int depth = path->p_depth;
		struct pxt4_pxt2tent *pxt2;

		/*
		 * Try to predict block placement assuming that we are
		 * filling in a file which will eventually be
		 * non-sparse --- i.e., in the case of libbfd writing
		 * an ELF object sections out-of-order but in a way
		 * the eventually results in a contiguous object or
		 * pxt2ecutable file, or some database pxt2tending a table
		 * space file.  However, this is actually somewhat
		 * non-ideal if we are writing a sparse file such as
		 * qemu or KVM writing a raw image file that is going
		 * to stay fairly sparse, since it will end up
		 * fragmenting the file system's free space.  Maybe we
		 * should have some hueristics or some way to allow
		 * userspace to pass a hint to file system,
		 * especially if the latter case turns out to be
		 * common.
		 */
		pxt2 = path[depth].p_pxt2t;
		if (pxt2) {
			pxt4_fsblk_t pxt2t_pblk = pxt4_pxt2t_pblock(pxt2);
			pxt4_lblk_t pxt2t_block = le32_to_cpu(pxt2->ee_block);

			if (block > pxt2t_block)
				return pxt2t_pblk + (block - pxt2t_block);
			else
				return pxt2t_pblk - (pxt2t_block - block);
		}

		/* it looks like indpxt2 is empty;
		 * try to find starting block from indpxt2 itself */
		if (path[depth].p_bh)
			return path[depth].p_bh->b_blocknr;
	}

	/* OK. use inode's group */
	return pxt4_inode_to_goal_block(inode);
}

/*
 * Allocation for a meta data block
 */
static pxt4_fsblk_t
pxt4_pxt2t_new_meta_block(handle_t *handle, struct inode *inode,
			struct pxt4_pxt2t_path *path,
			struct pxt4_pxt2tent *pxt2, int *err, unsigned int flags)
{
	pxt4_fsblk_t goal, newblock;

	goal = pxt4_pxt2t_find_goal(inode, path, le32_to_cpu(pxt2->ee_block));
	newblock = pxt4_new_meta_blocks(handle, inode, goal, flags,
					NULL, err);
	return newblock;
}

static inline int pxt4_pxt2t_space_block(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct pxt4_pxt2tent_header))
			/ sizeof(struct pxt4_pxt2tent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 6)
		size = 6;
#endif
	return size;
}

static inline int pxt4_pxt2t_space_block_idx(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct pxt4_pxt2tent_header))
			/ sizeof(struct pxt4_pxt2tent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 5)
		size = 5;
#endif
	return size;
}

static inline int pxt4_pxt2t_space_root(struct inode *inode, int check)
{
	int size;

	size = sizeof(PXT4_I(inode)->i_data);
	size -= sizeof(struct pxt4_pxt2tent_header);
	size /= sizeof(struct pxt4_pxt2tent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 3)
		size = 3;
#endif
	return size;
}

static inline int pxt4_pxt2t_space_root_idx(struct inode *inode, int check)
{
	int size;

	size = sizeof(PXT4_I(inode)->i_data);
	size -= sizeof(struct pxt4_pxt2tent_header);
	size /= sizeof(struct pxt4_pxt2tent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 4)
		size = 4;
#endif
	return size;
}

static inline int
pxt4_force_split_pxt2tent_at(handle_t *handle, struct inode *inode,
			   struct pxt4_pxt2t_path **ppath, pxt4_lblk_t lblk,
			   int nofail)
{
	struct pxt4_pxt2t_path *path = *ppath;
	int unwritten = pxt4_pxt2t_is_unwritten(path[path->p_depth].p_pxt2t);

	return pxt4_split_pxt2tent_at(handle, inode, ppath, lblk, unwritten ?
			PXT4_EXT_MARK_UNWRIT1|PXT4_EXT_MARK_UNWRIT2 : 0,
			PXT4_EX_NOCACHE | PXT4_GET_BLOCKS_PRE_IO |
			(nofail ? PXT4_GET_BLOCKS_METADATA_NOFAIL:0));
}

/*
 * Calculate the number of metadata blocks needed
 * to allocate @blocks
 * Worse case is one block per pxt2tent
 */
int pxt4_pxt2t_calc_metadata_amount(struct inode *inode, pxt4_lblk_t lblock)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);
	int idxs;

	idxs = ((inode->i_sb->s_blocksize - sizeof(struct pxt4_pxt2tent_header))
		/ sizeof(struct pxt4_pxt2tent_idx));

	/*
	 * If the new delayed allocation block is contiguous with the
	 * previous da block, it can share indpxt2 blocks with the
	 * previous block, so we only need to allocate a new indpxt2
	 * block every idxs leaf blocks.  At ldxs**2 blocks, we need
	 * an additional indpxt2 block, and at ldxs**3 blocks, yet
	 * another indpxt2 blocks.
	 */
	if (ei->i_da_metadata_calc_len &&
	    ei->i_da_metadata_calc_last_lblock+1 == lblock) {
		int num = 0;

		if ((ei->i_da_metadata_calc_len % idxs) == 0)
			num++;
		if ((ei->i_da_metadata_calc_len % (idxs*idxs)) == 0)
			num++;
		if ((ei->i_da_metadata_calc_len % (idxs*idxs*idxs)) == 0) {
			num++;
			ei->i_da_metadata_calc_len = 0;
		} else
			ei->i_da_metadata_calc_len++;
		ei->i_da_metadata_calc_last_lblock++;
		return num;
	}

	/*
	 * In the worst case we need a new set of indpxt2 blocks at
	 * every level of the inode's pxt2tent tree.
	 */
	ei->i_da_metadata_calc_len = 1;
	ei->i_da_metadata_calc_last_lblock = lblock;
	return pxt2t_depth(inode) + 1;
}

static int
pxt4_pxt2t_max_entries(struct inode *inode, int depth)
{
	int max;

	if (depth == pxt2t_depth(inode)) {
		if (depth == 0)
			max = pxt4_pxt2t_space_root(inode, 1);
		else
			max = pxt4_pxt2t_space_root_idx(inode, 1);
	} else {
		if (depth == 0)
			max = pxt4_pxt2t_space_block(inode, 1);
		else
			max = pxt4_pxt2t_space_block_idx(inode, 1);
	}

	return max;
}

static int pxt4_valid_pxt2tent(struct inode *inode, struct pxt4_pxt2tent *pxt2t)
{
	pxt4_fsblk_t block = pxt4_pxt2t_pblock(pxt2t);
	int len = pxt4_pxt2t_get_actual_len(pxt2t);
	pxt4_lblk_t lblock = le32_to_cpu(pxt2t->ee_block);

	/*
	 * We allow neither:
	 *  - zero length
	 *  - overflow/wrap-around
	 */
	if (lblock + len <= lblock)
		return 0;
	return pxt4_data_block_valid(PXT4_SB(inode->i_sb), block, len);
}

static int pxt4_valid_pxt2tent_idx(struct inode *inode,
				struct pxt4_pxt2tent_idx *pxt2t_idx)
{
	pxt4_fsblk_t block = pxt4_idx_pblock(pxt2t_idx);

	return pxt4_data_block_valid(PXT4_SB(inode->i_sb), block, 1);
}

static int pxt4_valid_pxt2tent_entries(struct inode *inode,
				struct pxt4_pxt2tent_header *eh,
				int depth)
{
	unsigned short entries;
	if (eh->eh_entries == 0)
		return 1;

	entries = le16_to_cpu(eh->eh_entries);

	if (depth == 0) {
		/* leaf entries */
		struct pxt4_pxt2tent *pxt2t = EXT_FIRST_EXTENT(eh);
		struct pxt4_super_block *es = PXT4_SB(inode->i_sb)->s_es;
		pxt4_fsblk_t pblock = 0;
		pxt4_lblk_t lblock = 0;
		pxt4_lblk_t prev = 0;
		int len = 0;
		while (entries) {
			if (!pxt4_valid_pxt2tent(inode, pxt2t))
				return 0;

			/* Check for overlapping pxt2tents */
			lblock = le32_to_cpu(pxt2t->ee_block);
			len = pxt4_pxt2t_get_actual_len(pxt2t);
			if ((lblock <= prev) && prev) {
				pblock = pxt4_pxt2t_pblock(pxt2t);
				es->s_last_error_block = cpu_to_le64(pblock);
				return 0;
			}
			pxt2t++;
			entries--;
			prev = lblock + len - 1;
		}
	} else {
		struct pxt4_pxt2tent_idx *pxt2t_idx = EXT_FIRST_INDEX(eh);
		while (entries) {
			if (!pxt4_valid_pxt2tent_idx(inode, pxt2t_idx))
				return 0;
			pxt2t_idx++;
			entries--;
		}
	}
	return 1;
}

static int __pxt4_pxt2t_check(const char *function, unsigned int line,
			    struct inode *inode, struct pxt4_pxt2tent_header *eh,
			    int depth, pxt4_fsblk_t pblk)
{
	const char *error_msg;
	int max = 0, err = -EFSCORRUPTED;

	if (unlikely(eh->eh_magic != PXT4_EXT_MAGIC)) {
		error_msg = "invalid magic";
		goto corrupted;
	}
	if (unlikely(le16_to_cpu(eh->eh_depth) != depth)) {
		error_msg = "unpxt2pected eh_depth";
		goto corrupted;
	}
	if (unlikely(eh->eh_max == 0)) {
		error_msg = "invalid eh_max";
		goto corrupted;
	}
	max = pxt4_pxt2t_max_entries(inode, depth);
	if (unlikely(le16_to_cpu(eh->eh_max) > max)) {
		error_msg = "too large eh_max";
		goto corrupted;
	}
	if (unlikely(le16_to_cpu(eh->eh_entries) > le16_to_cpu(eh->eh_max))) {
		error_msg = "invalid eh_entries";
		goto corrupted;
	}
	if (!pxt4_valid_pxt2tent_entries(inode, eh, depth)) {
		error_msg = "invalid pxt2tent entries";
		goto corrupted;
	}
	if (unlikely(depth > 32)) {
		error_msg = "too large eh_depth";
		goto corrupted;
	}
	/* Verify checksum on non-root pxt2tent tree nodes */
	if (pxt2t_depth(inode) != depth &&
	    !pxt4_pxt2tent_block_csum_verify(inode, eh)) {
		error_msg = "pxt2tent tree corrupted";
		err = -EFSBADCRC;
		goto corrupted;
	}
	return 0;

corrupted:
	pxt4_error_inode(inode, function, line, 0,
			 "pblk %llu bad header/pxt2tent: %s - magic %x, "
			 "entries %u, max %u(%u), depth %u(%u)",
			 (unsigned long long) pblk, error_msg,
			 le16_to_cpu(eh->eh_magic),
			 le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max),
			 max, le16_to_cpu(eh->eh_depth), depth);
	return err;
}

#define pxt4_pxt2t_check(inode, eh, depth, pblk)			\
	__pxt4_pxt2t_check(__func__, __LINE__, (inode), (eh), (depth), (pblk))

int pxt4_pxt2t_check_inode(struct inode *inode)
{
	return pxt4_pxt2t_check(inode, pxt2t_inode_hdr(inode), pxt2t_depth(inode), 0);
}

static void pxt4_cache_pxt2tents(struct inode *inode,
			       struct pxt4_pxt2tent_header *eh)
{
	struct pxt4_pxt2tent *pxt2 = EXT_FIRST_EXTENT(eh);
	pxt4_lblk_t prev = 0;
	int i;

	for (i = le16_to_cpu(eh->eh_entries); i > 0; i--, pxt2++) {
		unsigned int status = EXTENT_STATUS_WRITTEN;
		pxt4_lblk_t lblk = le32_to_cpu(pxt2->ee_block);
		int len = pxt4_pxt2t_get_actual_len(pxt2);

		if (prev && (prev != lblk))
			pxt4_es_cache_pxt2tent(inode, prev, lblk - prev, ~0,
					     EXTENT_STATUS_HOLE);

		if (pxt4_pxt2t_is_unwritten(pxt2))
			status = EXTENT_STATUS_UNWRITTEN;
		pxt4_es_cache_pxt2tent(inode, lblk, len,
				     pxt4_pxt2t_pblock(pxt2), status);
		prev = lblk + len;
	}
}

static struct buffer_head *
__read_pxt2tent_tree_block(const char *function, unsigned int line,
			 struct inode *inode, pxt4_fsblk_t pblk, int depth,
			 int flags)
{
	struct buffer_head		*bh;
	int				err;

	bh = sb_getblk_gfp(inode->i_sb, pblk, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);

	if (!bh_uptodate_or_lock(bh)) {
		trace_pxt4_pxt2t_load_pxt2tent(inode, pblk, _RET_IP_);
		err = bh_submit_read(bh);
		if (err < 0)
			goto errout;
	}
	if (buffer_verified(bh) && !(flags & PXT4_EX_FORCE_CACHE))
		return bh;
	if (!pxt4_has_feature_journal(inode->i_sb) ||
	    (inode->i_ino !=
	     le32_to_cpu(PXT4_SB(inode->i_sb)->s_es->s_journal_inum))) {
		err = __pxt4_pxt2t_check(function, line, inode,
				       pxt2t_block_hdr(bh), depth, pblk);
		if (err)
			goto errout;
	}
	set_buffer_verified(bh);
	/*
	 * If this is a leaf block, cache all of its entries
	 */
	if (!(flags & PXT4_EX_NOCACHE) && depth == 0) {
		struct pxt4_pxt2tent_header *eh = pxt2t_block_hdr(bh);
		pxt4_cache_pxt2tents(inode, eh);
	}
	return bh;
errout:
	put_bh(bh);
	return ERR_PTR(err);

}

#define read_pxt2tent_tree_block(inode, pblk, depth, flags)		\
	__read_pxt2tent_tree_block(__func__, __LINE__, (inode), (pblk),   \
				 (depth), (flags))

/*
 * This function is called to cache a file's pxt2tent information in the
 * pxt2tent status tree
 */
int pxt4_pxt2t_precache(struct inode *inode)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);
	struct pxt4_pxt2t_path *path = NULL;
	struct buffer_head *bh;
	int i = 0, depth, ret = 0;

	if (!pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS))
		return 0;	/* not an pxt2tent-mapped inode */

	down_read(&ei->i_data_sem);
	depth = pxt2t_depth(inode);

	path = kcalloc(depth + 1, sizeof(struct pxt4_pxt2t_path),
		       GFP_NOFS);
	if (path == NULL) {
		up_read(&ei->i_data_sem);
		return -ENOMEM;
	}

	/* Don't cache anything if there are no pxt2ternal pxt2tent blocks */
	if (depth == 0)
		goto out;
	path[0].p_hdr = pxt2t_inode_hdr(inode);
	ret = pxt4_pxt2t_check(inode, path[0].p_hdr, depth, 0);
	if (ret)
		goto out;
	path[0].p_idx = EXT_FIRST_INDEX(path[0].p_hdr);
	while (i >= 0) {
		/*
		 * If this is a leaf block or we've reached the end of
		 * the indpxt2 block, go up
		 */
		if ((i == depth) ||
		    path[i].p_idx > EXT_LAST_INDEX(path[i].p_hdr)) {
			brelse(path[i].p_bh);
			path[i].p_bh = NULL;
			i--;
			continue;
		}
		bh = read_pxt2tent_tree_block(inode,
					    pxt4_idx_pblock(path[i].p_idx++),
					    depth - i - 1,
					    PXT4_EX_FORCE_CACHE);
		if (IS_ERR(bh)) {
			ret = PTR_ERR(bh);
			break;
		}
		i++;
		path[i].p_bh = bh;
		path[i].p_hdr = pxt2t_block_hdr(bh);
		path[i].p_idx = EXT_FIRST_INDEX(path[i].p_hdr);
	}
	pxt4_set_inode_state(inode, PXT4_STATE_EXT_PRECACHED);
out:
	up_read(&ei->i_data_sem);
	pxt4_pxt2t_drop_refs(path);
	kfree(path);
	return ret;
}

#ifdef EXT_DEBUG
static void pxt4_pxt2t_show_path(struct inode *inode, struct pxt4_pxt2t_path *path)
{
	int k, l = path->p_depth;

	pxt2t_debug("path:");
	for (k = 0; k <= l; k++, path++) {
		if (path->p_idx) {
		  pxt2t_debug("  %d->%llu", le32_to_cpu(path->p_idx->ei_block),
			    pxt4_idx_pblock(path->p_idx));
		} else if (path->p_pxt2t) {
			pxt2t_debug("  %d:[%d]%d:%llu ",
				  le32_to_cpu(path->p_pxt2t->ee_block),
				  pxt4_pxt2t_is_unwritten(path->p_pxt2t),
				  pxt4_pxt2t_get_actual_len(path->p_pxt2t),
				  pxt4_pxt2t_pblock(path->p_pxt2t));
		} else
			pxt2t_debug("  []");
	}
	pxt2t_debug("\n");
}

static void pxt4_pxt2t_show_leaf(struct inode *inode, struct pxt4_pxt2t_path *path)
{
	int depth = pxt2t_depth(inode);
	struct pxt4_pxt2tent_header *eh;
	struct pxt4_pxt2tent *pxt2;
	int i;

	if (!path)
		return;

	eh = path[depth].p_hdr;
	pxt2 = EXT_FIRST_EXTENT(eh);

	pxt2t_debug("Displaying leaf pxt2tents for inode %lu\n", inode->i_ino);

	for (i = 0; i < le16_to_cpu(eh->eh_entries); i++, pxt2++) {
		pxt2t_debug("%d:[%d]%d:%llu ", le32_to_cpu(pxt2->ee_block),
			  pxt4_pxt2t_is_unwritten(pxt2),
			  pxt4_pxt2t_get_actual_len(pxt2), pxt4_pxt2t_pblock(pxt2));
	}
	pxt2t_debug("\n");
}

static void pxt4_pxt2t_show_move(struct inode *inode, struct pxt4_pxt2t_path *path,
			pxt4_fsblk_t newblock, int level)
{
	int depth = pxt2t_depth(inode);
	struct pxt4_pxt2tent *pxt2;

	if (depth != level) {
		struct pxt4_pxt2tent_idx *idx;
		idx = path[level].p_idx;
		while (idx <= EXT_MAX_INDEX(path[level].p_hdr)) {
			pxt2t_debug("%d: move %d:%llu in new indpxt2 %llu\n", level,
					le32_to_cpu(idx->ei_block),
					pxt4_idx_pblock(idx),
					newblock);
			idx++;
		}

		return;
	}

	pxt2 = path[depth].p_pxt2t;
	while (pxt2 <= EXT_MAX_EXTENT(path[depth].p_hdr)) {
		pxt2t_debug("move %d:%llu:[%d]%d in new leaf %llu\n",
				le32_to_cpu(pxt2->ee_block),
				pxt4_pxt2t_pblock(pxt2),
				pxt4_pxt2t_is_unwritten(pxt2),
				pxt4_pxt2t_get_actual_len(pxt2),
				newblock);
		pxt2++;
	}
}

#else
#define pxt4_pxt2t_show_path(inode, path)
#define pxt4_pxt2t_show_leaf(inode, path)
#define pxt4_pxt2t_show_move(inode, path, newblock, level)
#endif

void pxt4_pxt2t_drop_refs(struct pxt4_pxt2t_path *path)
{
	int depth, i;

	if (!path)
		return;
	depth = path->p_depth;
	for (i = 0; i <= depth; i++, path++)
		if (path->p_bh) {
			brelse(path->p_bh);
			path->p_bh = NULL;
		}
}

/*
 * pxt4_pxt2t_binsearch_idx:
 * binary search for the closest indpxt2 of the given block
 * the header must be checked before calling this
 */
static void
pxt4_pxt2t_binsearch_idx(struct inode *inode,
			struct pxt4_pxt2t_path *path, pxt4_lblk_t block)
{
	struct pxt4_pxt2tent_header *eh = path->p_hdr;
	struct pxt4_pxt2tent_idx *r, *l, *m;


	pxt2t_debug("binsearch for %u(idx):  ", block);

	l = EXT_FIRST_INDEX(eh) + 1;
	r = EXT_LAST_INDEX(eh);
	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ei_block))
			r = m - 1;
		else
			l = m + 1;
		pxt2t_debug("%p(%u):%p(%u):%p(%u) ", l, le32_to_cpu(l->ei_block),
				m, le32_to_cpu(m->ei_block),
				r, le32_to_cpu(r->ei_block));
	}

	path->p_idx = l - 1;
	pxt2t_debug("  -> %u->%lld ", le32_to_cpu(path->p_idx->ei_block),
		  pxt4_idx_pblock(path->p_idx));

#ifdef CHECK_BINSEARCH
	{
		struct pxt4_pxt2tent_idx *chix, *ix;
		int k;

		chix = ix = EXT_FIRST_INDEX(eh);
		for (k = 0; k < le16_to_cpu(eh->eh_entries); k++, ix++) {
		  if (k != 0 &&
		      le32_to_cpu(ix->ei_block) <= le32_to_cpu(ix[-1].ei_block)) {
				printk(KERN_DEBUG "k=%d, ix=0x%p, "
				       "first=0x%p\n", k,
				       ix, EXT_FIRST_INDEX(eh));
				printk(KERN_DEBUG "%u <= %u\n",
				       le32_to_cpu(ix->ei_block),
				       le32_to_cpu(ix[-1].ei_block));
			}
			BUG_ON(k && le32_to_cpu(ix->ei_block)
					   <= le32_to_cpu(ix[-1].ei_block));
			if (block < le32_to_cpu(ix->ei_block))
				break;
			chix = ix;
		}
		BUG_ON(chix != path->p_idx);
	}
#endif

}

/*
 * pxt4_pxt2t_binsearch:
 * binary search for closest pxt2tent of the given block
 * the header must be checked before calling this
 */
static void
pxt4_pxt2t_binsearch(struct inode *inode,
		struct pxt4_pxt2t_path *path, pxt4_lblk_t block)
{
	struct pxt4_pxt2tent_header *eh = path->p_hdr;
	struct pxt4_pxt2tent *r, *l, *m;

	if (eh->eh_entries == 0) {
		/*
		 * this leaf is empty:
		 * we get such a leaf in split/add case
		 */
		return;
	}

	pxt2t_debug("binsearch for %u:  ", block);

	l = EXT_FIRST_EXTENT(eh) + 1;
	r = EXT_LAST_EXTENT(eh);

	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ee_block))
			r = m - 1;
		else
			l = m + 1;
		pxt2t_debug("%p(%u):%p(%u):%p(%u) ", l, le32_to_cpu(l->ee_block),
				m, le32_to_cpu(m->ee_block),
				r, le32_to_cpu(r->ee_block));
	}

	path->p_pxt2t = l - 1;
	pxt2t_debug("  -> %d:%llu:[%d]%d ",
			le32_to_cpu(path->p_pxt2t->ee_block),
			pxt4_pxt2t_pblock(path->p_pxt2t),
			pxt4_pxt2t_is_unwritten(path->p_pxt2t),
			pxt4_pxt2t_get_actual_len(path->p_pxt2t));

#ifdef CHECK_BINSEARCH
	{
		struct pxt4_pxt2tent *chpxt2, *pxt2;
		int k;

		chpxt2 = pxt2 = EXT_FIRST_EXTENT(eh);
		for (k = 0; k < le16_to_cpu(eh->eh_entries); k++, pxt2++) {
			BUG_ON(k && le32_to_cpu(pxt2->ee_block)
					  <= le32_to_cpu(pxt2[-1].ee_block));
			if (block < le32_to_cpu(pxt2->ee_block))
				break;
			chpxt2 = pxt2;
		}
		BUG_ON(chpxt2 != path->p_pxt2t);
	}
#endif

}

int pxt4_pxt2t_tree_init(handle_t *handle, struct inode *inode)
{
	struct pxt4_pxt2tent_header *eh;

	eh = pxt2t_inode_hdr(inode);
	eh->eh_depth = 0;
	eh->eh_entries = 0;
	eh->eh_magic = PXT4_EXT_MAGIC;
	eh->eh_max = cpu_to_le16(pxt4_pxt2t_space_root(inode, 0));
	pxt4_mark_inode_dirty(handle, inode);
	return 0;
}

struct pxt4_pxt2t_path *
pxt4_find_pxt2tent(struct inode *inode, pxt4_lblk_t block,
		 struct pxt4_pxt2t_path **orig_path, int flags)
{
	struct pxt4_pxt2tent_header *eh;
	struct buffer_head *bh;
	struct pxt4_pxt2t_path *path = orig_path ? *orig_path : NULL;
	short int depth, i, ppos = 0;
	int ret;

	eh = pxt2t_inode_hdr(inode);
	depth = pxt2t_depth(inode);
	if (depth < 0 || depth > PXT4_MAX_EXTENT_DEPTH) {
		PXT4_ERROR_INODE(inode, "inode has invalid pxt2tent depth: %d",
				 depth);
		ret = -EFSCORRUPTED;
		goto err;
	}

	if (path) {
		pxt4_pxt2t_drop_refs(path);
		if (depth > path[0].p_maxdepth) {
			kfree(path);
			*orig_path = path = NULL;
		}
	}
	if (!path) {
		/* account possible depth increase */
		path = kcalloc(depth + 2, sizeof(struct pxt4_pxt2t_path),
				GFP_NOFS);
		if (unlikely(!path))
			return ERR_PTR(-ENOMEM);
		path[0].p_maxdepth = depth + 1;
	}
	path[0].p_hdr = eh;
	path[0].p_bh = NULL;

	i = depth;
	if (!(flags & PXT4_EX_NOCACHE) && depth == 0)
		pxt4_cache_pxt2tents(inode, eh);
	/* walk through the tree */
	while (i) {
		pxt2t_debug("depth %d: num %d, max %d\n",
			  ppos, le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));

		pxt4_pxt2t_binsearch_idx(inode, path + ppos, block);
		path[ppos].p_block = pxt4_idx_pblock(path[ppos].p_idx);
		path[ppos].p_depth = i;
		path[ppos].p_pxt2t = NULL;

		bh = read_pxt2tent_tree_block(inode, path[ppos].p_block, --i,
					    flags);
		if (IS_ERR(bh)) {
			ret = PTR_ERR(bh);
			goto err;
		}

		eh = pxt2t_block_hdr(bh);
		ppos++;
		path[ppos].p_bh = bh;
		path[ppos].p_hdr = eh;
	}

	path[ppos].p_depth = i;
	path[ppos].p_pxt2t = NULL;
	path[ppos].p_idx = NULL;

	/* find pxt2tent */
	pxt4_pxt2t_binsearch(inode, path + ppos, block);
	/* if not an empty leaf */
	if (path[ppos].p_pxt2t)
		path[ppos].p_block = pxt4_pxt2t_pblock(path[ppos].p_pxt2t);

	pxt4_pxt2t_show_path(inode, path);

	return path;

err:
	pxt4_pxt2t_drop_refs(path);
	kfree(path);
	if (orig_path)
		*orig_path = NULL;
	return ERR_PTR(ret);
}

/*
 * pxt4_pxt2t_insert_indpxt2:
 * insert new indpxt2 [@logical;@ptr] into the block at @curp;
 * check where to insert: before @curp or after @curp
 */
static int pxt4_pxt2t_insert_indpxt2(handle_t *handle, struct inode *inode,
				 struct pxt4_pxt2t_path *curp,
				 int logical, pxt4_fsblk_t ptr)
{
	struct pxt4_pxt2tent_idx *ix;
	int len, err;

	err = pxt4_pxt2t_get_access(handle, inode, curp);
	if (err)
		return err;

	if (unlikely(logical == le32_to_cpu(curp->p_idx->ei_block))) {
		PXT4_ERROR_INODE(inode,
				 "logical %d == ei_block %d!",
				 logical, le32_to_cpu(curp->p_idx->ei_block));
		return -EFSCORRUPTED;
	}

	if (unlikely(le16_to_cpu(curp->p_hdr->eh_entries)
			     >= le16_to_cpu(curp->p_hdr->eh_max))) {
		PXT4_ERROR_INODE(inode,
				 "eh_entries %d >= eh_max %d!",
				 le16_to_cpu(curp->p_hdr->eh_entries),
				 le16_to_cpu(curp->p_hdr->eh_max));
		return -EFSCORRUPTED;
	}

	if (logical > le32_to_cpu(curp->p_idx->ei_block)) {
		/* insert after */
		pxt2t_debug("insert new indpxt2 %d after: %llu\n", logical, ptr);
		ix = curp->p_idx + 1;
	} else {
		/* insert before */
		pxt2t_debug("insert new indpxt2 %d before: %llu\n", logical, ptr);
		ix = curp->p_idx;
	}

	len = EXT_LAST_INDEX(curp->p_hdr) - ix + 1;
	BUG_ON(len < 0);
	if (len > 0) {
		pxt2t_debug("insert new indpxt2 %d: "
				"move %d indices from 0x%p to 0x%p\n",
				logical, len, ix, ix + 1);
		memmove(ix + 1, ix, len * sizeof(struct pxt4_pxt2tent_idx));
	}

	if (unlikely(ix > EXT_MAX_INDEX(curp->p_hdr))) {
		PXT4_ERROR_INODE(inode, "ix > EXT_MAX_INDEX!");
		return -EFSCORRUPTED;
	}

	ix->ei_block = cpu_to_le32(logical);
	pxt4_idx_store_pblock(ix, ptr);
	le16_add_cpu(&curp->p_hdr->eh_entries, 1);

	if (unlikely(ix > EXT_LAST_INDEX(curp->p_hdr))) {
		PXT4_ERROR_INODE(inode, "ix > EXT_LAST_INDEX!");
		return -EFSCORRUPTED;
	}

	err = pxt4_pxt2t_dirty(handle, inode, curp);
	pxt4_std_error(inode->i_sb, err);

	return err;
}

/*
 * pxt4_pxt2t_split:
 * inserts new subtree into the path, using free indpxt2 entry
 * at depth @at:
 * - allocates all needed blocks (new leaf and all intermediate indpxt2 blocks)
 * - makes decision where to split
 * - moves remaining pxt2tents and indpxt2 entries (right to the split point)
 *   into the newly allocated blocks
 * - initializes subtree
 */
static int pxt4_pxt2t_split(handle_t *handle, struct inode *inode,
			  unsigned int flags,
			  struct pxt4_pxt2t_path *path,
			  struct pxt4_pxt2tent *newpxt2t, int at)
{
	struct buffer_head *bh = NULL;
	int depth = pxt2t_depth(inode);
	struct pxt4_pxt2tent_header *neh;
	struct pxt4_pxt2tent_idx *fidx;
	int i = at, k, m, a;
	pxt4_fsblk_t newblock, oldblock;
	__le32 border;
	pxt4_fsblk_t *ablocks = NULL; /* array of allocated blocks */
	int err = 0;
	size_t pxt2t_size = 0;

	/* make decision: where to split? */
	/* FIXME: now decision is simplest: at current pxt2tent */

	/* if current leaf will be split, then we should use
	 * border from split point */
	if (unlikely(path[depth].p_pxt2t > EXT_MAX_EXTENT(path[depth].p_hdr))) {
		PXT4_ERROR_INODE(inode, "p_pxt2t > EXT_MAX_EXTENT!");
		return -EFSCORRUPTED;
	}
	if (path[depth].p_pxt2t != EXT_MAX_EXTENT(path[depth].p_hdr)) {
		border = path[depth].p_pxt2t[1].ee_block;
		pxt2t_debug("leaf will be split."
				" npxt2t leaf starts at %d\n",
				  le32_to_cpu(border));
	} else {
		border = newpxt2t->ee_block;
		pxt2t_debug("leaf will be added."
				" npxt2t leaf starts at %d\n",
				le32_to_cpu(border));
	}

	/*
	 * If error occurs, then we break processing
	 * and mark filesystem read-only. indpxt2 won't
	 * be inserted and tree will be in consistent
	 * state. Npxt2t mount will repair buffers too.
	 */

	/*
	 * Get array to track all allocated blocks.
	 * We need this to handle errors and free blocks
	 * upon them.
	 */
	ablocks = kcalloc(depth, sizeof(pxt4_fsblk_t), GFP_NOFS);
	if (!ablocks)
		return -ENOMEM;

	/* allocate all needed blocks */
	pxt2t_debug("allocate %d blocks for indpxt2es/leaf\n", depth - at);
	for (a = 0; a < depth - at; a++) {
		newblock = pxt4_pxt2t_new_meta_block(handle, inode, path,
						   newpxt2t, &err, flags);
		if (newblock == 0)
			goto cleanup;
		ablocks[a] = newblock;
	}

	/* initialize new leaf */
	newblock = ablocks[--a];
	if (unlikely(newblock == 0)) {
		PXT4_ERROR_INODE(inode, "newblock == 0!");
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	bh = sb_getblk_gfp(inode->i_sb, newblock, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh)) {
		err = -ENOMEM;
		goto cleanup;
	}
	lock_buffer(bh);

	err = pxt4_journal_get_create_access(handle, bh);
	if (err)
		goto cleanup;

	neh = pxt2t_block_hdr(bh);
	neh->eh_entries = 0;
	neh->eh_max = cpu_to_le16(pxt4_pxt2t_space_block(inode, 0));
	neh->eh_magic = PXT4_EXT_MAGIC;
	neh->eh_depth = 0;

	/* move remainder of path[depth] to the new leaf */
	if (unlikely(path[depth].p_hdr->eh_entries !=
		     path[depth].p_hdr->eh_max)) {
		PXT4_ERROR_INODE(inode, "eh_entries %d != eh_max %d!",
				 path[depth].p_hdr->eh_entries,
				 path[depth].p_hdr->eh_max);
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	/* start copy from npxt2t pxt2tent */
	m = EXT_MAX_EXTENT(path[depth].p_hdr) - path[depth].p_pxt2t++;
	pxt4_pxt2t_show_move(inode, path, newblock, depth);
	if (m) {
		struct pxt4_pxt2tent *pxt2;
		pxt2 = EXT_FIRST_EXTENT(neh);
		memmove(pxt2, path[depth].p_pxt2t, sizeof(struct pxt4_pxt2tent) * m);
		le16_add_cpu(&neh->eh_entries, m);
	}

	/* zero out unused area in the pxt2tent block */
	pxt2t_size = sizeof(struct pxt4_pxt2tent_header) +
		sizeof(struct pxt4_pxt2tent) * le16_to_cpu(neh->eh_entries);
	memset(bh->b_data + pxt2t_size, 0, inode->i_sb->s_blocksize - pxt2t_size);
	pxt4_pxt2tent_block_csum_set(inode, neh);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	err = pxt4_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto cleanup;
	brelse(bh);
	bh = NULL;

	/* correct old leaf */
	if (m) {
		err = pxt4_pxt2t_get_access(handle, inode, path + depth);
		if (err)
			goto cleanup;
		le16_add_cpu(&path[depth].p_hdr->eh_entries, -m);
		err = pxt4_pxt2t_dirty(handle, inode, path + depth);
		if (err)
			goto cleanup;

	}

	/* create intermediate indpxt2es */
	k = depth - at - 1;
	if (unlikely(k < 0)) {
		PXT4_ERROR_INODE(inode, "k %d < 0!", k);
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	if (k)
		pxt2t_debug("create %d intermediate indices\n", k);
	/* insert new indpxt2 into current indpxt2 block */
	/* current depth stored in i var */
	i = depth - 1;
	while (k--) {
		oldblock = newblock;
		newblock = ablocks[--a];
		bh = sb_getblk(inode->i_sb, newblock);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			goto cleanup;
		}
		lock_buffer(bh);

		err = pxt4_journal_get_create_access(handle, bh);
		if (err)
			goto cleanup;

		neh = pxt2t_block_hdr(bh);
		neh->eh_entries = cpu_to_le16(1);
		neh->eh_magic = PXT4_EXT_MAGIC;
		neh->eh_max = cpu_to_le16(pxt4_pxt2t_space_block_idx(inode, 0));
		neh->eh_depth = cpu_to_le16(depth - i);
		fidx = EXT_FIRST_INDEX(neh);
		fidx->ei_block = border;
		pxt4_idx_store_pblock(fidx, oldblock);

		pxt2t_debug("int.indpxt2 at %d (block %llu): %u -> %llu\n",
				i, newblock, le32_to_cpu(border), oldblock);

		/* move remainder of path[i] to the new indpxt2 block */
		if (unlikely(EXT_MAX_INDEX(path[i].p_hdr) !=
					EXT_LAST_INDEX(path[i].p_hdr))) {
			PXT4_ERROR_INODE(inode,
					 "EXT_MAX_INDEX != EXT_LAST_INDEX ee_block %d!",
					 le32_to_cpu(path[i].p_pxt2t->ee_block));
			err = -EFSCORRUPTED;
			goto cleanup;
		}
		/* start copy indpxt2es */
		m = EXT_MAX_INDEX(path[i].p_hdr) - path[i].p_idx++;
		pxt2t_debug("cur 0x%p, last 0x%p\n", path[i].p_idx,
				EXT_MAX_INDEX(path[i].p_hdr));
		pxt4_pxt2t_show_move(inode, path, newblock, i);
		if (m) {
			memmove(++fidx, path[i].p_idx,
				sizeof(struct pxt4_pxt2tent_idx) * m);
			le16_add_cpu(&neh->eh_entries, m);
		}
		/* zero out unused area in the pxt2tent block */
		pxt2t_size = sizeof(struct pxt4_pxt2tent_header) +
		   (sizeof(struct pxt4_pxt2tent) * le16_to_cpu(neh->eh_entries));
		memset(bh->b_data + pxt2t_size, 0,
			inode->i_sb->s_blocksize - pxt2t_size);
		pxt4_pxt2tent_block_csum_set(inode, neh);
		set_buffer_uptodate(bh);
		unlock_buffer(bh);

		err = pxt4_handle_dirty_metadata(handle, inode, bh);
		if (err)
			goto cleanup;
		brelse(bh);
		bh = NULL;

		/* correct old indpxt2 */
		if (m) {
			err = pxt4_pxt2t_get_access(handle, inode, path + i);
			if (err)
				goto cleanup;
			le16_add_cpu(&path[i].p_hdr->eh_entries, -m);
			err = pxt4_pxt2t_dirty(handle, inode, path + i);
			if (err)
				goto cleanup;
		}

		i--;
	}

	/* insert new indpxt2 */
	err = pxt4_pxt2t_insert_indpxt2(handle, inode, path + at,
				    le32_to_cpu(border), newblock);

cleanup:
	if (bh) {
		if (buffer_locked(bh))
			unlock_buffer(bh);
		brelse(bh);
	}

	if (err) {
		/* free all allocated blocks in error case */
		for (i = 0; i < depth; i++) {
			if (!ablocks[i])
				continue;
			pxt4_free_blocks(handle, inode, NULL, ablocks[i], 1,
					 PXT4_FREE_BLOCKS_METADATA);
		}
	}
	kfree(ablocks);

	return err;
}

/*
 * pxt4_pxt2t_grow_indepth:
 * implements tree growing procedure:
 * - allocates new block
 * - moves top-level data (indpxt2 block or leaf) into the new block
 * - initializes new top-level, creating indpxt2 that points to the
 *   just created block
 */
static int pxt4_pxt2t_grow_indepth(handle_t *handle, struct inode *inode,
				 unsigned int flags)
{
	struct pxt4_pxt2tent_header *neh;
	struct buffer_head *bh;
	pxt4_fsblk_t newblock, goal = 0;
	struct pxt4_super_block *es = PXT4_SB(inode->i_sb)->s_es;
	int err = 0;
	size_t pxt2t_size = 0;

	/* Try to prepend new indpxt2 to old one */
	if (pxt2t_depth(inode))
		goal = pxt4_idx_pblock(EXT_FIRST_INDEX(pxt2t_inode_hdr(inode)));
	if (goal > le32_to_cpu(es->s_first_data_block)) {
		flags |= PXT4_MB_HINT_TRY_GOAL;
		goal--;
	} else
		goal = pxt4_inode_to_goal_block(inode);
	newblock = pxt4_new_meta_blocks(handle, inode, goal, flags,
					NULL, &err);
	if (newblock == 0)
		return err;

	bh = sb_getblk_gfp(inode->i_sb, newblock, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh))
		return -ENOMEM;
	lock_buffer(bh);

	err = pxt4_journal_get_create_access(handle, bh);
	if (err) {
		unlock_buffer(bh);
		goto out;
	}

	pxt2t_size = sizeof(PXT4_I(inode)->i_data);
	/* move top-level indpxt2/leaf into new block */
	memmove(bh->b_data, PXT4_I(inode)->i_data, pxt2t_size);
	/* zero out unused area in the pxt2tent block */
	memset(bh->b_data + pxt2t_size, 0, inode->i_sb->s_blocksize - pxt2t_size);

	/* set size of new block */
	neh = pxt2t_block_hdr(bh);
	/* old root could have indpxt2es or leaves
	 * so calculate e_max right way */
	if (pxt2t_depth(inode))
		neh->eh_max = cpu_to_le16(pxt4_pxt2t_space_block_idx(inode, 0));
	else
		neh->eh_max = cpu_to_le16(pxt4_pxt2t_space_block(inode, 0));
	neh->eh_magic = PXT4_EXT_MAGIC;
	pxt4_pxt2tent_block_csum_set(inode, neh);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	err = pxt4_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto out;

	/* Update top-level indpxt2: num,max,pointer */
	neh = pxt2t_inode_hdr(inode);
	neh->eh_entries = cpu_to_le16(1);
	pxt4_idx_store_pblock(EXT_FIRST_INDEX(neh), newblock);
	if (neh->eh_depth == 0) {
		/* Root pxt2tent block becomes indpxt2 block */
		neh->eh_max = cpu_to_le16(pxt4_pxt2t_space_root_idx(inode, 0));
		EXT_FIRST_INDEX(neh)->ei_block =
			EXT_FIRST_EXTENT(neh)->ee_block;
	}
	pxt2t_debug("new root: num %d(%d), lblock %d, ptr %llu\n",
		  le16_to_cpu(neh->eh_entries), le16_to_cpu(neh->eh_max),
		  le32_to_cpu(EXT_FIRST_INDEX(neh)->ei_block),
		  pxt4_idx_pblock(EXT_FIRST_INDEX(neh)));

	le16_add_cpu(&neh->eh_depth, 1);
	pxt4_mark_inode_dirty(handle, inode);
out:
	brelse(bh);

	return err;
}

/*
 * pxt4_pxt2t_create_new_leaf:
 * finds empty indpxt2 and adds new leaf.
 * if no free indpxt2 is found, then it requests in-depth growing.
 */
static int pxt4_pxt2t_create_new_leaf(handle_t *handle, struct inode *inode,
				    unsigned int mb_flags,
				    unsigned int gb_flags,
				    struct pxt4_pxt2t_path **ppath,
				    struct pxt4_pxt2tent *newpxt2t)
{
	struct pxt4_pxt2t_path *path = *ppath;
	struct pxt4_pxt2t_path *curp;
	int depth, i, err = 0;

repeat:
	i = depth = pxt2t_depth(inode);

	/* walk up to the tree and look for free indpxt2 entry */
	curp = path + depth;
	while (i > 0 && !EXT_HAS_FREE_INDEX(curp)) {
		i--;
		curp--;
	}

	/* we use already allocated block for indpxt2 block,
	 * so subsequent data blocks should be contiguous */
	if (EXT_HAS_FREE_INDEX(curp)) {
		/* if we found indpxt2 with free entry, then use that
		 * entry: create all needed subtree and add new leaf */
		err = pxt4_pxt2t_split(handle, inode, mb_flags, path, newpxt2t, i);
		if (err)
			goto out;

		/* refill path */
		path = pxt4_find_pxt2tent(inode,
				    (pxt4_lblk_t)le32_to_cpu(newpxt2t->ee_block),
				    ppath, gb_flags);
		if (IS_ERR(path))
			err = PTR_ERR(path);
	} else {
		/* tree is full, time to grow in depth */
		err = pxt4_pxt2t_grow_indepth(handle, inode, mb_flags);
		if (err)
			goto out;

		/* refill path */
		path = pxt4_find_pxt2tent(inode,
				   (pxt4_lblk_t)le32_to_cpu(newpxt2t->ee_block),
				    ppath, gb_flags);
		if (IS_ERR(path)) {
			err = PTR_ERR(path);
			goto out;
		}

		/*
		 * only first (depth 0 -> 1) produces free space;
		 * in all other cases we have to split the grown tree
		 */
		depth = pxt2t_depth(inode);
		if (path[depth].p_hdr->eh_entries == path[depth].p_hdr->eh_max) {
			/* now we need to split */
			goto repeat;
		}
	}

out:
	return err;
}

/*
 * search the closest allocated block to the left for *logical
 * and returns it at @logical + it's physical address at @phys
 * if *logical is the smallest allocated block, the function
 * returns 0 at @phys
 * return value contains 0 (success) or error code
 */
static int pxt4_pxt2t_search_left(struct inode *inode,
				struct pxt4_pxt2t_path *path,
				pxt4_lblk_t *logical, pxt4_fsblk_t *phys)
{
	struct pxt4_pxt2tent_idx *ix;
	struct pxt4_pxt2tent *pxt2;
	int depth, ee_len;

	if (unlikely(path == NULL)) {
		PXT4_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EFSCORRUPTED;
	}
	depth = path->p_depth;
	*phys = 0;

	if (depth == 0 && path->p_pxt2t == NULL)
		return 0;

	/* usually pxt2tent in the path covers blocks smaller
	 * then *logical, but it can be that pxt2tent is the
	 * first one in the file */

	pxt2 = path[depth].p_pxt2t;
	ee_len = pxt4_pxt2t_get_actual_len(pxt2);
	if (*logical < le32_to_cpu(pxt2->ee_block)) {
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != pxt2)) {
			PXT4_ERROR_INODE(inode,
					 "EXT_FIRST_EXTENT != pxt2 *logical %d ee_block %d!",
					 *logical, le32_to_cpu(pxt2->ee_block));
			return -EFSCORRUPTED;
		}
		while (--depth >= 0) {
			ix = path[depth].p_idx;
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				PXT4_ERROR_INODE(inode,
				  "ix (%d) != EXT_FIRST_INDEX (%d) (depth %d)!",
				  ix != NULL ? le32_to_cpu(ix->ei_block) : 0,
				  EXT_FIRST_INDEX(path[depth].p_hdr) != NULL ?
		le32_to_cpu(EXT_FIRST_INDEX(path[depth].p_hdr)->ei_block) : 0,
				  depth);
				return -EFSCORRUPTED;
			}
		}
		return 0;
	}

	if (unlikely(*logical < (le32_to_cpu(pxt2->ee_block) + ee_len))) {
		PXT4_ERROR_INODE(inode,
				 "logical %d < ee_block %d + ee_len %d!",
				 *logical, le32_to_cpu(pxt2->ee_block), ee_len);
		return -EFSCORRUPTED;
	}

	*logical = le32_to_cpu(pxt2->ee_block) + ee_len - 1;
	*phys = pxt4_pxt2t_pblock(pxt2) + ee_len - 1;
	return 0;
}

/*
 * search the closest allocated block to the right for *logical
 * and returns it at @logical + it's physical address at @phys
 * if *logical is the largest allocated block, the function
 * returns 0 at @phys
 * return value contains 0 (success) or error code
 */
static int pxt4_pxt2t_search_right(struct inode *inode,
				 struct pxt4_pxt2t_path *path,
				 pxt4_lblk_t *logical, pxt4_fsblk_t *phys,
				 struct pxt4_pxt2tent **ret_pxt2)
{
	struct buffer_head *bh = NULL;
	struct pxt4_pxt2tent_header *eh;
	struct pxt4_pxt2tent_idx *ix;
	struct pxt4_pxt2tent *pxt2;
	pxt4_fsblk_t block;
	int depth;	/* Note, NOT eh_depth; depth from top of tree */
	int ee_len;

	if (unlikely(path == NULL)) {
		PXT4_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EFSCORRUPTED;
	}
	depth = path->p_depth;
	*phys = 0;

	if (depth == 0 && path->p_pxt2t == NULL)
		return 0;

	/* usually pxt2tent in the path covers blocks smaller
	 * then *logical, but it can be that pxt2tent is the
	 * first one in the file */

	pxt2 = path[depth].p_pxt2t;
	ee_len = pxt4_pxt2t_get_actual_len(pxt2);
	if (*logical < le32_to_cpu(pxt2->ee_block)) {
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != pxt2)) {
			PXT4_ERROR_INODE(inode,
					 "first_pxt2tent(path[%d].p_hdr) != pxt2",
					 depth);
			return -EFSCORRUPTED;
		}
		while (--depth >= 0) {
			ix = path[depth].p_idx;
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				PXT4_ERROR_INODE(inode,
						 "ix != EXT_FIRST_INDEX *logical %d!",
						 *logical);
				return -EFSCORRUPTED;
			}
		}
		goto found_pxt2tent;
	}

	if (unlikely(*logical < (le32_to_cpu(pxt2->ee_block) + ee_len))) {
		PXT4_ERROR_INODE(inode,
				 "logical %d < ee_block %d + ee_len %d!",
				 *logical, le32_to_cpu(pxt2->ee_block), ee_len);
		return -EFSCORRUPTED;
	}

	if (pxt2 != EXT_LAST_EXTENT(path[depth].p_hdr)) {
		/* npxt2t allocated block in this leaf */
		pxt2++;
		goto found_pxt2tent;
	}

	/* go up and search for indpxt2 to the right */
	while (--depth >= 0) {
		ix = path[depth].p_idx;
		if (ix != EXT_LAST_INDEX(path[depth].p_hdr))
			goto got_indpxt2;
	}

	/* we've gone up to the root and found no indpxt2 to the right */
	return 0;

got_indpxt2:
	/* we've found indpxt2 to the right, let's
	 * follow it and find the closest allocated
	 * block to the right */
	ix++;
	block = pxt4_idx_pblock(ix);
	while (++depth < path->p_depth) {
		/* subtract from p_depth to get proper eh_depth */
		bh = read_pxt2tent_tree_block(inode, block,
					    path->p_depth - depth, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		eh = pxt2t_block_hdr(bh);
		ix = EXT_FIRST_INDEX(eh);
		block = pxt4_idx_pblock(ix);
		put_bh(bh);
	}

	bh = read_pxt2tent_tree_block(inode, block, path->p_depth - depth, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	eh = pxt2t_block_hdr(bh);
	pxt2 = EXT_FIRST_EXTENT(eh);
found_pxt2tent:
	*logical = le32_to_cpu(pxt2->ee_block);
	*phys = pxt4_pxt2t_pblock(pxt2);
	*ret_pxt2 = pxt2;
	if (bh)
		put_bh(bh);
	return 0;
}

/*
 * pxt4_pxt2t_npxt2t_allocated_block:
 * returns allocated block in subsequent pxt2tent or EXT_MAX_BLOCKS.
 * NOTE: it considers block number from indpxt2 entry as
 * allocated block. Thus, indpxt2 entries have to be consistent
 * with leaves.
 */
pxt4_lblk_t
pxt4_pxt2t_npxt2t_allocated_block(struct pxt4_pxt2t_path *path)
{
	int depth;

	BUG_ON(path == NULL);
	depth = path->p_depth;

	if (depth == 0 && path->p_pxt2t == NULL)
		return EXT_MAX_BLOCKS;

	while (depth >= 0) {
		if (depth == path->p_depth) {
			/* leaf */
			if (path[depth].p_pxt2t &&
				path[depth].p_pxt2t !=
					EXT_LAST_EXTENT(path[depth].p_hdr))
			  return le32_to_cpu(path[depth].p_pxt2t[1].ee_block);
		} else {
			/* indpxt2 */
			if (path[depth].p_idx !=
					EXT_LAST_INDEX(path[depth].p_hdr))
			  return le32_to_cpu(path[depth].p_idx[1].ei_block);
		}
		depth--;
	}

	return EXT_MAX_BLOCKS;
}

/*
 * pxt4_pxt2t_npxt2t_leaf_block:
 * returns first allocated block from npxt2t leaf or EXT_MAX_BLOCKS
 */
static pxt4_lblk_t pxt4_pxt2t_npxt2t_leaf_block(struct pxt4_pxt2t_path *path)
{
	int depth;

	BUG_ON(path == NULL);
	depth = path->p_depth;

	/* zero-tree has no leaf blocks at all */
	if (depth == 0)
		return EXT_MAX_BLOCKS;

	/* go to indpxt2 block */
	depth--;

	while (depth >= 0) {
		if (path[depth].p_idx !=
				EXT_LAST_INDEX(path[depth].p_hdr))
			return (pxt4_lblk_t)
				le32_to_cpu(path[depth].p_idx[1].ei_block);
		depth--;
	}

	return EXT_MAX_BLOCKS;
}

/*
 * pxt4_pxt2t_correct_indpxt2es:
 * if leaf gets modified and modified pxt2tent is first in the leaf,
 * then we have to correct all indpxt2es above.
 * TODO: do we need to correct tree in all cases?
 */
static int pxt4_pxt2t_correct_indpxt2es(handle_t *handle, struct inode *inode,
				struct pxt4_pxt2t_path *path)
{
	struct pxt4_pxt2tent_header *eh;
	int depth = pxt2t_depth(inode);
	struct pxt4_pxt2tent *pxt2;
	__le32 border;
	int k, err = 0;

	eh = path[depth].p_hdr;
	pxt2 = path[depth].p_pxt2t;

	if (unlikely(pxt2 == NULL || eh == NULL)) {
		PXT4_ERROR_INODE(inode,
				 "pxt2 %p == NULL or eh %p == NULL", pxt2, eh);
		return -EFSCORRUPTED;
	}

	if (depth == 0) {
		/* there is no tree at all */
		return 0;
	}

	if (pxt2 != EXT_FIRST_EXTENT(eh)) {
		/* we correct tree if first leaf got modified only */
		return 0;
	}

	/*
	 * TODO: we need correction if border is smaller than current one
	 */
	k = depth - 1;
	border = path[depth].p_pxt2t->ee_block;
	err = pxt4_pxt2t_get_access(handle, inode, path + k);
	if (err)
		return err;
	path[k].p_idx->ei_block = border;
	err = pxt4_pxt2t_dirty(handle, inode, path + k);
	if (err)
		return err;

	while (k--) {
		/* change all left-side indpxt2es */
		if (path[k+1].p_idx != EXT_FIRST_INDEX(path[k+1].p_hdr))
			break;
		err = pxt4_pxt2t_get_access(handle, inode, path + k);
		if (err)
			break;
		path[k].p_idx->ei_block = border;
		err = pxt4_pxt2t_dirty(handle, inode, path + k);
		if (err)
			break;
	}

	return err;
}

int
pxt4_can_pxt2tents_be_merged(struct inode *inode, struct pxt4_pxt2tent *pxt21,
				struct pxt4_pxt2tent *pxt22)
{
	unsigned short pxt2t1_ee_len, pxt2t2_ee_len;

	if (pxt4_pxt2t_is_unwritten(pxt21) != pxt4_pxt2t_is_unwritten(pxt22))
		return 0;

	pxt2t1_ee_len = pxt4_pxt2t_get_actual_len(pxt21);
	pxt2t2_ee_len = pxt4_pxt2t_get_actual_len(pxt22);

	if (le32_to_cpu(pxt21->ee_block) + pxt2t1_ee_len !=
			le32_to_cpu(pxt22->ee_block))
		return 0;

	/*
	 * To allow future support for preallocated pxt2tents to be added
	 * as an RO_COMPAT feature, refuse to merge to pxt2tents if
	 * this can result in the top bit of ee_len being set.
	 */
	if (pxt2t1_ee_len + pxt2t2_ee_len > EXT_INIT_MAX_LEN)
		return 0;
	/*
	 * The check for IO to unwritten pxt2tent is somewhat racy as we
	 * increment i_unwritten / set PXT4_STATE_DIO_UNWRITTEN only after
	 * dropping i_data_sem. But reserved blocks should save us in that
	 * case.
	 */
	if (pxt4_pxt2t_is_unwritten(pxt21) &&
	    (pxt4_test_inode_state(inode, PXT4_STATE_DIO_UNWRITTEN) ||
	     atomic_read(&PXT4_I(inode)->i_unwritten) ||
	     (pxt2t1_ee_len + pxt2t2_ee_len > EXT_UNWRITTEN_MAX_LEN)))
		return 0;
#ifdef AGGRESSIVE_TEST
	if (pxt2t1_ee_len >= 4)
		return 0;
#endif

	if (pxt4_pxt2t_pblock(pxt21) + pxt2t1_ee_len == pxt4_pxt2t_pblock(pxt22))
		return 1;
	return 0;
}

/*
 * This function tries to merge the "pxt2" pxt2tent to the npxt2t pxt2tent in the tree.
 * It always tries to merge towards right. If you want to merge towards
 * left, pass "pxt2 - 1" as argument instead of "pxt2".
 * Returns 0 if the pxt2tents (pxt2 and pxt2+1) were _not_ merged and returns
 * 1 if they got merged.
 */
static int pxt4_pxt2t_try_to_merge_right(struct inode *inode,
				 struct pxt4_pxt2t_path *path,
				 struct pxt4_pxt2tent *pxt2)
{
	struct pxt4_pxt2tent_header *eh;
	unsigned int depth, len;
	int merge_done = 0, unwritten;

	depth = pxt2t_depth(inode);
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

	while (pxt2 < EXT_LAST_EXTENT(eh)) {
		if (!pxt4_can_pxt2tents_be_merged(inode, pxt2, pxt2 + 1))
			break;
		/* merge with npxt2t pxt2tent! */
		unwritten = pxt4_pxt2t_is_unwritten(pxt2);
		pxt2->ee_len = cpu_to_le16(pxt4_pxt2t_get_actual_len(pxt2)
				+ pxt4_pxt2t_get_actual_len(pxt2 + 1));
		if (unwritten)
			pxt4_pxt2t_mark_unwritten(pxt2);

		if (pxt2 + 1 < EXT_LAST_EXTENT(eh)) {
			len = (EXT_LAST_EXTENT(eh) - pxt2 - 1)
				* sizeof(struct pxt4_pxt2tent);
			memmove(pxt2 + 1, pxt2 + 2, len);
		}
		le16_add_cpu(&eh->eh_entries, -1);
		merge_done = 1;
		WARN_ON(eh->eh_entries == 0);
		if (!eh->eh_entries)
			PXT4_ERROR_INODE(inode, "eh->eh_entries = 0!");
	}

	return merge_done;
}

/*
 * This function does a very simple check to see if we can collapse
 * an pxt2tent tree with a single pxt2tent tree leaf block into the inode.
 */
static void pxt4_pxt2t_try_to_merge_up(handle_t *handle,
				     struct inode *inode,
				     struct pxt4_pxt2t_path *path)
{
	size_t s;
	unsigned max_root = pxt4_pxt2t_space_root(inode, 0);
	pxt4_fsblk_t blk;

	if ((path[0].p_depth != 1) ||
	    (le16_to_cpu(path[0].p_hdr->eh_entries) != 1) ||
	    (le16_to_cpu(path[1].p_hdr->eh_entries) > max_root))
		return;

	/*
	 * We need to modify the block allocation bitmap and the block
	 * group descriptor to release the pxt2tent tree block.  If we
	 * can't get the journal credits, give up.
	 */
	if (pxt4_journal_pxt2tend(handle, 2))
		return;

	/*
	 * Copy the pxt2tent data up to the inode
	 */
	blk = pxt4_idx_pblock(path[0].p_idx);
	s = le16_to_cpu(path[1].p_hdr->eh_entries) *
		sizeof(struct pxt4_pxt2tent_idx);
	s += sizeof(struct pxt4_pxt2tent_header);

	path[1].p_maxdepth = path[0].p_maxdepth;
	memcpy(path[0].p_hdr, path[1].p_hdr, s);
	path[0].p_depth = 0;
	path[0].p_pxt2t = EXT_FIRST_EXTENT(path[0].p_hdr) +
		(path[1].p_pxt2t - EXT_FIRST_EXTENT(path[1].p_hdr));
	path[0].p_hdr->eh_max = cpu_to_le16(max_root);

	brelse(path[1].p_bh);
	pxt4_free_blocks(handle, inode, NULL, blk, 1,
			 PXT4_FREE_BLOCKS_METADATA | PXT4_FREE_BLOCKS_FORGET);
}

/*
 * This function tries to merge the @pxt2 pxt2tent to neighbours in the tree.
 * return 1 if merge left else 0.
 */
static void pxt4_pxt2t_try_to_merge(handle_t *handle,
				  struct inode *inode,
				  struct pxt4_pxt2t_path *path,
				  struct pxt4_pxt2tent *pxt2) {
	struct pxt4_pxt2tent_header *eh;
	unsigned int depth;
	int merge_done = 0;

	depth = pxt2t_depth(inode);
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

	if (pxt2 > EXT_FIRST_EXTENT(eh))
		merge_done = pxt4_pxt2t_try_to_merge_right(inode, path, pxt2 - 1);

	if (!merge_done)
		(void) pxt4_pxt2t_try_to_merge_right(inode, path, pxt2);

	pxt4_pxt2t_try_to_merge_up(handle, inode, path);
}

/*
 * check if a portion of the "newpxt2t" pxt2tent overlaps with an
 * pxt2isting pxt2tent.
 *
 * If there is an overlap discovered, it updates the length of the newpxt2t
 * such that there will be no overlap, and then returns 1.
 * If there is no overlap found, it returns 0.
 */
static unsigned int pxt4_pxt2t_check_overlap(struct pxt4_sb_info *sbi,
					   struct inode *inode,
					   struct pxt4_pxt2tent *newpxt2t,
					   struct pxt4_pxt2t_path *path)
{
	pxt4_lblk_t b1, b2;
	unsigned int depth, len1;
	unsigned int ret = 0;

	b1 = le32_to_cpu(newpxt2t->ee_block);
	len1 = pxt4_pxt2t_get_actual_len(newpxt2t);
	depth = pxt2t_depth(inode);
	if (!path[depth].p_pxt2t)
		goto out;
	b2 = PXT4_LBLK_CMASK(sbi, le32_to_cpu(path[depth].p_pxt2t->ee_block));

	/*
	 * get the npxt2t allocated block if the pxt2tent in the path
	 * is before the requested block(s)
	 */
	if (b2 < b1) {
		b2 = pxt4_pxt2t_npxt2t_allocated_block(path);
		if (b2 == EXT_MAX_BLOCKS)
			goto out;
		b2 = PXT4_LBLK_CMASK(sbi, b2);
	}

	/* check for wrap through zero on pxt2tent logical start block*/
	if (b1 + len1 < b1) {
		len1 = EXT_MAX_BLOCKS - b1;
		newpxt2t->ee_len = cpu_to_le16(len1);
		ret = 1;
	}

	/* check for overlap */
	if (b1 + len1 > b2) {
		newpxt2t->ee_len = cpu_to_le16(b2 - b1);
		ret = 1;
	}
out:
	return ret;
}

/*
 * pxt4_pxt2t_insert_pxt2tent:
 * tries to merge requsted pxt2tent into the pxt2isting pxt2tent or
 * inserts requested pxt2tent as new one into the tree,
 * creating new leaf in the no-space case.
 */
int pxt4_pxt2t_insert_pxt2tent(handle_t *handle, struct inode *inode,
				struct pxt4_pxt2t_path **ppath,
				struct pxt4_pxt2tent *newpxt2t, int gb_flags)
{
	struct pxt4_pxt2t_path *path = *ppath;
	struct pxt4_pxt2tent_header *eh;
	struct pxt4_pxt2tent *pxt2, *fpxt2;
	struct pxt4_pxt2tent *nearpxt2; /* nearest pxt2tent */
	struct pxt4_pxt2t_path *npath = NULL;
	int depth, len, err;
	pxt4_lblk_t npxt2t;
	int mb_flags = 0, unwritten;

	if (gb_flags & PXT4_GET_BLOCKS_DELALLOC_RESERVE)
		mb_flags |= PXT4_MB_DELALLOC_RESERVED;
	if (unlikely(pxt4_pxt2t_get_actual_len(newpxt2t) == 0)) {
		PXT4_ERROR_INODE(inode, "pxt4_pxt2t_get_actual_len(newpxt2t) == 0");
		return -EFSCORRUPTED;
	}
	depth = pxt2t_depth(inode);
	pxt2 = path[depth].p_pxt2t;
	eh = path[depth].p_hdr;
	if (unlikely(path[depth].p_hdr == NULL)) {
		PXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
		return -EFSCORRUPTED;
	}

	/* try to insert block into found pxt2tent and return */
	if (pxt2 && !(gb_flags & PXT4_GET_BLOCKS_PRE_IO)) {

		/*
		 * Try to see whether we should rather test the pxt2tent on
		 * right from pxt2, or from the left of pxt2. This is because
		 * pxt4_find_pxt2tent() can return either pxt2tent on the
		 * left, or on the right from the searched position. This
		 * will make merging more effective.
		 */
		if (pxt2 < EXT_LAST_EXTENT(eh) &&
		    (le32_to_cpu(pxt2->ee_block) +
		    pxt4_pxt2t_get_actual_len(pxt2) <
		    le32_to_cpu(newpxt2t->ee_block))) {
			pxt2 += 1;
			goto prepend;
		} else if ((pxt2 > EXT_FIRST_EXTENT(eh)) &&
			   (le32_to_cpu(newpxt2t->ee_block) +
			   pxt4_pxt2t_get_actual_len(newpxt2t) <
			   le32_to_cpu(pxt2->ee_block)))
			pxt2 -= 1;

		/* Try to append newpxt2 to the pxt2 */
		if (pxt4_can_pxt2tents_be_merged(inode, pxt2, newpxt2t)) {
			pxt2t_debug("append [%d]%d block to %u:[%d]%d"
				  "(from %llu)\n",
				  pxt4_pxt2t_is_unwritten(newpxt2t),
				  pxt4_pxt2t_get_actual_len(newpxt2t),
				  le32_to_cpu(pxt2->ee_block),
				  pxt4_pxt2t_is_unwritten(pxt2),
				  pxt4_pxt2t_get_actual_len(pxt2),
				  pxt4_pxt2t_pblock(pxt2));
			err = pxt4_pxt2t_get_access(handle, inode,
						  path + depth);
			if (err)
				return err;
			unwritten = pxt4_pxt2t_is_unwritten(pxt2);
			pxt2->ee_len = cpu_to_le16(pxt4_pxt2t_get_actual_len(pxt2)
					+ pxt4_pxt2t_get_actual_len(newpxt2t));
			if (unwritten)
				pxt4_pxt2t_mark_unwritten(pxt2);
			eh = path[depth].p_hdr;
			nearpxt2 = pxt2;
			goto merge;
		}

prepend:
		/* Try to prepend newpxt2 to the pxt2 */
		if (pxt4_can_pxt2tents_be_merged(inode, newpxt2t, pxt2)) {
			pxt2t_debug("prepend %u[%d]%d block to %u:[%d]%d"
				  "(from %llu)\n",
				  le32_to_cpu(newpxt2t->ee_block),
				  pxt4_pxt2t_is_unwritten(newpxt2t),
				  pxt4_pxt2t_get_actual_len(newpxt2t),
				  le32_to_cpu(pxt2->ee_block),
				  pxt4_pxt2t_is_unwritten(pxt2),
				  pxt4_pxt2t_get_actual_len(pxt2),
				  pxt4_pxt2t_pblock(pxt2));
			err = pxt4_pxt2t_get_access(handle, inode,
						  path + depth);
			if (err)
				return err;

			unwritten = pxt4_pxt2t_is_unwritten(pxt2);
			pxt2->ee_block = newpxt2t->ee_block;
			pxt4_pxt2t_store_pblock(pxt2, pxt4_pxt2t_pblock(newpxt2t));
			pxt2->ee_len = cpu_to_le16(pxt4_pxt2t_get_actual_len(pxt2)
					+ pxt4_pxt2t_get_actual_len(newpxt2t));
			if (unwritten)
				pxt4_pxt2t_mark_unwritten(pxt2);
			eh = path[depth].p_hdr;
			nearpxt2 = pxt2;
			goto merge;
		}
	}

	depth = pxt2t_depth(inode);
	eh = path[depth].p_hdr;
	if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max))
		goto has_space;

	/* probably npxt2t leaf has space for us? */
	fpxt2 = EXT_LAST_EXTENT(eh);
	npxt2t = EXT_MAX_BLOCKS;
	if (le32_to_cpu(newpxt2t->ee_block) > le32_to_cpu(fpxt2->ee_block))
		npxt2t = pxt4_pxt2t_npxt2t_leaf_block(path);
	if (npxt2t != EXT_MAX_BLOCKS) {
		pxt2t_debug("npxt2t leaf block - %u\n", npxt2t);
		BUG_ON(npath != NULL);
		npath = pxt4_find_pxt2tent(inode, npxt2t, NULL, 0);
		if (IS_ERR(npath))
			return PTR_ERR(npath);
		BUG_ON(npath->p_depth != path->p_depth);
		eh = npath[depth].p_hdr;
		if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max)) {
			pxt2t_debug("npxt2t leaf isn't full(%d)\n",
				  le16_to_cpu(eh->eh_entries));
			path = npath;
			goto has_space;
		}
		pxt2t_debug("npxt2t leaf has no free space(%d,%d)\n",
			  le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));
	}

	/*
	 * There is no free space in the found leaf.
	 * We're gonna add a new leaf in the tree.
	 */
	if (gb_flags & PXT4_GET_BLOCKS_METADATA_NOFAIL)
		mb_flags |= PXT4_MB_USE_RESERVED;
	err = pxt4_pxt2t_create_new_leaf(handle, inode, mb_flags, gb_flags,
				       ppath, newpxt2t);
	if (err)
		goto cleanup;
	depth = pxt2t_depth(inode);
	eh = path[depth].p_hdr;

has_space:
	nearpxt2 = path[depth].p_pxt2t;

	err = pxt4_pxt2t_get_access(handle, inode, path + depth);
	if (err)
		goto cleanup;

	if (!nearpxt2) {
		/* there is no pxt2tent in this leaf, create first one */
		pxt2t_debug("first pxt2tent in the leaf: %u:%llu:[%d]%d\n",
				le32_to_cpu(newpxt2t->ee_block),
				pxt4_pxt2t_pblock(newpxt2t),
				pxt4_pxt2t_is_unwritten(newpxt2t),
				pxt4_pxt2t_get_actual_len(newpxt2t));
		nearpxt2 = EXT_FIRST_EXTENT(eh);
	} else {
		if (le32_to_cpu(newpxt2t->ee_block)
			   > le32_to_cpu(nearpxt2->ee_block)) {
			/* Insert after */
			pxt2t_debug("insert %u:%llu:[%d]%d before: "
					"nearest %p\n",
					le32_to_cpu(newpxt2t->ee_block),
					pxt4_pxt2t_pblock(newpxt2t),
					pxt4_pxt2t_is_unwritten(newpxt2t),
					pxt4_pxt2t_get_actual_len(newpxt2t),
					nearpxt2);
			nearpxt2++;
		} else {
			/* Insert before */
			BUG_ON(newpxt2t->ee_block == nearpxt2->ee_block);
			pxt2t_debug("insert %u:%llu:[%d]%d after: "
					"nearest %p\n",
					le32_to_cpu(newpxt2t->ee_block),
					pxt4_pxt2t_pblock(newpxt2t),
					pxt4_pxt2t_is_unwritten(newpxt2t),
					pxt4_pxt2t_get_actual_len(newpxt2t),
					nearpxt2);
		}
		len = EXT_LAST_EXTENT(eh) - nearpxt2 + 1;
		if (len > 0) {
			pxt2t_debug("insert %u:%llu:[%d]%d: "
					"move %d pxt2tents from 0x%p to 0x%p\n",
					le32_to_cpu(newpxt2t->ee_block),
					pxt4_pxt2t_pblock(newpxt2t),
					pxt4_pxt2t_is_unwritten(newpxt2t),
					pxt4_pxt2t_get_actual_len(newpxt2t),
					len, nearpxt2, nearpxt2 + 1);
			memmove(nearpxt2 + 1, nearpxt2,
				len * sizeof(struct pxt4_pxt2tent));
		}
	}

	le16_add_cpu(&eh->eh_entries, 1);
	path[depth].p_pxt2t = nearpxt2;
	nearpxt2->ee_block = newpxt2t->ee_block;
	pxt4_pxt2t_store_pblock(nearpxt2, pxt4_pxt2t_pblock(newpxt2t));
	nearpxt2->ee_len = newpxt2t->ee_len;

merge:
	/* try to merge pxt2tents */
	if (!(gb_flags & PXT4_GET_BLOCKS_PRE_IO))
		pxt4_pxt2t_try_to_merge(handle, inode, path, nearpxt2);


	/* time to correct all indpxt2es above */
	err = pxt4_pxt2t_correct_indpxt2es(handle, inode, path);
	if (err)
		goto cleanup;

	err = pxt4_pxt2t_dirty(handle, inode, path + path->p_depth);

cleanup:
	pxt4_pxt2t_drop_refs(npath);
	kfree(npath);
	return err;
}

static int pxt4_fill_fiemap_pxt2tents(struct inode *inode,
				    pxt4_lblk_t block, pxt4_lblk_t num,
				    struct fiemap_pxt2tent_info *fieinfo)
{
	struct pxt4_pxt2t_path *path = NULL;
	struct pxt4_pxt2tent *pxt2;
	struct pxt2tent_status es;
	pxt4_lblk_t npxt2t, npxt2t_del, start = 0, end = 0;
	pxt4_lblk_t last = block + num;
	int pxt2ists, depth = 0, err = 0;
	unsigned int flags = 0;
	unsigned char blksize_bits = inode->i_sb->s_blocksize_bits;

	while (block < last && block != EXT_MAX_BLOCKS) {
		num = last - block;
		/* find pxt2tent for this block */
		down_read(&PXT4_I(inode)->i_data_sem);

		path = pxt4_find_pxt2tent(inode, block, &path, 0);
		if (IS_ERR(path)) {
			up_read(&PXT4_I(inode)->i_data_sem);
			err = PTR_ERR(path);
			path = NULL;
			break;
		}

		depth = pxt2t_depth(inode);
		if (unlikely(path[depth].p_hdr == NULL)) {
			up_read(&PXT4_I(inode)->i_data_sem);
			PXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
			err = -EFSCORRUPTED;
			break;
		}
		pxt2 = path[depth].p_pxt2t;
		npxt2t = pxt4_pxt2t_npxt2t_allocated_block(path);

		flags = 0;
		pxt2ists = 0;
		if (!pxt2) {
			/* there is no pxt2tent yet, so try to allocate
			 * all requested space */
			start = block;
			end = block + num;
		} else if (le32_to_cpu(pxt2->ee_block) > block) {
			/* need to allocate space before found pxt2tent */
			start = block;
			end = le32_to_cpu(pxt2->ee_block);
			if (block + num < end)
				end = block + num;
		} else if (block >= le32_to_cpu(pxt2->ee_block)
					+ pxt4_pxt2t_get_actual_len(pxt2)) {
			/* need to allocate space after found pxt2tent */
			start = block;
			end = block + num;
			if (end >= npxt2t)
				end = npxt2t;
		} else if (block >= le32_to_cpu(pxt2->ee_block)) {
			/*
			 * some part of requested space is covered
			 * by found pxt2tent
			 */
			start = block;
			end = le32_to_cpu(pxt2->ee_block)
				+ pxt4_pxt2t_get_actual_len(pxt2);
			if (block + num < end)
				end = block + num;
			pxt2ists = 1;
		} else {
			BUG();
		}
		BUG_ON(end <= start);

		if (!pxt2ists) {
			es.es_lblk = start;
			es.es_len = end - start;
			es.es_pblk = 0;
		} else {
			es.es_lblk = le32_to_cpu(pxt2->ee_block);
			es.es_len = pxt4_pxt2t_get_actual_len(pxt2);
			es.es_pblk = pxt4_pxt2t_pblock(pxt2);
			if (pxt4_pxt2t_is_unwritten(pxt2))
				flags |= FIEMAP_EXTENT_UNWRITTEN;
		}

		/*
		 * Find delayed pxt2tent and update es accordingly. We call
		 * it even in !pxt2ists case to find out whether es is the
		 * last pxt2isting pxt2tent or not.
		 */
		npxt2t_del = pxt4_find_delayed_pxt2tent(inode, &es);
		if (!pxt2ists && npxt2t_del) {
			pxt2ists = 1;
			flags |= (FIEMAP_EXTENT_DELALLOC |
				  FIEMAP_EXTENT_UNKNOWN);
		}
		up_read(&PXT4_I(inode)->i_data_sem);

		if (unlikely(es.es_len == 0)) {
			PXT4_ERROR_INODE(inode, "es.es_len == 0");
			err = -EFSCORRUPTED;
			break;
		}

		/*
		 * This is possible iff npxt2t == npxt2t_del == EXT_MAX_BLOCKS.
		 * we need to check npxt2t == EXT_MAX_BLOCKS because it is
		 * possible that an pxt2tent is with unwritten and delayed
		 * status due to when an pxt2tent is delayed allocated and
		 * is allocated by fallocate status tree will track both of
		 * them in a pxt2tent.
		 *
		 * So we could return a unwritten and delayed pxt2tent, and
		 * its block is equal to 'npxt2t'.
		 */
		if (npxt2t == npxt2t_del && npxt2t == EXT_MAX_BLOCKS) {
			flags |= FIEMAP_EXTENT_LAST;
			if (unlikely(npxt2t_del != EXT_MAX_BLOCKS ||
				     npxt2t != EXT_MAX_BLOCKS)) {
				PXT4_ERROR_INODE(inode,
						 "npxt2t pxt2tent == %u, npxt2t "
						 "delalloc pxt2tent = %u",
						 npxt2t, npxt2t_del);
				err = -EFSCORRUPTED;
				break;
			}
		}

		if (pxt2ists) {
			err = fiemap_fill_npxt2t_pxt2tent(fieinfo,
				(__u64)es.es_lblk << blksize_bits,
				(__u64)es.es_pblk << blksize_bits,
				(__u64)es.es_len << blksize_bits,
				flags);
			if (err < 0)
				break;
			if (err == 1) {
				err = 0;
				break;
			}
		}

		block = es.es_lblk + es.es_len;
	}

	pxt4_pxt2t_drop_refs(path);
	kfree(path);
	return err;
}

static int pxt4_fill_es_cache_info(struct inode *inode,
				   pxt4_lblk_t block, pxt4_lblk_t num,
				   struct fiemap_pxt2tent_info *fieinfo)
{
	pxt4_lblk_t npxt2t, end = block + num - 1;
	struct pxt2tent_status es;
	unsigned char blksize_bits = inode->i_sb->s_blocksize_bits;
	unsigned int flags;
	int err;

	while (block <= end) {
		npxt2t = 0;
		flags = 0;
		if (!pxt4_es_lookup_pxt2tent(inode, block, &npxt2t, &es))
			break;
		if (pxt4_es_is_unwritten(&es))
			flags |= FIEMAP_EXTENT_UNWRITTEN;
		if (pxt4_es_is_delayed(&es))
			flags |= (FIEMAP_EXTENT_DELALLOC |
				  FIEMAP_EXTENT_UNKNOWN);
		if (pxt4_es_is_hole(&es))
			flags |= PXT4_FIEMAP_EXTENT_HOLE;
		if (npxt2t == 0)
			flags |= FIEMAP_EXTENT_LAST;
		if (flags & (FIEMAP_EXTENT_DELALLOC|
			     PXT4_FIEMAP_EXTENT_HOLE))
			es.es_pblk = 0;
		else
			es.es_pblk = pxt4_es_pblock(&es);
		err = fiemap_fill_npxt2t_pxt2tent(fieinfo,
				(__u64)es.es_lblk << blksize_bits,
				(__u64)es.es_pblk << blksize_bits,
				(__u64)es.es_len << blksize_bits,
				flags);
		if (npxt2t == 0)
			break;
		block = npxt2t;
		if (err < 0)
			return err;
		if (err == 1)
			return 0;
	}
	return 0;
}


/*
 * pxt4_pxt2t_determine_hole - determine hole around given block
 * @inode:	inode we lookup in
 * @path:	path in pxt2tent tree to @lblk
 * @lblk:	pointer to logical block around which we want to determine hole
 *
 * Determine hole length (and start if easily possible) around given logical
 * block. We don't try too hard to find the beginning of the hole but @path
 * actually points to pxt2tent before @lblk, we provide it.
 *
 * The function returns the length of a hole starting at @lblk. We update @lblk
 * to the beginning of the hole if we managed to find it.
 */
static pxt4_lblk_t pxt4_pxt2t_determine_hole(struct inode *inode,
					   struct pxt4_pxt2t_path *path,
					   pxt4_lblk_t *lblk)
{
	int depth = pxt2t_depth(inode);
	struct pxt4_pxt2tent *pxt2;
	pxt4_lblk_t len;

	pxt2 = path[depth].p_pxt2t;
	if (pxt2 == NULL) {
		/* there is no pxt2tent yet, so gap is [0;-] */
		*lblk = 0;
		len = EXT_MAX_BLOCKS;
	} else if (*lblk < le32_to_cpu(pxt2->ee_block)) {
		len = le32_to_cpu(pxt2->ee_block) - *lblk;
	} else if (*lblk >= le32_to_cpu(pxt2->ee_block)
			+ pxt4_pxt2t_get_actual_len(pxt2)) {
		pxt4_lblk_t npxt2t;

		*lblk = le32_to_cpu(pxt2->ee_block) + pxt4_pxt2t_get_actual_len(pxt2);
		npxt2t = pxt4_pxt2t_npxt2t_allocated_block(path);
		BUG_ON(npxt2t == *lblk);
		len = npxt2t - *lblk;
	} else {
		BUG();
	}
	return len;
}

/*
 * pxt4_pxt2t_put_gap_in_cache:
 * calculate boundaries of the gap that the requested block fits into
 * and cache this gap
 */
static void
pxt4_pxt2t_put_gap_in_cache(struct inode *inode, pxt4_lblk_t hole_start,
			  pxt4_lblk_t hole_len)
{
	struct pxt2tent_status es;

	pxt4_es_find_pxt2tent_range(inode, &pxt4_es_is_delayed, hole_start,
				  hole_start + hole_len - 1, &es);
	if (es.es_len) {
		/* There's delayed pxt2tent containing lblock? */
		if (es.es_lblk <= hole_start)
			return;
		hole_len = min(es.es_lblk - hole_start, hole_len);
	}
	pxt2t_debug(" -> %u:%u\n", hole_start, hole_len);
	pxt4_es_insert_pxt2tent(inode, hole_start, hole_len, ~0,
			      EXTENT_STATUS_HOLE);
}

/*
 * pxt4_pxt2t_rm_idx:
 * removes indpxt2 from the indpxt2 block.
 */
static int pxt4_pxt2t_rm_idx(handle_t *handle, struct inode *inode,
			struct pxt4_pxt2t_path *path, int depth)
{
	int err;
	pxt4_fsblk_t leaf;

	/* free indpxt2 block */
	depth--;
	path = path + depth;
	leaf = pxt4_idx_pblock(path->p_idx);
	if (unlikely(path->p_hdr->eh_entries == 0)) {
		PXT4_ERROR_INODE(inode, "path->p_hdr->eh_entries == 0");
		return -EFSCORRUPTED;
	}
	err = pxt4_pxt2t_get_access(handle, inode, path);
	if (err)
		return err;

	if (path->p_idx != EXT_LAST_INDEX(path->p_hdr)) {
		int len = EXT_LAST_INDEX(path->p_hdr) - path->p_idx;
		len *= sizeof(struct pxt4_pxt2tent_idx);
		memmove(path->p_idx, path->p_idx + 1, len);
	}

	le16_add_cpu(&path->p_hdr->eh_entries, -1);
	err = pxt4_pxt2t_dirty(handle, inode, path);
	if (err)
		return err;
	pxt2t_debug("indpxt2 is empty, remove it, free block %llu\n", leaf);
	trace_pxt4_pxt2t_rm_idx(inode, leaf);

	pxt4_free_blocks(handle, inode, NULL, leaf, 1,
			 PXT4_FREE_BLOCKS_METADATA | PXT4_FREE_BLOCKS_FORGET);

	while (--depth >= 0) {
		if (path->p_idx != EXT_FIRST_INDEX(path->p_hdr))
			break;
		path--;
		err = pxt4_pxt2t_get_access(handle, inode, path);
		if (err)
			break;
		path->p_idx->ei_block = (path+1)->p_idx->ei_block;
		err = pxt4_pxt2t_dirty(handle, inode, path);
		if (err)
			break;
	}
	return err;
}

/*
 * pxt4_pxt2t_calc_credits_for_single_pxt2tent:
 * This routine returns max. credits that needed to insert an pxt2tent
 * to the pxt2tent tree.
 * When pass the actual path, the caller should calculate credits
 * under i_data_sem.
 */
int pxt4_pxt2t_calc_credits_for_single_pxt2tent(struct inode *inode, int nrblocks,
						struct pxt4_pxt2t_path *path)
{
	if (path) {
		int depth = pxt2t_depth(inode);
		int ret = 0;

		/* probably there is space in leaf? */
		if (le16_to_cpu(path[depth].p_hdr->eh_entries)
				< le16_to_cpu(path[depth].p_hdr->eh_max)) {

			/*
			 *  There are some space in the leaf tree, no
			 *  need to account for leaf block credit
			 *
			 *  bitmaps and block group descriptor blocks
			 *  and other metadata blocks still need to be
			 *  accounted.
			 */
			/* 1 bitmap, 1 block group descriptor */
			ret = 2 + PXT4_META_TRANS_BLOCKS(inode->i_sb);
			return ret;
		}
	}

	return pxt4_chunk_trans_blocks(inode, nrblocks);
}

/*
 * How many indpxt2/leaf blocks need to change/allocate to add @pxt2tents pxt2tents?
 *
 * If we add a single pxt2tent, then in the worse case, each tree level
 * indpxt2/leaf need to be changed in case of the tree split.
 *
 * If more pxt2tents are inserted, they could cause the whole tree split more
 * than once, but this is really rare.
 */
int pxt4_pxt2t_indpxt2_trans_blocks(struct inode *inode, int pxt2tents)
{
	int indpxt2;
	int depth;

	/* If we are converting the inline data, only one is needed here. */
	if (pxt4_has_inline_data(inode))
		return 1;

	depth = pxt2t_depth(inode);

	if (pxt2tents <= 1)
		indpxt2 = depth * 2;
	else
		indpxt2 = depth * 3;

	return indpxt2;
}

static inline int get_default_free_blocks_flags(struct inode *inode)
{
	if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode) ||
	    pxt4_test_inode_flag(inode, PXT4_INODE_EA_INODE))
		return PXT4_FREE_BLOCKS_METADATA | PXT4_FREE_BLOCKS_FORGET;
	else if (pxt4_should_journal_data(inode))
		return PXT4_FREE_BLOCKS_FORGET;
	return 0;
}

/*
 * pxt4_rereserve_cluster - increment the reserved cluster count when
 *                          freeing a cluster with a pending reservation
 *
 * @inode - file containing the cluster
 * @lblk - logical block in cluster to be reserved
 *
 * Increments the reserved cluster count and adjusts quota in a bigalloc
 * file system when freeing a partial cluster containing at least one
 * delayed and unwritten block.  A partial cluster meeting that
 * requirement will have a pending reservation.  If so, the
 * RERESERVE_CLUSTER flag is used when calling pxt4_free_blocks() to
 * defer reserved and allocated space accounting to a subsequent call
 * to this function.
 */
static void pxt4_rereserve_cluster(struct inode *inode, pxt4_lblk_t lblk)
{
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	struct pxt4_inode_info *ei = PXT4_I(inode);

	dquot_reclaim_block(inode, PXT4_C2B(sbi, 1));

	spin_lock(&ei->i_block_reservation_lock);
	ei->i_reserved_data_blocks++;
	percpu_counter_add(&sbi->s_dirtyclusters_counter, 1);
	spin_unlock(&ei->i_block_reservation_lock);

	percpu_counter_add(&sbi->s_freeclusters_counter, 1);
	pxt4_remove_pending(inode, lblk);
}

static int pxt4_remove_blocks(handle_t *handle, struct inode *inode,
			      struct pxt4_pxt2tent *pxt2,
			      struct partial_cluster *partial,
			      pxt4_lblk_t from, pxt4_lblk_t to)
{
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	unsigned short ee_len = pxt4_pxt2t_get_actual_len(pxt2);
	pxt4_fsblk_t last_pblk, pblk;
	pxt4_lblk_t num;
	int flags;

	/* only pxt2tent tail removal is allowed */
	if (from < le32_to_cpu(pxt2->ee_block) ||
	    to != le32_to_cpu(pxt2->ee_block) + ee_len - 1) {
		pxt4_error(sbi->s_sb,
			   "strange request: removal(2) %u-%u from %u:%u",
			   from, to, le32_to_cpu(pxt2->ee_block), ee_len);
		return 0;
	}

#ifdef EXTENTS_STATS
	spin_lock(&sbi->s_pxt2t_stats_lock);
	sbi->s_pxt2t_blocks += ee_len;
	sbi->s_pxt2t_pxt2tents++;
	if (ee_len < sbi->s_pxt2t_min)
		sbi->s_pxt2t_min = ee_len;
	if (ee_len > sbi->s_pxt2t_max)
		sbi->s_pxt2t_max = ee_len;
	if (pxt2t_depth(inode) > sbi->s_depth_max)
		sbi->s_depth_max = pxt2t_depth(inode);
	spin_unlock(&sbi->s_pxt2t_stats_lock);
#endif

	trace_pxt4_remove_blocks(inode, pxt2, from, to, partial);

	/*
	 * if we have a partial cluster, and it's different from the
	 * cluster of the last block in the pxt2tent, we free it
	 */
	last_pblk = pxt4_pxt2t_pblock(pxt2) + ee_len - 1;

	if (partial->state != initial &&
	    partial->pclu != PXT4_B2C(sbi, last_pblk)) {
		if (partial->state == tofree) {
			flags = get_default_free_blocks_flags(inode);
			if (pxt4_is_pending(inode, partial->lblk))
				flags |= PXT4_FREE_BLOCKS_RERESERVE_CLUSTER;
			pxt4_free_blocks(handle, inode, NULL,
					 PXT4_C2B(sbi, partial->pclu),
					 sbi->s_cluster_ratio, flags);
			if (flags & PXT4_FREE_BLOCKS_RERESERVE_CLUSTER)
				pxt4_rereserve_cluster(inode, partial->lblk);
		}
		partial->state = initial;
	}

	num = le32_to_cpu(pxt2->ee_block) + ee_len - from;
	pblk = pxt4_pxt2t_pblock(pxt2) + ee_len - num;

	/*
	 * We free the partial cluster at the end of the pxt2tent (if any),
	 * unless the cluster is used by another pxt2tent (partial_cluster
	 * state is nofree).  If a partial cluster pxt2ists here, it must be
	 * shared with the last block in the pxt2tent.
	 */
	flags = get_default_free_blocks_flags(inode);

	/* partial, left end cluster aligned, right end unaligned */
	if ((PXT4_LBLK_COFF(sbi, to) != sbi->s_cluster_ratio - 1) &&
	    (PXT4_LBLK_CMASK(sbi, to) >= from) &&
	    (partial->state != nofree)) {
		if (pxt4_is_pending(inode, to))
			flags |= PXT4_FREE_BLOCKS_RERESERVE_CLUSTER;
		pxt4_free_blocks(handle, inode, NULL,
				 PXT4_PBLK_CMASK(sbi, last_pblk),
				 sbi->s_cluster_ratio, flags);
		if (flags & PXT4_FREE_BLOCKS_RERESERVE_CLUSTER)
			pxt4_rereserve_cluster(inode, to);
		partial->state = initial;
		flags = get_default_free_blocks_flags(inode);
	}

	flags |= PXT4_FREE_BLOCKS_NOFREE_LAST_CLUSTER;

	/*
	 * For bigalloc file systems, we never free a partial cluster
	 * at the beginning of the pxt2tent.  Instead, we check to see if we
	 * need to free it on a subsequent call to pxt4_remove_blocks,
	 * or at the end of pxt4_pxt2t_rm_leaf or pxt4_pxt2t_remove_space.
	 */
	flags |= PXT4_FREE_BLOCKS_NOFREE_FIRST_CLUSTER;
	pxt4_free_blocks(handle, inode, NULL, pblk, num, flags);

	/* reset the partial cluster if we've freed past it */
	if (partial->state != initial && partial->pclu != PXT4_B2C(sbi, pblk))
		partial->state = initial;

	/*
	 * If we've freed the entire pxt2tent but the beginning is not left
	 * cluster aligned and is not marked as ineligible for freeing we
	 * record the partial cluster at the beginning of the pxt2tent.  It
	 * wasn't freed by the preceding pxt4_free_blocks() call, and we
	 * need to look farther to the left to determine if it's to be freed
	 * (not shared with another pxt2tent). Else, reset the partial
	 * cluster - we're either  done freeing or the beginning of the
	 * pxt2tent is left cluster aligned.
	 */
	if (PXT4_LBLK_COFF(sbi, from) && num == ee_len) {
		if (partial->state == initial) {
			partial->pclu = PXT4_B2C(sbi, pblk);
			partial->lblk = from;
			partial->state = tofree;
		}
	} else {
		partial->state = initial;
	}

	return 0;
}

/*
 * pxt4_pxt2t_rm_leaf() Removes the pxt2tents associated with the
 * blocks appearing between "start" and "end".  Both "start"
 * and "end" must appear in the same pxt2tent or EIO is returned.
 *
 * @handle: The journal handle
 * @inode:  The files inode
 * @path:   The path to the leaf
 * @partial_cluster: The cluster which we'll have to free if all pxt2tents
 *                   has been released from it.  However, if this value is
 *                   negative, it's a cluster just to the right of the
 *                   punched region and it must not be freed.
 * @start:  The first block to remove
 * @end:   The last block to remove
 */
static int
pxt4_pxt2t_rm_leaf(handle_t *handle, struct inode *inode,
		 struct pxt4_pxt2t_path *path,
		 struct partial_cluster *partial,
		 pxt4_lblk_t start, pxt4_lblk_t end)
{
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	int err = 0, correct_indpxt2 = 0;
	int depth = pxt2t_depth(inode), credits;
	struct pxt4_pxt2tent_header *eh;
	pxt4_lblk_t a, b;
	unsigned num;
	pxt4_lblk_t pxt2_ee_block;
	unsigned short pxt2_ee_len;
	unsigned unwritten = 0;
	struct pxt4_pxt2tent *pxt2;
	pxt4_fsblk_t pblk;

	/* the header must be checked already in pxt4_pxt2t_remove_space() */
	pxt2t_debug("truncate since %u in leaf to %u\n", start, end);
	if (!path[depth].p_hdr)
		path[depth].p_hdr = pxt2t_block_hdr(path[depth].p_bh);
	eh = path[depth].p_hdr;
	if (unlikely(path[depth].p_hdr == NULL)) {
		PXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
		return -EFSCORRUPTED;
	}
	/* find where to start removing */
	pxt2 = path[depth].p_pxt2t;
	if (!pxt2)
		pxt2 = EXT_LAST_EXTENT(eh);

	pxt2_ee_block = le32_to_cpu(pxt2->ee_block);
	pxt2_ee_len = pxt4_pxt2t_get_actual_len(pxt2);

	trace_pxt4_pxt2t_rm_leaf(inode, start, pxt2, partial);

	while (pxt2 >= EXT_FIRST_EXTENT(eh) &&
			pxt2_ee_block + pxt2_ee_len > start) {

		if (pxt4_pxt2t_is_unwritten(pxt2))
			unwritten = 1;
		else
			unwritten = 0;

		pxt2t_debug("remove pxt2t %u:[%d]%d\n", pxt2_ee_block,
			  unwritten, pxt2_ee_len);
		path[depth].p_pxt2t = pxt2;

		a = pxt2_ee_block > start ? pxt2_ee_block : start;
		b = pxt2_ee_block+pxt2_ee_len - 1 < end ?
			pxt2_ee_block+pxt2_ee_len - 1 : end;

		pxt2t_debug("  border %u:%u\n", a, b);

		/* If this pxt2tent is beyond the end of the hole, skip it */
		if (end < pxt2_ee_block) {
			/*
			 * We're going to skip this pxt2tent and move to another,
			 * so note that its first cluster is in use to avoid
			 * freeing it when removing blocks.  Eventually, the
			 * right edge of the truncated/punched region will
			 * be just to the left.
			 */
			if (sbi->s_cluster_ratio > 1) {
				pblk = pxt4_pxt2t_pblock(pxt2);
				partial->pclu = PXT4_B2C(sbi, pblk);
				partial->state = nofree;
			}
			pxt2--;
			pxt2_ee_block = le32_to_cpu(pxt2->ee_block);
			pxt2_ee_len = pxt4_pxt2t_get_actual_len(pxt2);
			continue;
		} else if (b != pxt2_ee_block + pxt2_ee_len - 1) {
			PXT4_ERROR_INODE(inode,
					 "can not handle truncate %u:%u "
					 "on pxt2tent %u:%u",
					 start, end, pxt2_ee_block,
					 pxt2_ee_block + pxt2_ee_len - 1);
			err = -EFSCORRUPTED;
			goto out;
		} else if (a != pxt2_ee_block) {
			/* remove tail of the pxt2tent */
			num = a - pxt2_ee_block;
		} else {
			/* remove whole pxt2tent: pxt2cellent! */
			num = 0;
		}
		/*
		 * 3 for leaf, sb, and inode plus 2 (bmap and group
		 * descriptor) for each block group; assume two block
		 * groups plus pxt2_ee_len/blocks_per_block_group for
		 * the worst case
		 */
		credits = 7 + 2*(pxt2_ee_len/PXT4_BLOCKS_PER_GROUP(inode->i_sb));
		if (pxt2 == EXT_FIRST_EXTENT(eh)) {
			correct_indpxt2 = 1;
			credits += (pxt2t_depth(inode)) + 1;
		}
		credits += PXT4_MAXQUOTAS_TRANS_BLOCKS(inode->i_sb);

		err = pxt4_pxt2t_truncate_pxt2tend_restart(handle, inode, credits);
		if (err)
			goto out;

		err = pxt4_pxt2t_get_access(handle, inode, path + depth);
		if (err)
			goto out;

		err = pxt4_remove_blocks(handle, inode, pxt2, partial, a, b);
		if (err)
			goto out;

		if (num == 0)
			/* this pxt2tent is removed; mark slot entirely unused */
			pxt4_pxt2t_store_pblock(pxt2, 0);

		pxt2->ee_len = cpu_to_le16(num);
		/*
		 * Do not mark unwritten if all the blocks in the
		 * pxt2tent have been removed.
		 */
		if (unwritten && num)
			pxt4_pxt2t_mark_unwritten(pxt2);
		/*
		 * If the pxt2tent was completely released,
		 * we need to remove it from the leaf
		 */
		if (num == 0) {
			if (end != EXT_MAX_BLOCKS - 1) {
				/*
				 * For hole punching, we need to scoot all the
				 * pxt2tents up when an pxt2tent is removed so that
				 * we dont have blank pxt2tents in the middle
				 */
				memmove(pxt2, pxt2+1, (EXT_LAST_EXTENT(eh) - pxt2) *
					sizeof(struct pxt4_pxt2tent));

				/* Now get rid of the one at the end */
				memset(EXT_LAST_EXTENT(eh), 0,
					sizeof(struct pxt4_pxt2tent));
			}
			le16_add_cpu(&eh->eh_entries, -1);
		}

		err = pxt4_pxt2t_dirty(handle, inode, path + depth);
		if (err)
			goto out;

		pxt2t_debug("new pxt2tent: %u:%u:%llu\n", pxt2_ee_block, num,
				pxt4_pxt2t_pblock(pxt2));
		pxt2--;
		pxt2_ee_block = le32_to_cpu(pxt2->ee_block);
		pxt2_ee_len = pxt4_pxt2t_get_actual_len(pxt2);
	}

	if (correct_indpxt2 && eh->eh_entries)
		err = pxt4_pxt2t_correct_indpxt2es(handle, inode, path);

	/*
	 * If there's a partial cluster and at least one pxt2tent remains in
	 * the leaf, free the partial cluster if it isn't shared with the
	 * current pxt2tent.  If it is shared with the current pxt2tent
	 * we reset the partial cluster because we've reached the start of the
	 * truncated/punched region and we're done removing blocks.
	 */
	if (partial->state == tofree && pxt2 >= EXT_FIRST_EXTENT(eh)) {
		pblk = pxt4_pxt2t_pblock(pxt2) + pxt2_ee_len - 1;
		if (partial->pclu != PXT4_B2C(sbi, pblk)) {
			int flags = get_default_free_blocks_flags(inode);

			if (pxt4_is_pending(inode, partial->lblk))
				flags |= PXT4_FREE_BLOCKS_RERESERVE_CLUSTER;
			pxt4_free_blocks(handle, inode, NULL,
					 PXT4_C2B(sbi, partial->pclu),
					 sbi->s_cluster_ratio, flags);
			if (flags & PXT4_FREE_BLOCKS_RERESERVE_CLUSTER)
				pxt4_rereserve_cluster(inode, partial->lblk);
		}
		partial->state = initial;
	}

	/* if this leaf is free, then we should
	 * remove it from indpxt2 block above */
	if (err == 0 && eh->eh_entries == 0 && path[depth].p_bh != NULL)
		err = pxt4_pxt2t_rm_idx(handle, inode, path, depth);

out:
	return err;
}

/*
 * pxt4_pxt2t_more_to_rm:
 * returns 1 if current indpxt2 has to be freed (even partial)
 */
static int
pxt4_pxt2t_more_to_rm(struct pxt4_pxt2t_path *path)
{
	BUG_ON(path->p_idx == NULL);

	if (path->p_idx < EXT_FIRST_INDEX(path->p_hdr))
		return 0;

	/*
	 * if truncate on deeper level happened, it wasn't partial,
	 * so we have to consider current indpxt2 for truncation
	 */
	if (le16_to_cpu(path->p_hdr->eh_entries) == path->p_block)
		return 0;
	return 1;
}

int pxt4_pxt2t_remove_space(struct inode *inode, pxt4_lblk_t start,
			  pxt4_lblk_t end)
{
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	int depth = pxt2t_depth(inode);
	struct pxt4_pxt2t_path *path = NULL;
	struct partial_cluster partial;
	handle_t *handle;
	int i = 0, err = 0;

	partial.pclu = 0;
	partial.lblk = 0;
	partial.state = initial;

	pxt2t_debug("truncate since %u to %u\n", start, end);

	/* probably first pxt2tent we're gonna free will be last in block */
	handle = pxt4_journal_start(inode, PXT4_HT_TRUNCATE, depth + 1);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

again:
	trace_pxt4_pxt2t_remove_space(inode, start, end, depth);

	/*
	 * Check if we are removing pxt2tents inside the pxt2tent tree. If that
	 * is the case, we are going to punch a hole inside the pxt2tent tree
	 * so we have to check whether we need to split the pxt2tent covering
	 * the last block to remove so we can easily remove the part of it
	 * in pxt4_pxt2t_rm_leaf().
	 */
	if (end < EXT_MAX_BLOCKS - 1) {
		struct pxt4_pxt2tent *pxt2;
		pxt4_lblk_t ee_block, pxt2_end, lblk;
		pxt4_fsblk_t pblk;

		/* find pxt2tent for or closest pxt2tent to this block */
		path = pxt4_find_pxt2tent(inode, end, NULL, PXT4_EX_NOCACHE);
		if (IS_ERR(path)) {
			pxt4_journal_stop(handle);
			return PTR_ERR(path);
		}
		depth = pxt2t_depth(inode);
		/* Leaf not may not pxt2ist only if inode has no blocks at all */
		pxt2 = path[depth].p_pxt2t;
		if (!pxt2) {
			if (depth) {
				PXT4_ERROR_INODE(inode,
						 "path[%d].p_hdr == NULL",
						 depth);
				err = -EFSCORRUPTED;
			}
			goto out;
		}

		ee_block = le32_to_cpu(pxt2->ee_block);
		pxt2_end = ee_block + pxt4_pxt2t_get_actual_len(pxt2) - 1;

		/*
		 * See if the last block is inside the pxt2tent, if so split
		 * the pxt2tent at 'end' block so we can easily remove the
		 * tail of the first part of the split pxt2tent in
		 * pxt4_pxt2t_rm_leaf().
		 */
		if (end >= ee_block && end < pxt2_end) {

			/*
			 * If we're going to split the pxt2tent, note that
			 * the cluster containing the block after 'end' is
			 * in use to avoid freeing it when removing blocks.
			 */
			if (sbi->s_cluster_ratio > 1) {
				pblk = pxt4_pxt2t_pblock(pxt2) + end - ee_block + 1;
				partial.pclu = PXT4_B2C(sbi, pblk);
				partial.state = nofree;
			}

			/*
			 * Split the pxt2tent in two so that 'end' is the last
			 * block in the first new pxt2tent. Also we should not
			 * fail removing space due to ENOSPC so try to use
			 * reserved block if that happens.
			 */
			err = pxt4_force_split_pxt2tent_at(handle, inode, &path,
							 end + 1, 1);
			if (err < 0)
				goto out;

		} else if (sbi->s_cluster_ratio > 1 && end >= pxt2_end &&
			   partial.state == initial) {
			/*
			 * If we're punching, there's an pxt2tent to the right.
			 * If the partial cluster hasn't been set, set it to
			 * that pxt2tent's first cluster and its state to nofree
			 * so it won't be freed should it contain blocks to be
			 * removed. If it's already set (tofree/nofree), we're
			 * retrying and keep the original partial cluster info
			 * so a cluster marked tofree as a result of earlier
			 * pxt2tent removal is not lost.
			 */
			lblk = pxt2_end + 1;
			err = pxt4_pxt2t_search_right(inode, path, &lblk, &pblk,
						    &pxt2);
			if (err)
				goto out;
			if (pblk) {
				partial.pclu = PXT4_B2C(sbi, pblk);
				partial.state = nofree;
			}
		}
	}
	/*
	 * We start scanning from right side, freeing all the blocks
	 * after i_size and walking into the tree depth-wise.
	 */
	depth = pxt2t_depth(inode);
	if (path) {
		int k = i = depth;
		while (--k > 0)
			path[k].p_block =
				le16_to_cpu(path[k].p_hdr->eh_entries)+1;
	} else {
		path = kcalloc(depth + 1, sizeof(struct pxt4_pxt2t_path),
			       GFP_NOFS);
		if (path == NULL) {
			pxt4_journal_stop(handle);
			return -ENOMEM;
		}
		path[0].p_maxdepth = path[0].p_depth = depth;
		path[0].p_hdr = pxt2t_inode_hdr(inode);
		i = 0;

		if (pxt4_pxt2t_check(inode, path[0].p_hdr, depth, 0)) {
			err = -EFSCORRUPTED;
			goto out;
		}
	}
	err = 0;

	while (i >= 0 && err == 0) {
		if (i == depth) {
			/* this is leaf block */
			err = pxt4_pxt2t_rm_leaf(handle, inode, path,
					       &partial, start, end);
			/* root level has p_bh == NULL, brelse() eats this */
			brelse(path[i].p_bh);
			path[i].p_bh = NULL;
			i--;
			continue;
		}

		/* this is indpxt2 block */
		if (!path[i].p_hdr) {
			pxt2t_debug("initialize header\n");
			path[i].p_hdr = pxt2t_block_hdr(path[i].p_bh);
		}

		if (!path[i].p_idx) {
			/* this level hasn't been touched yet */
			path[i].p_idx = EXT_LAST_INDEX(path[i].p_hdr);
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries)+1;
			pxt2t_debug("init indpxt2 ptr: hdr 0x%p, num %d\n",
				  path[i].p_hdr,
				  le16_to_cpu(path[i].p_hdr->eh_entries));
		} else {
			/* we were already here, see at npxt2t indpxt2 */
			path[i].p_idx--;
		}

		pxt2t_debug("level %d - indpxt2, first 0x%p, cur 0x%p\n",
				i, EXT_FIRST_INDEX(path[i].p_hdr),
				path[i].p_idx);
		if (pxt4_pxt2t_more_to_rm(path + i)) {
			struct buffer_head *bh;
			/* go to the npxt2t level */
			pxt2t_debug("move to level %d (block %llu)\n",
				  i + 1, pxt4_idx_pblock(path[i].p_idx));
			memset(path + i + 1, 0, sizeof(*path));
			bh = read_pxt2tent_tree_block(inode,
				pxt4_idx_pblock(path[i].p_idx), depth - i - 1,
				PXT4_EX_NOCACHE);
			if (IS_ERR(bh)) {
				/* should we reset i_size? */
				err = PTR_ERR(bh);
				break;
			}
			/* Yield here to deal with large pxt2tent trees.
			 * Should be a no-op if we did IO above. */
			cond_resched();
			if (WARN_ON(i + 1 > depth)) {
				err = -EFSCORRUPTED;
				break;
			}
			path[i + 1].p_bh = bh;

			/* save actual number of indpxt2es since this
			 * number is changed at the npxt2t iteration */
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries);
			i++;
		} else {
			/* we finished processing this indpxt2, go up */
			if (path[i].p_hdr->eh_entries == 0 && i > 0) {
				/* indpxt2 is empty, remove it;
				 * handle must be already prepared by the
				 * truncatei_leaf() */
				err = pxt4_pxt2t_rm_idx(handle, inode, path, i);
			}
			/* root level has p_bh == NULL, brelse() eats this */
			brelse(path[i].p_bh);
			path[i].p_bh = NULL;
			i--;
			pxt2t_debug("return to level %d\n", i);
		}
	}

	trace_pxt4_pxt2t_remove_space_done(inode, start, end, depth, &partial,
					 path->p_hdr->eh_entries);

	/*
	 * if there's a partial cluster and we have removed the first pxt2tent
	 * in the file, then we also free the partial cluster, if any
	 */
	if (partial.state == tofree && err == 0) {
		int flags = get_default_free_blocks_flags(inode);

		if (pxt4_is_pending(inode, partial.lblk))
			flags |= PXT4_FREE_BLOCKS_RERESERVE_CLUSTER;
		pxt4_free_blocks(handle, inode, NULL,
				 PXT4_C2B(sbi, partial.pclu),
				 sbi->s_cluster_ratio, flags);
		if (flags & PXT4_FREE_BLOCKS_RERESERVE_CLUSTER)
			pxt4_rereserve_cluster(inode, partial.lblk);
		partial.state = initial;
	}

	/* TODO: flpxt2ible tree reduction should be here */
	if (path->p_hdr->eh_entries == 0) {
		/*
		 * truncate to zero freed all the tree,
		 * so we need to correct eh_depth
		 */
		err = pxt4_pxt2t_get_access(handle, inode, path);
		if (err == 0) {
			pxt2t_inode_hdr(inode)->eh_depth = 0;
			pxt2t_inode_hdr(inode)->eh_max =
				cpu_to_le16(pxt4_pxt2t_space_root(inode, 0));
			err = pxt4_pxt2t_dirty(handle, inode, path);
		}
	}
out:
	pxt4_pxt2t_drop_refs(path);
	kfree(path);
	path = NULL;
	if (err == -EAGAIN)
		goto again;
	pxt4_journal_stop(handle);

	return err;
}

/*
 * called at mount time
 */
void pxt4_pxt2t_init(struct super_block *sb)
{
	/*
	 * possible initialization would be here
	 */

	if (pxt4_has_feature_pxt2tents(sb)) {
#if defined(AGGRESSIVE_TEST) || defined(CHECK_BINSEARCH) || defined(EXTENTS_STATS)
		printk(KERN_INFO "PXT4-fs: file pxt2tents enabled"
#ifdef AGGRESSIVE_TEST
		       ", aggressive tests"
#endif
#ifdef CHECK_BINSEARCH
		       ", check binsearch"
#endif
#ifdef EXTENTS_STATS
		       ", stats"
#endif
		       "\n");
#endif
#ifdef EXTENTS_STATS
		spin_lock_init(&PXT4_SB(sb)->s_pxt2t_stats_lock);
		PXT4_SB(sb)->s_pxt2t_min = 1 << 30;
		PXT4_SB(sb)->s_pxt2t_max = 0;
#endif
	}
}

/*
 * called at umount time
 */
void pxt4_pxt2t_release(struct super_block *sb)
{
	if (!pxt4_has_feature_pxt2tents(sb))
		return;

#ifdef EXTENTS_STATS
	if (PXT4_SB(sb)->s_pxt2t_blocks && PXT4_SB(sb)->s_pxt2t_pxt2tents) {
		struct pxt4_sb_info *sbi = PXT4_SB(sb);
		printk(KERN_ERR "PXT4-fs: %lu blocks in %lu pxt2tents (%lu ave)\n",
			sbi->s_pxt2t_blocks, sbi->s_pxt2t_pxt2tents,
			sbi->s_pxt2t_blocks / sbi->s_pxt2t_pxt2tents);
		printk(KERN_ERR "PXT4-fs: pxt2tents: %lu min, %lu max, max depth %lu\n",
			sbi->s_pxt2t_min, sbi->s_pxt2t_max, sbi->s_depth_max);
	}
#endif
}

static int pxt4_zeroout_es(struct inode *inode, struct pxt4_pxt2tent *pxt2)
{
	pxt4_lblk_t  ee_block;
	pxt4_fsblk_t ee_pblock;
	unsigned int ee_len;

	ee_block  = le32_to_cpu(pxt2->ee_block);
	ee_len    = pxt4_pxt2t_get_actual_len(pxt2);
	ee_pblock = pxt4_pxt2t_pblock(pxt2);

	if (ee_len == 0)
		return 0;

	return pxt4_es_insert_pxt2tent(inode, ee_block, ee_len, ee_pblock,
				     EXTENT_STATUS_WRITTEN);
}

/* FIXME!! we need to try to merge to left or right after zero-out  */
static int pxt4_pxt2t_zeroout(struct inode *inode, struct pxt4_pxt2tent *pxt2)
{
	pxt4_fsblk_t ee_pblock;
	unsigned int ee_len;

	ee_len    = pxt4_pxt2t_get_actual_len(pxt2);
	ee_pblock = pxt4_pxt2t_pblock(pxt2);
	return pxt4_issue_zeroout(inode, le32_to_cpu(pxt2->ee_block), ee_pblock,
				  ee_len);
}

/*
 * pxt4_split_pxt2tent_at() splits an pxt2tent at given block.
 *
 * @handle: the journal handle
 * @inode: the file inode
 * @path: the path to the pxt2tent
 * @split: the logical block where the pxt2tent is splitted.
 * @split_flags: indicates if the pxt2tent could be zeroout if split fails, and
 *		 the states(init or unwritten) of new pxt2tents.
 * @flags: flags used to insert new pxt2tent to pxt2tent tree.
 *
 *
 * Splits pxt2tent [a, b] into two pxt2tents [a, @split) and [@split, b], states
 * of which are deterimined by split_flag.
 *
 * There are two cases:
 *  a> the pxt2tent are splitted into two pxt2tent.
 *  b> split is not needed, and just mark the pxt2tent.
 *
 * return 0 on success.
 */
static int pxt4_split_pxt2tent_at(handle_t *handle,
			     struct inode *inode,
			     struct pxt4_pxt2t_path **ppath,
			     pxt4_lblk_t split,
			     int split_flag,
			     int flags)
{
	struct pxt4_pxt2t_path *path = *ppath;
	pxt4_fsblk_t newblock;
	pxt4_lblk_t ee_block;
	struct pxt4_pxt2tent *pxt2, newpxt2, orig_pxt2, zero_pxt2;
	struct pxt4_pxt2tent *pxt22 = NULL;
	unsigned int ee_len, depth;
	int err = 0;

	BUG_ON((split_flag & (PXT4_EXT_DATA_VALID1 | PXT4_EXT_DATA_VALID2)) ==
	       (PXT4_EXT_DATA_VALID1 | PXT4_EXT_DATA_VALID2));

	pxt2t_debug("pxt4_split_pxt2tents_at: inode %lu, logical"
		"block %llu\n", inode->i_ino, (unsigned long long)split);

	pxt4_pxt2t_show_leaf(inode, path);

	depth = pxt2t_depth(inode);
	pxt2 = path[depth].p_pxt2t;
	ee_block = le32_to_cpu(pxt2->ee_block);
	ee_len = pxt4_pxt2t_get_actual_len(pxt2);
	newblock = split - ee_block + pxt4_pxt2t_pblock(pxt2);

	BUG_ON(split < ee_block || split >= (ee_block + ee_len));
	BUG_ON(!pxt4_pxt2t_is_unwritten(pxt2) &&
	       split_flag & (PXT4_EXT_MAY_ZEROOUT |
			     PXT4_EXT_MARK_UNWRIT1 |
			     PXT4_EXT_MARK_UNWRIT2));

	err = pxt4_pxt2t_get_access(handle, inode, path + depth);
	if (err)
		goto out;

	if (split == ee_block) {
		/*
		 * case b: block @split is the block that the pxt2tent begins with
		 * then we just change the state of the pxt2tent, and splitting
		 * is not needed.
		 */
		if (split_flag & PXT4_EXT_MARK_UNWRIT2)
			pxt4_pxt2t_mark_unwritten(pxt2);
		else
			pxt4_pxt2t_mark_initialized(pxt2);

		if (!(flags & PXT4_GET_BLOCKS_PRE_IO))
			pxt4_pxt2t_try_to_merge(handle, inode, path, pxt2);

		err = pxt4_pxt2t_dirty(handle, inode, path + path->p_depth);
		goto out;
	}

	/* case a */
	memcpy(&orig_pxt2, pxt2, sizeof(orig_pxt2));
	pxt2->ee_len = cpu_to_le16(split - ee_block);
	if (split_flag & PXT4_EXT_MARK_UNWRIT1)
		pxt4_pxt2t_mark_unwritten(pxt2);

	/*
	 * path may lead to new leaf, not to original leaf any more
	 * after pxt4_pxt2t_insert_pxt2tent() returns,
	 */
	err = pxt4_pxt2t_dirty(handle, inode, path + depth);
	if (err)
		goto fix_pxt2tent_len;

	pxt22 = &newpxt2;
	pxt22->ee_block = cpu_to_le32(split);
	pxt22->ee_len   = cpu_to_le16(ee_len - (split - ee_block));
	pxt4_pxt2t_store_pblock(pxt22, newblock);
	if (split_flag & PXT4_EXT_MARK_UNWRIT2)
		pxt4_pxt2t_mark_unwritten(pxt22);

	err = pxt4_pxt2t_insert_pxt2tent(handle, inode, ppath, &newpxt2, flags);
	if (err == -ENOSPC && (PXT4_EXT_MAY_ZEROOUT & split_flag)) {
		if (split_flag & (PXT4_EXT_DATA_VALID1|PXT4_EXT_DATA_VALID2)) {
			if (split_flag & PXT4_EXT_DATA_VALID1) {
				err = pxt4_pxt2t_zeroout(inode, pxt22);
				zero_pxt2.ee_block = pxt22->ee_block;
				zero_pxt2.ee_len = cpu_to_le16(
						pxt4_pxt2t_get_actual_len(pxt22));
				pxt4_pxt2t_store_pblock(&zero_pxt2,
						      pxt4_pxt2t_pblock(pxt22));
			} else {
				err = pxt4_pxt2t_zeroout(inode, pxt2);
				zero_pxt2.ee_block = pxt2->ee_block;
				zero_pxt2.ee_len = cpu_to_le16(
						pxt4_pxt2t_get_actual_len(pxt2));
				pxt4_pxt2t_store_pblock(&zero_pxt2,
						      pxt4_pxt2t_pblock(pxt2));
			}
		} else {
			err = pxt4_pxt2t_zeroout(inode, &orig_pxt2);
			zero_pxt2.ee_block = orig_pxt2.ee_block;
			zero_pxt2.ee_len = cpu_to_le16(
						pxt4_pxt2t_get_actual_len(&orig_pxt2));
			pxt4_pxt2t_store_pblock(&zero_pxt2,
					      pxt4_pxt2t_pblock(&orig_pxt2));
		}

		if (err)
			goto fix_pxt2tent_len;
		/* update the pxt2tent length and mark as initialized */
		pxt2->ee_len = cpu_to_le16(ee_len);
		pxt4_pxt2t_try_to_merge(handle, inode, path, pxt2);
		err = pxt4_pxt2t_dirty(handle, inode, path + path->p_depth);
		if (err)
			goto fix_pxt2tent_len;

		/* update pxt2tent status tree */
		err = pxt4_zeroout_es(inode, &zero_pxt2);

		goto out;
	} else if (err)
		goto fix_pxt2tent_len;

out:
	pxt4_pxt2t_show_leaf(inode, path);
	return err;

fix_pxt2tent_len:
	pxt2->ee_len = orig_pxt2.ee_len;
	pxt4_pxt2t_dirty(handle, inode, path + path->p_depth);
	return err;
}

/*
 * pxt4_split_pxt2tents() splits an pxt2tent and mark pxt2tent which is covered
 * by @map as split_flags indicates
 *
 * It may result in splitting the pxt2tent into multiple pxt2tents (up to three)
 * There are three possibilities:
 *   a> There is no split required
 *   b> Splits in two pxt2tents: Split is happening at either end of the pxt2tent
 *   c> Splits in three pxt2tents: Somone is splitting in middle of the pxt2tent
 *
 */
static int pxt4_split_pxt2tent(handle_t *handle,
			      struct inode *inode,
			      struct pxt4_pxt2t_path **ppath,
			      struct pxt4_map_blocks *map,
			      int split_flag,
			      int flags)
{
	struct pxt4_pxt2t_path *path = *ppath;
	pxt4_lblk_t ee_block;
	struct pxt4_pxt2tent *pxt2;
	unsigned int ee_len, depth;
	int err = 0;
	int unwritten;
	int split_flag1, flags1;
	int allocated = map->m_len;

	depth = pxt2t_depth(inode);
	pxt2 = path[depth].p_pxt2t;
	ee_block = le32_to_cpu(pxt2->ee_block);
	ee_len = pxt4_pxt2t_get_actual_len(pxt2);
	unwritten = pxt4_pxt2t_is_unwritten(pxt2);

	if (map->m_lblk + map->m_len < ee_block + ee_len) {
		split_flag1 = split_flag & PXT4_EXT_MAY_ZEROOUT;
		flags1 = flags | PXT4_GET_BLOCKS_PRE_IO;
		if (unwritten)
			split_flag1 |= PXT4_EXT_MARK_UNWRIT1 |
				       PXT4_EXT_MARK_UNWRIT2;
		if (split_flag & PXT4_EXT_DATA_VALID2)
			split_flag1 |= PXT4_EXT_DATA_VALID1;
		err = pxt4_split_pxt2tent_at(handle, inode, ppath,
				map->m_lblk + map->m_len, split_flag1, flags1);
		if (err)
			goto out;
	} else {
		allocated = ee_len - (map->m_lblk - ee_block);
	}
	/*
	 * Update path is required because previous pxt4_split_pxt2tent_at() may
	 * result in split of original leaf or pxt2tent zeroout.
	 */
	path = pxt4_find_pxt2tent(inode, map->m_lblk, ppath, 0);
	if (IS_ERR(path))
		return PTR_ERR(path);
	depth = pxt2t_depth(inode);
	pxt2 = path[depth].p_pxt2t;
	if (!pxt2) {
		PXT4_ERROR_INODE(inode, "unpxt2pected hole at %lu",
				 (unsigned long) map->m_lblk);
		return -EFSCORRUPTED;
	}
	unwritten = pxt4_pxt2t_is_unwritten(pxt2);
	split_flag1 = 0;

	if (map->m_lblk >= ee_block) {
		split_flag1 = split_flag & PXT4_EXT_DATA_VALID2;
		if (unwritten) {
			split_flag1 |= PXT4_EXT_MARK_UNWRIT1;
			split_flag1 |= split_flag & (PXT4_EXT_MAY_ZEROOUT |
						     PXT4_EXT_MARK_UNWRIT2);
		}
		err = pxt4_split_pxt2tent_at(handle, inode, ppath,
				map->m_lblk, split_flag1, flags);
		if (err)
			goto out;
	}

	pxt4_pxt2t_show_leaf(inode, path);
out:
	return err ? err : allocated;
}

/*
 * This function is called by pxt4_pxt2t_map_blocks() if someone tries to write
 * to an unwritten pxt2tent. It may result in splitting the unwritten
 * pxt2tent into multiple pxt2tents (up to three - one initialized and two
 * unwritten).
 * There are three possibilities:
 *   a> There is no split required: Entire pxt2tent should be initialized
 *   b> Splits in two pxt2tents: Write is happening at either end of the pxt2tent
 *   c> Splits in three pxt2tents: Somone is writing in middle of the pxt2tent
 *
 * Pre-conditions:
 *  - The pxt2tent pointed to by 'path' is unwritten.
 *  - The pxt2tent pointed to by 'path' contains a superset
 *    of the logical span [map->m_lblk, map->m_lblk + map->m_len).
 *
 * Post-conditions on success:
 *  - the returned value is the number of blocks beyond map->l_lblk
 *    that are allocated and initialized.
 *    It is guaranteed to be >= map->m_len.
 */
static int pxt4_pxt2t_convert_to_initialized(handle_t *handle,
					   struct inode *inode,
					   struct pxt4_map_blocks *map,
					   struct pxt4_pxt2t_path **ppath,
					   int flags)
{
	struct pxt4_pxt2t_path *path = *ppath;
	struct pxt4_sb_info *sbi;
	struct pxt4_pxt2tent_header *eh;
	struct pxt4_map_blocks split_map;
	struct pxt4_pxt2tent zero_pxt21, zero_pxt22;
	struct pxt4_pxt2tent *pxt2, *abut_pxt2;
	pxt4_lblk_t ee_block, eof_block;
	unsigned int ee_len, depth, map_len = map->m_len;
	int allocated = 0, max_zeroout = 0;
	int err = 0;
	int split_flag = PXT4_EXT_DATA_VALID2;

	pxt2t_debug("pxt4_pxt2t_convert_to_initialized: inode %lu, logical"
		"block %llu, max_blocks %u\n", inode->i_ino,
		(unsigned long long)map->m_lblk, map_len);

	sbi = PXT4_SB(inode->i_sb);
	eof_block = (PXT4_I(inode)->i_disksize + inode->i_sb->s_blocksize - 1)
			>> inode->i_sb->s_blocksize_bits;
	if (eof_block < map->m_lblk + map_len)
		eof_block = map->m_lblk + map_len;

	depth = pxt2t_depth(inode);
	eh = path[depth].p_hdr;
	pxt2 = path[depth].p_pxt2t;
	ee_block = le32_to_cpu(pxt2->ee_block);
	ee_len = pxt4_pxt2t_get_actual_len(pxt2);
	zero_pxt21.ee_len = 0;
	zero_pxt22.ee_len = 0;

	trace_pxt4_pxt2t_convert_to_initialized_enter(inode, map, pxt2);

	/* Pre-conditions */
	BUG_ON(!pxt4_pxt2t_is_unwritten(pxt2));
	BUG_ON(!in_range(map->m_lblk, ee_block, ee_len));

	/*
	 * Attempt to transfer newly initialized blocks from the currently
	 * unwritten pxt2tent to its neighbor. This is much cheaper
	 * than an insertion followed by a merge as those involve costly
	 * memmove() calls. Transferring to the left is the common case in
	 * steady state for workloads doing fallocate(FALLOC_FL_KEEP_SIZE)
	 * followed by append writes.
	 *
	 * Limitations of the current logic:
	 *  - L1: we do not deal with writes covering the whole pxt2tent.
	 *    This would require removing the pxt2tent if the transfer
	 *    is possible.
	 *  - L2: we only attempt to merge with an pxt2tent stored in the
	 *    same pxt2tent tree node.
	 */
	if ((map->m_lblk == ee_block) &&
		/* See if we can merge left */
		(map_len < ee_len) &&		/*L1*/
		(pxt2 > EXT_FIRST_EXTENT(eh))) {	/*L2*/
		pxt4_lblk_t prev_lblk;
		pxt4_fsblk_t prev_pblk, ee_pblk;
		unsigned int prev_len;

		abut_pxt2 = pxt2 - 1;
		prev_lblk = le32_to_cpu(abut_pxt2->ee_block);
		prev_len = pxt4_pxt2t_get_actual_len(abut_pxt2);
		prev_pblk = pxt4_pxt2t_pblock(abut_pxt2);
		ee_pblk = pxt4_pxt2t_pblock(pxt2);

		/*
		 * A transfer of blocks from 'pxt2' to 'abut_pxt2' is allowed
		 * upon those conditions:
		 * - C1: abut_pxt2 is initialized,
		 * - C2: abut_pxt2 is logically abutting pxt2,
		 * - C3: abut_pxt2 is physically abutting pxt2,
		 * - C4: abut_pxt2 can receive the additional blocks without
		 *   overflowing the (initialized) length limit.
		 */
		if ((!pxt4_pxt2t_is_unwritten(abut_pxt2)) &&		/*C1*/
			((prev_lblk + prev_len) == ee_block) &&		/*C2*/
			((prev_pblk + prev_len) == ee_pblk) &&		/*C3*/
			(prev_len < (EXT_INIT_MAX_LEN - map_len))) {	/*C4*/
			err = pxt4_pxt2t_get_access(handle, inode, path + depth);
			if (err)
				goto out;

			trace_pxt4_pxt2t_convert_to_initialized_fastpath(inode,
				map, pxt2, abut_pxt2);

			/* Shift the start of pxt2 by 'map_len' blocks */
			pxt2->ee_block = cpu_to_le32(ee_block + map_len);
			pxt4_pxt2t_store_pblock(pxt2, ee_pblk + map_len);
			pxt2->ee_len = cpu_to_le16(ee_len - map_len);
			pxt4_pxt2t_mark_unwritten(pxt2); /* Restore the flag */

			/* Extend abut_pxt2 by 'map_len' blocks */
			abut_pxt2->ee_len = cpu_to_le16(prev_len + map_len);

			/* Result: number of initialized blocks past m_lblk */
			allocated = map_len;
		}
	} else if (((map->m_lblk + map_len) == (ee_block + ee_len)) &&
		   (map_len < ee_len) &&	/*L1*/
		   pxt2 < EXT_LAST_EXTENT(eh)) {	/*L2*/
		/* See if we can merge right */
		pxt4_lblk_t npxt2t_lblk;
		pxt4_fsblk_t npxt2t_pblk, ee_pblk;
		unsigned int npxt2t_len;

		abut_pxt2 = pxt2 + 1;
		npxt2t_lblk = le32_to_cpu(abut_pxt2->ee_block);
		npxt2t_len = pxt4_pxt2t_get_actual_len(abut_pxt2);
		npxt2t_pblk = pxt4_pxt2t_pblock(abut_pxt2);
		ee_pblk = pxt4_pxt2t_pblock(pxt2);

		/*
		 * A transfer of blocks from 'pxt2' to 'abut_pxt2' is allowed
		 * upon those conditions:
		 * - C1: abut_pxt2 is initialized,
		 * - C2: abut_pxt2 is logically abutting pxt2,
		 * - C3: abut_pxt2 is physically abutting pxt2,
		 * - C4: abut_pxt2 can receive the additional blocks without
		 *   overflowing the (initialized) length limit.
		 */
		if ((!pxt4_pxt2t_is_unwritten(abut_pxt2)) &&		/*C1*/
		    ((map->m_lblk + map_len) == npxt2t_lblk) &&		/*C2*/
		    ((ee_pblk + ee_len) == npxt2t_pblk) &&		/*C3*/
		    (npxt2t_len < (EXT_INIT_MAX_LEN - map_len))) {	/*C4*/
			err = pxt4_pxt2t_get_access(handle, inode, path + depth);
			if (err)
				goto out;

			trace_pxt4_pxt2t_convert_to_initialized_fastpath(inode,
				map, pxt2, abut_pxt2);

			/* Shift the start of abut_pxt2 by 'map_len' blocks */
			abut_pxt2->ee_block = cpu_to_le32(npxt2t_lblk - map_len);
			pxt4_pxt2t_store_pblock(abut_pxt2, npxt2t_pblk - map_len);
			pxt2->ee_len = cpu_to_le16(ee_len - map_len);
			pxt4_pxt2t_mark_unwritten(pxt2); /* Restore the flag */

			/* Extend abut_pxt2 by 'map_len' blocks */
			abut_pxt2->ee_len = cpu_to_le16(npxt2t_len + map_len);

			/* Result: number of initialized blocks past m_lblk */
			allocated = map_len;
		}
	}
	if (allocated) {
		/* Mark the block containing both pxt2tents as dirty */
		pxt4_pxt2t_dirty(handle, inode, path + depth);

		/* Update path to point to the right pxt2tent */
		path[depth].p_pxt2t = abut_pxt2;
		goto out;
	} else
		allocated = ee_len - (map->m_lblk - ee_block);

	WARN_ON(map->m_lblk < ee_block);
	/*
	 * It is safe to convert pxt2tent to initialized via pxt2plicit
	 * zeroout only if pxt2tent is fully inside i_size or new_size.
	 */
	split_flag |= ee_block + ee_len <= eof_block ? PXT4_EXT_MAY_ZEROOUT : 0;

	if (PXT4_EXT_MAY_ZEROOUT & split_flag)
		max_zeroout = sbi->s_pxt2tent_max_zeroout_kb >>
			(inode->i_sb->s_blocksize_bits - 10);

	if (IS_ENCRYPTED(inode))
		max_zeroout = 0;

	/*
	 * five cases:
	 * 1. split the pxt2tent into three pxt2tents.
	 * 2. split the pxt2tent into two pxt2tents, zeroout the head of the first
	 *    pxt2tent.
	 * 3. split the pxt2tent into two pxt2tents, zeroout the tail of the second
	 *    pxt2tent.
	 * 4. split the pxt2tent into two pxt2tents with out zeroout.
	 * 5. no splitting needed, just possibly zeroout the head and / or the
	 *    tail of the pxt2tent.
	 */
	split_map.m_lblk = map->m_lblk;
	split_map.m_len = map->m_len;

	if (max_zeroout && (allocated > split_map.m_len)) {
		if (allocated <= max_zeroout) {
			/* case 3 or 5 */
			zero_pxt21.ee_block =
				 cpu_to_le32(split_map.m_lblk +
					     split_map.m_len);
			zero_pxt21.ee_len =
				cpu_to_le16(allocated - split_map.m_len);
			pxt4_pxt2t_store_pblock(&zero_pxt21,
				pxt4_pxt2t_pblock(pxt2) + split_map.m_lblk +
				split_map.m_len - ee_block);
			err = pxt4_pxt2t_zeroout(inode, &zero_pxt21);
			if (err)
				goto out;
			split_map.m_len = allocated;
		}
		if (split_map.m_lblk - ee_block + split_map.m_len <
								max_zeroout) {
			/* case 2 or 5 */
			if (split_map.m_lblk != ee_block) {
				zero_pxt22.ee_block = pxt2->ee_block;
				zero_pxt22.ee_len = cpu_to_le16(split_map.m_lblk -
							ee_block);
				pxt4_pxt2t_store_pblock(&zero_pxt22,
						      pxt4_pxt2t_pblock(pxt2));
				err = pxt4_pxt2t_zeroout(inode, &zero_pxt22);
				if (err)
					goto out;
			}

			split_map.m_len += split_map.m_lblk - ee_block;
			split_map.m_lblk = ee_block;
			allocated = map->m_len;
		}
	}

	err = pxt4_split_pxt2tent(handle, inode, ppath, &split_map, split_flag,
				flags);
	if (err > 0)
		err = 0;
out:
	/* If we have gotten a failure, don't zero out status tree */
	if (!err) {
		err = pxt4_zeroout_es(inode, &zero_pxt21);
		if (!err)
			err = pxt4_zeroout_es(inode, &zero_pxt22);
	}
	return err ? err : allocated;
}

/*
 * This function is called by pxt4_pxt2t_map_blocks() from
 * pxt4_get_blocks_dio_write() when DIO to write
 * to an unwritten pxt2tent.
 *
 * Writing to an unwritten pxt2tent may result in splitting the unwritten
 * pxt2tent into multiple initialized/unwritten pxt2tents (up to three)
 * There are three possibilities:
 *   a> There is no split required: Entire pxt2tent should be unwritten
 *   b> Splits in two pxt2tents: Write is happening at either end of the pxt2tent
 *   c> Splits in three pxt2tents: Somone is writing in middle of the pxt2tent
 *
 * This works the same way in the case of initialized -> unwritten conversion.
 *
 * One of more indpxt2 blocks maybe needed if the pxt2tent tree grow after
 * the unwritten pxt2tent split. To prevent ENOSPC occur at the IO
 * complete, we need to split the unwritten pxt2tent before DIO submit
 * the IO. The unwritten pxt2tent called at this time will be split
 * into three unwritten pxt2tent(at most). After IO complete, the part
 * being filled will be convert to initialized by the end_io callback function
 * via pxt4_convert_unwritten_pxt2tents().
 *
 * Returns the size of unwritten pxt2tent to be written on success.
 */
static int pxt4_split_convert_pxt2tents(handle_t *handle,
					struct inode *inode,
					struct pxt4_map_blocks *map,
					struct pxt4_pxt2t_path **ppath,
					int flags)
{
	struct pxt4_pxt2t_path *path = *ppath;
	pxt4_lblk_t eof_block;
	pxt4_lblk_t ee_block;
	struct pxt4_pxt2tent *pxt2;
	unsigned int ee_len;
	int split_flag = 0, depth;

	pxt2t_debug("%s: inode %lu, logical block %llu, max_blocks %u\n",
		  __func__, inode->i_ino,
		  (unsigned long long)map->m_lblk, map->m_len);

	eof_block = (PXT4_I(inode)->i_disksize + inode->i_sb->s_blocksize - 1)
			>> inode->i_sb->s_blocksize_bits;
	if (eof_block < map->m_lblk + map->m_len)
		eof_block = map->m_lblk + map->m_len;
	/*
	 * It is safe to convert pxt2tent to initialized via pxt2plicit
	 * zeroout only if pxt2tent is fully insde i_size or new_size.
	 */
	depth = pxt2t_depth(inode);
	pxt2 = path[depth].p_pxt2t;
	ee_block = le32_to_cpu(pxt2->ee_block);
	ee_len = pxt4_pxt2t_get_actual_len(pxt2);

	/* Convert to unwritten */
	if (flags & PXT4_GET_BLOCKS_CONVERT_UNWRITTEN) {
		split_flag |= PXT4_EXT_DATA_VALID1;
	/* Convert to initialized */
	} else if (flags & PXT4_GET_BLOCKS_CONVERT) {
		split_flag |= ee_block + ee_len <= eof_block ?
			      PXT4_EXT_MAY_ZEROOUT : 0;
		split_flag |= (PXT4_EXT_MARK_UNWRIT2 | PXT4_EXT_DATA_VALID2);
	}
	flags |= PXT4_GET_BLOCKS_PRE_IO;
	return pxt4_split_pxt2tent(handle, inode, ppath, map, split_flag, flags);
}

static int pxt4_convert_unwritten_pxt2tents_endio(handle_t *handle,
						struct inode *inode,
						struct pxt4_map_blocks *map,
						struct pxt4_pxt2t_path **ppath)
{
	struct pxt4_pxt2t_path *path = *ppath;
	struct pxt4_pxt2tent *pxt2;
	pxt4_lblk_t ee_block;
	unsigned int ee_len;
	int depth;
	int err = 0;

	depth = pxt2t_depth(inode);
	pxt2 = path[depth].p_pxt2t;
	ee_block = le32_to_cpu(pxt2->ee_block);
	ee_len = pxt4_pxt2t_get_actual_len(pxt2);

	pxt2t_debug("pxt4_convert_unwritten_pxt2tents_endio: inode %lu, logical"
		"block %llu, max_blocks %u\n", inode->i_ino,
		  (unsigned long long)ee_block, ee_len);

	/* If pxt2tent is larger than requested it is a clear sign that we still
	 * have some pxt2tent state machine issues left. So pxt2tent_split is still
	 * required.
	 * TODO: Once all related issues will be fixed this situation should be
	 * illegal.
	 */
	if (ee_block != map->m_lblk || ee_len > map->m_len) {
#ifdef CONFIG_PXT4_DEBUG
		pxt4_warning(inode->i_sb, "Inode (%ld) finished: pxt2tent logical block %llu,"
			     " len %u; IO logical block %llu, len %u",
			     inode->i_ino, (unsigned long long)ee_block, ee_len,
			     (unsigned long long)map->m_lblk, map->m_len);
#endif
		err = pxt4_split_convert_pxt2tents(handle, inode, map, ppath,
						 PXT4_GET_BLOCKS_CONVERT);
		if (err < 0)
			return err;
		path = pxt4_find_pxt2tent(inode, map->m_lblk, ppath, 0);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = pxt2t_depth(inode);
		pxt2 = path[depth].p_pxt2t;
	}

	err = pxt4_pxt2t_get_access(handle, inode, path + depth);
	if (err)
		goto out;
	/* first mark the pxt2tent as initialized */
	pxt4_pxt2t_mark_initialized(pxt2);

	/* note: pxt4_pxt2t_correct_indpxt2es() isn't needed here because
	 * borders are not changed
	 */
	pxt4_pxt2t_try_to_merge(handle, inode, path, pxt2);

	/* Mark modified pxt2tent as dirty */
	err = pxt4_pxt2t_dirty(handle, inode, path + path->p_depth);
out:
	pxt4_pxt2t_show_leaf(inode, path);
	return err;
}

/*
 * Handle EOFBLOCKS_FL flag, clearing it if necessary
 */
static int check_eofblocks_fl(handle_t *handle, struct inode *inode,
			      pxt4_lblk_t lblk,
			      struct pxt4_pxt2t_path *path,
			      unsigned int len)
{
	int i, depth;
	struct pxt4_pxt2tent_header *eh;
	struct pxt4_pxt2tent *last_pxt2;

	if (!pxt4_test_inode_flag(inode, PXT4_INODE_EOFBLOCKS))
		return 0;

	depth = pxt2t_depth(inode);
	eh = path[depth].p_hdr;

	/*
	 * We're going to remove EOFBLOCKS_FL entirely in future so we
	 * do not care for this case anymore. Simply remove the flag
	 * if there are no pxt2tents.
	 */
	if (unlikely(!eh->eh_entries))
		goto out;
	last_pxt2 = EXT_LAST_EXTENT(eh);
	/*
	 * We should clear the EOFBLOCKS_FL flag if we are writing the
	 * last block in the last pxt2tent in the file.  We test this by
	 * first checking to see if the caller to
	 * pxt4_pxt2t_get_blocks() was interested in the last block (or
	 * a block beyond the last block) in the current pxt2tent.  If
	 * this turns out to be false, we can bail out from this
	 * function immediately.
	 */
	if (lblk + len < le32_to_cpu(last_pxt2->ee_block) +
	    pxt4_pxt2t_get_actual_len(last_pxt2))
		return 0;
	/*
	 * If the caller does appear to be planning to write at or
	 * beyond the end of the current pxt2tent, we then test to see
	 * if the current pxt2tent is the last pxt2tent in the file, by
	 * checking to make sure it was reached via the rightmost node
	 * at each level of the tree.
	 */
	for (i = depth-1; i >= 0; i--)
		if (path[i].p_idx != EXT_LAST_INDEX(path[i].p_hdr))
			return 0;
out:
	pxt4_clear_inode_flag(inode, PXT4_INODE_EOFBLOCKS);
	return pxt4_mark_inode_dirty(handle, inode);
}

static int
convert_initialized_pxt2tent(handle_t *handle, struct inode *inode,
			   struct pxt4_map_blocks *map,
			   struct pxt4_pxt2t_path **ppath,
			   unsigned int allocated)
{
	struct pxt4_pxt2t_path *path = *ppath;
	struct pxt4_pxt2tent *pxt2;
	pxt4_lblk_t ee_block;
	unsigned int ee_len;
	int depth;
	int err = 0;

	/*
	 * Make sure that the pxt2tent is no bigger than we support with
	 * unwritten pxt2tent
	 */
	if (map->m_len > EXT_UNWRITTEN_MAX_LEN)
		map->m_len = EXT_UNWRITTEN_MAX_LEN / 2;

	depth = pxt2t_depth(inode);
	pxt2 = path[depth].p_pxt2t;
	ee_block = le32_to_cpu(pxt2->ee_block);
	ee_len = pxt4_pxt2t_get_actual_len(pxt2);

	pxt2t_debug("%s: inode %lu, logical"
		"block %llu, max_blocks %u\n", __func__, inode->i_ino,
		  (unsigned long long)ee_block, ee_len);

	if (ee_block != map->m_lblk || ee_len > map->m_len) {
		err = pxt4_split_convert_pxt2tents(handle, inode, map, ppath,
				PXT4_GET_BLOCKS_CONVERT_UNWRITTEN);
		if (err < 0)
			return err;
		path = pxt4_find_pxt2tent(inode, map->m_lblk, ppath, 0);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = pxt2t_depth(inode);
		pxt2 = path[depth].p_pxt2t;
		if (!pxt2) {
			PXT4_ERROR_INODE(inode, "unpxt2pected hole at %lu",
					 (unsigned long) map->m_lblk);
			return -EFSCORRUPTED;
		}
	}

	err = pxt4_pxt2t_get_access(handle, inode, path + depth);
	if (err)
		return err;
	/* first mark the pxt2tent as unwritten */
	pxt4_pxt2t_mark_unwritten(pxt2);

	/* note: pxt4_pxt2t_correct_indpxt2es() isn't needed here because
	 * borders are not changed
	 */
	pxt4_pxt2t_try_to_merge(handle, inode, path, pxt2);

	/* Mark modified pxt2tent as dirty */
	err = pxt4_pxt2t_dirty(handle, inode, path + path->p_depth);
	if (err)
		return err;
	pxt4_pxt2t_show_leaf(inode, path);

	pxt4_update_inode_fsync_trans(handle, inode, 1);
	err = check_eofblocks_fl(handle, inode, map->m_lblk, path, map->m_len);
	if (err)
		return err;
	map->m_flags |= PXT4_MAP_UNWRITTEN;
	if (allocated > map->m_len)
		allocated = map->m_len;
	map->m_len = allocated;
	return allocated;
}

static int
pxt4_pxt2t_handle_unwritten_pxt2tents(handle_t *handle, struct inode *inode,
			struct pxt4_map_blocks *map,
			struct pxt4_pxt2t_path **ppath, int flags,
			unsigned int allocated, pxt4_fsblk_t newblock)
{
	struct pxt4_pxt2t_path *path = *ppath;
	int ret = 0;
	int err = 0;

	pxt2t_debug("pxt4_pxt2t_handle_unwritten_pxt2tents: inode %lu, logical "
		  "block %llu, max_blocks %u, flags %x, allocated %u\n",
		  inode->i_ino, (unsigned long long)map->m_lblk, map->m_len,
		  flags, allocated);
	pxt4_pxt2t_show_leaf(inode, path);

	/*
	 * When writing into unwritten space, we should not fail to
	 * allocate metadata blocks for the new pxt2tent block if needed.
	 */
	flags |= PXT4_GET_BLOCKS_METADATA_NOFAIL;

	trace_pxt4_pxt2t_handle_unwritten_pxt2tents(inode, map, flags,
						    allocated, newblock);

	/* get_block() before submit the IO, split the pxt2tent */
	if (flags & PXT4_GET_BLOCKS_PRE_IO) {
		ret = pxt4_split_convert_pxt2tents(handle, inode, map, ppath,
					 flags | PXT4_GET_BLOCKS_CONVERT);
		if (ret <= 0)
			goto out;
		map->m_flags |= PXT4_MAP_UNWRITTEN;
		goto out;
	}
	/* IO end_io complete, convert the filled pxt2tent to written */
	if (flags & PXT4_GET_BLOCKS_CONVERT) {
		if (flags & PXT4_GET_BLOCKS_ZERO) {
			if (allocated > map->m_len)
				allocated = map->m_len;
			err = pxt4_issue_zeroout(inode, map->m_lblk, newblock,
						 allocated);
			if (err < 0)
				goto out2;
		}
		ret = pxt4_convert_unwritten_pxt2tents_endio(handle, inode, map,
							   ppath);
		if (ret >= 0) {
			pxt4_update_inode_fsync_trans(handle, inode, 1);
			err = check_eofblocks_fl(handle, inode, map->m_lblk,
						 path, map->m_len);
		} else
			err = ret;
		map->m_flags |= PXT4_MAP_MAPPED;
		map->m_pblk = newblock;
		if (allocated > map->m_len)
			allocated = map->m_len;
		map->m_len = allocated;
		goto out2;
	}
	/* buffered IO case */
	/*
	 * repeat fallocate creation request
	 * we already have an unwritten pxt2tent
	 */
	if (flags & PXT4_GET_BLOCKS_UNWRIT_EXT) {
		map->m_flags |= PXT4_MAP_UNWRITTEN;
		goto map_out;
	}

	/* buffered READ or buffered write_begin() lookup */
	if ((flags & PXT4_GET_BLOCKS_CREATE) == 0) {
		/*
		 * We have blocks reserved already.  We
		 * return allocated blocks so that delalloc
		 * won't do block reservation for us.  But
		 * the buffer head will be unmapped so that
		 * a read from the block returns 0s.
		 */
		map->m_flags |= PXT4_MAP_UNWRITTEN;
		goto out1;
	}

	/* buffered write, writepage time, convert*/
	ret = pxt4_pxt2t_convert_to_initialized(handle, inode, map, ppath, flags);
	if (ret >= 0)
		pxt4_update_inode_fsync_trans(handle, inode, 1);
out:
	if (ret <= 0) {
		err = ret;
		goto out2;
	} else
		allocated = ret;
	map->m_flags |= PXT4_MAP_NEW;
	if (allocated > map->m_len)
		allocated = map->m_len;
	map->m_len = allocated;

map_out:
	map->m_flags |= PXT4_MAP_MAPPED;
	if ((flags & PXT4_GET_BLOCKS_KEEP_SIZE) == 0) {
		err = check_eofblocks_fl(handle, inode, map->m_lblk, path,
					 map->m_len);
		if (err < 0)
			goto out2;
	}
out1:
	if (allocated > map->m_len)
		allocated = map->m_len;
	pxt4_pxt2t_show_leaf(inode, path);
	map->m_pblk = newblock;
	map->m_len = allocated;
out2:
	return err ? err : allocated;
}

/*
 * get_implied_cluster_alloc - check to see if the requested
 * allocation (in the map structure) overlaps with a cluster already
 * allocated in an pxt2tent.
 *	@sb	The filesystem superblock structure
 *	@map	The requested lblk->pblk mapping
 *	@pxt2	The pxt2tent structure which might contain an implied
 *			cluster allocation
 *
 * This function is called by pxt4_pxt2t_map_blocks() after we failed to
 * find blocks that were already in the inode's pxt2tent tree.  Hence,
 * we know that the beginning of the requested region cannot overlap
 * the pxt2tent from the inode's pxt2tent tree.  There are three cases we
 * want to catch.  The first is this case:
 *
 *		 |--- cluster # N--|
 *    |--- pxt2tent ---|	|---- requested region ---|
 *			|==========|
 *
 * The second case that we need to test for is this one:
 *
 *   |--------- cluster # N ----------------|
 *	   |--- requested region --|   |------- pxt2tent ----|
 *	   |=======================|
 *
 * The third case is when the requested region lies between two pxt2tents
 * within the same cluster:
 *          |------------- cluster # N-------------|
 * |----- pxt2 -----|                  |---- pxt2_right ----|
 *                  |------ requested region ------|
 *                  |================|
 *
 * In each of the above cases, we need to set the map->m_pblk and
 * map->m_len so it corresponds to the return the pxt2tent labelled as
 * "|====|" from cluster #N, since it is already in use for data in
 * cluster PXT4_B2C(sbi, map->m_lblk).	We will then return 1 to
 * signal to pxt4_pxt2t_map_blocks() that map->m_pblk should be treated
 * as a new "allocated" block region.  Otherwise, we will return 0 and
 * pxt4_pxt2t_map_blocks() will then allocate one or more new clusters
 * by calling pxt4_mb_new_blocks().
 */
static int get_implied_cluster_alloc(struct super_block *sb,
				     struct pxt4_map_blocks *map,
				     struct pxt4_pxt2tent *pxt2,
				     struct pxt4_pxt2t_path *path)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	pxt4_lblk_t c_offset = PXT4_LBLK_COFF(sbi, map->m_lblk);
	pxt4_lblk_t pxt2_cluster_start, pxt2_cluster_end;
	pxt4_lblk_t rr_cluster_start;
	pxt4_lblk_t ee_block = le32_to_cpu(pxt2->ee_block);
	pxt4_fsblk_t ee_start = pxt4_pxt2t_pblock(pxt2);
	unsigned short ee_len = pxt4_pxt2t_get_actual_len(pxt2);

	/* The pxt2tent passed in that we are trying to match */
	pxt2_cluster_start = PXT4_B2C(sbi, ee_block);
	pxt2_cluster_end = PXT4_B2C(sbi, ee_block + ee_len - 1);

	/* The requested region passed into pxt4_map_blocks() */
	rr_cluster_start = PXT4_B2C(sbi, map->m_lblk);

	if ((rr_cluster_start == pxt2_cluster_end) ||
	    (rr_cluster_start == pxt2_cluster_start)) {
		if (rr_cluster_start == pxt2_cluster_end)
			ee_start += ee_len - 1;
		map->m_pblk = PXT4_PBLK_CMASK(sbi, ee_start) + c_offset;
		map->m_len = min(map->m_len,
				 (unsigned) sbi->s_cluster_ratio - c_offset);
		/*
		 * Check for and handle this case:
		 *
		 *   |--------- cluster # N-------------|
		 *		       |------- pxt2tent ----|
		 *	   |--- requested region ---|
		 *	   |===========|
		 */

		if (map->m_lblk < ee_block)
			map->m_len = min(map->m_len, ee_block - map->m_lblk);

		/*
		 * Check for the case where there is already another allocated
		 * block to the right of 'pxt2' but before the end of the cluster.
		 *
		 *          |------------- cluster # N-------------|
		 * |----- pxt2 -----|                  |---- pxt2_right ----|
		 *                  |------ requested region ------|
		 *                  |================|
		 */
		if (map->m_lblk > ee_block) {
			pxt4_lblk_t npxt2t = pxt4_pxt2t_npxt2t_allocated_block(path);
			map->m_len = min(map->m_len, npxt2t - map->m_lblk);
		}

		trace_pxt4_get_implied_cluster_alloc_pxt2it(sb, map, 1);
		return 1;
	}

	trace_pxt4_get_implied_cluster_alloc_pxt2it(sb, map, 0);
	return 0;
}


/*
 * Block allocation/map/preallocation routine for pxt2tents based files
 *
 *
 * Need to be called with
 * down_read(&PXT4_I(inode)->i_data_sem) if not allocating file system block
 * (ie, create is zero). Otherwise down_write(&PXT4_I(inode)->i_data_sem)
 *
 * return > 0, number of of blocks already mapped/allocated
 *          if create == 0 and these are pre-allocated blocks
 *          	buffer head is unmapped
 *          otherwise blocks are mapped
 *
 * return = 0, if plain look up failed (blocks have not been allocated)
 *          buffer head is unmapped
 *
 * return < 0, error case.
 */
int pxt4_pxt2t_map_blocks(handle_t *handle, struct inode *inode,
			struct pxt4_map_blocks *map, int flags)
{
	struct pxt4_pxt2t_path *path = NULL;
	struct pxt4_pxt2tent newpxt2, *pxt2, *pxt22;
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	pxt4_fsblk_t newblock = 0;
	int free_on_err = 0, err = 0, depth, ret;
	unsigned int allocated = 0, offset = 0;
	unsigned int allocated_clusters = 0;
	struct pxt4_allocation_request ar;
	pxt4_lblk_t cluster_offset;
	bool map_from_cluster = false;

	pxt2t_debug("blocks %u/%u requested for inode %lu\n",
		  map->m_lblk, map->m_len, inode->i_ino);
	trace_pxt4_pxt2t_map_blocks_enter(inode, map->m_lblk, map->m_len, flags);

	/* find pxt2tent for this block */
	path = pxt4_find_pxt2tent(inode, map->m_lblk, NULL, 0);
	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		path = NULL;
		goto out2;
	}

	depth = pxt2t_depth(inode);

	/*
	 * consistent leaf must not be empty;
	 * this situation is possible, though, _during_ tree modification;
	 * this is why assert can't be put in pxt4_find_pxt2tent()
	 */
	if (unlikely(path[depth].p_pxt2t == NULL && depth != 0)) {
		PXT4_ERROR_INODE(inode, "bad pxt2tent address "
				 "lblock: %lu, depth: %d pblock %lld",
				 (unsigned long) map->m_lblk, depth,
				 path[depth].p_block);
		err = -EFSCORRUPTED;
		goto out2;
	}

	pxt2 = path[depth].p_pxt2t;
	if (pxt2) {
		pxt4_lblk_t ee_block = le32_to_cpu(pxt2->ee_block);
		pxt4_fsblk_t ee_start = pxt4_pxt2t_pblock(pxt2);
		unsigned short ee_len;


		/*
		 * unwritten pxt2tents are treated as holes, pxt2cept that
		 * we split out initialized portions during a write.
		 */
		ee_len = pxt4_pxt2t_get_actual_len(pxt2);

		trace_pxt4_pxt2t_show_pxt2tent(inode, ee_block, ee_start, ee_len);

		/* if found pxt2tent covers block, simply return it */
		if (in_range(map->m_lblk, ee_block, ee_len)) {
			newblock = map->m_lblk - ee_block + ee_start;
			/* number of remaining blocks in the pxt2tent */
			allocated = ee_len - (map->m_lblk - ee_block);
			pxt2t_debug("%u fit into %u:%d -> %llu\n", map->m_lblk,
				  ee_block, ee_len, newblock);

			/*
			 * If the pxt2tent is initialized check whether the
			 * caller wants to convert it to unwritten.
			 */
			if ((!pxt4_pxt2t_is_unwritten(pxt2)) &&
			    (flags & PXT4_GET_BLOCKS_CONVERT_UNWRITTEN)) {
				allocated = convert_initialized_pxt2tent(
						handle, inode, map, &path,
						allocated);
				goto out2;
			} else if (!pxt4_pxt2t_is_unwritten(pxt2))
				goto out;

			ret = pxt4_pxt2t_handle_unwritten_pxt2tents(
				handle, inode, map, &path, flags,
				allocated, newblock);
			if (ret < 0)
				err = ret;
			else
				allocated = ret;
			goto out2;
		}
	}

	/*
	 * requested block isn't allocated yet;
	 * we couldn't try to create block if create flag is zero
	 */
	if ((flags & PXT4_GET_BLOCKS_CREATE) == 0) {
		pxt4_lblk_t hole_start, hole_len;

		hole_start = map->m_lblk;
		hole_len = pxt4_pxt2t_determine_hole(inode, path, &hole_start);
		/*
		 * put just found gap into cache to speed up
		 * subsequent requests
		 */
		pxt4_pxt2t_put_gap_in_cache(inode, hole_start, hole_len);

		/* Update hole_len to reflect hole size after map->m_lblk */
		if (hole_start != map->m_lblk)
			hole_len -= map->m_lblk - hole_start;
		map->m_pblk = 0;
		map->m_len = min_t(unsigned int, map->m_len, hole_len);

		goto out2;
	}

	/*
	 * Okay, we need to do block allocation.
	 */
	newpxt2.ee_block = cpu_to_le32(map->m_lblk);
	cluster_offset = PXT4_LBLK_COFF(sbi, map->m_lblk);

	/*
	 * If we are doing bigalloc, check to see if the pxt2tent returned
	 * by pxt4_find_pxt2tent() implies a cluster we can use.
	 */
	if (cluster_offset && pxt2 &&
	    get_implied_cluster_alloc(inode->i_sb, map, pxt2, path)) {
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		map_from_cluster = true;
		goto got_allocated_blocks;
	}

	/* find neighbour allocated blocks */
	ar.lleft = map->m_lblk;
	err = pxt4_pxt2t_search_left(inode, path, &ar.lleft, &ar.pleft);
	if (err)
		goto out2;
	ar.lright = map->m_lblk;
	pxt22 = NULL;
	err = pxt4_pxt2t_search_right(inode, path, &ar.lright, &ar.pright, &pxt22);
	if (err)
		goto out2;

	/* Check if the pxt2tent after searching to the right implies a
	 * cluster we can use. */
	if ((sbi->s_cluster_ratio > 1) && pxt22 &&
	    get_implied_cluster_alloc(inode->i_sb, map, pxt22, path)) {
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		map_from_cluster = true;
		goto got_allocated_blocks;
	}

	/*
	 * See if request is beyond maximum number of blocks we can have in
	 * a single pxt2tent. For an initialized pxt2tent this limit is
	 * EXT_INIT_MAX_LEN and for an unwritten pxt2tent this limit is
	 * EXT_UNWRITTEN_MAX_LEN.
	 */
	if (map->m_len > EXT_INIT_MAX_LEN &&
	    !(flags & PXT4_GET_BLOCKS_UNWRIT_EXT))
		map->m_len = EXT_INIT_MAX_LEN;
	else if (map->m_len > EXT_UNWRITTEN_MAX_LEN &&
		 (flags & PXT4_GET_BLOCKS_UNWRIT_EXT))
		map->m_len = EXT_UNWRITTEN_MAX_LEN;

	/* Check if we can really insert (m_lblk)::(m_lblk + m_len) pxt2tent */
	newpxt2.ee_len = cpu_to_le16(map->m_len);
	err = pxt4_pxt2t_check_overlap(sbi, inode, &newpxt2, path);
	if (err)
		allocated = pxt4_pxt2t_get_actual_len(&newpxt2);
	else
		allocated = map->m_len;

	/* allocate new block */
	ar.inode = inode;
	ar.goal = pxt4_pxt2t_find_goal(inode, path, map->m_lblk);
	ar.logical = map->m_lblk;
	/*
	 * We calculate the offset from the beginning of the cluster
	 * for the logical block number, since when we allocate a
	 * physical cluster, the physical block should start at the
	 * same offset from the beginning of the cluster.  This is
	 * needed so that future calls to get_implied_cluster_alloc()
	 * work correctly.
	 */
	offset = PXT4_LBLK_COFF(sbi, map->m_lblk);
	ar.len = PXT4_NUM_B2C(sbi, offset+allocated);
	ar.goal -= offset;
	ar.logical -= offset;
	if (S_ISREG(inode->i_mode))
		ar.flags = PXT4_MB_HINT_DATA;
	else
		/* disable in-core preallocation for non-regular files */
		ar.flags = 0;
	if (flags & PXT4_GET_BLOCKS_NO_NORMALIZE)
		ar.flags |= PXT4_MB_HINT_NOPREALLOC;
	if (flags & PXT4_GET_BLOCKS_DELALLOC_RESERVE)
		ar.flags |= PXT4_MB_DELALLOC_RESERVED;
	if (flags & PXT4_GET_BLOCKS_METADATA_NOFAIL)
		ar.flags |= PXT4_MB_USE_RESERVED;
	newblock = pxt4_mb_new_blocks(handle, &ar, &err);
	if (!newblock)
		goto out2;
	pxt2t_debug("allocate new block: goal %llu, found %llu/%u\n",
		  ar.goal, newblock, allocated);
	free_on_err = 1;
	allocated_clusters = ar.len;
	ar.len = PXT4_C2B(sbi, ar.len) - offset;
	if (ar.len > allocated)
		ar.len = allocated;

got_allocated_blocks:
	/* try to insert new pxt2tent into found leaf and return */
	pxt4_pxt2t_store_pblock(&newpxt2, newblock + offset);
	newpxt2.ee_len = cpu_to_le16(ar.len);
	/* Mark unwritten */
	if (flags & PXT4_GET_BLOCKS_UNWRIT_EXT){
		pxt4_pxt2t_mark_unwritten(&newpxt2);
		map->m_flags |= PXT4_MAP_UNWRITTEN;
	}

	err = 0;
	if ((flags & PXT4_GET_BLOCKS_KEEP_SIZE) == 0)
		err = check_eofblocks_fl(handle, inode, map->m_lblk,
					 path, ar.len);
	if (!err)
		err = pxt4_pxt2t_insert_pxt2tent(handle, inode, &path,
					     &newpxt2, flags);

	if (err && free_on_err) {
		int fb_flags = flags & PXT4_GET_BLOCKS_DELALLOC_RESERVE ?
			PXT4_FREE_BLOCKS_NO_QUOT_UPDATE : 0;
		/* free data blocks we just allocated */
		/* not a good idea to call discard here directly,
		 * but otherwise we'd need to call it every free() */
		pxt4_discard_preallocations(inode);
		pxt4_free_blocks(handle, inode, NULL, newblock,
				 PXT4_C2B(sbi, allocated_clusters), fb_flags);
		goto out2;
	}

	/* previous routine could use block we allocated */
	newblock = pxt4_pxt2t_pblock(&newpxt2);
	allocated = pxt4_pxt2t_get_actual_len(&newpxt2);
	if (allocated > map->m_len)
		allocated = map->m_len;
	map->m_flags |= PXT4_MAP_NEW;

	/*
	 * Reduce the reserved cluster count to reflect successful deferred
	 * allocation of delayed allocated clusters or direct allocation of
	 * clusters discovered to be delayed allocated.  Once allocated, a
	 * cluster is not included in the reserved count.
	 */
	if (test_opt(inode->i_sb, DELALLOC) && !map_from_cluster) {
		if (flags & PXT4_GET_BLOCKS_DELALLOC_RESERVE) {
			/*
			 * When allocating delayed allocated clusters, simply
			 * reduce the reserved cluster count and claim quota
			 */
			pxt4_da_update_reserve_space(inode, allocated_clusters,
							1);
		} else {
			pxt4_lblk_t lblk, len;
			unsigned int n;

			/*
			 * When allocating non-delayed allocated clusters
			 * (from fallocate, filemap, DIO, or clusters
			 * allocated when delalloc has been disabled by
			 * pxt4_nonda_switch), reduce the reserved cluster
			 * count by the number of allocated clusters that
			 * have previously been delayed allocated.  Quota
			 * has been claimed by pxt4_mb_new_blocks() above,
			 * so release the quota reservations made for any
			 * previously delayed allocated clusters.
			 */
			lblk = PXT4_LBLK_CMASK(sbi, map->m_lblk);
			len = allocated_clusters << sbi->s_cluster_bits;
			n = pxt4_es_delayed_clu(inode, lblk, len);
			if (n > 0)
				pxt4_da_update_reserve_space(inode, (int) n, 0);
		}
	}

	/*
	 * Cache the pxt2tent and update transaction to commit on fdatasync only
	 * when it is _not_ an unwritten pxt2tent.
	 */
	if ((flags & PXT4_GET_BLOCKS_UNWRIT_EXT) == 0)
		pxt4_update_inode_fsync_trans(handle, inode, 1);
	else
		pxt4_update_inode_fsync_trans(handle, inode, 0);
out:
	if (allocated > map->m_len)
		allocated = map->m_len;
	pxt4_pxt2t_show_leaf(inode, path);
	map->m_flags |= PXT4_MAP_MAPPED;
	map->m_pblk = newblock;
	map->m_len = allocated;
out2:
	pxt4_pxt2t_drop_refs(path);
	kfree(path);

	trace_pxt4_pxt2t_map_blocks_pxt2it(inode, flags, map,
				       err ? err : allocated);
	return err ? err : allocated;
}

int pxt4_pxt2t_truncate(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	pxt4_lblk_t last_block;
	int err = 0;

	/*
	 * TODO: optimization is possible here.
	 * Probably we need not scan at all,
	 * because page truncation is enough.
	 */

	/* we have to know where to truncate from in crash case */
	PXT4_I(inode)->i_disksize = inode->i_size;
	err = pxt4_mark_inode_dirty(handle, inode);
	if (err)
		return err;

	last_block = (inode->i_size + sb->s_blocksize - 1)
			>> PXT4_BLOCK_SIZE_BITS(sb);
retry:
	err = pxt4_es_remove_pxt2tent(inode, last_block,
				    EXT_MAX_BLOCKS - last_block);
	if (err == -ENOMEM) {
		cond_resched();
		congestion_wait(BLK_RW_ASYNC, HZ/50);
		goto retry;
	}
	if (err)
		return err;
	return pxt4_pxt2t_remove_space(inode, last_block, EXT_MAX_BLOCKS - 1);
}

static int pxt4_alloc_file_blocks(struct file *file, pxt4_lblk_t offset,
				  pxt4_lblk_t len, loff_t new_size,
				  int flags)
{
	struct inode *inode = file_inode(file);
	handle_t *handle;
	int ret = 0;
	int ret2 = 0;
	int retries = 0;
	int depth = 0;
	struct pxt4_map_blocks map;
	unsigned int credits;
	loff_t epos;

	BUG_ON(!pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS));
	map.m_lblk = offset;
	map.m_len = len;
	/*
	 * Don't normalize the request if it can fit in one pxt2tent so
	 * that it doesn't get unnecessarily split into multiple
	 * pxt2tents.
	 */
	if (len <= EXT_UNWRITTEN_MAX_LEN)
		flags |= PXT4_GET_BLOCKS_NO_NORMALIZE;

	/*
	 * credits to insert 1 pxt2tent into pxt2tent tree
	 */
	credits = pxt4_chunk_trans_blocks(inode, len);
	depth = pxt2t_depth(inode);

retry:
	while (ret >= 0 && len) {
		/*
		 * Recalculate credits when pxt2tent tree depth changes.
		 */
		if (depth != pxt2t_depth(inode)) {
			credits = pxt4_chunk_trans_blocks(inode, len);
			depth = pxt2t_depth(inode);
		}

		handle = pxt4_journal_start(inode, PXT4_HT_MAP_BLOCKS,
					    credits);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			break;
		}
		ret = pxt4_map_blocks(handle, inode, &map, flags);
		if (ret <= 0) {
			pxt4_debug("inode #%lu: block %u: len %u: "
				   "pxt4_pxt2t_map_blocks returned %d",
				   inode->i_ino, map.m_lblk,
				   map.m_len, ret);
			pxt4_mark_inode_dirty(handle, inode);
			ret2 = pxt4_journal_stop(handle);
			break;
		}
		map.m_lblk += ret;
		map.m_len = len = len - ret;
		epos = (loff_t)map.m_lblk << inode->i_blkbits;
		inode->i_ctime = current_time(inode);
		if (new_size) {
			if (epos > new_size)
				epos = new_size;
			if (pxt4_update_inode_size(inode, epos) & 0x1)
				inode->i_mtime = inode->i_ctime;
		} else {
			if (epos > inode->i_size)
				pxt4_set_inode_flag(inode,
						    PXT4_INODE_EOFBLOCKS);
		}
		pxt4_mark_inode_dirty(handle, inode);
		pxt4_update_inode_fsync_trans(handle, inode, 1);
		ret2 = pxt4_journal_stop(handle);
		if (ret2)
			break;
	}
	if (ret == -ENOSPC &&
			pxt4_should_retry_alloc(inode->i_sb, &retries)) {
		ret = 0;
		goto retry;
	}

	return ret > 0 ? ret2 : ret;
}

static long pxt4_zero_range(struct file *file, loff_t offset,
			    loff_t len, int mode)
{
	struct inode *inode = file_inode(file);
	handle_t *handle = NULL;
	unsigned int max_blocks;
	loff_t new_size = 0;
	int ret = 0;
	int flags;
	int credits;
	int partial_begin, partial_end;
	loff_t start, end;
	pxt4_lblk_t lblk;
	unsigned int blkbits = inode->i_blkbits;

	trace_pxt4_zero_range(inode, offset, len, mode);

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	/* Call pxt4_force_commit to flush all data in case of data=journal. */
	if (pxt4_should_journal_data(inode)) {
		ret = pxt4_force_commit(inode->i_sb);
		if (ret)
			return ret;
	}

	/*
	 * Round up offset. This is not fallocate, we neet to zero out
	 * blocks, so convert interior block aligned part of the range to
	 * unwritten and possibly manually zero out unaligned parts of the
	 * range.
	 */
	start = round_up(offset, 1 << blkbits);
	end = round_down((offset + len), 1 << blkbits);

	if (start < offset || end > offset + len)
		return -EINVAL;
	partial_begin = offset & ((1 << blkbits) - 1);
	partial_end = (offset + len) & ((1 << blkbits) - 1);

	lblk = start >> blkbits;
	max_blocks = (end >> blkbits);
	if (max_blocks < lblk)
		max_blocks = 0;
	else
		max_blocks -= lblk;

	inode_lock(inode);

	/*
	 * Indirect files do not support unwritten pxt2tnets
	 */
	if (!(pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS))) {
		ret = -EOPNOTSUPP;
		goto out_mutpxt2;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    (offset + len > i_size_read(inode) ||
	     offset + len > PXT4_I(inode)->i_disksize)) {
		new_size = offset + len;
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto out_mutpxt2;
	}

	flags = PXT4_GET_BLOCKS_CREATE_UNWRIT_EXT;
	if (mode & FALLOC_FL_KEEP_SIZE)
		flags |= PXT4_GET_BLOCKS_KEEP_SIZE;

	/* Wait all pxt2isting dio workers, newcomers will block on i_mutpxt2 */
	inode_dio_wait(inode);

	/* Preallocate the range including the unaligned edges */
	if (partial_begin || partial_end) {
		ret = pxt4_alloc_file_blocks(file,
				round_down(offset, 1 << blkbits) >> blkbits,
				(round_up((offset + len), 1 << blkbits) -
				 round_down(offset, 1 << blkbits)) >> blkbits,
				new_size, flags);
		if (ret)
			goto out_mutpxt2;

	}

	/* Zero range pxt2cluding the unaligned edges */
	if (max_blocks > 0) {
		flags |= (PXT4_GET_BLOCKS_CONVERT_UNWRITTEN |
			  PXT4_EX_NOCACHE);

		/*
		 * Prevent page faults from reinstantiating pages we have
		 * released from page cache.
		 */
		down_write(&PXT4_I(inode)->i_mmap_sem);

		ret = pxt4_break_layouts(inode);
		if (ret) {
			up_write(&PXT4_I(inode)->i_mmap_sem);
			goto out_mutpxt2;
		}

		ret = pxt4_update_disksize_before_punch(inode, offset, len);
		if (ret) {
			up_write(&PXT4_I(inode)->i_mmap_sem);
			goto out_mutpxt2;
		}
		/* Now release the pages and zero block aligned part of pages */
		truncate_pagecache_range(inode, start, end - 1);
		inode->i_mtime = inode->i_ctime = current_time(inode);

		ret = pxt4_alloc_file_blocks(file, lblk, max_blocks, new_size,
					     flags);
		up_write(&PXT4_I(inode)->i_mmap_sem);
		if (ret)
			goto out_mutpxt2;
	}
	if (!partial_begin && !partial_end)
		goto out_mutpxt2;

	/*
	 * In worst case we have to writeout two nonadjacent unwritten
	 * blocks and update the inode
	 */
	credits = (2 * pxt4_pxt2t_indpxt2_trans_blocks(inode, 2)) + 1;
	if (pxt4_should_journal_data(inode))
		credits += 2;
	handle = pxt4_journal_start(inode, PXT4_HT_MISC, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		pxt4_std_error(inode->i_sb, ret);
		goto out_mutpxt2;
	}

	inode->i_mtime = inode->i_ctime = current_time(inode);
	if (new_size) {
		pxt4_update_inode_size(inode, new_size);
	} else {
		/*
		* Mark that we allocate beyond EOF so the subsequent truncate
		* can proceed even if the new size is the same as i_size.
		*/
		if ((offset + len) > i_size_read(inode))
			pxt4_set_inode_flag(inode, PXT4_INODE_EOFBLOCKS);
	}
	pxt4_mark_inode_dirty(handle, inode);

	/* Zero out partial block at the edges of the range */
	ret = pxt4_zero_partial_blocks(handle, inode, offset, len);
	if (ret >= 0)
		pxt4_update_inode_fsync_trans(handle, inode, 1);

	if (file->f_flags & O_SYNC)
		pxt4_handle_sync(handle);

	pxt4_journal_stop(handle);
out_mutpxt2:
	inode_unlock(inode);
	return ret;
}

/*
 * preallocate space for a file. This implements pxt4's fallocate file
 * operation, which gets called from sys_fallocate system call.
 * For block-mapped files, posix_fallocate should fall back to the method
 * of writing zeroes to the required new blocks (the same behavior which is
 * pxt2pected for file systems which do not support fallocate() system call).
 */
long pxt4_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	loff_t new_size = 0;
	unsigned int max_blocks;
	int ret = 0;
	int flags;
	pxt4_lblk_t lblk;
	unsigned int blkbits = inode->i_blkbits;

	/*
	 * Encrypted inodes can't handle collapse range or insert
	 * range since we would need to re-encrypt blocks with a
	 * different IV or XTS tweak (which are based on the logical
	 * block number).
	 *
	 * XXX It's not clear why zero range isn't working, but we'll
	 * leave it disabled for encrypted inodes for now.  This is a
	 * bug we should fix....
	 */
	if (IS_ENCRYPTED(inode) &&
	    (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE |
		     FALLOC_FL_ZERO_RANGE)))
		return -EOPNOTSUPP;

	/* Return error if mode is not supported */
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE |
		     FALLOC_FL_INSERT_RANGE))
		return -EOPNOTSUPP;

	if (mode & FALLOC_FL_PUNCH_HOLE)
		return pxt4_punch_hole(inode, offset, len);

	ret = pxt4_convert_inline_data(inode);
	if (ret)
		return ret;

	if (mode & FALLOC_FL_COLLAPSE_RANGE)
		return pxt4_collapse_range(inode, offset, len);

	if (mode & FALLOC_FL_INSERT_RANGE)
		return pxt4_insert_range(inode, offset, len);

	if (mode & FALLOC_FL_ZERO_RANGE)
		return pxt4_zero_range(file, offset, len, mode);

	trace_pxt4_fallocate_enter(inode, offset, len, mode);
	lblk = offset >> blkbits;

	max_blocks = PXT4_MAX_BLOCKS(len, offset, blkbits);
	flags = PXT4_GET_BLOCKS_CREATE_UNWRIT_EXT;
	if (mode & FALLOC_FL_KEEP_SIZE)
		flags |= PXT4_GET_BLOCKS_KEEP_SIZE;

	inode_lock(inode);

	/*
	 * We only support preallocation for pxt2tent-based files only
	 */
	if (!(pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS))) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    (offset + len > i_size_read(inode) ||
	     offset + len > PXT4_I(inode)->i_disksize)) {
		new_size = offset + len;
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto out;
	}

	/* Wait all pxt2isting dio workers, newcomers will block on i_mutpxt2 */
	inode_dio_wait(inode);

	ret = pxt4_alloc_file_blocks(file, lblk, max_blocks, new_size, flags);
	if (ret)
		goto out;

	if (file->f_flags & O_SYNC && PXT4_SB(inode->i_sb)->s_journal) {
		ret = jbd3_complete_transaction(PXT4_SB(inode->i_sb)->s_journal,
						PXT4_I(inode)->i_sync_tid);
	}
out:
	inode_unlock(inode);
	trace_pxt4_fallocate_pxt2it(inode, offset, max_blocks, ret);
	return ret;
}

/*
 * This function convert a range of blocks to written pxt2tents
 * The caller of this function will pass the start offset and the size.
 * all unwritten pxt2tents within this range will be converted to
 * written pxt2tents.
 *
 * This function is called from the direct IO end io call back
 * function, to convert the fallocated pxt2tents after IO is completed.
 * Returns 0 on success.
 */
int pxt4_convert_unwritten_pxt2tents(handle_t *handle, struct inode *inode,
				   loff_t offset, ssize_t len)
{
	unsigned int max_blocks;
	int ret = 0;
	int ret2 = 0;
	struct pxt4_map_blocks map;
	unsigned int credits, blkbits = inode->i_blkbits;

	map.m_lblk = offset >> blkbits;
	max_blocks = PXT4_MAX_BLOCKS(len, offset, blkbits);

	/*
	 * This is somewhat ugly but the idea is clear: When transaction is
	 * reserved, everything goes into it. Otherwise we rather start several
	 * smaller transactions for conversion of each pxt2tent separately.
	 */
	if (handle) {
		handle = pxt4_journal_start_reserved(handle,
						     PXT4_HT_EXT_CONVERT);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
		credits = 0;
	} else {
		/*
		 * credits to insert 1 pxt2tent into pxt2tent tree
		 */
		credits = pxt4_chunk_trans_blocks(inode, max_blocks);
	}
	while (ret >= 0 && ret < max_blocks) {
		map.m_lblk += ret;
		map.m_len = (max_blocks -= ret);
		if (credits) {
			handle = pxt4_journal_start(inode, PXT4_HT_MAP_BLOCKS,
						    credits);
			if (IS_ERR(handle)) {
				ret = PTR_ERR(handle);
				break;
			}
		}
		ret = pxt4_map_blocks(handle, inode, &map,
				      PXT4_GET_BLOCKS_IO_CONVERT_EXT);
		if (ret <= 0)
			pxt4_warning(inode->i_sb,
				     "inode #%lu: block %u: len %u: "
				     "pxt4_pxt2t_map_blocks returned %d",
				     inode->i_ino, map.m_lblk,
				     map.m_len, ret);
		pxt4_mark_inode_dirty(handle, inode);
		if (credits)
			ret2 = pxt4_journal_stop(handle);
		if (ret <= 0 || ret2)
			break;
	}
	if (!credits)
		ret2 = pxt4_journal_stop(handle);
	return ret > 0 ? ret2 : ret;
}

/*
 * If newes is not pxt2isting pxt2tent (newes->ec_pblk equals zero) find
 * delayed pxt2tent at start of newes and update newes accordingly and
 * return start of the npxt2t delayed pxt2tent.
 *
 * If newes is pxt2isting pxt2tent (newes->ec_pblk is not equal zero)
 * return start of npxt2t delayed pxt2tent or EXT_MAX_BLOCKS if no delayed
 * pxt2tent found. Leave newes unmodified.
 */
static int pxt4_find_delayed_pxt2tent(struct inode *inode,
				    struct pxt2tent_status *newes)
{
	struct pxt2tent_status es;
	pxt4_lblk_t block, npxt2t_del;

	if (newes->es_pblk == 0) {
		pxt4_es_find_pxt2tent_range(inode, &pxt4_es_is_delayed,
					  newes->es_lblk,
					  newes->es_lblk + newes->es_len - 1,
					  &es);

		/*
		 * No pxt2tent in pxt2tent-tree contains block @newes->es_pblk,
		 * then the block may stay in 1)a hole or 2)delayed-pxt2tent.
		 */
		if (es.es_len == 0)
			/* A hole found. */
			return 0;

		if (es.es_lblk > newes->es_lblk) {
			/* A hole found. */
			newes->es_len = min(es.es_lblk - newes->es_lblk,
					    newes->es_len);
			return 0;
		}

		newes->es_len = es.es_lblk + es.es_len - newes->es_lblk;
	}

	block = newes->es_lblk + newes->es_len;
	pxt4_es_find_pxt2tent_range(inode, &pxt4_es_is_delayed, block,
				  EXT_MAX_BLOCKS, &es);
	if (es.es_len == 0)
		npxt2t_del = EXT_MAX_BLOCKS;
	else
		npxt2t_del = es.es_lblk;

	return npxt2t_del;
}

static int pxt4_xattr_fiemap(struct inode *inode,
				struct fiemap_pxt2tent_info *fieinfo)
{
	__u64 physical = 0;
	__u64 length;
	__u32 flags = FIEMAP_EXTENT_LAST;
	int blockbits = inode->i_sb->s_blocksize_bits;
	int error = 0;

	/* in-inode? */
	if (pxt4_test_inode_state(inode, PXT4_STATE_XATTR)) {
		struct pxt4_iloc iloc;
		int offset;	/* offset of xattr in inode */

		error = pxt4_get_inode_loc(inode, &iloc);
		if (error)
			return error;
		physical = (__u64)iloc.bh->b_blocknr << blockbits;
		offset = PXT4_GOOD_OLD_INODE_SIZE +
				PXT4_I(inode)->i_pxt2tra_isize;
		physical += offset;
		length = PXT4_SB(inode->i_sb)->s_inode_size - offset;
		flags |= FIEMAP_EXTENT_DATA_INLINE;
		brelse(iloc.bh);
	} else { /* pxt2ternal block */
		physical = (__u64)PXT4_I(inode)->i_file_acl << blockbits;
		length = inode->i_sb->s_blocksize;
	}

	if (physical)
		error = fiemap_fill_npxt2t_pxt2tent(fieinfo, 0, physical,
						length, flags);
	return (error < 0 ? error : 0);
}

static int _pxt4_fiemap(struct inode *inode,
			struct fiemap_pxt2tent_info *fieinfo,
			__u64 start, __u64 len,
			int (*fill)(struct inode *, pxt4_lblk_t,
				    pxt4_lblk_t,
				    struct fiemap_pxt2tent_info *))
{
	pxt4_lblk_t start_blk;
	u32 pxt4_fiemap_flags = FIEMAP_FLAG_SYNC|FIEMAP_FLAG_XATTR;

	int error = 0;

	if (pxt4_has_inline_data(inode)) {
		int has_inline = 1;

		error = pxt4_inline_data_fiemap(inode, fieinfo, &has_inline,
						start, len);

		if (has_inline)
			return error;
	}

	if (fieinfo->fi_flags & FIEMAP_FLAG_CACHE) {
		error = pxt4_pxt2t_precache(inode);
		if (error)
			return error;
		fieinfo->fi_flags &= ~FIEMAP_FLAG_CACHE;
	}

	/* fallback to generic here if not in pxt2tents fmt */
	if (!(pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS)) &&
	    fill == pxt4_fill_fiemap_pxt2tents)
		return generic_block_fiemap(inode, fieinfo, start, len,
			pxt4_get_block);

	if (fill == pxt4_fill_es_cache_info)
		pxt4_fiemap_flags &= FIEMAP_FLAG_XATTR;
	if (fiemap_check_flags(fieinfo, pxt4_fiemap_flags))
		return -EBADR;

	if (fieinfo->fi_flags & FIEMAP_FLAG_XATTR) {
		error = pxt4_xattr_fiemap(inode, fieinfo);
	} else {
		pxt4_lblk_t len_blks;
		__u64 last_blk;

		start_blk = start >> inode->i_sb->s_blocksize_bits;
		last_blk = (start + len - 1) >> inode->i_sb->s_blocksize_bits;
		if (last_blk >= EXT_MAX_BLOCKS)
			last_blk = EXT_MAX_BLOCKS-1;
		len_blks = ((pxt4_lblk_t) last_blk) - start_blk + 1;

		/*
		 * Walk the pxt2tent tree gathering pxt2tent information
		 * and pushing pxt2tents back to the user.
		 */
		error = fill(inode, start_blk, len_blks, fieinfo);
	}
	return error;
}

int pxt4_fiemap(struct inode *inode, struct fiemap_pxt2tent_info *fieinfo,
		__u64 start, __u64 len)
{
	return _pxt4_fiemap(inode, fieinfo, start, len,
			    pxt4_fill_fiemap_pxt2tents);
}

int pxt4_get_es_cache(struct inode *inode, struct fiemap_pxt2tent_info *fieinfo,
		      __u64 start, __u64 len)
{
	if (pxt4_has_inline_data(inode)) {
		int has_inline;

		down_read(&PXT4_I(inode)->xattr_sem);
		has_inline = pxt4_has_inline_data(inode);
		up_read(&PXT4_I(inode)->xattr_sem);
		if (has_inline)
			return 0;
	}

	return _pxt4_fiemap(inode, fieinfo, start, len,
			    pxt4_fill_es_cache_info);
}


/*
 * pxt4_access_path:
 * Function to access the path buffer for marking it dirty.
 * It also checks if there are sufficient credits left in the journal handle
 * to update path.
 */
static int
pxt4_access_path(handle_t *handle, struct inode *inode,
		struct pxt4_pxt2t_path *path)
{
	int credits, err;

	if (!pxt4_handle_valid(handle))
		return 0;

	/*
	 * Check if need to pxt2tend journal credits
	 * 3 for leaf, sb, and inode plus 2 (bmap and group
	 * descriptor) for each block group; assume two block
	 * groups
	 */
	if (handle->h_buffer_credits < 7) {
		credits = pxt4_writepage_trans_blocks(inode);
		err = pxt4_pxt2t_truncate_pxt2tend_restart(handle, inode, credits);
		/* EAGAIN is success */
		if (err && err != -EAGAIN)
			return err;
	}

	err = pxt4_pxt2t_get_access(handle, inode, path);
	return err;
}

/*
 * pxt4_pxt2t_shift_path_pxt2tents:
 * Shift the pxt2tents of a path structure lying between path[depth].p_pxt2t
 * and EXT_LAST_EXTENT(path[depth].p_hdr), by @shift blocks. @SHIFT tells
 * if it is right shift or left shift operation.
 */
static int
pxt4_pxt2t_shift_path_pxt2tents(struct pxt4_pxt2t_path *path, pxt4_lblk_t shift,
			    struct inode *inode, handle_t *handle,
			    enum SHIFT_DIRECTION SHIFT)
{
	int depth, err = 0;
	struct pxt4_pxt2tent *pxt2_start, *pxt2_last;
	bool update = 0;
	depth = path->p_depth;

	while (depth >= 0) {
		if (depth == path->p_depth) {
			pxt2_start = path[depth].p_pxt2t;
			if (!pxt2_start)
				return -EFSCORRUPTED;

			pxt2_last = EXT_LAST_EXTENT(path[depth].p_hdr);

			err = pxt4_access_path(handle, inode, path + depth);
			if (err)
				goto out;

			if (pxt2_start == EXT_FIRST_EXTENT(path[depth].p_hdr))
				update = 1;

			while (pxt2_start <= pxt2_last) {
				if (SHIFT == SHIFT_LEFT) {
					le32_add_cpu(&pxt2_start->ee_block,
						-shift);
					/* Try to merge to the left. */
					if ((pxt2_start >
					    EXT_FIRST_EXTENT(path[depth].p_hdr))
					    &&
					    pxt4_pxt2t_try_to_merge_right(inode,
					    path, pxt2_start - 1))
						pxt2_last--;
					else
						pxt2_start++;
				} else {
					le32_add_cpu(&pxt2_last->ee_block, shift);
					pxt4_pxt2t_try_to_merge_right(inode, path,
						pxt2_last);
					pxt2_last--;
				}
			}
			err = pxt4_pxt2t_dirty(handle, inode, path + depth);
			if (err)
				goto out;

			if (--depth < 0 || !update)
				break;
		}

		/* Update indpxt2 too */
		err = pxt4_access_path(handle, inode, path + depth);
		if (err)
			goto out;

		if (SHIFT == SHIFT_LEFT)
			le32_add_cpu(&path[depth].p_idx->ei_block, -shift);
		else
			le32_add_cpu(&path[depth].p_idx->ei_block, shift);
		err = pxt4_pxt2t_dirty(handle, inode, path + depth);
		if (err)
			goto out;

		/* we are done if current indpxt2 is not a starting indpxt2 */
		if (path[depth].p_idx != EXT_FIRST_INDEX(path[depth].p_hdr))
			break;

		depth--;
	}

out:
	return err;
}

/*
 * pxt4_pxt2t_shift_pxt2tents:
 * All the pxt2tents which lies in the range from @start to the last allocated
 * block for the @inode are shifted either towards left or right (depending
 * upon @SHIFT) by @shift blocks.
 * On success, 0 is returned, error otherwise.
 */
static int
pxt4_pxt2t_shift_pxt2tents(struct inode *inode, handle_t *handle,
		       pxt4_lblk_t start, pxt4_lblk_t shift,
		       enum SHIFT_DIRECTION SHIFT)
{
	struct pxt4_pxt2t_path *path;
	int ret = 0, depth;
	struct pxt4_pxt2tent *pxt2tent;
	pxt4_lblk_t stop, *iterator, pxt2_start, pxt2_end;

	/* Let path point to the last pxt2tent */
	path = pxt4_find_pxt2tent(inode, EXT_MAX_BLOCKS - 1, NULL,
				PXT4_EX_NOCACHE);
	if (IS_ERR(path))
		return PTR_ERR(path);

	depth = path->p_depth;
	pxt2tent = path[depth].p_pxt2t;
	if (!pxt2tent)
		goto out;

	stop = le32_to_cpu(pxt2tent->ee_block);

       /*
	* For left shifts, make sure the hole on the left is big enough to
	* accommodate the shift.  For right shifts, make sure the last pxt2tent
	* won't be shifted beyond EXT_MAX_BLOCKS.
	*/
	if (SHIFT == SHIFT_LEFT) {
		path = pxt4_find_pxt2tent(inode, start - 1, &path,
					PXT4_EX_NOCACHE);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = path->p_depth;
		pxt2tent =  path[depth].p_pxt2t;
		if (pxt2tent) {
			pxt2_start = le32_to_cpu(pxt2tent->ee_block);
			pxt2_end = le32_to_cpu(pxt2tent->ee_block) +
				pxt4_pxt2t_get_actual_len(pxt2tent);
		} else {
			pxt2_start = 0;
			pxt2_end = 0;
		}

		if ((start == pxt2_start && shift > pxt2_start) ||
		    (shift > start - pxt2_end)) {
			ret = -EINVAL;
			goto out;
		}
	} else {
		if (shift > EXT_MAX_BLOCKS -
		    (stop + pxt4_pxt2t_get_actual_len(pxt2tent))) {
			ret = -EINVAL;
			goto out;
		}
	}

	/*
	 * In case of left shift, iterator points to start and it is increased
	 * till we reach stop. In case of right shift, iterator points to stop
	 * and it is decreased till we reach start.
	 */
	if (SHIFT == SHIFT_LEFT)
		iterator = &start;
	else
		iterator = &stop;

	/*
	 * Its safe to start updating pxt2tents.  Start and stop are unsigned, so
	 * in case of right shift if pxt2tent with 0 block is reached, iterator
	 * becomes NULL to indicate the end of the loop.
	 */
	while (iterator && start <= stop) {
		path = pxt4_find_pxt2tent(inode, *iterator, &path,
					PXT4_EX_NOCACHE);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = path->p_depth;
		pxt2tent = path[depth].p_pxt2t;
		if (!pxt2tent) {
			PXT4_ERROR_INODE(inode, "unpxt2pected hole at %lu",
					 (unsigned long) *iterator);
			return -EFSCORRUPTED;
		}
		if (SHIFT == SHIFT_LEFT && *iterator >
		    le32_to_cpu(pxt2tent->ee_block)) {
			/* Hole, move to the npxt2t pxt2tent */
			if (pxt2tent < EXT_LAST_EXTENT(path[depth].p_hdr)) {
				path[depth].p_pxt2t++;
			} else {
				*iterator = pxt4_pxt2t_npxt2t_allocated_block(path);
				continue;
			}
		}

		if (SHIFT == SHIFT_LEFT) {
			pxt2tent = EXT_LAST_EXTENT(path[depth].p_hdr);
			*iterator = le32_to_cpu(pxt2tent->ee_block) +
					pxt4_pxt2t_get_actual_len(pxt2tent);
		} else {
			pxt2tent = EXT_FIRST_EXTENT(path[depth].p_hdr);
			if (le32_to_cpu(pxt2tent->ee_block) > 0)
				*iterator = le32_to_cpu(pxt2tent->ee_block) - 1;
			else
				/* Beginning is reached, end of the loop */
				iterator = NULL;
			/* Update path pxt2tent in case we need to stop */
			while (le32_to_cpu(pxt2tent->ee_block) < start)
				pxt2tent++;
			path[depth].p_pxt2t = pxt2tent;
		}
		ret = pxt4_pxt2t_shift_path_pxt2tents(path, shift, inode,
				handle, SHIFT);
		if (ret)
			break;
	}
out:
	pxt4_pxt2t_drop_refs(path);
	kfree(path);
	return ret;
}

/*
 * pxt4_collapse_range:
 * This implements the fallocate's collapse range functionality for pxt4
 * Returns: 0 and non-zero on error.
 */
int pxt4_collapse_range(struct inode *inode, loff_t offset, loff_t len)
{
	struct super_block *sb = inode->i_sb;
	pxt4_lblk_t punch_start, punch_stop;
	handle_t *handle;
	unsigned int credits;
	loff_t new_size, ioffset;
	int ret;

	/*
	 * We need to test this early because xfstests assumes that a
	 * collapse range of (0, 1) will return EOPNOTSUPP if the file
	 * system does not support collapse range.
	 */
	if (!pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS))
		return -EOPNOTSUPP;

	/* Collapse range works only on fs block size aligned offsets. */
	if (offset & (PXT4_CLUSTER_SIZE(sb) - 1) ||
	    len & (PXT4_CLUSTER_SIZE(sb) - 1))
		return -EINVAL;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	trace_pxt4_collapse_range(inode, offset, len);

	punch_start = offset >> PXT4_BLOCK_SIZE_BITS(sb);
	punch_stop = (offset + len) >> PXT4_BLOCK_SIZE_BITS(sb);

	/* Call pxt4_force_commit to flush all data in case of data=journal. */
	if (pxt4_should_journal_data(inode)) {
		ret = pxt4_force_commit(inode->i_sb);
		if (ret)
			return ret;
	}

	inode_lock(inode);
	/*
	 * There is no need to overlap collapse range with EOF, in which case
	 * it is effectively a truncate operation
	 */
	if (offset + len >= i_size_read(inode)) {
		ret = -EINVAL;
		goto out_mutpxt2;
	}

	/* Currently just for pxt2tent based files */
	if (!pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS)) {
		ret = -EOPNOTSUPP;
		goto out_mutpxt2;
	}

	/* Wait for pxt2isting dio to complete */
	inode_dio_wait(inode);

	/*
	 * Prevent page faults from reinstantiating pages we have released from
	 * page cache.
	 */
	down_write(&PXT4_I(inode)->i_mmap_sem);

	ret = pxt4_break_layouts(inode);
	if (ret)
		goto out_mmap;

	/*
	 * Need to round down offset to be aligned with page size boundary
	 * for page size > block size.
	 */
	ioffset = round_down(offset, PAGE_SIZE);
	/*
	 * Write tail of the last page before removed range since it will get
	 * removed from the page cache below.
	 */
	ret = filemap_write_and_wait_range(inode->i_mapping, ioffset, offset);
	if (ret)
		goto out_mmap;
	/*
	 * Write data that will be shifted to preserve them when discarding
	 * page cache below. We are also protected from pages becoming dirty
	 * by i_mmap_sem.
	 */
	ret = filemap_write_and_wait_range(inode->i_mapping, offset + len,
					   LLONG_MAX);
	if (ret)
		goto out_mmap;
	truncate_pagecache(inode, ioffset);

	credits = pxt4_writepage_trans_blocks(inode);
	handle = pxt4_journal_start(inode, PXT4_HT_TRUNCATE, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out_mmap;
	}

	down_write(&PXT4_I(inode)->i_data_sem);
	pxt4_discard_preallocations(inode);

	ret = pxt4_es_remove_pxt2tent(inode, punch_start,
				    EXT_MAX_BLOCKS - punch_start);
	if (ret) {
		up_write(&PXT4_I(inode)->i_data_sem);
		goto out_stop;
	}

	ret = pxt4_pxt2t_remove_space(inode, punch_start, punch_stop - 1);
	if (ret) {
		up_write(&PXT4_I(inode)->i_data_sem);
		goto out_stop;
	}
	pxt4_discard_preallocations(inode);

	ret = pxt4_pxt2t_shift_pxt2tents(inode, handle, punch_stop,
				     punch_stop - punch_start, SHIFT_LEFT);
	if (ret) {
		up_write(&PXT4_I(inode)->i_data_sem);
		goto out_stop;
	}

	new_size = i_size_read(inode) - len;
	i_size_write(inode, new_size);
	PXT4_I(inode)->i_disksize = new_size;

	up_write(&PXT4_I(inode)->i_data_sem);
	if (IS_SYNC(inode))
		pxt4_handle_sync(handle);
	inode->i_mtime = inode->i_ctime = current_time(inode);
	pxt4_mark_inode_dirty(handle, inode);
	pxt4_update_inode_fsync_trans(handle, inode, 1);

out_stop:
	pxt4_journal_stop(handle);
out_mmap:
	up_write(&PXT4_I(inode)->i_mmap_sem);
out_mutpxt2:
	inode_unlock(inode);
	return ret;
}

/*
 * pxt4_insert_range:
 * This function implements the FALLOC_FL_INSERT_RANGE flag of fallocate.
 * The data blocks starting from @offset to the EOF are shifted by @len
 * towards right to create a hole in the @inode. Inode size is increased
 * by len bytes.
 * Returns 0 on success, error otherwise.
 */
int pxt4_insert_range(struct inode *inode, loff_t offset, loff_t len)
{
	struct super_block *sb = inode->i_sb;
	handle_t *handle;
	struct pxt4_pxt2t_path *path;
	struct pxt4_pxt2tent *pxt2tent;
	pxt4_lblk_t offset_lblk, len_lblk, ee_start_lblk = 0;
	unsigned int credits, ee_len;
	int ret = 0, depth, split_flag = 0;
	loff_t ioffset;

	/*
	 * We need to test this early because xfstests assumes that an
	 * insert range of (0, 1) will return EOPNOTSUPP if the file
	 * system does not support insert range.
	 */
	if (!pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS))
		return -EOPNOTSUPP;

	/* Insert range works only on fs block size aligned offsets. */
	if (offset & (PXT4_CLUSTER_SIZE(sb) - 1) ||
			len & (PXT4_CLUSTER_SIZE(sb) - 1))
		return -EINVAL;

	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	trace_pxt4_insert_range(inode, offset, len);

	offset_lblk = offset >> PXT4_BLOCK_SIZE_BITS(sb);
	len_lblk = len >> PXT4_BLOCK_SIZE_BITS(sb);

	/* Call pxt4_force_commit to flush all data in case of data=journal */
	if (pxt4_should_journal_data(inode)) {
		ret = pxt4_force_commit(inode->i_sb);
		if (ret)
			return ret;
	}

	inode_lock(inode);
	/* Currently just for pxt2tent based files */
	if (!pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS)) {
		ret = -EOPNOTSUPP;
		goto out_mutpxt2;
	}

	/* Check for wrap through zero */
	if (inode->i_size + len > inode->i_sb->s_maxbytes) {
		ret = -EFBIG;
		goto out_mutpxt2;
	}

	/* Offset should be less than i_size */
	if (offset >= i_size_read(inode)) {
		ret = -EINVAL;
		goto out_mutpxt2;
	}

	/* Wait for pxt2isting dio to complete */
	inode_dio_wait(inode);

	/*
	 * Prevent page faults from reinstantiating pages we have released from
	 * page cache.
	 */
	down_write(&PXT4_I(inode)->i_mmap_sem);

	ret = pxt4_break_layouts(inode);
	if (ret)
		goto out_mmap;

	/*
	 * Need to round down to align start offset to page size boundary
	 * for page size > block size.
	 */
	ioffset = round_down(offset, PAGE_SIZE);
	/* Write out all dirty pages */
	ret = filemap_write_and_wait_range(inode->i_mapping, ioffset,
			LLONG_MAX);
	if (ret)
		goto out_mmap;
	truncate_pagecache(inode, ioffset);

	credits = pxt4_writepage_trans_blocks(inode);
	handle = pxt4_journal_start(inode, PXT4_HT_TRUNCATE, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out_mmap;
	}

	/* Expand file to avoid data loss if there is error while shifting */
	inode->i_size += len;
	PXT4_I(inode)->i_disksize += len;
	inode->i_mtime = inode->i_ctime = current_time(inode);
	ret = pxt4_mark_inode_dirty(handle, inode);
	if (ret)
		goto out_stop;

	down_write(&PXT4_I(inode)->i_data_sem);
	pxt4_discard_preallocations(inode);

	path = pxt4_find_pxt2tent(inode, offset_lblk, NULL, 0);
	if (IS_ERR(path)) {
		up_write(&PXT4_I(inode)->i_data_sem);
		goto out_stop;
	}

	depth = pxt2t_depth(inode);
	pxt2tent = path[depth].p_pxt2t;
	if (pxt2tent) {
		ee_start_lblk = le32_to_cpu(pxt2tent->ee_block);
		ee_len = pxt4_pxt2t_get_actual_len(pxt2tent);

		/*
		 * If offset_lblk is not the starting block of pxt2tent, split
		 * the pxt2tent @offset_lblk
		 */
		if ((offset_lblk > ee_start_lblk) &&
				(offset_lblk < (ee_start_lblk + ee_len))) {
			if (pxt4_pxt2t_is_unwritten(pxt2tent))
				split_flag = PXT4_EXT_MARK_UNWRIT1 |
					PXT4_EXT_MARK_UNWRIT2;
			ret = pxt4_split_pxt2tent_at(handle, inode, &path,
					offset_lblk, split_flag,
					PXT4_EX_NOCACHE |
					PXT4_GET_BLOCKS_PRE_IO |
					PXT4_GET_BLOCKS_METADATA_NOFAIL);
		}

		pxt4_pxt2t_drop_refs(path);
		kfree(path);
		if (ret < 0) {
			up_write(&PXT4_I(inode)->i_data_sem);
			goto out_stop;
		}
	} else {
		pxt4_pxt2t_drop_refs(path);
		kfree(path);
	}

	ret = pxt4_es_remove_pxt2tent(inode, offset_lblk,
			EXT_MAX_BLOCKS - offset_lblk);
	if (ret) {
		up_write(&PXT4_I(inode)->i_data_sem);
		goto out_stop;
	}

	/*
	 * if offset_lblk lies in a hole which is at start of file, use
	 * ee_start_lblk to shift pxt2tents
	 */
	ret = pxt4_pxt2t_shift_pxt2tents(inode, handle,
		ee_start_lblk > offset_lblk ? ee_start_lblk : offset_lblk,
		len_lblk, SHIFT_RIGHT);

	up_write(&PXT4_I(inode)->i_data_sem);
	if (IS_SYNC(inode))
		pxt4_handle_sync(handle);
	if (ret >= 0)
		pxt4_update_inode_fsync_trans(handle, inode, 1);

out_stop:
	pxt4_journal_stop(handle);
out_mmap:
	up_write(&PXT4_I(inode)->i_mmap_sem);
out_mutpxt2:
	inode_unlock(inode);
	return ret;
}

/**
 * pxt4_swap_pxt2tents() - Swap pxt2tents between two inodes
 * @handle: handle for this transaction
 * @inode1:	First inode
 * @inode2:	Second inode
 * @lblk1:	Start block for first inode
 * @lblk2:	Start block for second inode
 * @count:	Number of blocks to swap
 * @unwritten: Mark second inode's pxt2tents as unwritten after swap
 * @erp:	Pointer to save error value
 *
 * This helper routine does pxt2actly what is promise "swap pxt2tents". All other
 * stuff such as page-cache locking consistency, bh mapping consistency or
 * pxt2tent's data copying must be performed by caller.
 * Locking:
 * 		i_mutpxt2 is held for both inodes
 * 		i_data_sem is locked for write for both inodes
 * Assumptions:
 *		All pages from requested range are locked for both inodes
 */
int
pxt4_swap_pxt2tents(handle_t *handle, struct inode *inode1,
		  struct inode *inode2, pxt4_lblk_t lblk1, pxt4_lblk_t lblk2,
		  pxt4_lblk_t count, int unwritten, int *erp)
{
	struct pxt4_pxt2t_path *path1 = NULL;
	struct pxt4_pxt2t_path *path2 = NULL;
	int replaced_count = 0;

	BUG_ON(!rwsem_is_locked(&PXT4_I(inode1)->i_data_sem));
	BUG_ON(!rwsem_is_locked(&PXT4_I(inode2)->i_data_sem));
	BUG_ON(!inode_is_locked(inode1));
	BUG_ON(!inode_is_locked(inode2));

	*erp = pxt4_es_remove_pxt2tent(inode1, lblk1, count);
	if (unlikely(*erp))
		return 0;
	*erp = pxt4_es_remove_pxt2tent(inode2, lblk2, count);
	if (unlikely(*erp))
		return 0;

	while (count) {
		struct pxt4_pxt2tent *pxt21, *pxt22, tmp_pxt2;
		pxt4_lblk_t e1_blk, e2_blk;
		int e1_len, e2_len, len;
		int split = 0;

		path1 = pxt4_find_pxt2tent(inode1, lblk1, NULL, PXT4_EX_NOCACHE);
		if (IS_ERR(path1)) {
			*erp = PTR_ERR(path1);
			path1 = NULL;
		finish:
			count = 0;
			goto repeat;
		}
		path2 = pxt4_find_pxt2tent(inode2, lblk2, NULL, PXT4_EX_NOCACHE);
		if (IS_ERR(path2)) {
			*erp = PTR_ERR(path2);
			path2 = NULL;
			goto finish;
		}
		pxt21 = path1[path1->p_depth].p_pxt2t;
		pxt22 = path2[path2->p_depth].p_pxt2t;
		/* Do we have somthing to swap ? */
		if (unlikely(!pxt22 || !pxt21))
			goto finish;

		e1_blk = le32_to_cpu(pxt21->ee_block);
		e2_blk = le32_to_cpu(pxt22->ee_block);
		e1_len = pxt4_pxt2t_get_actual_len(pxt21);
		e2_len = pxt4_pxt2t_get_actual_len(pxt22);

		/* Hole handling */
		if (!in_range(lblk1, e1_blk, e1_len) ||
		    !in_range(lblk2, e2_blk, e2_len)) {
			pxt4_lblk_t npxt2t1, npxt2t2;

			/* if hole after pxt2tent, then go to npxt2t pxt2tent */
			npxt2t1 = pxt4_pxt2t_npxt2t_allocated_block(path1);
			npxt2t2 = pxt4_pxt2t_npxt2t_allocated_block(path2);
			/* If hole before pxt2tent, then shift to that pxt2tent */
			if (e1_blk > lblk1)
				npxt2t1 = e1_blk;
			if (e2_blk > lblk2)
				npxt2t2 = e2_blk;
			/* Do we have something to swap */
			if (npxt2t1 == EXT_MAX_BLOCKS || npxt2t2 == EXT_MAX_BLOCKS)
				goto finish;
			/* Move to the rightest boundary */
			len = npxt2t1 - lblk1;
			if (len < npxt2t2 - lblk2)
				len = npxt2t2 - lblk2;
			if (len > count)
				len = count;
			lblk1 += len;
			lblk2 += len;
			count -= len;
			goto repeat;
		}

		/* Prepare left boundary */
		if (e1_blk < lblk1) {
			split = 1;
			*erp = pxt4_force_split_pxt2tent_at(handle, inode1,
						&path1, lblk1, 0);
			if (unlikely(*erp))
				goto finish;
		}
		if (e2_blk < lblk2) {
			split = 1;
			*erp = pxt4_force_split_pxt2tent_at(handle, inode2,
						&path2,  lblk2, 0);
			if (unlikely(*erp))
				goto finish;
		}
		/* pxt4_split_pxt2tent_at() may result in leaf pxt2tent split,
		 * path must to be revalidated. */
		if (split)
			goto repeat;

		/* Prepare right boundary */
		len = count;
		if (len > e1_blk + e1_len - lblk1)
			len = e1_blk + e1_len - lblk1;
		if (len > e2_blk + e2_len - lblk2)
			len = e2_blk + e2_len - lblk2;

		if (len != e1_len) {
			split = 1;
			*erp = pxt4_force_split_pxt2tent_at(handle, inode1,
						&path1, lblk1 + len, 0);
			if (unlikely(*erp))
				goto finish;
		}
		if (len != e2_len) {
			split = 1;
			*erp = pxt4_force_split_pxt2tent_at(handle, inode2,
						&path2, lblk2 + len, 0);
			if (*erp)
				goto finish;
		}
		/* pxt4_split_pxt2tent_at() may result in leaf pxt2tent split,
		 * path must to be revalidated. */
		if (split)
			goto repeat;

		BUG_ON(e2_len != e1_len);
		*erp = pxt4_pxt2t_get_access(handle, inode1, path1 + path1->p_depth);
		if (unlikely(*erp))
			goto finish;
		*erp = pxt4_pxt2t_get_access(handle, inode2, path2 + path2->p_depth);
		if (unlikely(*erp))
			goto finish;

		/* Both pxt2tents are fully inside boundaries. Swap it now */
		tmp_pxt2 = *pxt21;
		pxt4_pxt2t_store_pblock(pxt21, pxt4_pxt2t_pblock(pxt22));
		pxt4_pxt2t_store_pblock(pxt22, pxt4_pxt2t_pblock(&tmp_pxt2));
		pxt21->ee_len = cpu_to_le16(e2_len);
		pxt22->ee_len = cpu_to_le16(e1_len);
		if (unwritten)
			pxt4_pxt2t_mark_unwritten(pxt22);
		if (pxt4_pxt2t_is_unwritten(&tmp_pxt2))
			pxt4_pxt2t_mark_unwritten(pxt21);

		pxt4_pxt2t_try_to_merge(handle, inode2, path2, pxt22);
		pxt4_pxt2t_try_to_merge(handle, inode1, path1, pxt21);
		*erp = pxt4_pxt2t_dirty(handle, inode2, path2 +
				      path2->p_depth);
		if (unlikely(*erp))
			goto finish;
		*erp = pxt4_pxt2t_dirty(handle, inode1, path1 +
				      path1->p_depth);
		/*
		 * Looks scarry ah..? second inode already points to new blocks,
		 * and it was successfully dirtied. But luckily error may happen
		 * only due to journal error, so full transaction will be
		 * aborted anyway.
		 */
		if (unlikely(*erp))
			goto finish;
		lblk1 += len;
		lblk2 += len;
		replaced_count += len;
		count -= len;

	repeat:
		pxt4_pxt2t_drop_refs(path1);
		kfree(path1);
		pxt4_pxt2t_drop_refs(path2);
		kfree(path2);
		path1 = path2 = NULL;
	}
	return replaced_count;
}

/*
 * pxt4_clu_mapped - determine whether any block in a logical cluster has
 *                   been mapped to a physical cluster
 *
 * @inode - file containing the logical cluster
 * @lclu - logical cluster of interest
 *
 * Returns 1 if any block in the logical cluster is mapped, signifying
 * that a physical cluster has been allocated for it.  Otherwise,
 * returns 0.  Can also return negative error codes.  Derived from
 * pxt4_pxt2t_map_blocks().
 */
int pxt4_clu_mapped(struct inode *inode, pxt4_lblk_t lclu)
{
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	struct pxt4_pxt2t_path *path;
	int depth, mapped = 0, err = 0;
	struct pxt4_pxt2tent *pxt2tent;
	pxt4_lblk_t first_lblk, first_lclu, last_lclu;

	/* search for the pxt2tent closest to the first block in the cluster */
	path = pxt4_find_pxt2tent(inode, PXT4_C2B(sbi, lclu), NULL, 0);
	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		path = NULL;
		goto out;
	}

	depth = pxt2t_depth(inode);

	/*
	 * A consistent leaf must not be empty.  This situation is possible,
	 * though, _during_ tree modification, and it's why an assert can't
	 * be put in pxt4_find_pxt2tent().
	 */
	if (unlikely(path[depth].p_pxt2t == NULL && depth != 0)) {
		PXT4_ERROR_INODE(inode,
		    "bad pxt2tent address - lblock: %lu, depth: %d, pblock: %lld",
				 (unsigned long) PXT4_C2B(sbi, lclu),
				 depth, path[depth].p_block);
		err = -EFSCORRUPTED;
		goto out;
	}

	pxt2tent = path[depth].p_pxt2t;

	/* can't be mapped if the pxt2tent tree is empty */
	if (pxt2tent == NULL)
		goto out;

	first_lblk = le32_to_cpu(pxt2tent->ee_block);
	first_lclu = PXT4_B2C(sbi, first_lblk);

	/*
	 * Three possible outcomes at this point - found pxt2tent spanning
	 * the target cluster, to the left of the target cluster, or to the
	 * right of the target cluster.  The first two cases are handled here.
	 * The last case indicates the target cluster is not mapped.
	 */
	if (lclu >= first_lclu) {
		last_lclu = PXT4_B2C(sbi, first_lblk +
				     pxt4_pxt2t_get_actual_len(pxt2tent) - 1);
		if (lclu <= last_lclu) {
			mapped = 1;
		} else {
			first_lblk = pxt4_pxt2t_npxt2t_allocated_block(path);
			first_lclu = PXT4_B2C(sbi, first_lblk);
			if (lclu == first_lclu)
				mapped = 1;
		}
	}

out:
	pxt4_pxt2t_drop_refs(path);
	kfree(path);

	return err ? err : mapped;
}
