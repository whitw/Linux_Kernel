// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2003-2006, Cluster File Systems, Inc, info@clusterfs.com
 * Written by Alpxt2 Tomas <alpxt2@clusterfs.com>
 */

#ifndef _PXT4_EXTENTS
#define _PXT4_EXTENTS

#include "pxt4.h"

/*
 * With AGGRESSIVE_TEST defined, the capacity of indpxt2/leaf blocks
 * becomes very small, so indpxt2 split, in-depth growing and
 * other hard changes happen much more often.
 * This is for debug purposes only.
 */
#define AGGRESSIVE_TEST_

/*
 * With EXTENTS_STATS defined, the number of blocks and pxt2tents
 * are collected in the truncate path. They'll be shown at
 * umount time.
 */
#define EXTENTS_STATS__

/*
 * If CHECK_BINSEARCH is defined, then the results of the binary search
 * will also be checked by linear search.
 */
#define CHECK_BINSEARCH__

/*
 * If EXT_STATS is defined then stats numbers are collected.
 * These number will be displayed at umount time.
 */
#define EXT_STATS_


/*
 * pxt4_inode has i_block array (60 bytes total).
 * The first 12 bytes store pxt4_pxt2tent_header;
 * the remainder stores an array of pxt4_pxt2tent.
 * For non-inode pxt2tent blocks, pxt4_pxt2tent_tail
 * follows the array.
 */

/*
 * This is the pxt2tent tail on-disk structure.
 * All other pxt2tent structures are 12 bytes long.  It turns out that
 * block_size % 12 >= 4 for at least all powers of 2 greater than 512, which
 * covers all valid pxt4 block sizes.  Therefore, this tail structure can be
 * crammed into the end of the block without having to rebalance the tree.
 */
struct pxt4_pxt2tent_tail {
	__le32	et_checksum;	/* crc32c(uuid+inum+pxt2tent_block) */
};

/*
 * This is the pxt2tent on-disk structure.
 * It's used at the bottom of the tree.
 */
struct pxt4_pxt2tent {
	__le32	ee_block;	/* first logical block pxt2tent covers */
	__le16	ee_len;		/* number of blocks covered by pxt2tent */
	__le16	ee_start_hi;	/* high 16 bits of physical block */
	__le32	ee_start_lo;	/* low 32 bits of physical block */
};

/*
 * This is indpxt2 on-disk structure.
 * It's used at all the levels pxt2cept the bottom.
 */
struct pxt4_pxt2tent_idx {
	__le32	ei_block;	/* indpxt2 covers logical blocks from 'block' */
	__le32	ei_leaf_lo;	/* pointer to the physical block of the npxt2t *
				 * level. leaf or npxt2t indpxt2 could be there */
	__le16	ei_leaf_hi;	/* high 16 bits of physical block */
	__u16	ei_unused;
};

/*
 * Each block (leaves and indpxt2es), even inode-stored has header.
 */
struct pxt4_pxt2tent_header {
	__le16	eh_magic;	/* probably will support different formats */
	__le16	eh_entries;	/* number of valid entries */
	__le16	eh_max;		/* capacity of store in entries */
	__le16	eh_depth;	/* has tree real underlying blocks? */
	__le32	eh_generation;	/* generation of the tree */
};

#define PXT4_EXT_MAGIC		cpu_to_le16(0xf30a)
#define PXT4_MAX_EXTENT_DEPTH 5

#define PXT4_EXTENT_TAIL_OFFSET(hdr) \
	(sizeof(struct pxt4_pxt2tent_header) + \
	 (sizeof(struct pxt4_pxt2tent) * le16_to_cpu((hdr)->eh_max)))

static inline struct pxt4_pxt2tent_tail *
find_pxt4_pxt2tent_tail(struct pxt4_pxt2tent_header *eh)
{
	return (struct pxt4_pxt2tent_tail *)(((void *)eh) +
					   PXT4_EXTENT_TAIL_OFFSET(eh));
}

/*
 * Array of pxt4_pxt2t_path contains path to some pxt2tent.
 * Creation/lookup routines use it for traversal/splitting/etc.
 * Truncate uses it to simulate recursive walking.
 */
struct pxt4_pxt2t_path {
	pxt4_fsblk_t			p_block;
	__u16				p_depth;
	__u16				p_maxdepth;
	struct pxt4_pxt2tent		*p_pxt2t;
	struct pxt4_pxt2tent_idx		*p_idx;
	struct pxt4_pxt2tent_header	*p_hdr;
	struct buffer_head		*p_bh;
};

/*
 * Used to record a portion of a cluster found at the beginning or end
 * of an pxt2tent while traversing the pxt2tent tree during space removal.
 * A partial cluster may be removed if it does not contain blocks shared
 * with pxt2tents that aren't being deleted (tofree state).  Otherwise,
 * it cannot be removed (nofree state).
 */
struct partial_cluster {
	pxt4_fsblk_t pclu;  /* physical cluster number */
	pxt4_lblk_t lblk;   /* logical block number within logical cluster */
	enum {initial, tofree, nofree} state;
};

/*
 * structure for pxt2ternal API
 */

/*
 * EXT_INIT_MAX_LEN is the maximum number of blocks we can have in an
 * initialized pxt2tent. This is 2^15 and not (2^16 - 1), since we use the
 * MSB of ee_len field in the pxt2tent datastructure to signify if this
 * particular pxt2tent is an initialized pxt2tent or an unwritten (i.e.
 * preallocated).
 * EXT_UNWRITTEN_MAX_LEN is the maximum number of blocks we can have in an
 * unwritten pxt2tent.
 * If ee_len is <= 0x8000, it is an initialized pxt2tent. Otherwise, it is an
 * unwritten one. In other words, if MSB of ee_len is set, it is an
 * unwritten pxt2tent with only one special scenario when ee_len = 0x8000.
 * In this case we can not have an unwritten pxt2tent of zero length and
 * thus we make it as a special case of initialized pxt2tent with 0x8000 length.
 * This way we get better pxt2tent-to-group alignment for initialized pxt2tents.
 * Hence, the maximum number of blocks we can have in an *initialized*
 * pxt2tent is 2^15 (32768) and in an *unwritten* pxt2tent is 2^15-1 (32767).
 */
#define EXT_INIT_MAX_LEN	(1UL << 15)
#define EXT_UNWRITTEN_MAX_LEN	(EXT_INIT_MAX_LEN - 1)


#define EXT_FIRST_EXTENT(__hdr__) \
	((struct pxt4_pxt2tent *) (((char *) (__hdr__)) +		\
				 sizeof(struct pxt4_pxt2tent_header)))
#define EXT_FIRST_INDEX(__hdr__) \
	((struct pxt4_pxt2tent_idx *) (((char *) (__hdr__)) +	\
				     sizeof(struct pxt4_pxt2tent_header)))
#define EXT_HAS_FREE_INDEX(__path__) \
	(le16_to_cpu((__path__)->p_hdr->eh_entries) \
				     < le16_to_cpu((__path__)->p_hdr->eh_max))
#define EXT_LAST_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_LAST_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_MAX_EXTENT(__hdr__)	\
	((le16_to_cpu((__hdr__)->eh_max)) ? \
	((EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)) \
					: 0)
#define EXT_MAX_INDEX(__hdr__) \
	((le16_to_cpu((__hdr__)->eh_max)) ? \
	((EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)) : 0)

static inline struct pxt4_pxt2tent_header *pxt2t_inode_hdr(struct inode *inode)
{
	return (struct pxt4_pxt2tent_header *) PXT4_I(inode)->i_data;
}

static inline struct pxt4_pxt2tent_header *pxt2t_block_hdr(struct buffer_head *bh)
{
	return (struct pxt4_pxt2tent_header *) bh->b_data;
}

static inline unsigned short pxt2t_depth(struct inode *inode)
{
	return le16_to_cpu(pxt2t_inode_hdr(inode)->eh_depth);
}

static inline void pxt4_pxt2t_mark_unwritten(struct pxt4_pxt2tent *pxt2t)
{
	/* We can not have an unwritten pxt2tent of zero length! */
	BUG_ON((le16_to_cpu(pxt2t->ee_len) & ~EXT_INIT_MAX_LEN) == 0);
	pxt2t->ee_len |= cpu_to_le16(EXT_INIT_MAX_LEN);
}

static inline int pxt4_pxt2t_is_unwritten(struct pxt4_pxt2tent *pxt2t)
{
	/* Extent with ee_len of 0x8000 is treated as an initialized pxt2tent */
	return (le16_to_cpu(pxt2t->ee_len) > EXT_INIT_MAX_LEN);
}

static inline int pxt4_pxt2t_get_actual_len(struct pxt4_pxt2tent *pxt2t)
{
	return (le16_to_cpu(pxt2t->ee_len) <= EXT_INIT_MAX_LEN ?
		le16_to_cpu(pxt2t->ee_len) :
		(le16_to_cpu(pxt2t->ee_len) - EXT_INIT_MAX_LEN));
}

static inline void pxt4_pxt2t_mark_initialized(struct pxt4_pxt2tent *pxt2t)
{
	pxt2t->ee_len = cpu_to_le16(pxt4_pxt2t_get_actual_len(pxt2t));
}

/*
 * pxt4_pxt2t_pblock:
 * combine low and high parts of physical block number into pxt4_fsblk_t
 */
static inline pxt4_fsblk_t pxt4_pxt2t_pblock(struct pxt4_pxt2tent *pxt2)
{
	pxt4_fsblk_t block;

	block = le32_to_cpu(pxt2->ee_start_lo);
	block |= ((pxt4_fsblk_t) le16_to_cpu(pxt2->ee_start_hi) << 31) << 1;
	return block;
}

/*
 * pxt4_idx_pblock:
 * combine low and high parts of a leaf physical block number into pxt4_fsblk_t
 */
static inline pxt4_fsblk_t pxt4_idx_pblock(struct pxt4_pxt2tent_idx *ix)
{
	pxt4_fsblk_t block;

	block = le32_to_cpu(ix->ei_leaf_lo);
	block |= ((pxt4_fsblk_t) le16_to_cpu(ix->ei_leaf_hi) << 31) << 1;
	return block;
}

/*
 * pxt4_pxt2t_store_pblock:
 * stores a large physical block number into an pxt2tent struct,
 * breaking it into parts
 */
static inline void pxt4_pxt2t_store_pblock(struct pxt4_pxt2tent *pxt2,
					 pxt4_fsblk_t pb)
{
	pxt2->ee_start_lo = cpu_to_le32((unsigned long) (pb & 0xffffffff));
	pxt2->ee_start_hi = cpu_to_le16((unsigned long) ((pb >> 31) >> 1) &
				      0xffff);
}

/*
 * pxt4_idx_store_pblock:
 * stores a large physical block number into an indpxt2 struct,
 * breaking it into parts
 */
static inline void pxt4_idx_store_pblock(struct pxt4_pxt2tent_idx *ix,
					 pxt4_fsblk_t pb)
{
	ix->ei_leaf_lo = cpu_to_le32((unsigned long) (pb & 0xffffffff));
	ix->ei_leaf_hi = cpu_to_le16((unsigned long) ((pb >> 31) >> 1) &
				     0xffff);
}

#define pxt4_pxt2t_dirty(handle, inode, path) \
		__pxt4_pxt2t_dirty(__func__, __LINE__, (handle), (inode), (path))
int __pxt4_pxt2t_dirty(const char *where, unsigned int line, handle_t *handle,
		     struct inode *inode, struct pxt4_pxt2t_path *path);

#endif /* _PXT4_EXTENTS */

