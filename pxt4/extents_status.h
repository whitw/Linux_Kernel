// SPDX-License-Identifier: GPL-2.0
/*
 *  fs/pxt4/pxt2tents_status.h
 *
 * Written by Yongqiang Yang <xiaoqiangnk@gmail.com>
 * Modified by
 *	Allison Henderson <achender@linux.vnet.ibm.com>
 *	Zheng Liu <wenqing.lz@taobao.com>
 *
 */

#ifndef _PXT4_EXTENTS_STATUS_H
#define _PXT4_EXTENTS_STATUS_H

/*
 * Turn on ES_DEBUG__ to get lots of info about pxt2tent status operations.
 */
#ifdef ES_DEBUG__
#define es_debug(fmt, ...)	printk(fmt, ##__VA_ARGS__)
#else
#define es_debug(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

/*
 * With ES_AGGRESSIVE_TEST defined, the result of es caching will be
 * checked with old map_block's result.
 */
#define ES_AGGRESSIVE_TEST__

/*
 * These flags live in the high bits of pxt2tent_status.es_pblk
 */
enum {
	ES_WRITTEN_B,
	ES_UNWRITTEN_B,
	ES_DELAYED_B,
	ES_HOLE_B,
	ES_REFERENCED_B,
	ES_FLAGS
};

#define ES_SHIFT (sizeof(pxt4_fsblk_t)*8 - ES_FLAGS)
#define ES_MASK (~((pxt4_fsblk_t)0) << ES_SHIFT)

#define EXTENT_STATUS_WRITTEN	(1 << ES_WRITTEN_B)
#define EXTENT_STATUS_UNWRITTEN (1 << ES_UNWRITTEN_B)
#define EXTENT_STATUS_DELAYED	(1 << ES_DELAYED_B)
#define EXTENT_STATUS_HOLE	(1 << ES_HOLE_B)
#define EXTENT_STATUS_REFERENCED	(1 << ES_REFERENCED_B)

#define ES_TYPE_MASK	((pxt4_fsblk_t)(EXTENT_STATUS_WRITTEN | \
			  EXTENT_STATUS_UNWRITTEN | \
			  EXTENT_STATUS_DELAYED | \
			  EXTENT_STATUS_HOLE) << ES_SHIFT)

struct pxt4_sb_info;
struct pxt4_pxt2tent;

struct pxt2tent_status {
	struct rb_node rb_node;
	pxt4_lblk_t es_lblk;	/* first logical block pxt2tent covers */
	pxt4_lblk_t es_len;	/* length of pxt2tent in block */
	pxt4_fsblk_t es_pblk;	/* first physical block */
};

struct pxt4_es_tree {
	struct rb_root root;
	struct pxt2tent_status *cache_es;	/* recently accessed pxt2tent */
};

struct pxt4_es_stats {
	unsigned long es_stats_shrunk;
	struct percpu_counter es_stats_cache_hits;
	struct percpu_counter es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

/*
 * Pending cluster reservations for bigalloc file systems
 *
 * A cluster with a pending reservation is a logical cluster shared by at
 * least one pxt2tent in the pxt2tents status tree with delayed and unwritten
 * status and at least one other written or unwritten pxt2tent.  The
 * reservation is said to be pending because a cluster reservation would
 * have to be taken in the event all blocks in the cluster shared with
 * written or unwritten pxt2tents were deleted while the delayed and
 * unwritten blocks remained.
 *
 * The set of pending cluster reservations is an auxiliary data structure
 * used with the pxt2tents status tree to implement reserved cluster/block
 * accounting for bigalloc file systems.  The set is kept in memory and
 * records all pending cluster reservations.
 *
 * Its primary function is to avoid the need to read pxt2tents from the
 * disk when invalidating pages as a result of a truncate, punch hole, or
 * collapse range operation.  Page invalidation requires a decrease in the
 * reserved cluster count if it results in the removal of all delayed
 * and unwritten pxt2tents (blocks) from a cluster that is not shared with a
 * written or unwritten pxt2tent, and no decrease otherwise.  Determining
 * whether the cluster is shared can be done by searching for a pending
 * reservation on it.
 *
 * Secondarily, it provides a potentially faster method for determining
 * whether the reserved cluster count should be increased when a physical
 * cluster is deallocated as a result of a truncate, punch hole, or
 * collapse range operation.  The necessary information is also present
 * in the pxt2tents status tree, but might be more rapidly accessed in
 * the pending reservation set in many cases due to smaller size.
 *
 * The pending cluster reservation set is implemented as a red-black tree
 * with the goal of minimizing per page search time overhead.
 */

struct pending_reservation {
	struct rb_node rb_node;
	pxt4_lblk_t lclu;
};

struct pxt4_pending_tree {
	struct rb_root root;
};

pxt2tern int __init pxt4_init_es(void);
pxt2tern void pxt4_pxt2it_es(void);
pxt2tern void pxt4_es_init_tree(struct pxt4_es_tree *tree);

pxt2tern int pxt4_es_insert_pxt2tent(struct inode *inode, pxt4_lblk_t lblk,
				 pxt4_lblk_t len, pxt4_fsblk_t pblk,
				 unsigned int status);
pxt2tern void pxt4_es_cache_pxt2tent(struct inode *inode, pxt4_lblk_t lblk,
				 pxt4_lblk_t len, pxt4_fsblk_t pblk,
				 unsigned int status);
pxt2tern int pxt4_es_remove_pxt2tent(struct inode *inode, pxt4_lblk_t lblk,
				 pxt4_lblk_t len);
pxt2tern void pxt4_es_find_pxt2tent_range(struct inode *inode,
				      int (*match_fn)(struct pxt2tent_status *es),
				      pxt4_lblk_t lblk, pxt4_lblk_t end,
				      struct pxt2tent_status *es);
pxt2tern int pxt4_es_lookup_pxt2tent(struct inode *inode, pxt4_lblk_t lblk,
				 pxt4_lblk_t *npxt2t_lblk,
				 struct pxt2tent_status *es);
pxt2tern bool pxt4_es_scan_range(struct inode *inode,
			       int (*matching_fn)(struct pxt2tent_status *es),
			       pxt4_lblk_t lblk, pxt4_lblk_t end);
pxt2tern bool pxt4_es_scan_clu(struct inode *inode,
			     int (*matching_fn)(struct pxt2tent_status *es),
			     pxt4_lblk_t lblk);

static inline unsigned int pxt4_es_status(struct pxt2tent_status *es)
{
	return es->es_pblk >> ES_SHIFT;
}

static inline unsigned int pxt4_es_type(struct pxt2tent_status *es)
{
	return (es->es_pblk & ES_TYPE_MASK) >> ES_SHIFT;
}

static inline int pxt4_es_is_written(struct pxt2tent_status *es)
{
	return (pxt4_es_type(es) & EXTENT_STATUS_WRITTEN) != 0;
}

static inline int pxt4_es_is_unwritten(struct pxt2tent_status *es)
{
	return (pxt4_es_type(es) & EXTENT_STATUS_UNWRITTEN) != 0;
}

static inline int pxt4_es_is_delayed(struct pxt2tent_status *es)
{
	return (pxt4_es_type(es) & EXTENT_STATUS_DELAYED) != 0;
}

static inline int pxt4_es_is_hole(struct pxt2tent_status *es)
{
	return (pxt4_es_type(es) & EXTENT_STATUS_HOLE) != 0;
}

static inline int pxt4_es_is_mapped(struct pxt2tent_status *es)
{
	return (pxt4_es_is_written(es) || pxt4_es_is_unwritten(es));
}

static inline int pxt4_es_is_delonly(struct pxt2tent_status *es)
{
	return (pxt4_es_is_delayed(es) && !pxt4_es_is_unwritten(es));
}

static inline void pxt4_es_set_referenced(struct pxt2tent_status *es)
{
	es->es_pblk |= ((pxt4_fsblk_t)EXTENT_STATUS_REFERENCED) << ES_SHIFT;
}

static inline void pxt4_es_clear_referenced(struct pxt2tent_status *es)
{
	es->es_pblk &= ~(((pxt4_fsblk_t)EXTENT_STATUS_REFERENCED) << ES_SHIFT);
}

static inline int pxt4_es_is_referenced(struct pxt2tent_status *es)
{
	return (pxt4_es_status(es) & EXTENT_STATUS_REFERENCED) != 0;
}

static inline pxt4_fsblk_t pxt4_es_pblock(struct pxt2tent_status *es)
{
	return es->es_pblk & ~ES_MASK;
}

static inline void pxt4_es_store_pblock(struct pxt2tent_status *es,
					pxt4_fsblk_t pb)
{
	pxt4_fsblk_t block;

	block = (pb & ~ES_MASK) | (es->es_pblk & ES_MASK);
	es->es_pblk = block;
}

static inline void pxt4_es_store_status(struct pxt2tent_status *es,
					unsigned int status)
{
	es->es_pblk = (((pxt4_fsblk_t)status << ES_SHIFT) & ES_MASK) |
		      (es->es_pblk & ~ES_MASK);
}

static inline void pxt4_es_store_pblock_status(struct pxt2tent_status *es,
					       pxt4_fsblk_t pb,
					       unsigned int status)
{
	es->es_pblk = (((pxt4_fsblk_t)status << ES_SHIFT) & ES_MASK) |
		      (pb & ~ES_MASK);
}

pxt2tern int pxt4_es_register_shrinker(struct pxt4_sb_info *sbi);
pxt2tern void pxt4_es_unregister_shrinker(struct pxt4_sb_info *sbi);

pxt2tern int pxt4_seq_es_shrinker_info_show(struct seq_file *seq, void *v);

pxt2tern int __init pxt4_init_pending(void);
pxt2tern void pxt4_pxt2it_pending(void);
pxt2tern void pxt4_init_pending_tree(struct pxt4_pending_tree *tree);
pxt2tern void pxt4_remove_pending(struct inode *inode, pxt4_lblk_t lblk);
pxt2tern bool pxt4_is_pending(struct inode *inode, pxt4_lblk_t lblk);
pxt2tern int pxt4_es_insert_delayed_block(struct inode *inode, pxt4_lblk_t lblk,
					bool allocated);
pxt2tern unsigned int pxt4_es_delayed_clu(struct inode *inode, pxt4_lblk_t lblk,
					pxt4_lblk_t len);
pxt2tern void pxt4_clear_inode_es(struct inode *inode);

#endif /* _PXT4_EXTENTS_STATUS_H */
