/* SPDX-License-Identifier: GPL-2.0 */
/*
 * probes.h - kprobe / kretprobe wiring for memory_tracker.ko.
 *
 * Two probe families are installed:
 *
 *   allocation side (kretprobe, so we see the returned pointer)
 *     __kmalloc_noprof            runtime-sized kmalloc()
 *     __kmalloc_node_noprof       kmalloc_node() / NUMA aware
 *     __kmalloc_cache_noprof      compile-time constant sized kmalloc()
 *     __kmalloc_cache_node_noprof constant sized kmalloc_node()
 *     __kmalloc_large_noprof      allocations above KMALLOC_MAX_CACHE_SIZE
 *     kmem_cache_alloc_noprof     explicit kmem_cache_alloc()
 *     kmem_cache_alloc_lru_noprof kmem_cache_alloc_lru() (inode/dentry caches)
 *
 *   release side (plain kprobe - the pointer is an argument, not a result)
 *     kfree
 *     kmem_cache_free
 *
 * Every probe is registered independently; a failure of one (blacklisted
 * symbol, ftrace conflict, ...) degrades coverage instead of failing the
 * whole module.  probes_stats() reports which ones actually landed.
 *
 * Context rules honoured by every handler:
 *   - never sleep, never allocate (kblock_note_alloc() only writes into a
 *     pre-allocated table, kring_push() only writes into pre-allocated slots);
 *   - IRQs may already be off, so all locking is raw_spin_lock_irqsave();
 *   - the caller address is read with copy_from_kernel_nofault() because the
 *     stack slot is not guaranteed to be mapped.
 */
#ifndef TRACKER_PROBES_H
#define TRACKER_PROBES_H

#include <linux/types.h>

/* Snapshot of every counter the module maintains.  Plain integers: the caller
 * (debugfs) is in process context and an unsynchronised read of an atomic64
 * torn across two reads is harmless for a statistics file. */
struct mt_probe_stats {
	/* allocation side */
	u64 alloc_seen;		/* successful allocations traced		*/
	u64 alloc_null;		/* allocator returned NULL			*/
	u64 alloc_table_full;	/* live-block table had no free slot		*/
	u64 oversize;		/* allocation at or above oversize_kb		*/

	/* release side */
	u64 free_seen;		/* clean single release				*/
	u64 double_free;
	u64 wrong_free;		/* kfree() on a kmem_cache block or vice versa	*/
	u64 cache_mismatch;	/* released through a different cache		*/
	u64 unknown_free;	/* pointer not allocated while we were loaded	*/

	/* probe plumbing */
	u64 probed_ok;		/* probes registered successfully		*/
	u64 probed_failed;	/* probes that could not be registered		*/
	u64 ret_missed;		/* kretprobe instances lost (maxactive)	*/
};

/* Register every probe.  Returns 0 even when some probes fail (partial
 * coverage is still useful); returns -ENOMEM only when the module is out of
 * memory.  Fills *ok / *failed when the pointers are non-NULL. */
int probes_register(unsigned int *ok, unsigned int *failed);

/* Unregister everything and wait for in-flight handlers to drain. */
void probes_unregister(void);

/* Copy the current counters into *out. */
void probes_stats(struct mt_probe_stats *out);

/* One row per symbol we tried to hook, so the operator can see the actual
 * coverage instead of assuming it. */
#define MT_MAX_PROBE_ROWS	16

struct mt_probe_status {
	const char *name;		/* symbol name as passed to kprobes	*/
	bool is_kretprobe;		/* true = allocation side		*/
	bool ok;			/* registration succeeded		*/
};

/* Copy up to MT_MAX_PROBE_ROWS rows into *out and store the number written
 * in *count.  Either pointer may be NULL. */
void probes_status(struct mt_probe_status *out, unsigned int *count);

#endif /* TRACKER_PROBES_H */
