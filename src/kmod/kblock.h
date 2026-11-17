/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kblock.h - kernel-side live-block table for memory_tracker.ko.
 *
 * Purpose
 * -------
 * The kretprobe handlers fire on every kmalloc()/kmem_cache_alloc() and on
 * every kfree()/kmem_cache_free().  To turn a raw "free" notification into a
 * *detection* we must remember what was allocated:
 *
 *   ptr -> { size, allocating cache, allocation time, allocator kind }
 *
 * That is exactly what this table stores.  It is the kernel counterpart of
 * src/core/block_table.c in the user-space tracker, but written for a context
 * that can run in IRQ handler, must never sleep, and must never allocate
 * memory (allocation is the very thing we are tracing - allocating inside the
 * allocator probe would recurse).
 *
 * Storage strategy
 * ----------------
 *   - a single flat, open-addressed (linear probing) array allocated once at
 *     module init with kvzalloc(), so the hot path never calls the allocator;
 *   - power-of-two capacity, index = hash(ptr) & mask;
 *   - one raw spinlock, taken with IRQs disabled, guards the whole table.
 *     kmalloc is already a globally contended point, and a 64-bit lock hold
 *     time of a few hash probes is negligible next to the allocation itself.
 *     Using a raw spinlock keeps the code correct in IRQ context.
 *
 * Quarantine / freed slots
 * ------------------------
 * A slot that is released keeps its pointer and flips to QUARANTINED instead
 * of becoming EMPTY.  That is what makes double-free detection possible: the
 * second free still finds the pointer and sees the QUARANTINED state.  A
 * quarantined slot is reused only when the probe chain needs a free slot and
 * the entry is older than `reap_age_ns` (default: never reaped early - we
 * simply reuse the oldest quarantined slot found while probing when the
 * table is full).  Reuse of a slot drops the quarantine for that pointer,
 * which only weakens detection, never produces a false positive.
 *
 * Known limitations (documented in docs/USAGE.md)
 * -----------------------------------------------
 *   - pointers allocated *before* the module was loaded are unknown, so their
 *     release is reported as UNKNOWN_FREE (informational, not an alert);
 *   - slot reuse means a very long running system can lose quarantine for
 *     pointers that were freed long ago.
 */
#ifndef TRACKER_KBLOCK_H
#define TRACKER_KBLOCK_H

#include <linux/types.h>
#include <linux/spinlock.h>

/* Slot states. */
#define KB_EMPTY	0u	/* never used / reaped				*/
#define KB_LIVE		1u	/* currently allocated				*/
#define KB_QUAR		2u	/* freed, kept for double-free detection	*/

/* Allocator kind recorded at allocation time. */
#define KB_KMALLOC	0u	/* kmalloc() family (__kmalloc*)			*/
#define KB_KMEM_CACHE	1u	/* kmem_cache_alloc()					*/

/* Result of kblock_lookup_free() - maps 1:1 onto an event type. */
enum kblock_free_result {
	KBF_OK = 0,		/* normal, single free				*/
	KBF_DOUBLE_FREE,	/* pointer was already in quarantine		*/
	KBF_WRONG_FREE,		/* kfree() on a kmem_cache block or vice versa	*/
	KBF_CACHE_MISMATCH,	/* kmem_cache_free() with a different cache	*/
	KBF_UNKNOWN_FREE,	/* pointer never seen by us			*/
};

/*
 * One table entry.  Kept compact (40 bytes) so that 64k slots stay inside a
 * couple of megabytes of vmalloc space.
 */
struct kblock {
	u64 ptr;
	u64 size;
	u64 cache;		/* struct kmem_cache * of the allocator, or 0	*/
	u64 alloc_ts;		/* ktime_get_ns() at allocation time		*/
	u32 state;		/* KB_EMPTY / KB_LIVE / KB_QUAR			*/
	u32 kind;		/* KB_KMALLOC / KB_KMEM_CACHE			*/
};

/* Allocate the table.  `bits` is log2 of the slot count (clamped 10..22). */
int kblock_init(unsigned int bits);

/* Release the table.  Safe to call when init never succeeded. */
void kblock_exit(void);

/*
 * Record an allocation.  Returns false when the table is full (the event is
 * then counted as dropped by the caller's stats).  Callable from IRQ context.
 */
bool kblock_note_alloc(u64 ptr, u64 size, u64 cache, u32 kind);

/*
 * Record a release and classify it.
 *   via_cache  : true when the release came from kmem_cache_free()
 *   cache      : the struct kmem_cache * passed to kmem_cache_free(), else 0
 *   out_size   : allocation size recorded at alloc time (0 when unknown)
 *   out_age_ns : lifetime of the block, 0 when unknown
 *
 * On KBF_DOUBLE_FREE / KBF_WRONG_FREE / KBF_CACHE_MISMATCH the slot is left in
 * quarantine so that a third release is still reported as a double free.
 */
enum kblock_free_result kblock_note_free(u64 ptr, bool via_cache, u64 cache,
					 u64 *out_size, u64 *out_age_ns);

/* Number of slots currently LIVE / QUARANTINED (for the stats file). */
void kblock_counts(u32 *live, u32 *quar);

/* Total slot capacity of the table (0 when the table was never created). */
u32 kblock_capacity(void);

/*
 * Read-only membership test used by the debugfs self test: is `ptr` in the
 * table right now, and in which state?  Returns false when absent.
 */
bool kblock_contains(u64 ptr, u32 *state);

/* Drop every entry (the debugfs `clear` command). */
void kblock_reset(void);

#endif /* TRACKER_KBLOCK_H */
