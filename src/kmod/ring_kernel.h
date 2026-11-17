/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ring_kernel.h - per-CPU lock-free trace ring for the kernel module.
 *
 * Design mirrors src/core/ring_buffer.c (the user-space tracker) so that the
 * two implementations can be compared side by side:
 *
 *   - one ring per CPU: the writer is always the current CPU, so no lock is
 *     ever taken on the hot path (a kprobe handler may run in IRQ context and
 *     must not sleep or contend on a mutex);
 *   - "reserve then write": the write index is bumped atomically first, the
 *     event is written into the reserved slot, and a per-slot sequence number
 *     is published last.  A reader that observes an even, matching sequence
 *     knows the slot content is complete and was not overwritten mid-read;
 *   - readers never block writers: a slow reader loses the oldest slots and
 *     the loss is reported as `dropped` instead of stalling allocation.
 *
 * The ring itself is allocated at module init (vzalloc), never inside a probe
 * handler.
 */
#ifndef TRACKER_RING_KERNEL_H
#define TRACKER_RING_KERNEL_H

#include <linux/types.h>
#include <linux/atomic.h>

/* Event kinds emitted by the probes.  Keep in sync with the names table in
 * debugfs_iface.c so the human-readable tag always matches the number. */
enum k_event_type {
	KEV_ALLOC = 0,		/* kmalloc / kmem_cache_alloc returned      */
	KEV_FREE,		/* kfree / kmem_cache_free observed        */
	KEV_DOUBLE_FREE,	/* same pointer released twice             */
	KEV_WRONG_FREE,		/* kfree() on a kmem_cache_alloc() block   */
	KEV_CACHE_MISMATCH,	/* freed through a different cache         */
	KEV_OVERSIZE,		/* allocation at or above the threshold    */
	KEV_UNKNOWN_FREE,	/* pointer never seen allocated by us      */
	KEV_SELFTEST,		/* marker emitted by the debugfs self test */
	KEV_TYPE_MAX
};

/* Bit flags carried in kev.flags. */
#define KEVF_FROM_CACHE	0x1u	/* came from kmem_cache_alloc_noprof      */
#define KEVF_SELFTEST	0x2u	/* produced by the debugfs self test      */
#define KEVF_ALERT	0x4u	/* this event is a detection, not a trace */

/*
 * One trace record, padded to a full cache line so that concurrent CPUs
 * writing adjacent slots never share a line (false sharing).
 */
struct k_event {
	u64 ts_ns;		/* ktime_get_ns() at the probe             */
	u64 ptr;		/* block address                           */
	u64 size;		/* allocation size (0 when unknown)        */
	u64 caller_ip;		/* return address of the caller, raw       */
	u64 aux;		/* cache pointer / lifetime, per event     */
	u32 type;		/* enum k_event_type                       */
	u32 flags;		/* KEVF_*                                  */
	u32 pid;		/* current->pid at the probe               */
	u32 cpu;		/* smp_processor_id() at the probe         */
} __aligned(64);

struct k_ring {
	struct k_event *events;	/* vzalloc'ed, `size` entries              */
	u64 *seqs;		/* per-slot generation, `size` entries      */
	atomic64_t write_pos;	/* monotonic, bumped once per event        */
	atomic64_t dropped;	/* slots overwritten before they were read  */
	atomic64_t read_pos;	/* consumer cursor (debugfs)               */
	u32 size;		/* power of two                            */
	u32 mask;		/* size - 1                                */
};

/* Allocate `size` (rounded up to a power of two) slots for every possible
 * CPU.  Returns 0 on success, -ENOMEM on failure (partial state is cleaned
 * up internally). */
int kring_init(u32 size);

/* Free every per-CPU ring.  Safe to call when init never ran. */
void kring_exit(void);

/*
 * Append one event to the ring of the CPU we are running on.
 * May be called from IRQ context, must not sleep.  Never fails.
 */
void kring_push(const struct k_event *ev);

/*
 * Move the consumer cursor of every CPU ring forward by `n` slots (used by
 * `clear` so a stale backlog is not replayed after a reset).
 */
void kring_advance_read(u64 n);

/*
 * Drop the whole backlog: snap every consumer cursor to the current write
 * index.  Events still being written by a producer on another CPU are kept,
 * only already-produced-but-unread records are discarded.
 */
void kring_clear(void);

/*
 * Drain up to `max` events from every CPU ring into `out`, oldest first per
 * CPU, and add the number of slots that had to be skipped to `*dropped`.
 * Callable from process context only (debugfs read).
 * Returns how many events were copied.
 */
u32 kring_drain(struct k_event *out, u32 max, u64 *dropped);

/* Total events produced / dropped across all CPUs (for the stats file). */
void kring_totals(u64 *produced, u64 *dropped);

/* Slots actually allocated per ring and number of rings (for the stats file). */
void kring_info(u32 *slots, u32 *nr_rings);

#endif /* TRACKER_RING_KERNEL_H */
