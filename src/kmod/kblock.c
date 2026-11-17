// SPDX-License-Identifier: GPL-2.0
/*
 * kblock.c - live-block table for memory_tracker.ko (see kblock.h).
 *
 * Why a table at all
 * ------------------
 * A kprobe on kfree() only tells us "something was released".  To turn that
 * into a *detection* (double free, wrong allocator, unknown pointer) we must
 * know what was there before.  That memory lives here.
 *
 * Constraints imposed by the probe context
 * ----------------------------------------
 *   - no sleeping:      we run with IRQs disabled under a raw spinlock;
 *   - no allocating:    kmalloc inside a kmalloc probe would recurse, so the
 *                       whole table is one flat array allocated at init;
 *   - no rehashing:     the capacity is fixed at load time (`bits` module
 *                       parameter), the hash is a multiplicative mix of the
 *                       pointer and collisions are resolved by linear
 *                       probing.
 *
 * Slot lifecycle
 * --------------
 *   EMPTY  --alloc-->  LIVE  --free-->  QUAR  --alloc-->  LIVE ...
 *
 * QUAR (quarantine) is the whole point of keeping the slot instead of clearing
 * it: the pointer value survives its own free, so a second free of the same
 * pointer is recognised as DOUBLE_FREE rather than UNKNOWN_FREE.  A quarantined
 * slot is only recycled when the probe chain needs a free slot, which can only
 * weaken detection - never create a false positive.
 *
 * Locking
 * -------
 * One raw spinlock guards the entire table and is always taken with IRQs
 * disabled (raw_spin_lock_irqsave).  kmalloc is already a globally contended
 * point; adding a few hundred nanoseconds of hash probing there is
 * acceptable, and a raw lock is the only kind that is legal in IRQ context.
 */
#include "kblock.h"

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>

/* Table storage.  Allocated once by kblock_init(), never touched again by the
 * allocator.  Guarded by g_lock. */
static struct kblock *g_tab;
static u32 g_mask;		/* capacity - 1, capacity is a power of two	*/
static u32 g_capacity;

/* Live / quarantined slot counters, kept incrementally so that kblock_counts()
 * is O(1) instead of a full scan under the lock. */
static u32 g_live;
static u32 g_quar;

static raw_spinlock_t g_lock;

/* Multiplicative hash: a 64-bit multiply by an odd constant spreads kernel
 * pointers (which are page aligned, i.e. low bits zero) across all bits, then
 * the high bits are folded down to the table index. */
static inline u32 kblock_hash(u64 ptr)
{
	u64 h = ptr * 0x9E3779B97F4A7C15ULL;

	h ^= h >> 32;
	return (u32)h;
}

int kblock_init(unsigned int bits)
{
	size_t bytes;

	if (bits < 10)
		bits = 10;		/* 1024 slots - the practical floor	*/
	if (bits > 22)
		bits = 22;		/* 4M slots ≈ 160MB - the hard ceiling	*/

	g_capacity = 1u << bits;
	g_mask = g_capacity - 1;

	bytes = (size_t)g_capacity * sizeof(struct kblock);

	g_tab = kvzalloc(bytes, GFP_KERNEL);
	if (!g_tab) {
		g_capacity = 0;
		g_mask = 0;
		return -ENOMEM;
	}

	raw_spin_lock_init(&g_lock);
	g_live = 0;
	g_quar = 0;
	return 0;
}

void kblock_exit(void)
{
	if (!g_tab)
		return;
	kvfree(g_tab);
	g_tab = NULL;
	g_capacity = 0;
	g_mask = 0;
	g_live = 0;
	g_quar = 0;
}

/*
 * Find the slot holding `ptr`.
 *
 * Returns the slot index, or -1 when the pointer is not in the table.  Linear
 * probing stops at the first EMPTY slot because EMPTY is the only state that
 * guarantees "not present": QUAR acts as a tombstone and the walk continues
 * past it.
 *
 * Must be called with g_lock held.
 */
static int kblock_find(u64 ptr)
{
	u32 start = kblock_hash(ptr) & g_mask;
	u32 i;

	for (i = 0; i <= g_mask; i++) {
		u32 idx = (start + i) & g_mask;
		const struct kblock *e = &g_tab[idx];

		if (e->state == KB_EMPTY)
			return -1;
		if (e->ptr == ptr && e->state != KB_EMPTY)
			return (int)idx;
	}
	return -1;
}

/*
 * Find a slot to insert into.
 *
 * Preference order:
 *   1. an EMPTY slot (cheap, keeps quarantine intact);
 *   2. the first QUAR slot seen along the probe chain (recycle a tombstone -
 *      the pointer recorded there loses its double-free protection);
 *   3. nothing -> the table is full and the caller must drop the event.
 *
 * Returns the slot index, or -1 when the table is completely full.
 * Must be called with g_lock held.
 */
static int kblock_free_slot(void)
{
	u32 i;
	int tomb = -1;

	for (i = 0; i <= g_mask; i++) {
		struct kblock *e = &g_tab[i];

		if (e->state == KB_EMPTY)
			return (int)i;
		if (e->state == KB_QUAR && tomb < 0)
			tomb = (int)i;
	}
	return tomb;
}

bool kblock_note_alloc(u64 ptr, u64 size, u64 cache, u32 kind)
{
	unsigned long flags;
	int idx;
	struct kblock *e;
	bool ok = true;

	if (!g_tab || !ptr)
		return false;

	raw_spin_lock_irqsave(&g_lock, flags);

	idx = kblock_find(ptr);
	if (idx < 0) {
		idx = kblock_free_slot();
		if (idx < 0) {
			ok = false;		/* table full -> caller counts */
			goto out;
		}
		e = &g_tab[idx];

		/* EMPTY -> LIVE grows the live count; QUAR -> LIVE just moves
		 * a slot from one bucket to the other. */
		if (e->state == KB_EMPTY)
			g_live++;
		else
			g_quar--;

		e->ptr = ptr;
		e->state = KB_LIVE;
	} else {
		/*
		 * The pointer was already known.  Two possibilities:
		 *   - it was quarantined: a legitimate free followed by a new
		 *     allocation of the same address (the allocator recycling
		 *     the slot).  Nothing unusual.
		 *   - it was still LIVE: we missed the matching free, which
		 *     happens for allocations made before this module was
		 *     loaded and for paths our probes do not cover.  Record
		 *     the fresh state; this is reported as a stats counter,
		 *     not as an alert.
		 */
		e = &g_tab[idx];
		if (e->state == KB_QUAR) {
			g_quar--;
			g_live++;
		}
		e->state = KB_LIVE;
	}

	e->size = size;
	e->cache = cache;
	e->kind = kind;
	e->alloc_ts = ktime_get_ns();

out:
	raw_spin_unlock_irqrestore(&g_lock, flags);
	return ok;
}

enum kblock_free_result kblock_note_free(u64 ptr, bool via_cache, u64 cache,
					 u64 *out_size, u64 *out_age_ns)
{
	unsigned long flags;
	enum kblock_free_result res;
	struct kblock *e;
	int idx;
	u64 now;

	if (out_size)
		*out_size = 0;
	if (out_age_ns)
		*out_age_ns = 0;

	if (!g_tab || !ptr)
		return KBF_UNKNOWN_FREE;

	raw_spin_lock_irqsave(&g_lock, flags);

	idx = kblock_find(ptr);
	if (idx < 0) {
		res = KBF_UNKNOWN_FREE;
		goto out;
	}

	e = &g_tab[idx];
	now = ktime_get_ns();

	if (out_size)
		*out_size = e->size;
	if (out_age_ns && e->alloc_ts && now >= e->alloc_ts)
		*out_age_ns = now - e->alloc_ts;

	if (e->state == KB_QUAR) {
		/*
		 * The pointer is already in quarantine: this is the second
		 * (or third, ...) release of the same address.  Leave the
		 * state alone so a fourth release is still reported.
		 */
		res = KBF_DOUBLE_FREE;
		goto out;
	}

	/* State is KB_LIVE here. */
	if (via_cache != (e->kind == KB_KMEM_CACHE)) {
		/*
		 * kfree() on a kmem_cache_alloc() block, or the other way
		 * round.  Both are undefined behaviour in the kernel and are
		 * exactly the class of bug this module exists to catch.
		 */
		res = KBF_WRONG_FREE;
	} else if (via_cache && cache && e->cache && cache != e->cache) {
		/* Released through a different cache than it was allocated
		 * from - also undefined behaviour (SLUB freelist corruption). */
		res = KBF_CACHE_MISMATCH;
	} else {
		res = KBF_OK;
	}

	/* Quarantine the slot in every classified case so the next release of
	 * this pointer is reported as a double free instead of silently
	 * matching a recycled entry. */
	e->state = KB_QUAR;
	g_live--;
	g_quar++;

out:
	raw_spin_unlock_irqrestore(&g_lock, flags);
	return res;
}

void kblock_counts(u32 *live, u32 *quar)
{
	unsigned long flags;

	if (live)
		*live = 0;
	if (quar)
		*quar = 0;
	if (!g_tab)
		return;

	raw_spin_lock_irqsave(&g_lock, flags);
	if (live)
		*live = g_live;
	if (quar)
		*quar = g_quar;
	raw_spin_unlock_irqrestore(&g_lock, flags);
}

u32 kblock_capacity(void)
{
	return g_capacity;
}

bool kblock_contains(u64 ptr, u32 *state)
{
	unsigned long flags;
	int idx;
	bool found = false;

	if (!g_tab || !ptr)
		return false;

	raw_spin_lock_irqsave(&g_lock, flags);
	idx = kblock_find(ptr);
	if (idx >= 0) {
		found = true;
		if (state)
			*state = g_tab[idx].state;
	}
	raw_spin_unlock_irqrestore(&g_lock, flags);
	return found;
}

void kblock_reset(void)
{
	unsigned long flags;

	if (!g_tab)
		return;

	raw_spin_lock_irqsave(&g_lock, flags);
	memset(g_tab, 0, (size_t)g_capacity * sizeof(struct kblock));
	g_live = 0;
	g_quar = 0;
	raw_spin_unlock_irqrestore(&g_lock, flags);
}
