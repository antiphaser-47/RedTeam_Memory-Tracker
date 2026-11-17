// SPDX-License-Identifier: GPL-2.0
/*
 * ring_kernel.c - per-CPU lock-free trace ring (see ring_kernel.h).
 *
 * Concurrency model
 * -----------------
 *   writer : exactly one context per CPU (the CPU itself, possibly in IRQ
 *            context).  Two contexts on the *same* CPU can never run at the
 *            same time, so a given slot is only ever written by one agent at
 *            a time and no lock is required on the hot path.
 *   reader : the debugfs `events` file, running on some other CPU.  It only
 *            ever reads, and it validates every slot through a per-slot
 *            generation number before copying it out.
 *
 * Publication protocol for one slot
 * ---------------------------------
 *   1. seq[slot] <- 0                 (0 == "being written")
 *   2. smp_wmb()
 *   3. events[slot] <- payload
 *   4. smp_wmb()
 *   5. seq[slot] <- index + 1         (unique, monotonic -> "complete")
 *
 * The reader accepts a slot only when it observed `index + 1` both before and
 * after copying the payload.  Anything else (0 = in flight, an older/newer
 * generation = overwritten) is counted as dropped instead of being reported as
 * a torn record.  That is the same guarantee the user-space ring gives, just
 * with a generation array instead of C11 seqlocks.
 */
#include "ring_kernel.h"

#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/string.h>

/* One entry per possible CPU.  Indexed by CPU id, allocated once at init. */
static struct k_ring *g_rings;
static u32 g_nr_rings;

/* Round up to a power of two, minimum 1. */
static u32 round_up_pow2(u32 v)
{
	u32 p = 1;

	if (v == 0)
		return 1;
	while (p < v) {
		if (p > (1u << 30))
			return p;
		p <<= 1;
	}
	return p;
}

/* Slots per ring actually allocated (after rounding), reported by
 * kring_info() so the stats file shows the real number, not the request. */
static u32 g_slots;

int kring_init(u32 size)
{
	unsigned int cpu;

	g_nr_rings = nr_cpu_ids;
	g_rings = kcalloc(g_nr_rings, sizeof(*g_rings), GFP_KERNEL);
	if (!g_rings) {
		g_nr_rings = 0;
		return -ENOMEM;
	}

	size = round_up_pow2(size);
	g_slots = size;

	for_each_possible_cpu(cpu) {
		struct k_ring *r = &g_rings[cpu];

		r->size = size;
		r->mask = size - 1;

		r->events = vzalloc((size_t)size * sizeof(struct k_event));
		if (!r->events)
			goto fail;

		r->seqs = vzalloc((size_t)size * sizeof(u64));
		if (!r->seqs)
			goto fail;

		/* vzalloc'ed memory is zeroed, so every generation number
		 * starts at 0 = "never written", which the reader treats as a
		 * mismatch and therefore skips. */
		atomic64_set(&r->write_pos, 0);
		atomic64_set(&r->dropped,  0);
		atomic64_set(&r->read_pos, 0);
	}
	return 0;

fail:
	kring_exit();
	return -ENOMEM;
}

void kring_exit(void)
{
	unsigned int cpu;

	if (!g_rings)
		return;

	for_each_possible_cpu(cpu) {
		struct k_ring *r = &g_rings[cpu];

		vfree(r->events);
		vfree(r->seqs);
		r->events = NULL;
		r->seqs   = NULL;
	}
	kfree(g_rings);
	g_rings = NULL;
	g_nr_rings = 0;
	g_slots = 0;
}

void kring_info(u32 *slots, u32 *nr_rings)
{
	if (slots)
		*slots = g_slots;
	if (nr_rings)
		*nr_rings = g_nr_rings;
}

void kring_push(const struct k_event *ev)
{
	struct k_ring *r;
	u64 idx, *seq;
	u32 slot;

	if (!g_rings || !ev)
		return;

	/*
	 * this_cpu_ptr() needs preemption off to be meaningful.  A kprobe
	 * handler already runs with preemption disabled; for the (rare) call
	 * sites that do not, take the cheap guard explicitly.
	 */
	preempt_disable();
	r = this_cpu_ptr(g_rings);
	if (!r->events) {
		preempt_enable();
		return;
	}

	idx = atomic64_inc_return(&r->write_pos) - 1;
	slot = (u32)idx & r->mask;
	seq = &r->seqs[slot];

	WRITE_ONCE(*seq, 0);		/* mark: being written      */
	smp_wmb();
	r->events[slot] = *ev;		/* publish the payload      */
	smp_wmb();
	WRITE_ONCE(*seq, idx + 1);	/* mark: complete           */

	preempt_enable();
}

void kring_advance_read(u64 n)
{
	unsigned int cpu;

	if (!g_rings || !n)
		return;
	for_each_possible_cpu(cpu)
		atomic64_add(n, &g_rings[cpu].read_pos);
}

void kring_clear(void)
{
	unsigned int cpu;

	if (!g_rings)
		return;
	for_each_possible_cpu(cpu) {
		struct k_ring *r = &g_rings[cpu];

		/* Publish the cursor with a full barrier so a concurrent
		 * drain on another CPU either sees the old value (and skips
		 * the record) or the new one (and skips it too).  Either way
		 * no torn record can be produced. */
		atomic64_set(&r->read_pos, atomic64_read(&r->write_pos));
	}
}

u32 kring_drain(struct k_event *out, u32 max, u64 *dropped)
{
	u32 copied = 0;
	u64 lost = 0;
	unsigned int cpu;

	if (!g_rings || !out || !max)
		return 0;

	for_each_possible_cpu(cpu) {
		struct k_ring *r = &g_rings[cpu];
		u64 end, read, start, i;
		u64 ring_lost = 0;

		if (!r->events)
			continue;

		end  = atomic64_read(&r->write_pos);
		read = atomic64_read(&r->read_pos);

		/* Never read slots that have already been recycled. */
		start = (end > r->size) ? (end - r->size) : 0;
		if (read < start) {
			ring_lost += start - read;
			read = start;
		}
		if (read > end)
			read = end;		/* clear() moved it forward */

		for (i = read; i < end && copied < max; i++) {
			u32 slot = (u32)i & r->mask;
			u64 want = i + 1;
			u64 g;
			struct k_event tmp;

			g = READ_ONCE(r->seqs[slot]);
			if (g != want) {
				/* mid-write (0) or already reused (other) */
				ring_lost++;
				continue;
			}
			smp_rmb();
			tmp = r->events[slot];
			smp_rmb();
			if (READ_ONCE(r->seqs[slot]) != g) {
				ring_lost++;	/* overwritten while copying */
				continue;
			}
			out[copied++] = tmp;
		}
		atomic64_set(&r->read_pos, i);

		/* Fold this round's losses into the persistent counter so
		 * kring_totals() keeps reporting them after the drain. */
		if (ring_lost) {
			atomic64_add(ring_lost, &r->dropped);
			lost += ring_lost;
		}
	}

	if (dropped)
		*dropped += lost;
	return copied;
}

void kring_totals(u64 *produced, u64 *dropped)
{
	u64 p = 0, d = 0;
	unsigned int cpu;

	if (!g_rings) {
		if (produced)
			*produced = 0;
		if (dropped)
			*dropped = 0;
		return;
	}

	for_each_possible_cpu(cpu) {
		const struct k_ring *r = &g_rings[cpu];

		p += (u64)atomic64_read(&r->write_pos);
		d += (u64)atomic64_read(&r->dropped);
	}
	if (produced)
		*produced = p;
	if (dropped)
		*dropped = d;
}
