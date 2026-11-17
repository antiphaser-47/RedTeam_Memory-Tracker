/*
 * ring_buffer.c - lock-free SPSC circular buffer of TraceEvent records.
 *
 * See include/ring_buffer.h for the concurrency protocol.
 *
 * Key invariants maintained here:
 *   I1  head is advanced ONLY by rb_push (producer)
 *   I2  tail is advanced ONLY by rb_pop   (consumer)
 *   I3  a slot's sequence is odd while the producer writes it, even when
 *       the payload is stable, and encodes the generation (head value) that
 *       last wrote the slot
 *   I4  the producer never blocks: when it would exceed `size` outstanding
 *       events it overwrites the oldest slot and bumps `dropped`
 * ---------------------------------------------------------------------------
 */
#include "ring_buffer.h"

#include <stdlib.h>
#include <string.h>

/* Round `v` up to the next power of two (minimum 1). */
static uint32_t next_pow2(uint32_t v)
{
    uint32_t p = 1;

    if (v == 0)
        return 1;
    while (p < v) {
        /* Guard against overflow past 2^31 - the ring is never that big. */
        if (p > (1u << 30))
            return p;
        p <<= 1;
    }
    return p;
}

/* ---- portable 64-byte aligned allocation -------------------------------
 * C11 aligned_alloc() is what the POSIX build wants, but the MinGW CRT
 * headers do not declare it at all, so the Windows build uses the CRT's
 * _aligned_malloc()/_aligned_free() pair instead (they are the same
 * guarantee: a block aligned to at least the requested boundary).
 * The free side must match the alloc side, hence rb_aligned_free(). */
#if defined(_WIN32)
#  include <malloc.h>
static void *rb_aligned_alloc(size_t align, size_t size)
{
    return _aligned_malloc(size, align);
}
static void rb_aligned_free(void *p)
{
    _aligned_free(p);
}
#else
static void *rb_aligned_alloc(size_t align, size_t size)
{
    return aligned_alloc(align, size);
}
static void rb_aligned_free(void *p)
{
    free(p);
}
#endif

int rb_init(RingBuffer *rb, uint32_t size)
{
    uint32_t slots;

    if (!rb)
        return -1;

    memset(rb, 0, sizeof(*rb));

    slots = next_pow2(size ? size : RING_DEFAULT_SIZE);

    /* aligned_alloc requires the byte count to be a multiple of the
     * alignment; slots is a power of two and sizeof(TraceEvent) == 64, so
     * slots * 64 is always a multiple of 64. */
    rb->events = (TraceEvent *)rb_aligned_alloc(64,
                                                (size_t)slots * sizeof(TraceEvent));
    rb->seqs    = (_Atomic uint64_t *)calloc(slots, sizeof(_Atomic uint64_t));

    if (!rb->events || !rb->seqs) {
        rb_aligned_free(rb->events);
        free(rb->seqs);
        rb->events = NULL;
        rb->seqs   = NULL;
        return -1;
    }

    rb->size = slots;
    rb->mask = slots - 1;

    atomic_init(&rb->head,     0);
    atomic_init(&rb->tail,     0);
    atomic_init(&rb->dropped,  0);
    atomic_init(&rb->produced, 0);

    return 0;
}

void rb_free(RingBuffer *rb)
{
    if (!rb)
        return;
    rb_aligned_free(rb->events);
    free(rb->seqs);
    rb->events = NULL;
    rb->seqs   = NULL;
    rb->size   = 0;
    rb->mask   = 0;
}

bool rb_push(RingBuffer *rb, const TraceEvent *ev)
{
    uint64_t h;
    uint32_t idx;

    if (!rb || !ev || !rb->events)
        return false;

    /* I1: claim the next slot index.  Note that the producer does NOT try to
     * account for overwritten events here: reading `tail` would be racy and
     * would over-count whenever the consumer has already drained further
     * than the producer's snapshot.  The consumer counts losses exactly when
     * it skips forward (see rb_pop), which is the only place where "this
     * event will never be delivered" can be known for certain. */
    h = atomic_fetch_add_explicit(&rb->head, 1, memory_order_acq_rel);
    idx = (uint32_t)(h & rb->mask);

    /* Mark the slot as "being written" (odd sequence), fill it, then mark it
     * stable again with the generation that produced it. */
    atomic_store_explicit(&rb->seqs[idx], (h << 1) | 1u, memory_order_release);

    rb->events[idx] = *ev;
    rb->events[idx].seq = h;

    atomic_store_explicit(&rb->seqs[idx], h << 1, memory_order_release);

    atomic_fetch_add_explicit(&rb->produced, 1, memory_order_relaxed);
    return true;
}

bool rb_pop(RingBuffer *rb, TraceEvent *out)
{
    if (!rb || !out || !rb->events)
        return false;

    for (;;) {
        uint64_t t, h, s1, s2, gen;
        uint32_t idx;
        TraceEvent tmp;

        /* I2: read our own cursor. */
        t = atomic_load_explicit(&rb->tail, memory_order_acquire);
        h = atomic_load_explicit(&rb->head, memory_order_acquire);

        if (t >= h)
            return false;                       /* empty */

        /* More than `size` events are outstanding: everything before
         * h - size has been overwritten by the producer and can never be
         * delivered.  Skip it and account for the loss here - this is the
         * only place where `dropped` can be incremented exactly. */
        if (h - t > (uint64_t)rb->size) {
            uint64_t want  = h - (uint64_t)rb->size;
            uint64_t old_t = t;

            if (atomic_compare_exchange_weak_explicit(&rb->tail, &t, want,
                                                      memory_order_acq_rel,
                                                      memory_order_acquire)) {
                atomic_fetch_add_explicit(&rb->dropped, want - old_t,
                                          memory_order_relaxed);
            }
            continue;                           /* re-evaluate */
        }

        idx = (uint32_t)(t & rb->mask);

        /* Seqlock read: sample sequence, copy, sample again. */
        s1 = atomic_load_explicit(&rb->seqs[idx], memory_order_acquire);
        if (s1 & 1u)
            continue;                           /* producer mid-write */

        tmp = rb->events[idx];

        s2 = atomic_load_explicit(&rb->seqs[idx], memory_order_acquire);
        if (s1 != s2)
            continue;                           /* torn read, retry */

        gen = s1 >> 1;                          /* generation that owns slot */
        if (gen != t) {
            /* The slot belongs to a newer generation, which means the
             * producer has already lapped us.  Do NOT jump straight to `gen`:
             * events between t and gen may still be sitting in their own
             * slots.  Just re-load `head` on the next iteration - the
             * `h - t > size` branch above will then compute the exact
             * overwrite boundary (h - size) and count the loss. */
            continue;
        }

        *out = tmp;

        /* Publish consumption of this slot. */
        atomic_store_explicit(&rb->tail, t + 1, memory_order_release);
        return true;
    }
}

uint64_t rb_count(const RingBuffer *rb)
{
    uint64_t h, t, d;

    if (!rb || !rb->events)
        return 0;

    h = atomic_load_explicit((_Atomic uint64_t *)&rb->head,
                             memory_order_acquire);
    t = atomic_load_explicit((_Atomic uint64_t *)&rb->tail,
                             memory_order_acquire);

    d = (h > t) ? (h - t) : 0;
    return (d > (uint64_t)rb->size) ? (uint64_t)rb->size : d;
}

uint64_t rb_dropped(const RingBuffer *rb)
{
    if (!rb || !rb->events)
        return 0;
    return atomic_load_explicit((_Atomic uint64_t *)&rb->dropped,
                                memory_order_acquire);
}

uint64_t rb_produced(const RingBuffer *rb)
{
    if (!rb || !rb->events)
        return 0;
    return atomic_load_explicit((_Atomic uint64_t *)&rb->produced,
                                memory_order_acquire);
}

void rb_reset(RingBuffer *rb)
{
    if (!rb || !rb->events)
        return;

    /* Drain everything by aligning tail with head.  Only the consumer should
     * call this (the scanner thread at start-up), so a plain store is fine. */
    {
        uint64_t h = atomic_load_explicit(&rb->head, memory_order_acquire);
        atomic_store_explicit(&rb->tail, h, memory_order_release);
    }
}
