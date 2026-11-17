/*
 * ring_buffer.h
 * ---------------------------------------------------------------------------
 * Single-Producer / Single-Consumer (SPSC) lock-free circular buffer of
 * fixed-size TraceEvent records.
 *
 * Why a circular buffer?
 * ----------------------
 * This is the software equivalent of the CoreSight trace buffer:
 *   - bounded memory: the tracker can never be exhausted by an event storm
 *   - overwrite-oldest policy: when full, the newest events win and the
 *     oldest ones are lost (counted in `dropped` when the consumer drains
 *     past them), exactly like a hardware trace sink that keeps the most
 *     recent window of activity
 *   - lock free: the producer (application thread allocating memory) and the
 *     consumer (scanner thread) never block each other
 *
 * Concurrency protocol
 * --------------------
 *   head : written ONLY by the producer (monotonic, never wraps in practice)
 *   tail : written ONLY by the consumer (monotonic)
 *   seqs : per-slot sequence lock.  odd  = producer is writing that slot
 *                             even = slot content is stable
 *
 * The consumer performs a seqlock read: read seq, copy the payload, re-read
 * seq.  If the two sequence numbers differ (or the odd "writing" flag was
 * seen) the read was torn and is retried.  This is what makes it safe for
 * the producer to overwrite a slot the consumer is currently reading.
 *
 * Overwrite accounting: the producer cannot know whether an event it is
 * clobbering was already consumed (reading `tail` would be a racy snapshot),
 * so `dropped` is incremented by the *consumer* when it skips a range of
 * generations that can no longer be delivered.  That makes
 * consumed + dropped == produced hold exactly.
 * ---------------------------------------------------------------------------
 */
#ifndef TRACKER_CORE_RING_BUFFER_H
#define TRACKER_CORE_RING_BUFFER_H

#include "tracker_types.h"

#include <stdatomic.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RingBuffer {
    TraceEvent        *events;   /* slot storage, `size` entries             */
    _Atomic uint64_t  *seqs;     /* per-slot sequence lock, `size` entries   */
    _Atomic uint64_t   head;     /* producer cursor (monotonic)              */
    _Atomic uint64_t   tail;     /* consumer cursor (monotonic)              */
    _Atomic uint64_t   dropped;  /* events overwritten before being consumed */
    _Atomic uint64_t   produced; /* total successful pushes                  */
    uint32_t           size;     /* slot count, always a power of two        */
    uint32_t           mask;     /* size - 1, used for fast modulo           */
} RingBuffer;

/* Initialise the ring.  `size` is rounded UP to the next power of two;
 * pass 0 to use RING_DEFAULT_SIZE.  Returns 0 on success, -1 on OOM. */
int  rb_init(RingBuffer *rb, uint32_t size);

/* Release all memory owned by the ring.  Safe to call twice. */
void rb_free(RingBuffer *rb);

/* Push one event.  Never blocks.  If the ring is full the oldest event is
 * overwritten and the `dropped` counter is incremented.
 * Returns false only when rb or ev is NULL. */
bool rb_push(RingBuffer *rb, const TraceEvent *ev);

/* Pop the oldest event into *out.  Returns false when the ring is empty.
 * Retries internally if it observes a torn (mid-write) slot. */
bool rb_pop(RingBuffer *rb, TraceEvent *out);

/* Number of events currently readable (capped at `size`). */
uint64_t rb_count(const RingBuffer *rb);

/* Number of events lost to overwrite-oldest since init. */
uint64_t rb_dropped(const RingBuffer *rb);

/* Total number of successful pushes since init. */
uint64_t rb_produced(const RingBuffer *rb);

/* Discard everything currently buffered (used when a cycle ends). */
void rb_reset(RingBuffer *rb);

#ifdef __cplusplus
}
#endif

#endif /* TRACKER_CORE_RING_BUFFER_H */
