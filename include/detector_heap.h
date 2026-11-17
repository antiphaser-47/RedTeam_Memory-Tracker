/*
 * detector_heap.h
 */
#ifndef TRACKER_DETECTOR_HEAP_H
#define TRACKER_DETECTOR_HEAP_H

#include "detectors.h"

/*
 * The heap detector needs three *synchronous* hooks in addition to the
 * normal scanner callbacks.  They cannot be driven from the ring buffer
 * because the evidence has to be collected while the chunk is still valid:
 *
 *   heap_on_alloc()   call from the platform's allocation path, right after
 *                     the pointer becomes known.  Evicts the address from
 *                     the quarantine - a recycled address is no longer
 *                     evidence of anything.
 *
 *   heap_on_free()    call from the platform's free path BEFORE the real
 *                     free() runs.  This is the only moment at which the
 *                     block's content can still be snapshotted, which is
 *                     what makes use-after-free detection possible later.
 *                     A second call for an address already in quarantine is
 *                     reported as a double free.
 *
 *   heap_add_redzone() declare a canary region that the caller owns (and
 *                     therefore can safely place after a block).  The scan
 *                     verifies the canary bytes every cycle.
 *
 * scan_heap_on_event() remains registered so that an allocation event seen
 * late (during the ring drain) still evicts a quarantined address - but
 * only when the event is genuinely newer than the free, otherwise the
 * allocation that *preceded* the free would wrongly clear the evidence.
 */
void scan_heap_on_event(ScanContext *ctx, const TraceEvent *ev);
void scan_heap(ScanContext *ctx);

void heap_on_alloc(uint64_t ptr);
void heap_on_free(const PlatformOps *ops, Logger *log,
                  uint64_t ptr, uint64_t size);
void heap_add_redzone(uint64_t block_ptr, uint64_t rz_ptr,
                      uint64_t rz_size, uint8_t fill);

/* Drop every quarantine entry and redzone (test isolation). */
void heap_reset(void);

#endif /* TRACKER_DETECTOR_HEAP_H */
