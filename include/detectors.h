/*
 * detectors.h
 * ---------------------------------------------------------------------------
 * Scanner / detector interface.
 *
 * A detector is a pair of optional callbacks:
 *
 *   on_event  called for every event drained out of the ring buffer
 *             (the heap detector uses it only as a late-eviction fallback;
 *              its real work happens in the synchronous heap_on_* hooks)
 *   on_scan   called once per cycle after the ring has been drained
 *             (used by the RWX / entropy / ROP / hook detectors)
 *
 * Detectors receive a ScanContext that bundles everything they need, so a
 * detector never has to reach into scheduler internals.
 * ---------------------------------------------------------------------------
 */
#ifndef TRACKER_CORE_DETECTORS_H
#define TRACKER_CORE_DETECTORS_H

#include "tracker_types.h"
#include "block_table.h"
#include "logger.h"
#include "platform.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ScanContext {
    BlockTable        *blocks;         /* live allocation table             */
    const PlatformOps *ops;            /* platform vtable                   */
    Logger            *log;            /* logger                            */
    uint64_t           cycle;          /* current cycle number (1-based)    */
    uint64_t           window_start_ns;/* recording window start            */
    uint64_t           window_end_ns;  /* recording window end              */
} ScanContext;

typedef struct Scanner {
    const char *name;                            /* short identifier       */
    void (*on_event)(ScanContext *ctx, const TraceEvent *ev); /* may be NULL */
    void (*on_scan)(ScanContext *ctx);                     /* may be NULL    */
} Scanner;

/* -----------------------------------------------------------------------
 * Concrete detectors (implemented across P2/P3/P4)
 * -------------------------------------------------------------------- */

/* src/core/detector_rwx.c      - RWX regions + permission transitions       */
void scan_rwx_on_event(ScanContext *ctx, const TraceEvent *ev);
void scan_rwx(ScanContext *ctx);

/* src/core/detector_entropy.c  - entropy, NOP sled, INT3 sled, printability */
void scan_entropy(ScanContext *ctx);

/* src/core/detector_hook.c     - inline hooks (E9/FF25/CC) + GOT tampering  */
void scan_hooks(ScanContext *ctx);

/* src/core/detector_rop.c      - Capstone verified ROP gadgets              */
void scan_rop(ScanContext *ctx);

/* src/core/detector_ret2libc.c - dangerous function addresses               */
void scan_ret2libc(ScanContext *ctx);

/* src/core/detector_heap.c     - UAF / double free / redzone overflow       *
 *                               (plus the synchronous heap_on_alloc /
 *                                heap_on_free / heap_add_redzone hooks -     *
 *                                see detector_heap.h for why they exist)     */
void scan_heap_on_event(ScanContext *ctx, const TraceEvent *ev);
void scan_heap(ScanContext *ctx);

/* Detector state reset (called between test cases). */
void detectors_reset(void);

/* Build the default scanner table used by the main programs.
 * *count receives the number of entries. */
const Scanner *detectors_default_table(size_t *count);

#ifdef __cplusplus
}
#endif

#endif /* TRACKER_CORE_DETECTORS_H */
