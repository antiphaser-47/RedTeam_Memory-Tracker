/*
 * scheduler.h
 * ---------------------------------------------------------------------------
 * The "CoreSight cadence" state machine.
 *
 *   every SCAN_INTERVAL_SEC (20 s) seconds:
 *       1. OPEN  the recording window   (state = SCH_RECORDING, 3 s)
 *          - events pushed now get EVF_IN_WINDOW and are logged in detail
 *       2. CLOSE the recording window
 *       3. SCAN  (state = SCH_SCANNING)
 *          - drain the ring buffer (log in-window events, count the rest)
 *          - run every registered detector's on_event / on_scan callback
 *          - write a cycle summary
 *       4. sleep the remainder of the 20 s budget
 *
 * The scheduler never creates threads itself: the platform main() starts a
 * thread whose body is scheduler_run().  That keeps threading (and every
 * related OS difference) out of the portable core.
 * ---------------------------------------------------------------------------
 */
#ifndef TRACKER_CORE_SCHEDULER_H
#define TRACKER_CORE_SCHEDULER_H

#include "tracker_types.h"
#include "ring_buffer.h"
#include "block_table.h"
#include "logger.h"
#include "platform.h"
#include "detectors.h"

#include <stdatomic.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum SchedulerState {
    SCH_IDLE       = 0,   /* sleeping between cycles                       */
    SCH_RECORDING  = 1,   /* recording window open, events tagged in-window*/
    SCH_SCANNING   = 2    /* ring drained + detectors running              */
} SchedulerState;

typedef struct Scheduler {
    RingBuffer        *ring;
    BlockTable        *blocks;
    Logger            *log;
    const PlatformOps *ops;
    const Scanner     *scanners;      /* array of detectors                */
    size_t             n_scanners;

    uint32_t interval_sec;            /* full cycle length (20)            */
    uint32_t record_sec;              /* recording window length (3)       */
    uint32_t first_delay_sec;         /* delay before the first cycle      */

    _Atomic int      running;         /* set to 0 to request shutdown      */
    _Atomic int      window_open;     /* 1 while the recording window runs */
    _Atomic uint64_t cycle;           /* cycles started (0 initially)      */
    _Atomic uint64_t completed;       /* cycles whose scan phase finished  */
    _Atomic uint64_t event_seq;       /* monotonic event id source         */
    _Atomic uint64_t pushed_in;       /* events pushed inside the window   */
    _Atomic uint64_t pushed_out;      /* events pushed outside the window  */

    SchedulerState   state;           /* only touched by scheduler_run()   */
} Scheduler;

/* Wire up a scheduler.  Does not start any thread. */
void scheduler_init(Scheduler *s,
                    RingBuffer *ring,
                    BlockTable *blocks,
                    Logger *log,
                    const PlatformOps *ops,
                    const Scanner *scanners, size_t n_scanners,
                    uint32_t interval_sec,
                    uint32_t record_sec,
                    uint32_t first_delay_sec);

/* Ask the scheduler to exit.  Thread safe; returns immediately. */
void scheduler_stop(Scheduler *s);

/* 1 while the scheduler still wants to run. */
int  scheduler_running(const Scheduler *s);

/* Push one event into the ring.
 * Fills in seq / timestamp / pid / cpu and the EVF_IN_WINDOW flag.
 * Safe to call from any thread. */
void scheduler_record(Scheduler *s, TraceEvent *ev);

/* The scheduler thread body: runs until scheduler_stop() is called.
 * Returns NULL (pthread compatible). */
void *scheduler_run(void *arg);

/* Current state (for diagnostics). */
SchedulerState scheduler_state(const Scheduler *s);

#ifdef __cplusplus
}
#endif

#endif /* TRACKER_CORE_SCHEDULER_H */
