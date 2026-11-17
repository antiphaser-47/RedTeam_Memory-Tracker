/*
 * scheduler.c - the "scan every 20 s / record 3 s" state machine.
 *
 * Threading model: this file never creates threads.  The platform main()
 * spawns a pthread (or Win32 thread via winpthreads) whose entry point is
 * scheduler_run().  All sleeping goes through ops->sleep_ms() in 100 ms
 * slices so that scheduler_stop() takes effect quickly instead of after a
 * full 20-second nap.
 * ---------------------------------------------------------------------------
 */
#include "scheduler.h"

#include <string.h>

void scheduler_init(Scheduler *s,
                    RingBuffer *ring,
                    BlockTable *blocks,
                    Logger *log,
                    const PlatformOps *ops,
                    const Scanner *scanners, size_t n_scanners,
                    uint32_t interval_sec,
                    uint32_t record_sec,
                    uint32_t first_delay_sec)
{
    memset(s, 0, sizeof(*s));

    s->ring            = ring;
    s->blocks          = blocks;
    s->log             = log;
    s->ops             = ops;
    s->scanners        = scanners;
    s->n_scanners      = n_scanners;
    s->interval_sec    = interval_sec    ? interval_sec    : SCAN_INTERVAL_SEC;
    s->record_sec      = record_sec      ? record_sec      : RECORD_DURATION_SEC;
    s->first_delay_sec = first_delay_sec;

    atomic_init(&s->running,     0);
    atomic_init(&s->window_open, 0);
    atomic_init(&s->cycle,       0);
    atomic_init(&s->completed,   0);
    atomic_init(&s->event_seq,   0);
    atomic_init(&s->pushed_in,   0);
    atomic_init(&s->pushed_out,  0);

    s->state = SCH_IDLE;
}

void scheduler_stop(Scheduler *s)
{
    if (!s)
        return;
    atomic_store_explicit(&s->running, 0, memory_order_release);
    atomic_store_explicit(&s->window_open, 0, memory_order_release);
}

int scheduler_running(const Scheduler *s)
{
    if (!s)
        return 0;
    return atomic_load_explicit((_Atomic int *)&s->running,
                                memory_order_acquire);
}

SchedulerState scheduler_state(const Scheduler *s)
{
    if (!s)
        return SCH_IDLE;
    return s->state;
}

void scheduler_record(Scheduler *s, TraceEvent *ev)
{
    int in_window;

    if (!s || !ev)
        return;

    in_window = atomic_load_explicit(&s->window_open, memory_order_acquire);

    ev->seq     = atomic_fetch_add_explicit(&s->event_seq, 1,
                                            memory_order_relaxed);
    ev->flags   = (uint16_t)((ev->flags & (uint16_t)~EVF_IN_WINDOW) |
                             (in_window ? EVF_IN_WINDOW : 0));
    ev->timestamp_ns = s->ops->now_ns();
    ev->pid     = (int32_t)s->ops->pid();
    ev->cpu     = s->ops->cpu();

    if (in_window)
        atomic_fetch_add_explicit(&s->pushed_in, 1, memory_order_relaxed);
    else
        atomic_fetch_add_explicit(&s->pushed_out, 1, memory_order_relaxed);

    rb_push(s->ring, ev);
}

/* Sleep up to `ms`, waking early when the scheduler is asked to stop. */
static void sleep_interruptible(Scheduler *s, uint64_t ms)
{
    uint64_t elapsed = 0;

    while (elapsed < ms && atomic_load_explicit(&s->running,
                                                memory_order_acquire)) {
        uint64_t chunk = ms - elapsed;

        if (chunk > 100)
            chunk = 100;                 /* 100 ms shutdown latency budget */

        s->ops->sleep_ms(chunk);
        elapsed += chunk;
    }
}

/* Drain the ring buffer: log in-window events in detail, count the rest,
 * and hand every event to the detectors' on_event hook. */
static uint64_t drain_ring(Scheduler *s, ScanContext *ctx,
                           uint64_t *n_in, uint64_t *n_out)
{
    TraceEvent ev;
    uint64_t total = 0;

    *n_in  = 0;
    *n_out = 0;

    while (rb_pop(s->ring, &ev)) {
        size_t i;

        if (ev.flags & EVF_IN_WINDOW) {
            (*n_in)++;
            log_event(s->log, (EventType)ev.type,
                      "addr=0x%016llx size=%llu perms=0x%x stack=0x%016llx "
                      "ip=0x%016llx",
                      (unsigned long long)ev.ptr,
                      (unsigned long long)ev.size,
                      (unsigned)ev.aux,
                      (unsigned long long)ev.stack_hash,
                      (unsigned long long)ev.caller_ip);
        } else {
            (*n_out)++;
        }

        for (i = 0; i < s->n_scanners; i++) {
            if (s->scanners[i].on_event)
                s->scanners[i].on_event(ctx, &ev);
        }
        total++;
    }
    return total;
}

void *scheduler_run(void *arg)
{
    Scheduler *s = (Scheduler *)arg;
    const PlatformOps *ops;

    if (!s || !s->ops)
        return NULL;

    ops = s->ops;
    atomic_store_explicit(&s->running, 1, memory_order_release);

    log_event(s->log, ETYPE_STATS,
              "scheduler thread started: interval=%us record=%us ring=%u slots",
              s->interval_sec, s->record_sec,
              s->ring ? s->ring->size : 0u);

    if (s->first_delay_sec)
        sleep_interruptible(s, (uint64_t)s->first_delay_sec * 1000u);

    while (atomic_load_explicit(&s->running, memory_order_acquire)) {
        uint64_t cycle, win_start, win_end, spent_ms, budget_ms;
        uint64_t n_in = 0, n_out = 0, drained = 0;
        uint32_t i;
        ScanContext ctx;

        /* ---------------- cycle start ---------------- */
        cycle    = atomic_fetch_add_explicit(&s->cycle, 1,
                                             memory_order_relaxed) + 1;
        win_start = ops->now_ns();

        logger_set_cycle(s->log, cycle, win_start);
        s->state = SCH_RECORDING;
        atomic_store_explicit(&s->window_open, 1, memory_order_release);

        log_event(s->log, ETYPE_SCAN_BEGIN,
                  "recording window OPEN (%u s)", s->record_sec);

        /* ---------------- recording window ---------------- */
        sleep_interruptible(s, (uint64_t)s->record_sec * 1000u);

        atomic_store_explicit(&s->window_open, 0, memory_order_release);
        win_end = ops->now_ns();
        s->state = SCH_SCANNING;

        log_event(s->log, ETYPE_SCAN_END,
                  "recording window CLOSED (%.3f s elapsed)",
                  (double)(win_end - win_start) / 1e9);

        /* ---------------- scan phase ---------------- */
        memset(&ctx, 0, sizeof(ctx));
        ctx.blocks          = s->blocks;
        ctx.ops             = s->ops;
        ctx.log             = s->log;
        ctx.cycle           = cycle;
        ctx.window_start_ns = win_start;
        ctx.window_end_ns   = win_end;

        drained = drain_ring(s, &ctx, &n_in, &n_out);

        for (i = 0; i < s->n_scanners; i++) {
            if (s->scanners[i].on_scan)
                s->scanners[i].on_scan(&ctx);
        }

        {
            uint64_t ring_left   = rb_count(s->ring);
            uint64_t ring_dropped = rb_dropped(s->ring);

            log_event(s->log, ETYPE_STATS,
                      "cycle summary: drained=%llu (in-window=%llu, "
                      "out-of-window=%llu) still-buffered=%llu "
                      "ring-dropped=%llu blocks=%u",
                      (unsigned long long)drained,
                      (unsigned long long)n_in,
                      (unsigned long long)n_out,
                      (unsigned long long)ring_left,
                      (unsigned long long)ring_dropped,
                      bt_count(s->blocks));
        }

        logger_flush(s->log);
        s->state = SCH_IDLE;

        /* Publish "this cycle's scan is done" so the main thread can wait
         * for a deterministic number of completed cycles before exiting. */
        atomic_fetch_add_explicit(&s->completed, 1, memory_order_release);

        /* ---------------- sleep the remainder of the budget ----------------
         * The whole cycle (record + scan + sleep) must total interval_sec so
         * that scans really do happen every 20 seconds. */
        win_end  = ops->now_ns();
        spent_ms = (win_end - win_start) / 1000000ULL;
        budget_ms = (uint64_t)s->interval_sec * 1000ULL;

        if (budget_ms > spent_ms)
            sleep_interruptible(s, budget_ms - spent_ms);
    }

    log_event(s->log, ETYPE_STATS, "scheduler thread stopped");
    return NULL;
}
