/*
 * test_ring.c - unit tests for the SPSC circular buffer.
 *
 * Coverage:
 *   T1  basic FIFO ordering for a handful of events
 *   T2  empty pop returns false
 *   T3  overflow: oldest events are overwritten, `dropped` counts them and
 *       the surviving events are exactly the newest `size` ones
 *   T4  seqlock integrity under a concurrent producer/consumer: every event
 *       consumed is internally consistent (no torn payload) and the number
 *       of consumed + dropped == produced
 *   T5  rb_reset drains the buffer
 *
 * Exit code 0 = all tests passed, 1 = at least one failure.
 * ---------------------------------------------------------------------------
 */
#include "ring_buffer.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (cond) {                                                        \
            printf("  PASS  %s\n", msg);                                   \
        } else {                                                           \
            printf("  FAIL  %s\n", msg);                                   \
            g_failures++;                                                  \
        }                                                                  \
    } while (0)

/* Build an event whose payload is fully determined by `tag` so that torn
 * reads are detectable: every field derives from the same value. */
static TraceEvent make_event(uint64_t tag)
{
    TraceEvent ev;

    memset(&ev, 0, sizeof(ev));
    ev.seq          = tag;
    ev.timestamp_ns = tag * 1000u;
    ev.type         = ETYPE_ALLOC;
    ev.flags        = 0;
    ev.cpu          = 0;
    ev.ptr          = 0x100000000ULL + tag;
    ev.size         = tag;
    ev.pid          = (int32_t)tag;
    ev.aux          = (int32_t)tag;
    ev.caller_ip    = tag;
    ev.stack_hash   = tag * 2654435761ULL;
    return ev;
}

/* Verify a consumed event still matches its tag (catches torn reads). */
static int event_consistent(const TraceEvent *ev, uint64_t tag)
{
    return ev->seq          == tag &&
           ev->timestamp_ns == tag * 1000u &&
           ev->ptr          == 0x100000000ULL + tag &&
           ev->size         == tag &&
           ev->pid          == (int32_t)tag &&
           ev->aux          == (int32_t)tag &&
           ev->caller_ip    == tag &&
           ev->stack_hash   == tag * 2654435761ULL;
}

/* ---- T1 / T2 ----------------------------------------------------------- */
static void test_basic_fifo(void)
{
    RingBuffer rb;
    TraceEvent ev, out;
    int i, ok = 1, popped = 0;

    printf("T1/T2: basic FIFO ordering + empty pop\n");

    CHECK(rb_init(&rb, 16) == 0, "rb_init(16)");
    CHECK(rb_count(&rb) == 0, "ring starts empty");
    CHECK(rb_pop(&rb, &out) == false, "pop on empty returns false");

    for (i = 0; i < 10; i++) {
        ev = make_event((uint64_t)i);
        if (!rb_push(&rb, &ev))
            ok = 0;
    }
    CHECK(ok, "10 pushes succeed");
    CHECK(rb_count(&rb) == 10, "count == 10 after 10 pushes");

    ok = 1;
    while (rb_pop(&rb, &out)) {
        if (!event_consistent(&out, (uint64_t)popped))
            ok = 0;
        popped++;
    }
    CHECK(ok, "payloads intact");
    CHECK(popped == 10, "popped exactly 10 events");
    CHECK(rb_count(&rb) == 0, "ring empty after draining");

    rb_free(&rb);
}

/* ---- T3 --------------------------------------------------------------- */
static void test_overwrite_oldest(void)
{
    RingBuffer rb;
    TraceEvent ev, out;
    uint32_t i;
    const uint32_t cap = 8;
    const uint32_t total = 20;      /* push 20 into a slot-8 ring */
    int ok = 1;
    uint64_t popped = 0;

    printf("T3: overwrite-oldest + dropped counter\n");

    CHECK(rb_init(&rb, cap) == 0, "rb_init(8)");
    CHECK(rb.size == 8, "capacity rounded to requested power of two");

    for (i = 0; i < total; i++) {
        ev = make_event(i);
        rb_push(&rb, &ev);
    }

    CHECK(rb_count(&rb) == cap, "count capped at capacity");
    CHECK(rb_produced(&rb) == total, "produced == total pushes");

    /* The surviving events must be exactly tags 12..19.  `dropped` is
     * accounted by the consumer while it skips the overwritten range, so it
     * is only meaningful after draining. */
    ok = 1;
    while (rb_pop(&rb, &out)) {
        uint64_t expect = (uint64_t)(total - cap) + popped;
        if (!event_consistent(&out, expect))
            ok = 0;
        popped++;
    }
    CHECK(ok, "surviving events are the newest `cap` ones, in order");
    CHECK(popped == cap, "popped exactly `cap` events");
    CHECK(rb_dropped(&rb) == (uint64_t)total - cap,
          "dropped == pushed - capacity (counted during drain)");

    rb_free(&rb);
}

/* ---- T4: concurrent producer / consumer ------------------------------- */
#define T4_EVENTS 200000u
#define T4_RING   1024u

typedef struct {
    RingBuffer *rb;
    int         error;
    uint64_t    consumed;
} t4_ctx_t;

static void *t4_producer(void *arg)
{
    t4_ctx_t *c = (t4_ctx_t *)arg;
    uint32_t i;

    for (i = 0; i < T4_EVENTS; i++) {
        TraceEvent ev = make_event(i);
        rb_push(c->rb, &ev);
    }
    return NULL;
}

static void *t4_consumer(void *arg)
{
    t4_ctx_t *c = (t4_ctx_t *)arg;
    TraceEvent out;
    uint64_t last = 0;
    int first = 1;

    for (;;) {
        if (!rb_pop(c->rb, &out)) {
            /* Ring empty: the producer is done once it has pushed
             * everything and we have drained up to its head. */
            if (rb_produced(c->rb) >= T4_EVENTS &&
                rb_count(c->rb) == 0)
                break;
            continue;
        }

        /* A torn read would make one of these comparisons fail. */
        if (!event_consistent(&out, out.seq)) {
            c->error = 1;
            break;
        }
        /* Events must never go backwards in sequence for the portion we
         * actually observe (overwrite may skip forward, never backward). */
        if (!first && out.seq < last) {
            c->error = 2;
            break;
        }
        last = out.seq;
        first = 0;
        c->consumed++;
    }
    return NULL;
}

static void test_concurrent(void)
{
    RingBuffer rb;
    pthread_t prod, cons;
    t4_ctx_t pc, cc;
    uint64_t consumed, dropped;

    printf("T4: concurrent producer/consumer integrity\n");

    CHECK(rb_init(&rb, T4_RING) == 0, "rb_init(1024)");

    memset(&pc, 0, sizeof(pc));
    memset(&cc, 0, sizeof(cc));
    pc.rb = &rb;
    cc.rb = &rb;

    pthread_create(&prod, NULL, t4_producer, &pc);
    pthread_create(&cons, NULL, t4_consumer, &cc);

    pthread_join(prod, NULL);
    pthread_join(cons, NULL);

    consumed = cc.consumed;
    dropped  = rb_dropped(&rb);

    printf("        produced=%llu consumed=%llu dropped=%llu\n",
           (unsigned long long)rb_produced(&rb),
           (unsigned long long)consumed,
           (unsigned long long)dropped);

    CHECK(cc.error == 0, "no torn / out-of-order event observed");
    CHECK(rb_produced(&rb) == T4_EVENTS, "all events were pushed");
    CHECK(consumed + dropped == T4_EVENTS,
          "consumed + dropped == produced (no event lost silently)");

    rb_free(&rb);
}

/* ---- T5 --------------------------------------------------------------- */
static void test_reset(void)
{
    RingBuffer rb;
    TraceEvent ev, out;
    int i;

    printf("T5: rb_reset drains the buffer\n");

    CHECK(rb_init(&rb, 32) == 0, "rb_init(32)");
    for (i = 0; i < 5; i++) {
        ev = make_event((uint64_t)i);
        rb_push(&rb, &ev);
    }
    CHECK(rb_count(&rb) == 5, "5 events buffered");
    rb_reset(&rb);
    CHECK(rb_count(&rb) == 0, "count == 0 after reset");
    CHECK(rb_pop(&rb, &out) == false, "pop after reset returns false");

    rb_free(&rb);
    rb_free(&rb);   /* double free must be safe */
    CHECK(1, "rb_free is idempotent");
}

int main(void)
{
    printf("=== ring_buffer unit tests ===\n");

    test_basic_fifo();
    test_overwrite_oldest();
    test_concurrent();
    test_reset();

    printf("=== %s (%d failure(s)) ===\n",
           g_failures ? "FAILED" : "ALL PASSED", g_failures);
    return g_failures ? 1 : 0;
}
