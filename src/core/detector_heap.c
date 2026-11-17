/*
 * detector_heap.c - heap lifetime forensics: use-after-free, double free
 *                   and redzone (buffer overflow) detection.
 *
 * ---------------------------------------------------------------------------
 * [why it works]
 *
 *   The allocator itself is the witness.  Three distinct mistakes leave
 *   three distinct traces in memory that a periodic scanner can observe:
 *
 *   1. DOUBLE FREE
 *      Freeing the same address twice without an allocation in between is
 *      never legitimate.  Because our free hook runs synchronously, the
 *      second call finds the address already sitting in the quarantine and
 *      can name the exact interval between the two frees.
 *
 *   2. USE-AFTER-FREE (write)
 *      Right after free() we snapshot a slice of the chunk.  If nobody
 *      touches it again the slice is still identical at the next scan.  If
 *      the program (or an attacker using a stale pointer) writes into the
 *      freed chunk, the bytes differ - and the chunk was never reallocated,
 *      because a reallocation would have evicted it from the quarantine.
 *      The snapshot deliberately starts 16 bytes in: that is where glibc's
 *      tcache stores its next-pointer and key, so allocator bookkeeping is
 *      never mistaken for application activity.
 *
 *   3. OVERFLOW (redzone)
 *      A redzone is a canary region the caller owns immediately after a
 *      block.  Any write past the end of the block lands in the canary and
 *      changes its fill byte.  Scanning the canary therefore turns an
 *      out-of-bounds write into a named alert with an exact offset.
 *      (The optional LD_PRELOAD shim builds these canaries automatically
 *      around every malloc - see src/linux/preload_shim.c.)
 *
 * [how to do it]
 *   heap_on_free()   -> quarantine insert + content snapshot   (sync)
 *   heap_on_alloc()  -> quarantine evict on address reuse      (sync)
 *   scan_heap()      -> byte-compare every snapshot, verify every redzone
 *   The detector keeps its own bounded tables so the live BlockTable stays
 *   purely "currently allocated" and the summary counts stay meaningful.
 * ---------------------------------------------------------------------------
 */
#include "detector_heap.h"

#include <string.h>

/* ---- tuning ------------------------------------------------------------- */

#define Q_CAPACITY    1024u      /* quarantine slots, power of two          */
#define Q_SNAP_MAX    64u        /* bytes snapshotted per freed chunk       */
#define Q_SNAP_HEAD   16u        /* skip allocator metadata at the head     */
#define RZ_CAPACITY   64u        /* registered redzones, power of two       */
#define RZ_READ_MAX   256u       /* bytes verified per redzone per scan     */

/* Slot states come from block_table.h: BT_EMPTY / BT_LIVE / BT_TOMBSTONE. */

/* ---- quarantine --------------------------------------------------------- */

typedef struct q_entry {
    uint64_t ptr;                /* hash key                               */
    uint64_t size;
    uint64_t free_time_ns;       /* 0 = slot not holding a freed chunk     */
    uint32_t snap_off;           /* snapshot starts at ptr + snap_off      */
    uint32_t snap_len;           /* 0 = snapshot unavailable               */
    uint32_t alerted;            /* UAF already reported for this entry    */
    uint32_t state;              /* BT_*                                   */
    uint8_t  snap[Q_SNAP_MAX];   /* content captured immediately after free*/
} q_entry;

/* ---- redzone ------------------------------------------------------------ */

typedef struct rz_entry {
    uint64_t block_ptr;          /* owning block (BlockTable key)          */
    uint64_t rz_ptr;             /* hash key                               */
    uint64_t rz_size;
    uint8_t  fill;               /* expected byte value everywhere         */
    uint8_t  alerted;            /* overrun already reported               */
    uint32_t state;              /* BT_*                                   */
} rz_entry;

static q_entry  g_q[Q_CAPACITY];
static rz_entry g_rz[RZ_CAPACITY];

/* Cumulative counters - survive across cycles so one finding is never
 * reported twice just because the scan repeats. */
static unsigned g_stat_uaf;
static unsigned g_stat_dfree;
static unsigned g_stat_ovf;
static unsigned g_stat_reuse;

/* murmur3 fmix64 - same finaliser as block_table.c, so pointer keys are
 * spread evenly even though heap addresses share their low bits. */
static uint64_t hash_ptr(uint64_t p)
{
    p ^= p >> 33;
    p *= 0xff51afd7ed558ccdULL;
    p ^= p >> 33;
    p *= 0xc4ceb9fe1a85ec53ULL;
    p ^= p >> 33;
    return p;
}

/* Open-addressing lookup with tombstone recycling.
 * create = 0 -> return NULL when the key is absent (never inserts)
 * create = 1 -> insert a fresh zeroed entry when the key is absent        */
static q_entry *q_find(uint64_t ptr, int create)
{
    uint32_t idx = (uint32_t)hash_ptr(ptr) & (Q_CAPACITY - 1u);
    uint32_t steps;
    int32_t  tomb = -1;

    for (steps = 0; steps < Q_CAPACITY; steps++) {
        q_entry *e = &g_q[idx];

        if (e->state == BT_EMPTY) {
            if (!create)
                return NULL;
            /* Reuse the first tombstone seen so probe chains stay short. */
            if (tomb >= 0)
                e = &g_q[(uint32_t)tomb];
            memset(e, 0, sizeof(*e));
            e->ptr   = ptr;
            e->state = BT_LIVE;
            return e;
        }
        if (e->state == BT_TOMBSTONE) {
            if (tomb < 0)
                tomb = (int32_t)idx;
        } else if (e->ptr == ptr) {
            return e;
        }
        idx = (idx + 1u) & (Q_CAPACITY - 1u);
    }
    return NULL;                          /* table full - give up quietly  */
}

static rz_entry *rz_find(uint64_t rz_ptr, int create)
{
    uint32_t idx = (uint32_t)hash_ptr(rz_ptr ^ 0x9E3779B97F4A7C15ULL) &
                   (RZ_CAPACITY - 1u);
    uint32_t steps;
    int32_t  tomb = -1;

    for (steps = 0; steps < RZ_CAPACITY; steps++) {
        rz_entry *e = &g_rz[idx];

        if (e->state == BT_EMPTY) {
            if (!create)
                return NULL;
            if (tomb >= 0)
                e = &g_rz[(uint32_t)tomb];
            memset(e, 0, sizeof(*e));
            e->rz_ptr = rz_ptr;
            e->state  = BT_LIVE;
            return e;
        }
        if (e->state == BT_TOMBSTONE) {
            if (tomb < 0)
                tomb = (int32_t)idx;
        } else if (e->rz_ptr == rz_ptr) {
            return e;
        }
        idx = (idx + 1u) & (RZ_CAPACITY - 1u);
    }
    return NULL;
}

/* =========================================================================
 * Synchronous hooks (called by the platform front ends)
 * ====================================================================== */

void heap_on_free(const PlatformOps *ops, Logger *log,
                  uint64_t ptr, uint64_t size)
{
    q_entry *e;

    if (!ptr)
        return;

    e = q_find(ptr, 1);
    if (!e)
        return;                           /* quarantine full - cannot track */

    if (e->free_time_ns != 0) {
        /* Still quarantined: nothing reallocated it, so this is the same
         * pointer being released a second time. */
        g_stat_dfree++;
        if (log)
            log_event(log, ETYPE_DOUBLE_FREE,
                      "*** double free: 0x%016llx (size=%llu) was already "
                      "freed %.3f ms ago ***",
                      (unsigned long long)ptr,
                      (unsigned long long)size,
                      ops ? (double)(ops->now_ns() - e->free_time_ns) / 1e6
                          : 0.0);
        return;
    }

    /* ---- first free of this address: take the evidence --------------- */
    e->size        = size;
    e->free_time_ns = ops ? ops->now_ns() : 0;
    e->alerted     = 0;

    e->snap_off = (size > Q_SNAP_HEAD) ? Q_SNAP_HEAD : 0u;
    e->snap_len = (size > (uint64_t)e->snap_off)
                  ? (uint32_t)(size - e->snap_off) : 0u;
    if (e->snap_len > Q_SNAP_MAX)
        e->snap_len = Q_SNAP_MAX;

    /* The chunk is still allocated here, so the read must succeed unless
     * the pointer was bogus to begin with.  Failure just means "no
     * snapshot", not an error. */
    if (e->snap_len &&
        (!ops || !ops->read_safe(ptr + e->snap_off, e->snap, e->snap_len)))
        e->snap_len = 0;
}

void heap_on_alloc(uint64_t ptr)
{
    q_entry *e;

    if (!ptr)
        return;

    e = q_find(ptr, 0);
    if (e && e->free_time_ns) {
        /* The address was recycled by a fresh allocation: everything we
         * knew about the previous occupant is now irrelevant. */
        e->free_time_ns = 0;
        e->snap_len     = 0;
        e->alerted      = 0;
        e->state        = BT_TOMBSTONE;
        g_stat_reuse++;
    }
}

void heap_add_redzone(uint64_t block_ptr, uint64_t rz_ptr,
                      uint64_t rz_size, uint8_t fill)
{
    rz_entry *r;

    if (!rz_ptr || rz_size == 0)
        return;

    r = rz_find(rz_ptr, 1);
    if (!r)
        return;

    r->block_ptr = block_ptr;
    r->rz_size   = rz_size;
    r->fill      = fill;
    r->alerted   = 0;
}

void heap_reset(void)
{
    memset(g_q,  0, sizeof(g_q));
    memset(g_rz, 0, sizeof(g_rz));
    g_stat_uaf    = 0;
    g_stat_dfree  = 0;
    g_stat_ovf    = 0;
    g_stat_reuse  = 0;
}

/* =========================================================================
 * Event-driven fallback
 * ------------------------------------------------------------------------
 * An ALLOC event observed during the ring drain proves the address was
 * handed out again - but ONLY when the event is newer than the free.  The
 * allocation that came *before* the free is still in the ring too, and
 * letting that one evict the quarantine would wipe the UAF evidence for
 * every block that is freed inside the same recording window.
 * ====================================================================== */

void scan_heap_on_event(ScanContext *ctx, const TraceEvent *ev)
{
    q_entry *e;

    if (!ctx || !ev || ev->type != ETYPE_ALLOC)
        return;

    e = q_find(ev->ptr, 0);
    if (e && e->free_time_ns && ev->timestamp_ns > e->free_time_ns)
        heap_on_alloc(ev->ptr);
}

static void add_tag(BlockRecord *b, const char *tag)
{
    if (b->tag[0])
        strncat(b->tag, ",", sizeof(b->tag) - strlen(b->tag) - 1);
    strncat(b->tag, tag, sizeof(b->tag) - strlen(b->tag) - 1);
    b->flags |= BLK_SUSPICIOUS;
}

/* =========================================================================
 * The scan
 * ====================================================================== */

void scan_heap(ScanContext *ctx)
{
    uint8_t cur[Q_SNAP_MAX];
    uint8_t rzbuf[RZ_READ_MAX];
    uint32_t i;
    int quarantined = 0, uaf = 0, overflow = 0;

    if (!ctx)
        return;

    /* ---- 1. use-after-free: did anything write into a freed chunk? --- */
    for (i = 0; i < Q_CAPACITY; i++) {
        q_entry *e = &g_q[i];
        uint32_t k;

        if (e->state != BT_LIVE || e->free_time_ns == 0)
            continue;
        quarantined++;

        if (e->alerted || e->snap_len == 0)
            continue;

        /* The chunk may have been munmap()'d (large allocations) - then we
         * simply have nothing to compare and stay silent. */
        if (!ctx->ops->read_safe(e->ptr + e->snap_off, cur, e->snap_len))
            continue;

        if (memcmp(cur, e->snap, e->snap_len) == 0)
            continue;

        for (k = 0; k < e->snap_len; k++) {
            if (cur[k] != e->snap[k])
                break;
        }

        e->alerted = 1;
        g_stat_uaf++;
        uaf++;

        log_event(ctx->log, ETYPE_UAF,
                  "*** use-after-free write: 0x%016llx size=%llu "
                  "offset+%u expected=0x%02X got=0x%02X "
                  "(freed %.3f ms before this scan, never reallocated) ***",
                  (unsigned long long)e->ptr,
                  (unsigned long long)e->size,
                  (unsigned)(e->snap_off + k),
                  (unsigned)e->snap[k],
                  (unsigned)cur[k],
                  (double)(ctx->ops->now_ns() - e->free_time_ns) / 1e6);
    }

    /* ---- 2. redzone: did anything write past a block? ---------------- */
    for (i = 0; i < RZ_CAPACITY; i++) {
        rz_entry *r = &g_rz[i];
        BlockRecord *b;
        size_t n, k;

        if (r->state != BT_LIVE || r->alerted)
            continue;

        n = r->rz_size < RZ_READ_MAX ? (size_t)r->rz_size : RZ_READ_MAX;
        if (n == 0)
            continue;
        if (!ctx->ops->read_safe(r->rz_ptr, rzbuf, n))
            continue;                     /* owner freed - nothing to check */

        for (k = 0; k < n; k++) {
            if (rzbuf[k] != r->fill)
                break;
        }
        if (k == n)
            continue;                     /* canary intact                */

        r->alerted = 1;
        g_stat_ovf++;
        overflow++;

        b = bt_find(ctx->blocks, r->block_ptr);
        if (b) {
            b->hit_mask |= HIT_OVERFLOW;
            if ((b->hit_mask & HIT_OVERFLOW) && b->tag[0] == '\0')
                add_tag(b, "OVERFLOW");
            else if (!strstr(b->tag, "OVERFLOW"))
                add_tag(b, "OVERFLOW");
        }

        log_event(ctx->log, ETYPE_OVERFLOW,
                  "*** redzone overrun: block 0x%016llx redzone 0x%016llx "
                  "size=%llu offset=%llu expected=0x%02X got=0x%02X "
                  "(buffer overflow past the end of the block) ***",
                  (unsigned long long)r->block_ptr,
                  (unsigned long long)r->rz_ptr,
                  (unsigned long long)r->rz_size,
                  (unsigned long long)k,
                  (unsigned)r->fill,
                  (unsigned)rzbuf[k]);
    }

    /* ---- 3. one summary line per cycle -------------------------------- */
    log_event_sev(ctx->log, ETYPE_STATS, SEV_DEBUG,
                  "heap scan: quarantined=%d this-cycle uaf=%d overflow=%d "
                  "cumulative uaf=%u double-free=%u overflow=%u "
                  "reuse=%u redzones=%u",
                  quarantined, uaf, overflow,
                  g_stat_uaf, g_stat_dfree, g_stat_ovf,
                  g_stat_reuse, (unsigned)RZ_CAPACITY);
}
