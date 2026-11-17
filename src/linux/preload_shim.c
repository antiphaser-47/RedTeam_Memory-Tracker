/*
 * preload_shim.c - optional LD_PRELOAD heap guard (deliverable #4).
 *
 * ---------------------------------------------------------------------------
 * WHAT IT IS
 *   A drop-in shared object that makes ANY Linux program's heap self-checking:
 *
 *       LD_PRELOAD=./libtracker_preload.so ./target_program
 *
 *   It interposes malloc/calloc/realloc/free and wraps every allocation with
 *   a bookkeeping header in front and a redzone canary behind it.  When the
 *   program releases the block the canaries are verified, which turns the two
 *   most common heap mistakes into named alerts with an exact offset:
 *
 *       [OVERFLOW]   a write past the end of the block (or before its start)
 *       [DOUBLE_FREE]the same pointer released twice
 *
 *   This is the mechanism the main tracker's heap detector describes in
 *   src/core/detector_heap.c - here it is wired into an allocator that any
 *   third-party binary can be started with, without recompiling it.
 *
 * ---------------------------------------------------------------------------
 * WHY IT CAN BE USED ON ARBITRARY PROGRAMS
 *   Everything it needs at run time is resolved through dlsym(RTLD_NEXT, ...),
 *   so it never calls itself recursively.  Internal bookkeeping uses a
 *   statically allocated table plus a bootstrap bump allocator, because the
 *   very first malloc() can happen before the constructor has run.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT DELIBERATELY DOES NOT DO
 *   - no use-after-free scan: once free() returns the bytes to the allocator
 *     there is nothing left to compare, and holding on to every freed block
 *     would defeat the allocator's purpose.  UAF detection stays in the main
 *     tracker (which snapshots the chunk before releasing it).
 *   - no interposition of mmap/mprotect: those belong to the RWX detector in
 *     the main tracker, which observes them through /proc/self/maps.
 *
 * ---------------------------------------------------------------------------
 * USAGE
 *   TRACKER_SHIM_LOG=/tmp/shim.log   also append to a log file
 *   TRACKER_SHIM_QUIET=1             suppress the console output
 *   TRACKER_SHIM_TABLE=N             hash table entries (default 65536)
 * ---------------------------------------------------------------------------
 */
#define _GNU_SOURCE

#include "logger.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* =========================================================================
 * Tunables
 * ====================================================================== */

#define HDR_SIZE        32u     /* bookkeeping header before the payload    */
#define BACK_CANARY     16u     /* canary bytes after the payload           */
#define DEFAULT_TABLE   65536u  /* tracked-pointer slots (power of two)     */

#define MAGIC_LIVE      0x5348494D4C495645ULL   /* "SHIMLIVE"             */
#define MAGIC_DEAD      0x5348494D44454144ULL   /* "SHIMDEAD"             */

/* Slot states - same vocabulary as block_table.h. */
#define SLOT_EMPTY      0u
#define SLOT_LIVE       1u
#define SLOT_FREED      2u

typedef struct shim_hdr {
    uint64_t magic;            /* MAGIC_LIVE while the block is allocated  */
    uint64_t size;             /* payload size requested by the program    */
    uint64_t canary_seed;      /* derives the expected redzone byte        */
    uint64_t reserved;
} shim_hdr;

typedef struct slot {
    uint64_t ptr;              /* payload pointer (= header + HDR_SIZE)    */
    uint64_t size;
    uint8_t  fill;             /* expected redzone byte                    */
    uint8_t  state;            /* SLOT_*                                  */
    uint8_t  pad[6];
} slot;

/* =========================================================================
 * State
 * ====================================================================== */

static slot *volatile        g_table = NULL;
static uint32_t              g_mask  = 0;

static Logger                g_log;
static int                   g_log_ready = 0;
static int                   g_console   = 1;

/* Reentrancy guard: anything that happens while we are inside one of our
 * own hooks must go straight to the real allocator, otherwise fopen() /
 * printf() / dlsym() inside the logger would call back into us. */
static __thread int          g_inside = 0;

static atomic_flag           g_lock = ATOMIC_FLAG_INIT;

/* Real allocator entry points, filled in by the constructor. */
static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*realloc_fn)(void *, size_t);
static void  (*real_free)(void *);

/* Bootstrap bump allocator for the window before dlsym() is usable. */
#define BOOT_SIZE (1u << 20)
static unsigned char         g_boot[BOOT_SIZE];
static size_t                g_boot_used = 0;

static void lock_raw(void)
{
    while (atomic_flag_test_and_set_explicit(&g_lock, memory_order_acquire))
        ;                                   /* spin: never sleeps, never
                                             * allocates, never recurses */
}

static void unlock_raw(void)
{
    atomic_flag_clear_explicit(&g_lock, memory_order_release);
}

static void *boot_alloc(size_t n)
{
    void *p;

    n = (n + 15u) & ~(size_t)15u;
    if (g_boot_used + n > BOOT_SIZE)
        return NULL;                        /* exhausted: caller falls back */
    p = g_boot + g_boot_used;
    g_boot_used += n;
    return p;
}

static int in_boot(const void *p)
{
    return p >= (const void *)g_boot &&
           p < (const void *)(g_boot + BOOT_SIZE);
}

/* =========================================================================
 * Symbol resolution
 * ====================================================================== */

static int g_resolving = 0;

static void resolve_real(void)
{
    if (g_resolving)
        return;
    g_resolving = 1;

    if (!real_malloc)  real_malloc  = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
    if (!real_calloc)  real_calloc  = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
    if (!realloc_fn)   realloc_fn   = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
    if (!real_free)    real_free    = (void (*)(void *))dlsym(RTLD_NEXT, "free");

    g_resolving = 0;
}

/* =========================================================================
 * Logging
 * ====================================================================== */

static void shim_log(EventType type, const char *fmt, ...)
{
    va_list args;

    if (!g_log_ready)
        return;

    va_start(args, fmt);
    /* logger.c exposes only the printf-style wrappers; format here, then
     * emit through log_event so the line gets the usual timestamp/tag. */
    {
        char buf[512];

        vsnprintf(buf, sizeof(buf), fmt, args);
        log_event(&g_log, type, "%s", buf);
    }
    va_end(args);
}

/* =========================================================================
 * Pointer table (open addressing, linear probing, no allocation)
 * ====================================================================== */

static uint64_t hash_ptr(uint64_t p)
{
    p ^= p >> 33;
    p *= 0xff51afd7ed558ccdULL;
    p ^= p >> 33;
    p *= 0xc4ceb9fe1a85ec53ULL;
    p ^= p >> 33;
    return p;
}

/* mode 0 = lookup only, mode 1 = insert-or-update as LIVE.
 * Returns the slot or NULL. */
static slot *table_find(uint64_t ptr, int insert)
{
    uint32_t idx;
    uint32_t steps;
    int32_t  tomb = -1;

    if (!g_table)
        return NULL;

    idx = (uint32_t)hash_ptr(ptr) & g_mask;

    for (steps = 0; steps <= g_mask; steps++) {
        slot *s = &g_table[idx];

        if (s->state == SLOT_EMPTY) {
            if (!insert)
                return NULL;
            if (tomb >= 0)
                s = &g_table[(uint32_t)tomb];
            s->ptr   = ptr;
            s->size  = 0;
            s->fill  = 0;
            s->state = SLOT_LIVE;
            return s;
        }

        /* Key match wins over the state test: a FREED slot must still be
         * findable by its own address, otherwise a second free() of the
         * same pointer would not be recognised as ours and would be handed
         * straight to the allocator (exactly the crash we exist to stop).
         * Only FREED slots with a DIFFERENT key act as tombstones. */
        if (s->ptr == ptr)
            return s;

        if (s->state == SLOT_FREED) {
            if (tomb < 0)
                tomb = (int32_t)idx;
        }
        idx = (idx + 1u) & g_mask;
    }
    return NULL;                            /* table full */
}

/* =========================================================================
 * Core wrapper used by every allocation entry point
 * ====================================================================== */

static void *shim_alloc(size_t payload, void *base)
{
    shim_hdr *h = (shim_hdr *)base;
    uint8_t  *redzone;
    uint64_t  seed;
    void     *user;

    seed = (uint64_t)(uintptr_t)base ^ 0x9E3779B97F4A7C15ULL;

    h->magic       = MAGIC_LIVE;
    h->size        = payload;
    h->canary_seed = seed;
    h->reserved    = 0;

    user = (unsigned char *)base + HDR_SIZE;

    /* Redzone immediately after the payload: this is the byte that an
     * off-by-one (or worse) write will hit first. */
    redzone = (uint8_t *)user + payload;
    memset(redzone, (int)(0xA5u ^ (seed & 0xFFu)), BACK_CANARY);

    lock_raw();
    {
        slot *s = table_find((uint64_t)(uintptr_t)user, 1);

        if (s) {
            s->size  = payload;
            s->fill  = (uint8_t)(0xA5u ^ (seed & 0xFFu));
            s->state = SLOT_LIVE;
        }
    }
    unlock_raw();

    return user;
}

static void *shim_malloc(size_t n)
{
    void *base;
    int prev;

    if (!real_malloc) {
        resolve_real();
        if (!real_malloc)
            return boot_alloc(n);
    }

    prev = g_inside;
    g_inside = 1;
    /* HDR_SIZE + payload + BACK_CANARY. */
    base = real_malloc(HDR_SIZE + n + BACK_CANARY);
    g_inside = prev;                        /* restore, do not clear: this
                                             * hook may be nested inside an
                                             * outer one (logger -> malloc) */

    if (!base)
        return NULL;

    return shim_alloc(n, base);
}

/* =========================================================================
 * Public interposers
 * ====================================================================== */

void *malloc(size_t n)
{
    if (!real_malloc) {
        resolve_real();
        if (!real_malloc) {
            void *p = boot_alloc(n);
            if (p)
                return p;
            resolve_real();
            if (!real_malloc)
                return NULL;
        }
    }
    return shim_malloc(n);
}

void *calloc(size_t nmemb, size_t size)
{
    size_t total;
    void  *p;

    if (nmemb && size > (size_t)-1 / nmemb)
        return NULL;                        /* overflow: same as glibc */

    total = nmemb * size;

    if (!real_calloc) {
        resolve_real();
        if (!real_calloc) {
            /* Bootstrap path: bump allocator + manual zeroing. */
            p = boot_alloc(total ? total : 1);
            if (p)
                memset(p, 0, total ? total : 1);
            return p;
        }
    }

    {
        /* calloc has no wrapper of its own: ask the real allocator for the
         * enlarged block, zero everything, then stamp our bookkeeping. */
        int prev = g_inside;
        size_t want = HDR_SIZE + total + BACK_CANARY;
        void  *base;

        g_inside = 1;
        base = real_calloc(1, want);
        g_inside = prev;

        if (!base)
            return NULL;

        p = shim_alloc(total, base);
        memset(p, 0, total);
        return p;
    }
}

void *realloc(void *ptr, size_t n)
{
    void *fresh;
    size_t old = 0;
    const void *old_user = ptr;

    if (!ptr)
        return malloc(n);
    if (n == 0) {
        free(ptr);
        return NULL;
    }

    if (in_boot(ptr)) {
        /* Bootstrap blocks cannot be moved; copy into a real allocation. */
        fresh = malloc(n);
        if (fresh)
            memcpy(fresh, ptr, n < BOOT_SIZE ? n : BOOT_SIZE);
        return fresh;
    }

    if (!realloc_fn) {
        resolve_real();
        if (!realloc_fn)
            return NULL;
    }

    /* Ask the table (authoritative) how big the payload was, then copy the
     * smaller of the two sizes. */
    lock_raw();
    {
        slot *s = table_find((uint64_t)(uintptr_t)ptr, 0);

        if (s && s->state == SLOT_LIVE)
            old = s->size;
    }
    unlock_raw();

    if (old && old > n)
        old = n;

    fresh = malloc(n);                      /* goes through our wrapper so
                                             * the new block gets a header */
    if (!fresh)
        return NULL;

    if (old)
        memcpy(fresh, ptr, old);

    free(ptr);
    (void)old_user;
    return fresh;
}

void free(void *ptr)
{
    shim_hdr *h;
    uint8_t  *redzone;
    size_t    i;
    slot     *s;
    int       ours = 0;

    if (!ptr)
        return;

    if (in_boot(ptr))
        return;                             /* bootstrap memory is static */

    if (g_inside || !real_free) {
        if (!real_free)
            resolve_real();
        if (!real_free)
            return;
    }

    /* Look the pointer up BEFORE touching the header: a pointer that we did
     * not allocate (foreign allocator, or an allocation made before the
     * shim was loaded) must be handed straight to the real free(). */
    lock_raw();
    s = table_find((uint64_t)(uintptr_t)ptr, 0);
    if (s && s->state != SLOT_EMPTY)
        ours = (s->ptr == (uint64_t)(uintptr_t)ptr);
    unlock_raw();

    if (!ours) {
        int prev = g_inside;

        g_inside = 1;
        real_free(ptr);
        g_inside = prev;
        return;
    }

    /* ---- double free ------------------------------------------------- */
    if (s->state == SLOT_FREED) {
        shim_log(ETYPE_DOUBLE_FREE,
                 "*** double free (LD_PRELOAD shim): 0x%016llx was already "
                 "freed, block size=%llu ***",
                 (unsigned long long)ptr, (unsigned long long)s->size);
        return;                             /* do not hand it back twice */
    }

    h = (shim_hdr *)((unsigned char *)ptr - HDR_SIZE);

    /* ---- header integrity (a backwards write lands here first) -------- */
    if (h->magic != MAGIC_LIVE) {
        shim_log(ETYPE_OVERFLOW,
                 "*** heap header corrupted (LD_PRELOAD shim): 0x%016llx "
                 "magic=0x%016llx (buffer underflow or allocator reuse) ***",
                 (unsigned long long)ptr, (unsigned long long)h->magic);
    }

    /* ---- redzone (a forwards write lands here first) ------------------ */
    redzone = (uint8_t *)ptr + s->size;
    for (i = 0; i < BACK_CANARY; i++) {
        if (redzone[i] != s->fill) {
            shim_log(ETYPE_OVERFLOW,
                     "*** redzone overrun (LD_PRELOAD shim): block 0x%016llx "
                     "size=%llu offset=%llu expected=0x%02X got=0x%02X "
                     "(buffer overflow past the end of the block) ***",
                     (unsigned long long)ptr,
                     (unsigned long long)s->size,
                     (unsigned long long)i,
                     (unsigned)s->fill, (unsigned)redzone[i]);
            break;
        }
    }

    /* ---- retire the slot --------------------------------------------- */
    h->magic = MAGIC_DEAD;                  /* poison: a later write into a
                                             * dead header is detectable */
    lock_raw();
    s->state = SLOT_FREED;
    unlock_raw();

    {
        int prev = g_inside;

        g_inside = 1;
        real_free((unsigned char *)ptr - HDR_SIZE);
        g_inside = prev;
    }
}

/* =========================================================================
 * Construction / teardown
 * ====================================================================== */

static void __attribute__((constructor)) shim_init(void)
{
    const char *log_path;
    const char *quiet;
    const char *tbl;
    size_t      want = DEFAULT_TABLE;

    resolve_real();
    if (!real_malloc || !real_free)
        return;                             /* cannot hook: stay inert */

    quiet = getenv("TRACKER_SHIM_QUIET");
    g_console = (quiet && *quiet == '1') ? 0 : 1;

    tbl = getenv("TRACKER_SHIM_TABLE");
    if (tbl) {
        unsigned long v = strtoul(tbl, NULL, 10);

        if (v >= 1024u && v <= (1u << 22))
            want = v;
    }
    /* Round up to a power of two for the mask-based probe. */
    {
        size_t p = 1024u;

        while (p < want)
            p <<= 1;
        want = p;
    }

    g_table = (slot *)real_malloc(want * sizeof(slot));
    if (!g_table)
        return;
    memset(g_table, 0, want * sizeof(slot));
    g_mask = (uint32_t)(want - 1u);

    log_path = getenv("TRACKER_SHIM_LOG");
    if (logger_open(&g_log, log_path && *log_path ? log_path : NULL,
                    0) == 0) {
        g_log.echo_console = g_console;
        g_log_ready = 1;
        shim_log(ETYPE_STATS,
                 "LD_PRELOAD heap guard active: table=%u slots, redzone=%u "
                 "bytes, log=%s",
                 (unsigned)want, (unsigned)BACK_CANARY,
                 (log_path && *log_path) ? log_path : "(console only)");
    }
}

static void __attribute__((destructor)) shim_fini(void)
{
    if (g_log_ready) {
        shim_log(ETYPE_STATS, "LD_PRELOAD heap guard stopped");
        logger_close(&g_log);
        g_log_ready = 0;
    }
}
