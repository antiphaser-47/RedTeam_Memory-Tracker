/*
 * main_win.c - Windows user-space front end (deliverable #2: tracker.exe).
 *
 * Responsibilities of this file (everything here is Windows specific):
 *   - argument parsing (identical CLI to tracker_linux)
 *   - wiring logger + ring + block table + detectors + scheduler together
 *   - the allocation tracking helpers used by the self test
 *   - the built-in self-test cases that exercise every detector, ported
 *     from main_linux.c (mprotect -> VirtualProtect, mmap -> VirtualAlloc,
 *     SIGINT -> SetConsoleCtrlHandler)
 *   - lifecycle: start thread, wait for N cycles (or Enter), tear down
 *
 * This binary is produced by `make win` with the MinGW cross toolchain and
 * is NOT executed on the Linux build host; tests/test_win.bat mirrors
 * tests/run_test.sh so the same expectations can be checked on Windows.
 *
 * Usage:
 *   tracker.exe --selftest --cycles 1 --log out.log
 * ---------------------------------------------------------------------------
 */
#define WIN32_LEAN_AND_MEAN
#include "scheduler.h"
#include "detectors.h"
#include "detector_hook.h"
#include "detector_heap.h"

#include <windows.h>
#include <io.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

/* =========================================================================
 * Globals
 * ====================================================================== */

static const PlatformOps *g_ops      = NULL;
static RingBuffer         g_ring;
static BlockTable         g_blocks;
static Logger             g_log;
static Scheduler          g_sched;
static pthread_t          g_thread;
static int                g_thread_started = 0;

/* Blocks allocated by the self test that must be released at exit. */
#define LEAK_MAX 64
typedef struct {
    void    *ptr;
    size_t   size;
    int      is_virt;      /* 1 = VirtualFree, 0 = free() */
} alloc_entry;

static alloc_entry g_allocs[LEAK_MAX];
static int         g_nallocs = 0;

/* =========================================================================
 * Allocation tracking helpers
 * ====================================================================== */

static void remember_alloc(void *p, size_t size, int is_virt)
{
    if (!p || g_nallocs >= LEAK_MAX)
        return;
    g_allocs[g_nallocs].ptr     = p;
    g_allocs[g_nallocs].size    = size;
    g_allocs[g_nallocs].is_virt = is_virt;
    g_nallocs++;
}

/* Record an allocation into the block table and push an ALLOC event. */
static void track_alloc(void *p, size_t size)
{
    BlockRecord *b;
    TraceEvent ev;

    if (!p)
        return;

    b = bt_find(&g_blocks, (uint64_t)(uintptr_t)p);
    if (!b)
        b = bt_insert(&g_blocks, (uint64_t)(uintptr_t)p);
    if (!b)
        return;

    b->ptr           = (uint64_t)(uintptr_t)p;
    b->size          = size;
    b->alloc_time_ns = g_ops->now_ns();
    b->stack_hash    = g_ops->stack_hash();
    b->perms         = (uint32_t)g_ops->get_perms((uint64_t)(uintptr_t)p);
    b->entropy       = 0.0;
    b->hit_mask      = 0;
    b->gadget_count  = 0;
    b->tag[0]        = '\0';
    b->flags         = BLK_ACTIVE;

    memset(&ev, 0, sizeof(ev));
    ev.type       = ETYPE_ALLOC;
    ev.ptr        = (uint64_t)(uintptr_t)p;
    ev.size       = size;
    ev.aux        = (int32_t)b->perms;
    ev.caller_ip  = g_ops->caller_ip();
    ev.stack_hash = b->stack_hash;

    /* Tell the heap detector first: if this address happens to sit in its
     * quarantine it must be evicted before anyone can mistake the old
     * evidence for a fresh finding. */
    heap_on_alloc((uint64_t)(uintptr_t)p);

    scheduler_record(&g_sched, &ev);
}

/* Record a free, compute the lifetime, then drop the block from the table. */
static void track_free(void *p)
{
    BlockRecord *b;
    TraceEvent ev;
    uint64_t lifetime_ms = 0;
    uint64_t size = 0;

    if (!p)
        return;

    b = bt_find(&g_blocks, (uint64_t)(uintptr_t)p);
    if (b) {
        size = b->size;
        if (b->alloc_time_ns)
            lifetime_ms = (g_ops->now_ns() - b->alloc_time_ns) / 1000000ULL;
    }

    memset(&ev, 0, sizeof(ev));
    ev.type = ETYPE_FREE;
    ev.ptr  = (uint64_t)(uintptr_t)p;
    ev.size = size;
    ev.aux  = (int32_t)lifetime_ms;   /* aux carries the lifetime in ms */
    ev.caller_ip  = g_ops->caller_ip();
    ev.stack_hash = b ? b->stack_hash : 0;

    scheduler_record(&g_sched, &ev);

    /* Hand the block over to the heap detector BEFORE the underlying
     * allocator releases the chunk: the content snapshot has to be taken
     * while the bytes are still ours, and a second call for the same
     * address is what a double free looks like from here. */
    heap_on_free(g_ops, &g_log, (uint64_t)(uintptr_t)p, size);

    if (b)
        bt_remove(&g_blocks, (uint64_t)(uintptr_t)p);
}

/* Track + allocate via malloc(). */
static void *tmalloc(size_t size)
{
    void *p = malloc(size);

    if (p)
        track_alloc(p, size);
    return p;
}

/* Free a tracked malloc() block. */
static void tfree(void *p)
{
    if (!p)
        return;
    track_free(p);
    free(p);
}

/* =========================================================================
 * Self-test cases
 * ------------------------------------------------------------------------
 * Every case creates a situation that one specific detector must notice.
 * The results are asserted by tests/test_win.bat (grep/findstr on the log
 * tags) - the same expectations as tests/run_test.sh on Linux.
 * ====================================================================== */

/* Deterministic PRNG (xorshift64*) so the test log is reproducible. */
static uint64_t g_prng = 0x9E3779B97F4A7C15ULL;
static uint32_t prng_next(void)
{
    g_prng ^= g_prng >> 12;
    g_prng ^= g_prng << 25;
    g_prng ^= g_prng >> 27;
    return (uint32_t)((g_prng * 0x2545F4914F6CDD1DULL) >> 32);
}

/*
 * Case 1: benign low-entropy block.  Baseline: must be recorded but must NOT
 * produce any alert.
 */
static void case_normal_block(void)
{
    void *p = tmalloc(1024);

    if (!p) {
        log_event(&g_log, ETYPE_ERROR, "case_normal_block: malloc failed");
        return;
    }
    memset(p, 0x41, 1024);
    log_event(&g_log, ETYPE_ALLOC, "case1: normal 1 KiB block of 0x41 @ %p", p);
}

/*
 * Case 2: high-entropy block.  Uniform random bytes -> H ~= 8.0 > 7.5.
 * Stands in for an encrypted / packed payload staged on the heap.
 */
static void case_high_entropy(void)
{
    unsigned char *p = tmalloc(2048);
    int i;

    if (!p) {
        log_event(&g_log, ETYPE_ERROR, "case_high_entropy: malloc failed");
        return;
    }
    for (i = 0; i < 2048; i++)
        p[i] = (unsigned char)(prng_next() & 0xFF);

    log_event(&g_log, ETYPE_ALLOC,
              "case2: 2 KiB of random bytes @ %p (expect HIGH_ENTROPY)", p);
}

/*
 * Case 3: NOP sled.  512 consecutive 0x90 bytes is far past the 16-byte
 * threshold - the classic shellcode landing pad.
 */
static void case_nop_sled(void)
{
    unsigned char *p = tmalloc(512);

    if (!p) {
        log_event(&g_log, ETYPE_ERROR, "case_nop_sled: malloc failed");
        return;
    }
    memset(p, 0x90, 512);
    log_event(&g_log, ETYPE_ALLOC,
              "case3: 512-byte NOP sled @ %p (expect NOP_SLED)", p);
}

/*
 * Case 4: RWX region containing gadget-like bytes.  This is the signature of
 * shellcode staging: a page that is simultaneously writable and executable.
 */
static void case_rwx(void)
{
    unsigned char *p = g_ops->alloc_rwx(4096);

    if (!p) {
        log_event(&g_log, ETYPE_ERROR,
                  "case_rwx: RWX allocation refused (W^X policy?)");
        return;
    }

    memset(p, 0x00, 4096);
    /* pop rax; ret   -> 58 C3
     * pop rdi; ret   -> 5F C3        (at offset 100) */
    p[0]   = 0x58;
    p[1]   = 0xC3;
    p[100] = 0x5F;
    p[101] = 0xC3;

    remember_alloc(p, 4096, 1);
    track_alloc(p, 4096);

    log_event(&g_log, ETYPE_ALLOC,
              "case4: RWX page @ %p (expect RWX alert)", p);
}

/*
 * Case 5: non-printable blob in a data (non-executable) block.  0x01..0x1f
 * gives entropy ~4.9 (below the encryption threshold) but a 0% printable
 * ratio, which is what LOW_PRINTABLE is for.
 */
static void case_low_printable(void)
{
    unsigned char *p = tmalloc(256);
    int i;

    if (!p) {
        log_event(&g_log, ETYPE_ERROR, "case_low_printable: malloc failed");
        return;
    }
    for (i = 0; i < 256; i++)
        p[i] = (unsigned char)((i % 31) + 1);   /* 0x01 .. 0x1F */

    log_event(&g_log, ETYPE_ALLOC,
              "case5: control-byte block @ %p (expect LOW_PRINTABLE)", p);
}

/*
 * Case 6: genuine inline hook.
 *
 * We patch the first five bytes of our *own* function with `E9 rel32`,
 * which is byte-for-byte what an API hooker does to a DLL export, then
 * restore the original page permissions.  The function is never called
 * afterwards, so the process stays healthy while the hook detector has a
 * real, unmodified-by-test-double target to find.
 *
 * On Windows the .text page is read+execute, so VirtualProtect() is used
 * to make it writable - the exact call every inline hooker has to make.
 */
static int victim_dummy = 0;

__attribute__((noinline, used))
static int victim_function(int x)
{
    /* Deliberately non-trivial so the body is comfortably longer than the
     * five bytes we are about to overwrite. */
    int i, acc = x;

    for (i = 0; i < 8; i++) {
        acc = acc * 3 + i;
        victim_dummy += (acc & 1);
    }
    return acc;
}

static void case_inline_hook(void)
{
    unsigned char *fn = (unsigned char *)(uintptr_t)victim_function;
    DWORD old_prot = 0, tmp = 0;
    int32_t rel;
    unsigned char orig[5];

    if (!VirtualProtect((void *)fn, 4096, PAGE_EXECUTE_READWRITE, &old_prot)) {
        log_event(&g_log, ETYPE_ERROR,
                  "case_inline_hook: VirtualProtect(RWX) failed: %lu",
                  (unsigned long)GetLastError());
        return;
    }

    memcpy(orig, fn, 5);

    /* E9 rel32 : jmp rel32, target = &fn[5] + rel  (classic 5-byte hook).
     * rel = 0 makes the jump land on the instruction immediately after the
     * patch, so the tampered function stays harmless if anything did call
     * it - we only need the byte pattern to be real. */
    rel = 0;
    fn[0] = 0xE9;
    memcpy(fn + 1, &rel, 4);

    /* Restore the original page protections: the hook must survive in an
     * RX page, exactly like a real patched export. */
    VirtualProtect((void *)fn, 4096, PAGE_EXECUTE_READ, &tmp);

    hook_watch("victim_function", (void *)victim_function);

    log_event(&g_log, ETYPE_ALLOC,
              "case6: patched victim_function[0..4] = %02X %02X %02X %02X %02X "
              "(original %02X %02X %02X %02X %02X), expect HOOK alert",
              fn[0], fn[1], fn[2], fn[3], fn[4],
              orig[0], orig[1], orig[2], orig[3], orig[4]);

    /* Never call victim_function() from here on. */
}

/*
 * Case 7: alloc + free inside the recording window, so a [FREE] line with a
 * measured lifetime lands in the log.
 */
static void case_alloc_free_cycle(void)
{
    void *p = tmalloc(64);

    if (!p) {
        log_event(&g_log, ETYPE_ERROR, "case_alloc_free_cycle: malloc failed");
        return;
    }
    memset(p, 0x5A, 64);
    log_event(&g_log, ETYPE_ALLOC, "case7: short-lived 64-byte block @ %p", p);
    tfree(p);           /* free immediately -> lifetime ~0 ms */
}

/*
 * Case 8: write-then-flip permission transition.
 *   VirtualAlloc(RW) -> write -> VirtualProtect(RX)
 * The block is recorded while RW; by scan time it is RX, which is precisely
 * the "stage code, then make it executable" pattern.
 */
static void case_perm_transition(void)
{
    void *p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE);
    DWORD old_prot = 0;

    if (!p) {
        log_event(&g_log, ETYPE_ERROR,
                  "case_perm_transition: VirtualAlloc failed: %lu",
                  (unsigned long)GetLastError());
        return;
    }

    memset(p, 0xC3, 4096);           /* fill with `ret` bytes */

    remember_alloc(p, 4096, 1);
    track_alloc(p, 4096);            /* recorded with perms = RW */

    if (!VirtualProtect(p, 4096, PAGE_EXECUTE_READ, &old_prot)) {
        log_event(&g_log, ETYPE_ERROR,
                  "case_perm_transition: VirtualProtect(RX) failed: %lu",
                  (unsigned long)GetLastError());
        return;
    }

    log_event(&g_log, ETYPE_ALLOC,
              "case8: page flipped RW -> RX @ %p (expect PERM_CHANGE)", p);
}

/*
 * Case 9: double free.
 *   free(p) -> free(p) again with no allocation in between.
 *
 * Why the second *real* free() is not executed: the CRT heap aborts the
 * process on a genuine second free ("Heap corruption" / debug CRT
 * assertion).  The tracker's whole point is to notice the second release
 * BEFORE the allocator kills the process, so the test drives the tracker's
 * free path (heap_on_free) a second time and leaves the allocator alone.
 * That is exactly the order a detour-based free hook uses: hook first,
 * real free() second.
 */
static void case_double_free(void)
{
    void *p = tmalloc(48);

    if (!p) {
        log_event(&g_log, ETYPE_ERROR, "case_double_free: malloc failed");
        return;
    }
    memset(p, 0x77, 48);
    log_event(&g_log, ETYPE_ALLOC, "case9: 48-byte block staged for double free @ %p", p);

    tfree(p);                        /* first release: quarantined */

    /* Second release of the same address, tracker-side only. */
    heap_on_free(g_ops, &g_log, (uint64_t)(uintptr_t)p, 48);
    log_event(&g_log, ETYPE_FREE,
              "case9: second release of %p (expect DOUBLE_FREE)", p);
}

/*
 * Case 10: use-after-free write.
 *   free(p) -> write through the stale pointer -> scan compares the
 *   snapshot taken at free time with the bytes still sitting there.
 *
 * The write starts at offset 64: the first 16 bytes of a freed heap chunk
 * hold allocator bookkeeping on most allocators, which the snapshot
 * deliberately skips so allocator metadata is never mistaken for program
 * activity.
 */
static void case_use_after_free(void)
{
    unsigned char *p = tmalloc(128);

    if (!p) {
        log_event(&g_log, ETYPE_ERROR, "case_use_after_free: malloc failed");
        return;
    }
    memset(p, 0x5A, 128);
    log_event(&g_log, ETYPE_ALLOC,
              "case10: 128-byte block staged for use-after-free @ %p", p);

    tfree(p);                        /* snapshot taken inside track_free */

    /* Write through the stale pointer (the chunk is still mapped). */
    p[64] = 0xDE;
    p[65] = 0xAD;
    log_event(&g_log, ETYPE_ALLOC,
              "case10: wrote DE AD at offset 64 of freed %p (expect UAF)", p);
}

/*
 * Case 11: buffer overflow caught by a redzone canary.
 *   One 80-byte allocation: the first 64 bytes are the "block", the last 16
 *   are a canary region registered with heap_add_redzone().  Writing two
 *   bytes past the block flips the canary, which the next scan reports as
 *   an OVERFLOW with the exact offset.
 */
static void case_redzone_overflow(void)
{
    uint8_t *buf = tmalloc(64 + 16);

    if (!buf) {
        log_event(&g_log, ETYPE_ERROR, "case_redzone_overflow: malloc failed");
        return;
    }
    memset(buf, 0x42, 64);           /* block content             */
    memset(buf + 64, 0xCC, 16);      /* canary, one byte per slot */

    heap_add_redzone((uint64_t)(uintptr_t)buf,
                     (uint64_t)(uintptr_t)(buf + 64), 16, 0xCC);

    log_event(&g_log, ETYPE_ALLOC,
              "case11: 64-byte block + 16-byte redzone @ %p", buf);

    buf[64] = 0xEE;                  /* one byte past the block   */
    buf[65] = 0xFF;                  /* two bytes past the block  */
    log_event(&g_log, ETYPE_ALLOC,
              "case11: wrote 2 bytes past the block (expect OVERFLOW) @ %p", buf);
}

static void run_selftest(void)
{
    log_event(&g_log, ETYPE_SCAN_BEGIN, "=== self test: 11 cases ===");

    case_normal_block();
    case_high_entropy();
    case_nop_sled();
    case_rwx();
    case_low_printable();
    case_inline_hook();
    case_alloc_free_cycle();
    case_perm_transition();
    case_double_free();
    case_use_after_free();
    case_redzone_overflow();

    log_event(&g_log, ETYPE_SCAN_END, "=== self test: all 11 cases staged ===");
}

/* =========================================================================
 * Summary / cleanup
 * ====================================================================== */

static void print_summary(void)
{
    BlockRecord *b;
    uint32_t iter = 0;
    int suspicious = 0, total = 0;

    log_event(&g_log, ETYPE_STATS, "---- final summary ----");

    while ((b = bt_next(&g_blocks, &iter)) != NULL) {
        char hits[256];

        total++;
        if (!b->hit_mask)
            continue;

        suspicious++;
        hit_mask_to_string(b->hit_mask, hits, sizeof(hits));
        log_event(&g_log, ETYPE_STATS,
                  "0x%016llx size=%llu perms=0x%x entropy=%.2f hits=[%s] "
                  "tag=\"%s\" stack=0x%016llx",
                  (unsigned long long)b->ptr,
                  (unsigned long long)b->size,
                  (unsigned)b->perms, b->entropy,
                  hits, b->tag,
                  (unsigned long long)b->stack_hash);
    }

    log_event(&g_log, ETYPE_STATS,
              "blocks tracked=%d suspicious=%d ring: produced=%llu "
              "dropped=%llu consumed-events-last-cycle see log above",
              total, suspicious,
              (unsigned long long)rb_produced(&g_ring),
              (unsigned long long)rb_dropped(&g_ring));
}

static void release_allocs(void)
{
    int i;

    for (i = 0; i < g_nallocs; i++) {
        if (g_allocs[i].is_virt)
            VirtualFree(g_allocs[i].ptr, 0, MEM_RELEASE);
        else
            free(g_allocs[i].ptr);
        g_nallocs--;
        i--;
    }
}

/* =========================================================================
 * Console / lifecycle
 * ====================================================================== */

/* ANSI colours need ENABLE_VIRTUAL_TERMINAL_PROCESSING on Windows 10 and
 * later; on older versions the escapes are simply printed as text, which
 * the --no-color flag exists to avoid. */
static void win_enable_vt(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;

    if (out && out != INVALID_HANDLE_VALUE && GetConsoleMode(out, &mode))
        SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static BOOL WINAPI on_console_ctrl(DWORD ctrl_type)
{
    (void)ctrl_type;
    scheduler_stop(&g_sched);
    return TRUE;                        /* handled: keep the process alive
                                         * long enough to write the report */
}

static void usage(const char *argv0)
{
    printf(
        "CoreSight-style real-time memory tracker (Windows x64)\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "  --log PATH        log file path (default: memory_tracker.log)\n"
        "  --interval N      seconds between scans     (default: %u)\n"
        "  --record N        recording window, seconds (default: %u)\n"
        "  --cycles N        exit after N completed cycles (default: wait Enter)\n"
        "  --first-delay N   delay before the first cycle, seconds (default: 0)\n"
        "  --ring N          ring buffer slots, power of two (default: %u)\n"
        "  --selftest        run the 11 built-in detection test cases\n"
        "  --no-color        disable ANSI colours on the console\n"
        "  -h, --help        this text\n",
        argv0, SCAN_INTERVAL_SEC, RECORD_DURATION_SEC, RING_DEFAULT_SIZE);
}

/* =========================================================================
 * main
 * ====================================================================== */

int main(int argc, char **argv)
{
    const char *log_path   = "memory_tracker.log";
    uint32_t interval      = SCAN_INTERVAL_SEC;
    uint32_t record        = RECORD_DURATION_SEC;
    uint32_t cycles_target = 0;
    uint32_t first_delay   = 0;
    uint32_t ring_size     = RING_DEFAULT_SIZE;
    int want_selftest      = 0;
    int use_color          = 1;
    const Scanner *scanners;
    size_t n_scanners = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--log") && i + 1 < argc) {
            log_path = argv[++i];
        } else if (!strcmp(argv[i], "--interval") && i + 1 < argc) {
            interval = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--record") && i + 1 < argc) {
            record = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--cycles") && i + 1 < argc) {
            cycles_target = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--first-delay") && i + 1 < argc) {
            first_delay = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--ring") && i + 1 < argc) {
            ring_size = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--selftest")) {
            want_selftest = 1;
        } else if (!strcmp(argv[i], "--no-color")) {
            use_color = 0;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    g_ops = platform_get();

    /* ---- console banner ------------------------------------------------ */
    if (use_color)
        win_enable_vt();
    if (use_color)
        printf("\033[96m");
    printf("+========================================================+\n"
           "|  CoreSight-style Memory Tracker - Windows user space   |\n"
           "|  cadence: record %us every %us, then scan             |\n"
           "+========================================================+\n",
           record, interval);
    if (use_color)
        printf("\033[0m");

    /* ---- subsystems ---------------------------------------------------- */
    if (logger_open(&g_log, log_path, use_color) != 0) {
        fprintf(stderr, "error: cannot open log file %s: %s\n",
                log_path, strerror(errno));
        return 1;
    }

    if (rb_init(&g_ring, ring_size) != 0) {
        fprintf(stderr, "error: ring buffer allocation failed\n");
        logger_close(&g_log);
        return 1;
    }

    if (bt_init(&g_blocks, 0) != 0) {
        fprintf(stderr, "error: block table allocation failed\n");
        rb_free(&g_ring);
        logger_close(&g_log);
        return 1;
    }

    detectors_reset();
    scanners = detectors_default_table(&n_scanners);

    scheduler_init(&g_sched, &g_ring, &g_blocks, &g_log, g_ops,
                   scanners, n_scanners, interval, record, first_delay);

    log_event(&g_log, ETYPE_STATS,
              "init: platform=%s interval=%us record=%us ring=%u "
              "detectors=%u",
              g_ops->name, interval, record, g_ring.size,
              (unsigned)n_scanners);

    SetConsoleCtrlHandler(on_console_ctrl, TRUE);

    /* ---- start the scheduler thread ------------------------------------ */
    if (pthread_create(&g_thread, NULL, scheduler_run, &g_sched) != 0) {
        fprintf(stderr, "error: cannot start scheduler thread\n");
        logger_close(&g_log);
        return 1;
    }
    g_thread_started = 1;

    /* ---- self test ------------------------------------------------------
     * Wait until the recording window is actually open before staging the
     * test cases; otherwise the ALLOC events would be pushed "outside the
     * window" and would only be counted, not logged in detail. */
    if (want_selftest) {
        uint64_t waited = 0;

        while (!atomic_load(&g_sched.window_open) && waited < 5000) {
            g_ops->sleep_ms(10);
            waited += 10;
        }

        if (atomic_load(&g_sched.window_open))
            run_selftest();
        else
            log_event(&g_log, ETYPE_ERROR,
                      "self test skipped: recording window never opened");
    }

    /* ---- wait for completion ------------------------------------------- */
    if (cycles_target > 0) {
        uint64_t waited = 0;

        while (atomic_load(&g_sched.completed) < cycles_target &&
               atomic_load(&g_sched.running) && waited < 3600000ULL) {
            g_ops->sleep_ms(100);
            waited += 100;
        }

        log_event(&g_log, ETYPE_STATS, "reached %u completed cycle(s)",
                  cycles_target);
    } else if (_isatty(_fileno(stdin))) {
        printf("\nPress Enter to stop tracking and exit...\n");
        getchar();
    } else {
        /* No tty and no --cycles: run until interrupted. */
        while (atomic_load(&g_sched.running)) {
            g_ops->sleep_ms(250);
            if (atomic_load(&g_sched.completed) >= 1 &&
                atomic_load(&g_sched.cycle) >= 1)
                break;
        }
    }

    /* ---- teardown -------------------------------------------------------- */
    scheduler_stop(&g_sched);
    if (g_thread_started) {
        pthread_join(g_thread, NULL);
        g_thread_started = 0;
    }

    print_summary();
    release_allocs();

    logger_close(&g_log);

    rb_free(&g_ring);
    bt_free(&g_blocks);

    printf("\ntracker.exe: done (log: %s)\n", log_path);
    return 0;
}
