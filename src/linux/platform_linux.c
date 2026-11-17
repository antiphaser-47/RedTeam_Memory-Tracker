/*
 * platform_linux.c - Linux user-space implementation of the PlatformOps
 *                    vtable (see include/platform.h).
 *
 * What lives here (and only here):
 *   - /proc/self/maps parsing with a cached, binary-searchable snapshot
 *   - fault-proof memory reads (SIGSEGV/SIGBUS + sigsetjmp guard)
 *   - call-stack fingerprinting via backtrace()
 *   - module enumeration via dl_iterate_phdr()
 *   - RWX allocation helpers used by the test cases
 * ---------------------------------------------------------------------------
 */
#define _GNU_SOURCE   /* dl_iterate_phdr(), sched_getcpu(), backtrace() */

#include "platform.h"
#include "platform_linux.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <sched.h>
#include <dlfcn.h>
#include <link.h>
#include <execinfo.h>
#include <sys/mman.h>

/* =========================================================================
 * Time / scheduling
 * ====================================================================== */

static void linux_sleep_ms(uint64_t ms)
{
    struct timespec req, rem;

    req.tv_sec  = (time_t)(ms / 1000u);
    req.tv_nsec = (long)((ms % 1000u) * 1000000u);

    /* nanosleep returns -1/EINTR when a signal (e.g. our SIGINT handler)
     * arrives mid-sleep; resume with the remaining time in that case. */
    while (nanosleep(&req, &rem) != 0) {
        if (errno != EINTR)
            break;
        req = rem;
    }
}

static uint64_t linux_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint32_t linux_pid(void)
{
    return (uint32_t)getpid();
}

static uint16_t linux_cpu(void)
{
    /* sched_getcpu() is a GNU extension - available under _GNU_SOURCE. */
    int c = sched_getcpu();
    return (uint16_t)(c >= 0 ? c : 0);
}

/* =========================================================================
 * /proc/self/maps snapshot
 * ------------------------------------------------------------------------
 * The naive implementation re-opened /proc/self/maps for every single
 * address lookup, which turned an O(log n) query into two syscalls plus a
 * line-by-line parse.  During a scan over thousands of blocks that dominated
 * the runtime.  The snapshot below is refreshed:
 *   - when it is older than MAPS_TTL_NS
 *   - when a lookup misses (new mappings, munmap, mprotect)
 * Explicit invalidation (linux_maps_invalidate) is called by main right
 * after it changes the address space.
 * ====================================================================== */

#define MAPS_MAX       8192
#define MAPS_TTL_NS    (300ULL * 1000000ULL)   /* 300 ms */

typedef struct map_entry {
    uint64_t start;
    uint64_t end;
    uint32_t perms;      /* PERM_* bits */
    char     path[256];
} map_entry;

static map_entry          g_maps[MAPS_MAX];
static int                g_maps_n = 0;
static uint64_t           g_maps_loaded_ns = 0;
static pthread_mutex_t    g_maps_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t parse_perms(const char *p)
{
    uint32_t r = 0;

    if (p[0] == 'r') r |= PERM_R;
    if (p[1] == 'w') r |= PERM_W;
    if (p[2] == 'x') r |= PERM_X;
    return r;
}

/* Must be called with g_maps_lock held.  Returns 0 on success. */
static int load_maps_locked(void)
{
    FILE *fp;
    char line[512];
    int n = 0;

    fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp) && n < MAPS_MAX) {
        unsigned long long s = 0, e = 0;
        char perms[8] = {0};
        char path[256] = {0};

        /* address perms offset dev inode pathname */
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %255[^\n]",
                   &s, &e, perms, path) < 3)
            continue;

        g_maps[n].start = (uint64_t)s;
        g_maps[n].end   = (uint64_t)e;
        g_maps[n].perms = parse_perms(perms);
        /* Trim leading whitespace of the path. */
        {
            char *p = path;
            while (*p == ' ' || *p == '\t') p++;
            snprintf(g_maps[n].path, sizeof(g_maps[n].path), "%s", p);
        }
        n++;
    }

    fclose(fp);
    g_maps_n          = n;
    g_maps_loaded_ns  = linux_now_ns();
    return 0;
}

void linux_maps_invalidate(void)
{
    pthread_mutex_lock(&g_maps_lock);
    g_maps_loaded_ns = 0;         /* force a reload on next lookup */
    pthread_mutex_unlock(&g_maps_lock);
}

/* Binary search for the region containing `addr`.  Returns index or -1.
 * Caller must hold g_maps_lock. */
static int maps_bsearch_locked(uint64_t addr)
{
    int lo = 0, hi = g_maps_n - 1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;

        if (addr < g_maps[mid].start)
            hi = mid - 1;
        else if (addr >= g_maps[mid].end)
            lo = mid + 1;
        else
            return mid;
    }
    return -1;
}

static uint32_t linux_get_perms(uint64_t addr)
{
    uint64_t now;
    int idx = -1;
    int attempt;

    if (addr == 0)
        return 0;

    for (attempt = 0; attempt < 2; attempt++) {
        pthread_mutex_lock(&g_maps_lock);

        now = linux_now_ns();
        if (g_maps_n == 0 ||
            (now - g_maps_loaded_ns) > MAPS_TTL_NS) {
            if (load_maps_locked() != 0) {
                pthread_mutex_unlock(&g_maps_lock);
                return 0;
            }
        }

        idx = maps_bsearch_locked(addr);
        if (idx >= 0) {
            uint32_t perms = g_maps[idx].perms;

            pthread_mutex_unlock(&g_maps_lock);
            return perms;
        }

        pthread_mutex_unlock(&g_maps_lock);

        /* Miss: the region was probably created after the snapshot.
         * Force a reload and retry once. */
        pthread_mutex_lock(&g_maps_lock);
        load_maps_locked();
        pthread_mutex_unlock(&g_maps_lock);
    }
    return 0;
}

int linux_enum_maps_impl(int (*cb)(uint64_t, uint64_t, uint32_t, void *),
                         void *user)
{
    int i, reported = 0;

    /* Always read a fresh snapshot: address space walks are rare. */
    pthread_mutex_lock(&g_maps_lock);
    load_maps_locked();

    for (i = 0; i < g_maps_n; i++) {
        if (cb(g_maps[i].start, g_maps[i].end, g_maps[i].perms, user))
            break;
        reported++;
    }
    pthread_mutex_unlock(&g_maps_lock);
    return reported;
}

/* =========================================================================
 * Fault-proof memory read
 * ------------------------------------------------------------------------
 * Why this exists: a scanner that dereferences a pointer which the program
 * has just munmap()'d would crash the very process it is monitoring.  On
 * Windows we would use SEH (__try/__except); POSIX has no structured
 * exceptions, so we combine:
 *   1. a permission pre-check against the maps snapshot, and
 *   2. a SIGSEGV/SIGBUS handler that longjmps back out of the fault.
 * The handler is thread-local, which matters because Linux delivers the
 * fault signal to the thread that actually touched the bad address.
 * ====================================================================== */

static __thread sigjmp_buf  g_read_jmp;
static __thread volatile sig_atomic_t g_read_guarded = 0;

static void fault_handler(int sig)
{
    if (g_read_guarded) {
        /* Expected fault inside read_safe(): unwind back to the guard. */
        siglongjmp(g_read_jmp, 1);
    }

    /* Unexpected fault: restore default behaviour so the core dump / status
     * still reports the real signal instead of looping forever. */
    signal(sig, SIG_DFL);
    raise(sig);
}

static pthread_once_t g_fault_once = PTHREAD_ONCE_INIT;

static void install_fault_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;   /* allow the signal to re-enter safely */

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
}

static int linux_read_safe(uint64_t addr, void *dst, size_t len)
{
    int ok = 0;

    if (addr == 0 || !dst || len == 0)
        return 0;

    /* Fast reject: reading a region without the 'r' bit always faults, so
     * skip the signal dance entirely. */
    if ((linux_get_perms(addr) & PERM_R) == 0)
        return 0;
    if (len > 1 &&
        (linux_get_perms(addr + len - 1) & PERM_R) == 0)
        return 0;

    pthread_once(&g_fault_once, install_fault_handlers);

    g_read_guarded = 1;
    if (sigsetjmp(g_read_jmp, 1) == 0) {
        memcpy(dst, (const void *)(uintptr_t)addr, len);
        ok = 1;
    } else {
        ok = 0;
    }
    g_read_guarded = 0;

    return ok;
}

/* =========================================================================
 * Call stack fingerprint
 * ====================================================================== */

#define FNV64_OFFSET 14695981039346656037ULL
#define FNV64_PRIME  1099511628211ULL

static uint64_t linux_stack_hash(void)
{
    void *frames[MAX_STACK_DEPTH];
    int n, i;
    uint64_t h = FNV64_OFFSET;

    n = backtrace(frames, MAX_STACK_DEPTH);
    if (n <= 0)
        return 0;

    /* Skip frame 0 (this function) and frame 1 (the caller of the tracker
     * helper) so that all tracker-internal call paths hash identically. */
    for (i = 2; i < n; i++) {
        h ^= (uint64_t)(uintptr_t)frames[i];
        h *= FNV64_PRIME;
    }
    return h;
}

static uint64_t linux_caller_ip(void)
{
    /* Level 0 only: GCC documents levels > 0 as unsafe (they can corrupt the
     * frame pointer chain on some targets).  The *interesting* call site is
     * captured by linux_stack_hash() above; this field only needs to be a
     * stable "who called the tracker" marker. */
    return (uint64_t)(uintptr_t)__builtin_return_address(0);
}

/* =========================================================================
 * Module enumeration (dl_iterate_phdr)
 * ====================================================================== */

typedef struct {
    int (*cb)(const char *, uint64_t, uint64_t, void *);
    void *user;
} mod_walk_ctx;

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    mod_walk_ctx *ctx = (mod_walk_ctx *)data;
    uint64_t lo = UINT64_MAX, hi = 0;
    const char *name;
    char exe_path[256];
    size_t i;

    (void)size;

    for (i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type != PT_LOAD)
            continue;
        {
            uint64_t b = (uint64_t)info->dlpi_addr +
                         (uint64_t)info->dlpi_phdr[i].p_vaddr;
            uint64_t e = b + (uint64_t)info->dlpi_phdr[i].p_memsz;

            if (b < lo) lo = b;
            if (e > hi) hi = e;
        }
    }

    if (lo == UINT64_MAX)
        return 0;

    /* dlpi_name is empty for the main executable - resolve the real path so
     * reports show something useful instead of an empty string. */
    name = info->dlpi_name;
    if (!name || !*name) {
        ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (n > 0) {
            exe_path[n] = '\0';
            name = exe_path;
        } else {
            name = "(main executable)";
        }
    }

    return ctx->cb(name, lo, hi - lo, ctx->user);
}

static int linux_enum_modules(int (*cb)(const char *, uint64_t, uint64_t,
                                        void *),
                              void *user)
{
    mod_walk_ctx ctx;

    ctx.cb   = cb;
    ctx.user = user;
    return dl_iterate_phdr(phdr_callback, &ctx);
}

/* =========================================================================
 * RWX helpers (test cases only)
 * ====================================================================== */

static void *linux_alloc_rwx(size_t size)
{
    void *p;

    if (size == 0)
        return NULL;

    p = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;

    linux_maps_invalidate();
    return p;
}

static int linux_free_rwx(void *p, size_t size)
{
    if (!p || size == 0)
        return 0;
    if (munmap(p, size) != 0)
        return 0;

    linux_maps_invalidate();
    return 1;
}

/* =========================================================================
 * Symbol resolution / module classification
 * ------------------------------------------------------------------------
 * These two entries exist so that the hook and ret2libc detectors never
 * have to include <dlfcn.h>: the Windows build substitutes GetProcAddress
 * and a DLL-name predicate, and the detector source stays 100% identical.
 * ====================================================================== */

static void *linux_sym_lookup(const char *name)
{
    if (!name)
        return NULL;
    /* RTLD_DEFAULT searches every object loaded into the process
     * (main executable, libc, libdl, LD_PRELOAD'd libraries, ...) which is
     * exactly the lookup an attacker's substituted symbol would win. */
    return dlsym(RTLD_DEFAULT, name);
}

static int linux_is_expected_module(const char *name)
{
    if (!name || !*name)
        return 0;

    /* Deliberately specific substrings: a bare "libc" would also match
     * /home/user/libcrypto.so, and "ld" would match nearly everything. */
    if (strstr(name, "libc.so")  != NULL)  return 1;   /* libc.so.6       */
    if (strstr(name, "libc-")    != NULL)  return 1;   /* libc-2.39.so    */
    if (strstr(name, "libdl")    != NULL)  return 1;   /* libdl.so.2      */
    if (strstr(name, "ld-linux") != NULL)  return 1;   /* ld-linux-x86-64 */
    return 0;
}

/* =========================================================================
 * Vtable
 * ====================================================================== */

static const PlatformOps g_linux_ops = {
    .name                = "linux",
    .sleep_ms            = linux_sleep_ms,
    .now_ns              = linux_now_ns,
    .pid                 = linux_pid,
    .cpu                 = linux_cpu,
    .get_perms           = linux_get_perms,
    .read_safe           = linux_read_safe,
    .stack_hash          = linux_stack_hash,
    .caller_ip           = linux_caller_ip,
    .enum_maps           = linux_enum_maps_impl,
    .enum_modules        = linux_enum_modules,
    .sym_lookup          = linux_sym_lookup,
    .is_expected_module  = linux_is_expected_module,
    .alloc_rwx           = linux_alloc_rwx,
    .free_rwx            = linux_free_rwx,
};

const PlatformOps *platform_get(void)
{
    return &g_linux_ops;
}
