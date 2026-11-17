/*
 * detector_ret2libc.c - ret2libc / return-to-library attack surface report.
 *
 * [why it works]
 *   ret2libc / return-to-library does not inject code; it reuses functions
 *   that are *already* mapped and executable.  The attacker only needs two
 *   things:
 *     1. the address of a useful function (system / WinExec / VirtualAlloc)
 *     2. a pointer to a useful string ("/bin/sh", a command line, ...)
 *   Both are sitting in the process right now, so simply *listing* them is
 *   both useful reconnaissance output and a baseline: if an address changes
 *   between runs (ASLR) or a function appears that should not be there
 *   (injected library), that is worth seeing.
 *
 * [how to do it]
 *   - resolve the dangerous functions through the platform symbol lookup
 *     and report their addresses
 *   - locate the classic argument string (see RET2_ARG_STRING) inside the
 *     module that owns the C runtime, by scanning its readable pages
 *   - check the allocator hooks (__malloc_hook / __free_hook): on glibc
 *     < 2.34 a non-NULL hook is the single most direct ret2libc primitive,
 *     because every allocation will call whatever address is stored there.
 *     Platforms without those symbols simply resolve nothing and skip.
 *   - flag any dangerous function whose containing module is NOT the core
 *     runtime module, which means a preload library, a hijacked DLL search
 *     order or a patched symbol table is interposing on it
 *
 * This detector is process-wide: it does not operate on individual blocks.
 * ---------------------------------------------------------------------------
 */
#include "detector_ret2libc.h"

#include <stdio.h>
#include <string.h>

#define RET2_MAX_REPORT 24

/* Functions whose address is directly useful to an attacker.  The list is
 * merged on purpose: names that do not exist on the current platform fail
 * to resolve and are skipped, so the detector needs no #ifdef. */
static const char *const k_dangerous[] = {
    /* POSIX / libc side */
    "system", "execve", "execv", "execvp", "execl", "popen",
    "mprotect", "mmap", "dlopen", "dlsym",
    "setuid", "seteuid", "setgid", "setresuid",
    /* Windows side */
    "WinExec", "CreateProcessA", "CreateProcessW",
    "LoadLibraryA", "LoadLibraryExA", "GetProcAddress",
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory",
    "OpenProcess", "TerminateProcess",
    "NtProtectVirtualMemory", "NtWriteVirtualMemory", "QueueUserAPC"
};

/* Allocator hook symbols.  glibc removed them in 2.34+ and Windows never
 * had them; sym_lookup() returns NULL there and the loop is a no-op. */
static const char *const k_hooks[] = {
    "__malloc_hook", "__free_hook", "__realloc_hook", "__memalign_hook"
};

/* Module that owns the C runtime, filled in during the scan. */
typedef struct {
    uint64_t addr;
    uint64_t size;
    int      found;
    int    (*pred)(const char *);       /* platform module classifier       */
} runtime_loc;

/* Accept only the module identified by the platform predicate - this is
 * what makes the same source mean "libc.so" on Linux and "msvcrt.dll" (or
 * "kernel32.dll") on Windows. */
static int find_runtime_cb(const char *name, uint64_t base, uint64_t size,
                           void *user)
{
    runtime_loc *loc = (runtime_loc *)user;

    if (!name || loc->found)
        return 0;
    if (!loc->pred || loc->pred(name)) {
        loc->addr  = base;
        loc->size  = size;
        loc->found = 1;
        return 1;                       /* stop the walk */
    }
    return 0;
}

/* Find the module that contains `addr`.  Returns 1 and fills name/base. */
typedef struct {
    uint64_t        addr;
    char           *name;
    size_t          name_len;
    uint64_t        base;
    int             found;
} addr_owner;

static int owner_cb(const char *name, uint64_t base, uint64_t size,
                    void *user)
{
    addr_owner *o = (addr_owner *)user;

    if (o->addr >= base && o->addr < base + size) {
        snprintf(o->name, o->name_len, "%s", name ? name : "(unknown)");
        o->base  = base;
        o->found = 1;
        return 1;                        /* stop the walk */
    }
    return 0;
}

static int module_of_addr(ScanContext *ctx, uint64_t addr,
                          char *out, size_t out_len, uint64_t *base_out)
{
    addr_owner o;

    memset(&o, 0, sizeof(o));
    o.addr     = addr;
    o.name     = out;
    o.name_len = out_len;
    ctx->ops->enum_modules(owner_cb, &o);
    if (base_out)
        *base_out = o.base;
    return o.found;
}

/* "libc.so.6" -> "libc.so.6"; "/usr/lib/x86_64-linux-gnu/libc.so.6" ->
 * "libc.so.6".  Keeps log lines readable on both platforms. */
static const char *short_name(const char *path)
{
    const char *slash;

    if (!path)
        return "(unknown)";
    slash = strrchr(path, '/');
#ifdef _WIN32
    {
        const char *bslash = strrchr(path, '\\');
        if (bslash && (!slash || bslash > slash))
            slash = bslash;
    }
#endif
    return slash ? slash + 1 : path;
}

/* Search a module for a NUL-terminated ASCII string.
 * Returns the address or 0.  Bounded so a huge libc cannot stall the scan. */
static uint64_t find_string(ScanContext *ctx, uint64_t base, uint64_t size,
                            const char *needle)
{
    size_t needle_len = strlen(needle);
    uint64_t off;
    uint8_t buf[4096];
    const uint64_t max_scan = 16ULL * 1024ULL * 1024ULL;   /* 16 MiB cap */
    size_t overlap = needle_len - 1;
    uint64_t limit = size < max_scan ? size : max_scan;

    for (off = 0; off < limit; off += sizeof(buf) - overlap) {
        size_t chunk = (size_t)((limit - off) < sizeof(buf)
                                ? (limit - off) : sizeof(buf));
        size_t i;

        if (!ctx->ops->read_safe(base + off, buf, chunk))
            continue;

        if (chunk < needle_len)
            continue;

        for (i = 0; i + needle_len <= chunk; i++) {
            if (memcmp(buf + i, needle, needle_len) == 0)
                return base + off + i;
        }
    }
    return 0;
}

/* The argument string every ret2libc chain needs, chosen per platform:
 * POSIX shells take "/bin/sh", Windows shells take "cmd.exe". */
#ifdef _WIN32
#define RET2_ARG_STRING "cmd.exe"
#else
#define RET2_ARG_STRING "/bin/sh"
#endif

void scan_ret2libc(ScanContext *ctx)
{
    runtime_loc rt;
    uint64_t argstr = 0;
    int reported = 0, outside = 0, i;
    static int s_reported_once = 0;      /* full detail only on the 1st scan */

    if (!ctx)
        return;

    /* ---- 0. locate the C runtime module -------------------------- */
    memset(&rt, 0, sizeof(rt));
    rt.pred = ctx->ops->is_expected_module;
    ctx->ops->enum_modules(find_runtime_cb, &rt);

    if (!rt.found) {
        log_event_sev(ctx->log, ETYPE_RET2LIBC, SEV_DEBUG,
                      "ret2libc: core runtime module not located (unusual)");
        return;
    }

    log_event_sev(ctx->log, ETYPE_RET2LIBC, SEV_DEBUG,
                  "ret2libc: runtime module @ 0x%016llx size=%llu",
                  (unsigned long long)rt.addr,
                  (unsigned long long)rt.size);

    /* ---- 1. dangerous function addresses ------------------------- */
    for (i = 0; i < (int)(sizeof(k_dangerous) / sizeof(k_dangerous[0]));
         i++) {
        void *a = ctx->ops->sym_lookup(k_dangerous[i]);
        uint64_t addr;
        char owner[256];
        uint64_t owner_base = 0;
        int owner_found = 0;

        if (!a)
            continue;

        addr = (uint64_t)(uintptr_t)a;

        /* Which module actually provides this symbol?  Anything that is
         * not the core runtime module means a substitute implementation is
         * in play (LD_PRELOAD / DLL hijack / patched import table). */
        owner[0]      = '\0';
        owner_base    = 0;
        owner_found   = module_of_addr(ctx, addr, owner, sizeof(owner),
                                       &owner_base);

        if (!owner_found || !ctx->ops->is_expected_module(owner)) {
            outside++;
            log_event(ctx->log, ETYPE_RET2LIBC,
                      "*** %s resolves OUTSIDE the core runtime module "
                      "@ 0x%016llx (module = %s) ***",
                      k_dangerous[i], (unsigned long long)addr,
                      owner_found ? owner : "(no module)");
            reported++;
            continue;
        }

        if (!s_reported_once && reported < RET2_MAX_REPORT) {
            log_event(ctx->log, ETYPE_RET2LIBC,
                      "%s @ 0x%016llx (%s+0x%llx)",
                      k_dangerous[i],
                      (unsigned long long)addr,
                      short_name(owner),
                      (unsigned long long)(addr - owner_base));
            reported++;
        }
    }

    /* ---- 2. the argument string every ret2libc chain needs -------- */
    argstr = find_string(ctx, rt.addr, rt.size, RET2_ARG_STRING);
    if (argstr) {
        if (!s_reported_once)
            log_event(ctx->log, ETYPE_RET2LIBC,
                      "\"%s\" string @ 0x%016llx (runtime+0x%llx) "
                      "- the classic ret2libc argument",
                      RET2_ARG_STRING,
                      (unsigned long long)argstr,
                      (unsigned long long)(argstr - rt.addr));
        reported++;
    } else {
        log_event_sev(ctx->log, ETYPE_RET2LIBC, SEV_DEBUG,
                      "ret2libc: \"%s\" not found in the runtime module",
                      RET2_ARG_STRING);
    }

    /* ---- 3. allocator hooks -------------------------------------- */
    for (i = 0; i < (int)(sizeof(k_hooks) / sizeof(k_hooks[0])); i++) {
        void *sym = ctx->ops->sym_lookup(k_hooks[i]);
        void **hook = (void **)sym;

        if (!hook)
            continue;                    /* absent on this platform */

        {
            void *value = *hook;

            if (value) {
                /* A set allocator hook is an arbitrary-call primitive. */
                log_event(ctx->log, ETYPE_RET2LIBC,
                          "*** %s is SET -> 0x%016llx "
                          "(every allocation will call it) ***",
                          k_hooks[i], (unsigned long long)(uintptr_t)value);
                reported++;
            } else if (!s_reported_once) {
                log_event_sev(ctx->log, ETYPE_RET2LIBC, SEV_DEBUG,
                              "%s: NULL (hooking primitive not in use)",
                              k_hooks[i]);
            }
        }
    }

    if (!s_reported_once)
        log_event(ctx->log, ETYPE_RET2LIBC,
                  "ret2libc surface mapped: %d dangerous symbol(s), "
                  "\"%s\" %s, hooks checked=%d, outside-runtime=%d",
                  reported, RET2_ARG_STRING,
                  argstr ? "FOUND" : "not found",
                  (int)(sizeof(k_hooks) / sizeof(k_hooks[0])), outside);

    s_reported_once = 1;
}
