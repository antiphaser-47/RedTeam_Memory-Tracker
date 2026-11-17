/*
 * platform_win.c - Windows user-space implementation of the PlatformOps
 *                  vtable (see include/platform.h).
 *
 * What lives here (and only here):
 *   - VirtualQuery based permission queries over the process address space
 *   - fault-proof memory reads built on ReadProcessMemory (the Windows
 *     equivalent of the Linux SIGSEGV guard - see win_read_safe)
 *   - call-stack fingerprinting via CaptureStackBackTrace()
 *   - module enumeration via EnumProcessModulesEx()
 *   - symbol resolution via GetProcAddress() over the modules that are
 *     always loaded (this is what replaces dlsym in the detectors)
 *   - RWX allocation helpers used by the test cases
 *
 * Deliberate differences from platform_linux.c:
 *   - there is no /proc snapshot to cache: VirtualQuery already is an
 *     O(log n) kernel lookup, so win_get_perms() queries directly and no
 *     explicit invalidation hook is required
 *   - there is no signal handler: ReadProcessMemory reports a failure
 *     instead of raising an exception when a page is unreadable, which
 *     removes the whole setjmp/longjmp dance
 * ---------------------------------------------------------------------------
 */
#define WIN32_LEAN_AND_MEAN
#include "platform.h"

#include <windows.h>
#include <psapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* =========================================================================
 * Time / scheduling
 * ====================================================================== */

static void win_sleep_ms(uint64_t ms)
{
    /* Sleep() has a ~15 ms granularity, which is far finer than the 100 ms
     * slices the scheduler uses - no need for a waitable timer here. */
    Sleep((DWORD)(ms > 0xFFFFFFFFu ? 0xFFFFFFFFu : ms));
}

static uint64_t win_now_ns(void)
{
    /* QueryPerformanceCounter is monotonic across all cores on every
     * Windows version the tracker supports (unlike GetTickCount). */
    static LARGE_INTEGER freq;
    static int init = 0;
    LARGE_INTEGER now;

    if (!init) {
        QueryPerformanceFrequency(&freq);
        init = 1;
    }
    QueryPerformanceCounter(&now);

    return (uint64_t)((now.QuadPart * 1000000000ULL) / (uint64_t)freq.QuadPart);
}

static uint32_t win_pid(void)
{
    return (uint32_t)GetCurrentProcessId();
}

static uint16_t win_cpu(void)
{
    return (uint16_t)GetCurrentProcessorNumber();
}

/* =========================================================================
 * Permission bits
 * ====================================================================== */

/* Map a Win32 PAGE_* protection constant onto the OS-neutral PERM_* mask.
 * PAGE_NOACCESS and PAGE_GUARD deliberately map to "no permissions": a
 * guard page is not readable by the scanner even though the base protect
 * bits say it is. */
static uint32_t protect_to_perms(DWORD protect)
{
    switch (protect & 0xFFu) {
    case PAGE_READONLY:            return PERM_R;
    case PAGE_READWRITE:           return PERM_R | PERM_W;
    case PAGE_WRITECOPY:           return PERM_R | PERM_W;
    case PAGE_EXECUTE:             return PERM_X;
    case PAGE_EXECUTE_READ:        return PERM_R | PERM_X;
    case PAGE_EXECUTE_READWRITE:   return PERM_RWX;
    case PAGE_EXECUTE_WRITECOPY:   return PERM_RWX;
    default:                       return 0;   /* NOACCESS / unknown */
    }
}

static uint32_t win_get_perms(uint64_t addr)
{
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQuery((const void *)(uintptr_t)addr, &mbi, sizeof(mbi)) == 0)
        return 0;
    if (mbi.State != MEM_COMMIT)
        return 0;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return 0;
    return protect_to_perms(mbi.Protect);
}

/* =========================================================================
 * Fault-proof memory read
 * ------------------------------------------------------------------------
 * Why this exists: a scanner that dereferences a pointer the program has
 * just VirtualFree()'d would crash the very process it is monitoring.
 *
 * The Linux build wraps memcpy() in a SIGSEGV handler; on Windows the
 * equivalent primitive is ReadProcessMemory(), which performs the copy
 * from inside the kernel and reports failure instead of raising an
 * exception.  Every page in the range is validated first (committed,
 * readable, not a guard page) so that a partial range is rejected before
 * any byte is copied.
 * ====================================================================== */

static int win_read_safe(uint64_t addr, void *dst, size_t len)
{
    unsigned char *out = (unsigned char *)dst;
    size_t done = 0;

    if (addr == 0 || dst == NULL || len == 0)
        return 0;

    while (done < len) {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t cur = (uintptr_t)addr + done;
        size_t chunk;
        SIZE_T got = 0;

        if (VirtualQuery((const void *)cur, &mbi, sizeof(mbi)) == 0)
            return 0;
        if (mbi.State != MEM_COMMIT)
            return 0;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
            return 0;
        if (protect_to_perms(mbi.Protect) == 0)
            return 0;                     /* not readable */

        /* Clamp this chunk to the end of the region so the next loop
         * iteration re-validates the following region. */
        chunk = (size_t)((uintptr_t)mbi.BaseAddress + mbi.RegionSize - cur);
        if (chunk > len - done)
            chunk = len - done;

        if (!ReadProcessMemory(GetCurrentProcess(), (const void *)cur,
                               out + done, chunk, &got) || got != chunk)
            return 0;

        done += chunk;
    }
    return 1;
}

/* =========================================================================
 * Call stack fingerprint
 * ====================================================================== */

#define FNV64_OFFSET 14695981039346656037ULL
#define FNV64_PRIME  1099511628211ULL

static uint64_t win_stack_hash(void)
{
    void *frames[MAX_STACK_DEPTH];
    WORD n, i;
    uint64_t h = FNV64_OFFSET;

    /* FramesToSkip = 2 mirrors the Linux build: frame 0 is this function
     * and frame 1 is the tracker helper that called it, so every
     * tracker-internal call path hashes identically on both platforms. */
    n = CaptureStackBackTrace(2, MAX_STACK_DEPTH, frames, NULL);
    if (n == 0)
        return 0;

    for (i = 0; i < n; i++) {
        h ^= (uint64_t)(uintptr_t)frames[i];
        h *= FNV64_PRIME;
    }
    return h;
}

static uint64_t win_caller_ip(void)
{
    /* Level 0 only, for the same reason as on Linux: GCC documents deeper
     * levels as unsafe.  The interesting call site is captured by
     * win_stack_hash() above. */
    return (uint64_t)(uintptr_t)__builtin_return_address(0);
}

/* =========================================================================
 * Memory map walk
 * ====================================================================== */

int win_enum_maps_impl(int (*cb)(uint64_t, uint64_t, uint32_t, void *),
                       void *user)
{
    /* User-space ceiling on x64 Windows; VirtualQuery walks forward from
     * here one region at a time. */
    uintptr_t addr = 0x10000;
    const uintptr_t limit = 0x00007FFFFFFEFFFFULL;
    int reported = 0;

    if (!cb)
        return 0;

    while (addr < limit) {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t next;

        if (VirtualQuery((const void *)addr, &mbi, sizeof(mbi)) == 0)
            break;

        next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr)
            break;                          /* overflow guard */

        if (mbi.State == MEM_COMMIT) {
            uint32_t perms = 0;

            if (!(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
                perms = protect_to_perms(mbi.Protect);

            if (cb((uint64_t)(uintptr_t)mbi.BaseAddress,
                   (uint64_t)next, perms, user))
                break;
            reported++;
        }
        addr = next;
    }
    return reported;
}

/* =========================================================================
 * Module enumeration (EnumProcessModulesEx)
 * ====================================================================== */

int win_enum_modules(int (*cb)(const char *, uint64_t, uint64_t, void *),
                     void *user)
{
    HMODULE mods[512];
    DWORD needed = 0;
    DWORD count;
    DWORD i;
    int reported = 0;

    if (!cb)
        return 0;

    if (!EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof(mods),
                              &needed, LIST_MODULES_ALL))
        return 0;

    count = needed / sizeof(HMODULE);
    if (count > sizeof(mods) / sizeof(mods[0]))
        count = sizeof(mods) / sizeof(mods[0]);

    for (i = 0; i < count; i++) {
        MODULEINFO mi;
        char name[MAX_PATH];

        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi,
                                  sizeof(mi)))
            continue;

        name[0] = '\0';
        GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, MAX_PATH);
        if (!name[0])
            continue;

        reported++;
        if (cb(name, (uint64_t)(uintptr_t)mi.lpBaseOfDll,
               (uint64_t)mi.SizeOfImage, user))
            break;
    }
    return reported;
}

/* =========================================================================
 * Symbol resolution / module classification
 * ------------------------------------------------------------------------
 * The Windows half of the contract described in include/platform.h: the
 * detectors never touch <dlfcn.h>, they only ever call ops->sym_lookup()
 * and ops->is_expected_module().
 * ====================================================================== */

/* Modules that are virtually always present in a user-mode process.  The
 * list is intentionally "already loaded only": GetProcAddress is never
 * allowed to pull a new DLL into the process just because we want to
 * enumerate it (that would itself change the thing we are measuring). */
static const char *const k_sym_modules[] = {
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "msvcrt.dll",
    "ucrtbase.dll",
    "user32.dll",
    "advapi32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "ws2_32.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "combase.dll"
};

static void *win_sym_lookup(const char *name)
{
    size_t i;

    if (!name || !*name)
        return NULL;

    /* The main executable first: a symbol defined by the program itself
     * should resolve to that definition, exactly like dlsym(RTLD_DEFAULT)
     * prefers the executable over the libraries. */
    {
        HMODULE exe = GetModuleHandleA(NULL);
        FARPROC p = exe ? GetProcAddress(exe, name) : NULL;

        if (p)
            return (void *)(uintptr_t)p;
    }

    for (i = 0; i < sizeof(k_sym_modules) / sizeof(k_sym_modules[0]); i++) {
        HMODULE h = GetModuleHandleA(k_sym_modules[i]);
        FARPROC p;

        if (!h)
            continue;
        p = GetProcAddress(h, name);
        if (p)
            return (void *)(uintptr_t)p;
    }
    return NULL;
}

/* Strip any directory component so "C:\Windows\System32\ntdll.dll" and
 * "ntdll.dll" compare equal. */
static const char *module_basename(const char *path)
{
    const char *slash;
    const char *bslash;

    if (!path)
        return "";
    slash  = strrchr(path, '/');
    bslash = strrchr(path, '\\');
    if (bslash && (!slash || bslash > slash))
        slash = bslash;
    return slash ? slash + 1 : path;
}

static int name_starts_ci(const char *name, const char *prefix)
{
    while (*prefix) {
        char a = *name++;
        char b = *prefix++;

        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b)
            return 0;
        if (a == '\0')
            return 0;
    }
    return 1;
}

static int win_is_expected_module(const char *name)
{
    /* Modules that are *supposed* to own the process's core system calls
     * and C runtime.  A dangerous symbol living anywhere else means a DLL
     * hijack, an IAT patch or an injected module is interposing on it.
     * The CRT entries cover both the old msvcrt.dll and the Universal CRT
     * (ucrtbase + the api-ms-win-crt-* forwards). */
    static const char *const k_expected[] = {
        "ntdll", "kernel32", "kernelbase",
        "msvcrt", "ucrtbase", "api-ms-win-crt-",
        "vcruntime", "msvcp",
        "user32", "advapi32", "shell32", "shlwapi",
        "ws2_32", "rpcrt4", "sechost", "combase",
        "psapi", "bcrypt", "crypt32", "ole32"
    };
    const char *base;
    size_t i;

    if (!name || !*name)
        return 0;

    base = module_basename(name);
    for (i = 0; i < sizeof(k_expected) / sizeof(k_expected[0]); i++) {
        if (name_starts_ci(base, k_expected[i]))
            return 1;
    }
    return 0;
}

/* =========================================================================
 * RWX helpers (test cases only)
 * ====================================================================== */

static void *win_alloc_rwx(size_t size)
{
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
}

static int win_free_rwx(void *p, size_t size)
{
    (void)size;                            /* MEM_RELEASE frees the whole */
    return p && VirtualFree(p, 0, MEM_RELEASE) ? 1 : 0;
}

/* =========================================================================
 * Vtable
 * ====================================================================== */

static const PlatformOps g_win_ops = {
    .name                = "windows",
    .sleep_ms            = win_sleep_ms,
    .now_ns              = win_now_ns,
    .pid                 = win_pid,
    .cpu                 = win_cpu,
    .get_perms           = win_get_perms,
    .read_safe           = win_read_safe,
    .stack_hash          = win_stack_hash,
    .caller_ip           = win_caller_ip,
    .enum_maps           = win_enum_maps_impl,
    .enum_modules        = win_enum_modules,
    .sym_lookup          = win_sym_lookup,
    .is_expected_module  = win_is_expected_module,
    .alloc_rwx           = win_alloc_rwx,
    .free_rwx            = win_free_rwx,
};

const PlatformOps *platform_get(void)
{
    return &g_win_ops;
}
