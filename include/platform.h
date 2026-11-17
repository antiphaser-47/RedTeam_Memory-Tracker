/*
 * platform.h
 * ---------------------------------------------------------------------------
 * Platform abstraction layer (the ONLY place where OS differences live).
 *
 * Everything in src/core/ is portable C11; it talks to the operating system
 * exclusively through this vtable.  Two implementations exist:
 *
 *   src/linux/platform_linux.c   /proc/self/maps, backtrace(), mmap()
 *   src/win/platform_win.c       VirtualQuery, CaptureStackBackTrace,
 *                                VirtualAlloc, GetProcAddress
 *
 * Keeping the vtable small is deliberate: every extra entry is one more
 * function that must be written (and tested) twice.
 * ---------------------------------------------------------------------------
 */
#ifndef TRACKER_CORE_PLATFORM_H
#define TRACKER_CORE_PLATFORM_H

#include "tracker_types.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration so the scanner can talk to the platform without a
 * circular include. */
typedef struct PlatformOps PlatformOps;

struct PlatformOps {
    /* Human readable platform name, e.g. "linux" / "windows". */
    const char *name;

    /* --- time / scheduling ------------------------------------------- */

    /* Sleep for at least `ms` milliseconds. */
    void     (*sleep_ms)(uint64_t ms);

    /* Monotonic nanosecond timestamp (CLOCK_MONOTONIC / QueryPerformance). */
    uint64_t (*now_ns)(void);

    /* Current process id. */
    uint32_t (*pid)(void);

    /* Current CPU core (user space: always 0). */
    uint16_t (*cpu)(void);

    /* --- memory introspection ---------------------------------------- */

    /* Permission bitmask (PERM_R|PERM_W|PERM_X) for `addr`.
     * Returns 0 when the address is not mapped / not queryable. */
    uint32_t (*get_perms)(uint64_t addr);

    /* Safely copy `len` bytes from `addr` into `dst`.
     * Returns 1 on success, 0 if the memory could not be read
     * (unmapped, no-access, guard page, ...).  Implementations must never
     * crash the process - this is what replaces SEH on Windows and the
     * missing probe on Linux. */
    int      (*read_safe)(uint64_t addr, void *dst, size_t len);

    /* FNV-1a hash of the current call stack (skipping the caller frames
     * that belong to the tracker itself). */
    uint64_t (*stack_hash)(void);

    /* Return address of the caller of the function calling this (best
     * effort; 0 when unavailable). */
    uint64_t (*caller_ip)(void);

    /* Walk the process memory map and invoke `cb` for every region.
     * `cb` returns non-zero to stop the walk early.
     * Returns the number of regions reported. */
    int      (*enum_maps)(int (*cb)(uint64_t start, uint64_t end,
                                    uint32_t perms, void *user),
                          void *user);

    /* Walk the loaded modules / shared objects.
     * `cb` receives (name, base, size, user); non-zero stops the walk. */
    int      (*enum_modules)(int (*cb)(const char *name, uint64_t base,
                                       uint64_t size, void *user),
                             void *user);

    /* --- symbol / module introspection -------------------------------- */

    /* Resolve a well-known exported symbol by name.
     *   Linux   -> dlsym(RTLD_DEFAULT, name)   (libc, libdl, ld-linux, ...)
     *   Windows -> GetProcAddress() over the modules that are always loaded
     *              (exe, kernel32, ntdll, msvcrt/ucrtbase, user32, ...)
     * Returns NULL when the symbol does not exist on this platform.  This
     * is what keeps the hook / ret2libc detectors free of <dlfcn.h>. */
    void *(*sym_lookup)(const char *name);

    /* Return 1 when `name` identifies a module that is *supposed* to own
     * the process's core system calls and C runtime:
     *   Linux   -> libc.so*, libc-*, libdl*, ld-linux*
     *   Windows -> kernel32*, kernelbase*, ntdll*, msvcrt*, ucrtbase*,
     *              api-ms-win-crt*, user32*, advapi32*, shell32*
     * The hook and ret2libc detectors use this to notice a symbol that
     * resolved into the WRONG module (LD_PRELOAD / DLL hijack / IAT patch). */
    int   (*is_expected_module)(const char *name);

    /* --- test-hook helpers (used by the self test cases) -------------- */

    /* Allocate `size` bytes of read-write-execute memory.
     * Returns NULL on failure.  Used by RWX test cases. */
    void    *(*alloc_rwx)(size_t size);

    /* Release memory returned by alloc_rwx.  Returns 1 on success. */
    int      (*free_rwx)(void *p, size_t size);
};

/* Return the vtable for the current build target. */
const PlatformOps *platform_get(void);

#ifdef __cplusplus
}
#endif

#endif /* TRACKER_CORE_PLATFORM_H */
