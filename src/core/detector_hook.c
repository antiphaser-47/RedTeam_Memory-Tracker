/*
 * detector_hook.c - inline hook and symbol redirection detection.
 *
 * [why it works]
 *   A hooked function is redirected at one of three places:
 *
 *     (a) prologue patch  - the first bytes of the function are overwritten
 *         with a jump, so control leaves the real code immediately:
 *             E9 xx xx xx xx              jmp rel32
 *             FF 25 xx xx xx xx           jmp qword ptr [rip+disp]  (IAT/GOT)
 *             68 xx xx xx xx C3           push imm32 ; ret
 *             48 B8 xx..xx FF E0          movabs rax, imm64 ; jmp rax
 *             CC                          int3  (breakpoint stub / AV trampoline)
 *
 *     (b) pointer table patch - the GOT/PLT entry (Linux) or IAT entry
 *         (Windows) that the caller dereferences is overwritten, so the
 *         function itself looks pristine but resolves elsewhere.
 *
 *     (c) whole-library substitution - LD_PRELOAD / DLL search order hijack
 *         makes the symbol lookup return an address that does not live in
 *         the module that is supposed to own the symbol.
 *
 * [how to do it]
 *   For every watched symbol:
 *     1. resolve the address (registration list first, then sym_lookup)
 *     2. determine which loaded module contains that address
 *     3. if the address does NOT belong to the expected module -> (c)
 *     4. read the first 16 bytes safely and match the jump patterns -> (a)
 *   Both checks are cheap, so this runs every scan cycle.
 *
 * NOTE: modern EDR/AV products hook ntdll/libc *legitimately*.  A hit here
 * means "something is interposing on this call", which is information, not
 * proof of malice - see docs/USAGE.md.
 * ---------------------------------------------------------------------------
 */
#include "detector_hook.h"

#include <string.h>

#define HOOK_MAX_WATCH 64
#define HOOK_MAX_DETAIL 24

typedef struct watch_entry {
    char     name[64];
    void    *addr;        /* pre-registered address (test hooks)      */
    int      self_module; /* 1 = skip the "wrong module" check       */
} watch_entry;

static watch_entry g_watch[HOOK_MAX_WATCH];
static int         g_nwatch = 0;
static int         g_defaults_seeded = 0;

/* Register an address explicitly.  Used by the self test to watch a
 * function inside our own binary (the symbol lookup cannot see static
 * symbols). */
void hook_watch(const char *name, void *addr)
{
    if (!name || !addr || g_nwatch >= HOOK_MAX_WATCH)
        return;

    snprintf(g_watch[g_nwatch].name, sizeof(g_watch[g_nwatch].name),
             "%s", name);
    g_watch[g_nwatch].addr        = addr;
    g_watch[g_nwatch].self_module = 1;
    g_nwatch++;
}

static void hook_add_defaults(const PlatformOps *ops)
{
    /* One merged table for both platforms.  Names that do not exist on the
     * current OS simply fail to resolve and are skipped, so no #ifdef is
     * needed here - the platform layer decides what a symbol means.
     *
     * The interesting entries are the ones every injector needs: page
     * protection (to make shellcode executable), file/process control (to
     * drop a payload) and introspection (anti-debug / self-injection). */
    static const char *const k_syms[] = {
        /* allocation / protection: the primitives every injector needs */
        "mmap", "mprotect", "malloc", "free",
        "VirtualAlloc", "VirtualProtect", "VirtualAllocEx",
        "VirtualProtectEx", "WriteProcessMemory",
        /* file & process control */
        "open", "read", "write", "execve", "execv",
        "CreateFileA", "ReadFile", "WriteFile",
        "CreateProcessA", "CreateProcessW", "WinExec",
        /* introspection / anti-debug favourites */
        "ptrace", "dlopen", "system", "popen",
        "LoadLibraryA", "GetProcAddress", "OpenProcess",
        "TerminateProcess", "NtProtectVirtualMemory",
        "NtWriteVirtualMemory", "QueueUserAPC"
    };
    size_t i;

    if (!ops || g_defaults_seeded)
        return;                          /* defaults already installed */

    g_defaults_seeded = 1;

    for (i = 0; i < sizeof(k_syms) / sizeof(k_syms[0]); i++) {
        void *a = ops->sym_lookup(k_syms[i]);

        if (!a || g_nwatch >= HOOK_MAX_WATCH)
            continue;
        snprintf(g_watch[g_nwatch].name, sizeof(g_watch[g_nwatch].name),
                 "%s", k_syms[i]);
        g_watch[g_nwatch].addr        = a;
        g_watch[g_nwatch].self_module = 0;
        g_nwatch++;
    }
}

void hook_reset(void)
{
    g_nwatch = 0;
    g_defaults_seeded = 0;
}

/* ---- module lookup ---------------------------------------------------- */

typedef struct {
    uint64_t addr;
    char     name[256];
    uint64_t base;
    uint64_t size;
    int      found;
} module_loc;

static int find_module_cb(const char *name, uint64_t base, uint64_t size,
                          void *user)
{
    module_loc *loc = (module_loc *)user;

    if (loc->addr >= base && loc->addr < base + size) {
        snprintf(loc->name, sizeof(loc->name), "%s", name);
        loc->base  = base;
        loc->size  = size;
        loc->found = 1;
        return 1;                        /* stop the walk */
    }
    return 0;
}

/* ---- prologue classification ------------------------------------------ */

typedef struct {
    const char *kind;      /* short machine-code description              */
    int         is_jump;   /* 1 if control flow leaves the function       */
    uint64_t    target;    /* resolved target when computable, else 0     */
} prologue_info;

static prologue_info classify_prologue(const uint8_t *b, size_t n,
                                       uint64_t func_addr)
{
    prologue_info info = { "clean", 0, 0 };

    if (n < 2)
        return info;

    /* E9 rel32 - relative jump, the classic 5-byte inline hook. */
    if (b[0] == 0xE9 && n >= 5) {
        int32_t rel;
        memcpy(&rel, b + 1, sizeof(rel));
        info.kind    = "JMP rel32 (E9)";
        info.is_jump = 1;
        info.target  = func_addr + 5 + (int64_t)rel;
        return info;
    }

    /* EB rel8 - short jump, used by very small detours. */
    if (b[0] == 0xEB && n >= 2) {
        int8_t rel = (int8_t)b[1];
        info.kind    = "JMP rel8 (EB)";
        info.is_jump = 1;
        info.target  = func_addr + 2 + (int64_t)rel;
        return info;
    }

    /* FF 25 disp32 - jmp qword ptr [rip+disp]: imports via GOT/IAT. */
    if (b[0] == 0xFF && b[1] == 0x25 && n >= 6) {
        int32_t rel;
        memcpy(&rel, b + 2, sizeof(rel));
        info.kind    = "JMP [rip+disp32] (FF 25)";
        info.is_jump = 1;
        info.target  = func_addr + 6 + (int64_t)rel;
        return info;
    }

    /* 68 imm32 ; C3 - push addr ; ret */
    if (b[0] == 0x68 && n >= 6 && b[5] == 0xC3) {
        uint32_t imm;
        memcpy(&imm, b + 1, sizeof(imm));
        info.kind    = "PUSH imm32; RET (68 .. C3)";
        info.is_jump = 1;
        info.target  = imm;
        return info;
    }

    /* 48 B8 imm64 ; FF E0 - movabs rax, addr ; jmp rax */
    if (b[0] == 0x48 && b[1] == 0xB8 && n >= 12 &&
        b[10] == 0xFF && b[11] == 0xE0) {
        uint64_t imm;
        memcpy(&imm, b + 2, sizeof(imm));
        info.kind    = "MOVABS RAX,imm64; JMP RAX";
        info.is_jump = 1;
        info.target  = imm;
        return info;
    }

    if (b[0] == 0xCC) {
        info.kind    = "INT3 (CC)";
        info.is_jump = 1;
        return info;
    }

    /* Nothing recognisable - report the raw bytes, still "clean". */
    return info;
}

/* ---- the scan --------------------------------------------------------- */

void scan_hooks(ScanContext *ctx)
{
    int i;
    int jumps = 0, redirected = 0, unreadable = 0, detail = 0;

    if (!ctx)
        return;

    hook_add_defaults(ctx->ops);

    for (i = 0; i < g_nwatch; i++) {
        void *addr = g_watch[i].addr;
        module_loc loc;
        uint8_t bytes[16];
        prologue_info info;

        if (!addr)
            continue;

        /* --- (c) does the symbol live where it should? --------------- */
        memset(&loc, 0, sizeof(loc));
        loc.addr = (uint64_t)(uintptr_t)addr;
        ctx->ops->enum_modules(find_module_cb, &loc);

        if (!g_watch[i].self_module && loc.found) {
            /* A symbol that does not live in the module that is supposed to
             * own it means an LD_PRELOAD library, a hijacked DLL search
             * order or a patched symbol table redirected it. */
            if (!ctx->ops->is_expected_module(loc.name)) {
                if (detail < HOOK_MAX_DETAIL) {
                    log_event(ctx->log, ETYPE_HOOK_DETECT,
                              "*** %s resolved into \"%s\" "
                              "(expected the core runtime module) @ %p ***",
                              g_watch[i].name, loc.name, addr);
                    detail++;
                }
                redirected++;
            }
        }

        /* --- (a) prologue patch ------------------------------------- */
        if (!ctx->ops->read_safe((uint64_t)(uintptr_t)addr,
                                 bytes, sizeof(bytes))) {
            unreadable++;
            continue;
        }

        info = classify_prologue(bytes, sizeof(bytes),
                                 (uint64_t)(uintptr_t)addr);

        if (!info.is_jump) {
            /* Log the clean baseline once per symbol per run so an analyst
             * can compare against it later. */
            log_event_sev(ctx->log, ETYPE_HOOK_DETECT, SEV_DEBUG,
                          "%s: clean (%02X %02X %02X %02X %02X) @ %p",
                          g_watch[i].name,
                          bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
                          addr);
            continue;
        }

        jumps++;
        log_event(ctx->log, ETYPE_HOOK_DETECT,
                  "*** inline hook: %s -> %s%s @ %p%s ***",
                  g_watch[i].name, info.kind,
                  info.target ? "" : " (target n/a)",
                  addr, info.target ? "" : "");

        if (info.target) {
            module_loc tgt;
            memset(&tgt, 0, sizeof(tgt));
            tgt.addr = info.target;
            ctx->ops->enum_modules(find_module_cb, &tgt);

            log_event(ctx->log, ETYPE_HOOK_DETECT,
                      "    target = 0x%016llx  module = %s",
                      (unsigned long long)info.target,
                      tgt.found ? tgt.name : "(outside any loaded module)");
        }

        if (detail < HOOK_MAX_DETAIL) {
            log_event(ctx->log, ETYPE_HOOK_DETECT,
                      "    prologue: %02X %02X %02X %02X %02X %02X %02X %02X "
                      "%02X %02X %02X %02X %02X %02X %02X %02X",
                      bytes[0], bytes[1], bytes[2], bytes[3],
                      bytes[4], bytes[5], bytes[6], bytes[7],
                      bytes[8], bytes[9], bytes[10], bytes[11],
                      bytes[12], bytes[13], bytes[14], bytes[15]);
            detail++;
        }
    }

    log_event_sev(ctx->log, ETYPE_HOOK_DETECT, SEV_DEBUG,
                  "hook scan: watched=%d inline-hooks=%d redirected=%d "
                  "unreadable=%d",
                  g_nwatch, jumps, redirected, unreadable);
}
