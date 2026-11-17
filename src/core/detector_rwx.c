/*
 * detector_rwx.c - read-write-execute region detection + permission
 *                  transitions.
 *
 * [why it works]
 *   DEP/NX exists precisely so that writable pages are never executable.
 *   Shellcode has to live *somewhere* while it is being written, and it has
 *   to be executable while it runs - so attackers either (a) allocate a page
 *   that is RWX from the start, or (b) allocate RW, write, then flip it to
 *   RX with mprotect/VirtualProtect.  Both are visible to a tracker that
 *   re-reads the permission bits of every tracked block.
 *
 * [how to do it]
 *   on_event : catch RWX at allocation time (fast path, happens while the
 *              recording window is open, so the alert lands in the log with
 *              full context).
 *   on_scan  : re-query every live block's permissions; flag brand new RWX
 *              regions and any block whose permission mask changed since it
 *              was recorded (the RW -> RX transition signature).
 * ---------------------------------------------------------------------------
 */
#include "detector_rwx.h"

#include <string.h>

/* How many blocks we report in detail per scan before switching to a
 * summary line.  Keeps a pathological scan (thousands of RWX blocks) from
 * flooding the log. */
#define RWX_MAX_DETAIL 32

void scan_rwx_on_event(ScanContext *ctx, const TraceEvent *ev)
{
    BlockRecord *b;
    uint32_t perms;

    if (!ctx || !ev)
        return;

    if (ev->type != ETYPE_ALLOC)
        return;

    perms = (uint32_t)ev->aux;
    if ((perms & PERM_W) == 0 || (perms & PERM_X) == 0)
        return;                         /* not writable+executable */

    b = bt_find(ctx->blocks, ev->ptr);
    if (b) {
        b->hit_mask |= HIT_RWX;
        b->flags    |= BLK_SUSPICIOUS;
        if (b->tag[0])
            strncat(b->tag, ",RWX", sizeof(b->tag) - strlen(b->tag) - 1);
        else
            strncat(b->tag, "RWX", sizeof(b->tag) - strlen(b->tag) - 1);
    }

    log_event(ctx->log, ETYPE_RWX_ALERT,
              "RWX region allocated @ 0x%016llx size=%llu perms=0x%x "
              "stack=0x%016llx",
              (unsigned long long)ev->ptr,
              (unsigned long long)ev->size,
              (unsigned)perms,
              (unsigned long long)ev->stack_hash);

    /* A brand new RWX region is the single most indicative signal we have -
     * show the first few bytes so an analyst can eyeball the payload
     * without attaching a debugger. */
    {
        uint8_t buf[32];
        size_t n = ev->size < sizeof(buf) ? (size_t)ev->size : sizeof(buf);

        if (n && ctx->ops->read_safe(ev->ptr, buf, n)) {
            log_event_sev(ctx->log, ETYPE_RWX_ALERT, SEV_ALERT,
                          "first %u byte(s) of the RWX region:", (unsigned)n);
            log_hexdump(ctx->log, buf, n, 2);
        }
    }
}

void scan_rwx(ScanContext *ctx)
{
    BlockRecord *b;
    uint32_t iter = 0;
    int flagged = 0, transitions = 0, total_rwx = 0;

    if (!ctx)
        return;

    while ((b = bt_next(ctx->blocks, &iter)) != NULL) {
        uint32_t now = ctx->ops->get_perms(b->ptr);
        uint32_t before = b->perms;

        if (now == 0)
            continue;                   /* unmapped / not queryable */

        /* --- brand new RWX region ------------------------------- */
        if ((now & PERM_W) && (now & PERM_X)) {
            total_rwx++;

            if ((b->hit_mask & HIT_RWX) == 0) {
                b->hit_mask |= HIT_RWX;
                b->flags    |= BLK_SUSPICIOUS;
                if (b->tag[0])
                    strncat(b->tag, ",RWX",
                            sizeof(b->tag) - strlen(b->tag) - 1);
                else
                    strncat(b->tag, "RWX",
                            sizeof(b->tag) - strlen(b->tag) - 1);

                if (flagged < RWX_MAX_DETAIL) {
                    log_event(ctx->log, ETYPE_RWX_ALERT,
                              "RWX region @ 0x%016llx size=%llu perms=0x%x "
                              "(found during scan)",
                              (unsigned long long)b->ptr,
                              (unsigned long long)b->size,
                              (unsigned)now);
                    flagged++;
                }
            }
        }

        /* --- permission transition --------------------------------
         * Example: 0x3 (RW) -> 0x5 (RX) means somebody wrote code into the
         * page and then made it executable - the classic "write then flip"
         * shellcode staging pattern. */
        if (before && now != before) {
            if ((b->hit_mask & HIT_PERM_CHANGE) == 0) {
                b->hit_mask |= HIT_PERM_CHANGE;
                b->flags    |= BLK_SUSPICIOUS;
                if (b->tag[0])
                    strncat(b->tag, ",PERM_CHANGE",
                            sizeof(b->tag) - strlen(b->tag) - 1);
                else
                    strncat(b->tag, "PERM_CHANGE",
                            sizeof(b->tag) - strlen(b->tag) - 1);
            }

            log_event(ctx->log, ETYPE_PERM_CHANGE,
                      "permissions changed @ 0x%016llx: 0x%x -> 0x%x "
                      "(%s%s%s -> %s%s%s)",
                      (unsigned long long)b->ptr,
                      (unsigned)before, (unsigned)now,
                      (before & PERM_R) ? "r" : "-",
                      (before & PERM_W) ? "w" : "-",
                      (before & PERM_X) ? "x" : "-",
                      (now    & PERM_R) ? "r" : "-",
                      (now    & PERM_W) ? "w" : "-",
                      (now    & PERM_X) ? "x" : "-");
            transitions++;
        }

        b->perms = now;                 /* remember for the next comparison */
    }

    if (flagged >= RWX_MAX_DETAIL)
        log_event(ctx->log, ETYPE_RWX_ALERT,
                  "... %d additional RWX region(s) not listed individually",
                  total_rwx - RWX_MAX_DETAIL);

    if (transitions)
        log_event(ctx->log, ETYPE_PERM_CHANGE,
                  "%d permission transition(s) observed this cycle",
                  transitions);
}
