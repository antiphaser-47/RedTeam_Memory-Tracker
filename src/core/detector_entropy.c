/*
 * detector_entropy.c - content based payload detection.
 *
 * Four independent signals, all computed over the first up-to-4 KiB of a
 * tracked block (reading is fault-proof, see platform read_safe):
 *
 *  1. Shannon entropy  H = -sum(p_i * log2 p_i)
 *       0   = perfectly repetitive (all 0x00 / all 0x41)
 *       ~4  = normal English text or compiled code
 *       7.5+= strong encryption or a well packed / encoded payload
 *     Shellcode is rarely stored in the clear, so encrypted blobs are one
 *     of the most reliable "something is staged here" indicators.
 *
 *  2. NOP sled        - a run of >= 16 bytes of 0x90.
 *     Attackers pad payloads so that "landing" anywhere in the sled still
 *     slides down into the real entry point (e.g. when the exact address
 *     cannot be predicted).
 *
 *  3. INT3 sled       - same idea using 0xCC, common in Windows payloads
 *     and in debug stubs.
 *
 *  4. Printable ratio - normal text/strings are almost all printable ASCII.
 *     A block that is >90% non-printable bytes is machine code or binary
 *     data, not data the application meant to keep as text.
 *
 * [why it works]  Encrypted/padded payloads cannot avoid leaving these
 * statistical traces behind.  [how to do it]  compute them over a bounded
 * window of each block during the scan phase and tag the block.
 * ---------------------------------------------------------------------------
 */
#include "detector_entropy.h"

#include <math.h>
#include <string.h>

#define ENTROPY_MAX_DETAIL 16

/* Shannon entropy over `size` bytes.  Returns 0.0 for empty input. */
static double shannon_entropy(const uint8_t *data, size_t size)
{
    size_t freq[256] = {0};
    double h = 0.0;
    size_t i;

    if (!data || size == 0)
        return 0.0;

    for (i = 0; i < size; i++)
        freq[data[i]]++;

    for (i = 0; i < 256; i++) {
        double p;

        if (!freq[i])
            continue;
        p = (double)freq[i] / (double)size;
        h -= p * log2(p);
    }
    return h;
}

/* Longest run of `needle` bytes. */
static size_t longest_run(const uint8_t *data, size_t size, uint8_t needle)
{
    size_t best = 0, cur = 0, i;

    for (i = 0; i < size; i++) {
        if (data[i] == needle) {
            cur++;
            if (cur > best)
                best = cur;
        } else {
            cur = 0;
        }
    }
    return best;
}

static void add_tag(BlockRecord *b, const char *tag)
{
    if (b->tag[0])
        strncat(b->tag, ",", sizeof(b->tag) - strlen(b->tag) - 1);
    strncat(b->tag, tag, sizeof(b->tag) - strlen(b->tag) - 1);
    b->flags |= BLK_SUSPICIOUS;
}

void scan_entropy(ScanContext *ctx)
{
    BlockRecord *b;
    uint32_t iter = 0;
    uint8_t buf[SCAN_MAX_BYTES_PER_BLOCK];
    int high_entropy = 0, nops = 0, int3s = 0, low_print = 0;
    int detail_budget = ENTROPY_MAX_DETAIL;

    if (!ctx)
        return;

    while ((b = bt_next(ctx->blocks, &iter)) != NULL) {
        size_t want = b->size < sizeof(buf) ? (size_t)b->size : sizeof(buf);
        size_t printable = 0, i;
        double e;
        size_t nop_run, int3_run;

        if (want == 0)
            continue;

        /* Fault-proof read: the block may have been freed/unmapped between
         * the alloc event and this scan. */
        if (!ctx->ops->read_safe(b->ptr, buf, want))
            continue;

        e = shannon_entropy(buf, want);
        b->entropy = e;

        for (i = 0; i < want; i++) {
            if (buf[i] >= 0x20 && buf[i] < 0x7f)
                printable++;
        }

        /* ---- 1. high entropy ---------------------------------- */
        if (e > ENTROPY_THRESHOLD && (b->hit_mask & HIT_HIGH_ENTROPY) == 0) {
            b->hit_mask |= HIT_HIGH_ENTROPY;
            add_tag(b, "HIGH_ENTROPY");

            if (detail_budget > 0) {
                log_event(ctx->log, ETYPE_HIGH_ENTROPY,
                          "entropy %.2f > %.2f @ 0x%016llx size=%llu "
                          "(possibly encrypted/encoded payload)",
                          e, (double)ENTROPY_THRESHOLD,
                          (unsigned long long)b->ptr,
                          (unsigned long long)b->size);
                detail_budget--;
            }
            high_entropy++;
        }

        /* ---- 2. NOP sled -------------------------------------- */
        nop_run = longest_run(buf, want, 0x90);
        if (nop_run >= NOP_SLED_MIN_RUN &&
            (b->hit_mask & HIT_NOP_SLED) == 0) {
            b->hit_mask |= HIT_NOP_SLED;
            add_tag(b, "NOP_SLED");
            log_event(ctx->log, ETYPE_NOP_SLED,
                      "NOP sled of %u byte(s) @ 0x%016llx "
                      "(landing pad for shellcode)",
                      (unsigned)nop_run, (unsigned long long)b->ptr);
            nops++;
        }

        /* ---- 3. INT3 sled ------------------------------------- */
        int3_run = longest_run(buf, want, 0xCC);
        if (int3_run >= INT3_SLED_MIN_RUN &&
            (b->hit_mask & HIT_INT3_SLED) == 0) {
            b->hit_mask |= HIT_INT3_SLED;
            add_tag(b, "INT3_SLED");
            log_event(ctx->log, ETYPE_INT3_SLED,
                      "INT3 sled of %u byte(s) @ 0x%016llx",
                      (unsigned)int3_run, (unsigned long long)b->ptr);
            int3s++;
        }

        /* ---- 4. printable ratio --------------------------------
         * Only meaningful for ordinary data blocks.  Blocks that are
         * executable (shellcode) or that already produced a code-shaped
         * signal (sled / encryption) are excluded so one payload does not
         * generate three redundant alerts. */
        if (want >= 64 &&
            (b->hit_mask & (HIT_HIGH_ENTROPY | HIT_NOP_SLED |
                            HIT_INT3_SLED)) == 0 &&
            (b->perms & PERM_X) == 0) {
            double ratio = (double)printable / (double)want;

            if (ratio < PRINTABLE_RATIO_MIN &&
                (b->hit_mask & HIT_LOW_PRINTABLE) == 0 &&
                (b->hit_mask & HIT_HIGH_ENTROPY) == 0) {
                b->hit_mask |= HIT_LOW_PRINTABLE;
                add_tag(b, "LOW_PRINTABLE");
                log_event(ctx->log, ETYPE_LOW_PRINTABLE,
                          "only %.1f%% printable bytes @ 0x%016llx "
                          "(machine code / binary blob)",
                          ratio * 100.0, (unsigned long long)b->ptr);
                low_print++;
            }
        }
    }

    if (high_entropy || nops || int3s || low_print)
        log_event_sev(ctx->log, ETYPE_STATS, SEV_DEBUG,
                      "content scan: new high-entropy=%d nop-sled=%d "
                      "int3-sled=%d low-printable=%d",
                      high_entropy, nops, int3s, low_print);
}
