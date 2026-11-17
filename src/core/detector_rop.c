/*
 * detector_rop.c - ROP gadget detection with Capstone verification.
 *
 * [why it works]
 *   A ROP chain is built entirely out of existing code: the attacker never
 *   injects instructions, they only redirect `ret` into short instruction
 *   fragments ("gadgets") that end in a control-transfer instruction.
 *   For that to be possible the fragments must already exist somewhere
 *   readable-and-executable, which means we can find them by disassembling
 *   executable memory and looking for the shapes an attacker needs:
 *
 *     pop reg; ret               - load an argument, then continue the chain
 *     xchg reg, rsp; ret         - stack pivot onto attacker-controlled data
 *     syscall; ret               - raw kernel call, bypasses libc hooks
 *     leave; ret                 - frame-pointer based pivot
 *     pop ... ; ret (multi)      - set several arguments at once
 *
 * [why Capstone instead of raw byte matching]
 *   A naive scan for the two bytes `58 C3` matches almost anything: those
 *   bytes appear inside the immediates of unrelated instructions, in string
 *   constants, in compressed data...  That is exactly the false-positive
 *   problem the naive version has.  Capstone decodes linearly from every
 *   offset and only reports a gadget when the CPU would *actually* execute
 *   that instruction sequence starting at that address - which is the real
 *   definition of a gadget.
 *
 * [how to do it]
 *   1. only scan regions whose permissions include X (executable)
 *   2. capstone-disassemble from every offset up to a small window
 *   3. accept only sequences ending in RET / JMP RAX / SYSCALL with at most
 *      N instructions, where every instruction is on the attacker's wish
 *      list (pop / xchg / mov / leave / int)
 *   4. cap the number of reported gadgets per block so one code-heavy block
 *      cannot flood the log
 * ---------------------------------------------------------------------------
 */
#include "detector_rop.h"

#include <capstone/capstone.h>
#include <string.h>

/* Per-block limits: bounded work per scan cycle. */
#define ROP_MAX_INSTR     6      /* longest accepted gadget (instructions)  */
#define ROP_MAX_PER_BLOCK 8      /* reported gadgets before summarising     */
#define ROP_MAX_BLOCKS    64     /* blocks we detail-report per cycle       */

typedef struct {
    const char *mnemonic;
    const char *operand_prefix;  /* NULL = accept any operand              */
} gadget_step;

/* The canonical attacker-useful fragments, ordered by usefulness. */
static const char *const k_pop_mnemonics[] = {
    "pop", "popa", "popad"
};

static int is_pop(const cs_insn *in)
{
    size_t i;

    for (i = 0; i < sizeof(k_pop_mnemonics) / sizeof(k_pop_mnemonics[0]); i++) {
        if (!strcmp(in->mnemonic, k_pop_mnemonics[i]))
            return 1;
    }
    return 0;
}

static int is_pivot(const cs_insn *in)
{
    /* Stack pivots: move a controlled value into RSP. */
    if (!strcmp(in->mnemonic, "xchg") &&
        (strstr(in->op_str, "rsp") || strstr(in->op_str, "esp")))
        return 1;
    if (!strcmp(in->mnemonic, "leave"))
        return 1;
    return 0;
}

/* `ret` / `retn` / `retf` - the instruction that closes a gadget. */
static int is_ret_insn(const cs_insn *in)
{
    return !strcmp(in->mnemonic, "ret") ||
           !strcmp(in->mnemonic, "retn") ||
           !strcmp(in->mnemonic, "retf");
}

/*
 * Detect the "zero-fill artifact".
 *
 * A page of 0x00 bytes (or 0xFF) decodes as a long run of
 *   `add byte ptr [rax], al`
 * which Capstone will happily chain into things like
 *   `add byte ptr [rax], al; add byte ptr [rax], al; pop rdi; ret`
 * Technically executable, practically meaningless: it is padding, not a
 * fragment an attacker chose.  Byte patterns that decode to a byte-sized
 * memory ALU operation are the unmistakable signature of uninitialised or
 * zeroed memory, so chains containing them are rejected.
 */
static int is_pad_artifact(const cs_insn *in)
{
    static const char *const k_alu[] = {
        "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp",
        "mov", "test"
    };
    size_t i;

    for (i = 0; i < sizeof(k_alu) / sizeof(k_alu[0]); i++) {
        if (!strcmp(in->mnemonic, k_alu[i]) &&
            !strncmp(in->op_str, "byte ptr [", 10))
            return 1;
    }
    return 0;
}

static int is_useful_reg_op(const cs_insn *in)
{
    static const char *const k_ok[] = {
        "mov", "movzx", "movsx", "lea", "add", "sub", "xor", "and", "or",
        "shl", "shr", "sar", "imul", "neg", "not", "inc", "dec", "push"
    };
    size_t i;

    for (i = 0; i < sizeof(k_ok) / sizeof(k_ok[0]); i++) {
        if (!strcmp(in->mnemonic, k_ok[i]))
            return 1;
    }
    return 0;
}

/* Does this instruction end a gadget usefully? */
static int terminates(const cs_insn *in)
{
    if (is_ret_insn(in))
        return 1;

    /* syscall; ret and jmp rax style terminators are high value. */
    if (!strcmp(in->mnemonic, "syscall") || !strcmp(in->mnemonic, "sysenter"))
        return 1;
    if (!strcmp(in->mnemonic, "jmp") &&
        (strstr(in->op_str, "rax") || strstr(in->op_str, "eax") ||
         strstr(in->op_str, "rsp") || strstr(in->op_str, "esp")))
        return 1;
    return 0;
}

/* A gadget must START with something an attacker can use.  A bare `ret`
 * (or a run of them, which is what a page filled with 0xC3 decodes to) is
 * not a gadget - it is padding, and reporting it would drown the real
 * findings in noise. */
static int is_valid_start(const cs_insn *in)
{
    if (is_ret_insn(in))
        return 0;
    if (is_pad_artifact(in))
        return 0;
    if (is_pop(in) || is_pivot(in) || is_useful_reg_op(in))
        return 1;
    if (!strcmp(in->mnemonic, "syscall") || !strcmp(in->mnemonic, "sysenter"))
        return 1;
    if (!strcmp(in->mnemonic, "jmp") &&
        (strstr(in->op_str, "rax") || strstr(in->op_str, "eax") ||
         strstr(in->op_str, "rsp") || strstr(in->op_str, "esp")))
        return 1;
    return 0;
}

/* Score a complete gadget so we can keep the most dangerous ones. */
static int gadget_score(const cs_insn *insns, size_t count)
{
    size_t i;
    int score = 0;

    for (i = 0; i < count; i++) {
        if (is_pop(&insns[i]))                 score += 2;
        if (is_pivot(&insns[i]))               score += 5;
        if (!strcmp(insns[i].mnemonic, "syscall")) score += 6;
        if (!strcmp(insns[i].mnemonic, "jmp")) score += 4;
    }
    return score;
}

/* Format a gadget as "pop rdi; ret". */
static void format_gadget(const cs_insn *insns, size_t count,
                          char *out, size_t out_len)
{
    size_t used = 0;
    size_t i;

    out[0] = '\0';
    for (i = 0; i < count; i++) {
        int n;

        n = snprintf(out + used, out_len - used, "%s%s%s",
                     used ? "; " : "",
                     insns[i].mnemonic,
                     insns[i].op_str[0] ? " " : "");
        if (n < 0 || (size_t)n >= out_len - used)
            break;
        used += (size_t)n;

        n = snprintf(out + used, out_len - used, "%s",
                     insns[i].op_str);
        if (n < 0 || (size_t)n >= out_len - used)
            break;
        used += (size_t)n;
    }
}

/* =========================================================================
 * The scan
 * ====================================================================== */

void scan_rop(ScanContext *ctx)
{
    BlockRecord *b;
    uint32_t iter = 0;
    csh handle;
    int cs_ok;
    int blocks_flagged = 0, blocks_scanned = 0;
    uint8_t buf[SCAN_MAX_BYTES_PER_BLOCK];

    if (!ctx)
        return;

    cs_ok = (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK);
    if (!cs_ok) {
        log_event(ctx->log, ETYPE_ERROR,
                  "ROP: capstone initialisation failed - detector disabled");
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    while ((b = bt_next(ctx->blocks, &iter)) != NULL) {
        size_t want, off;
        int found = 0;
        int reported = 0;
        char sample[192];

        /* Gadget hunting only makes sense in executable memory: a gadget in
         * a data page is a coincidence, not a chain. */
        if ((b->perms & PERM_X) == 0)
            continue;
        if (b->size < 4)
            continue;

        want = b->size < sizeof(buf) ? (size_t)b->size : sizeof(buf);
        if (!ctx->ops->read_safe(b->ptr, buf, want))
            continue;

        blocks_scanned++;
        sample[0] = '\0';

        /* Linear sweep: try to start a gadget at every offset.  Capstone
         * will refuse offsets that are not instruction boundaries, which is
         * exactly the correctness property we want. */
        for (off = 0; off + 1 < want; off++) {
            cs_insn *insn = NULL;
            size_t n, i;
            size_t window = want - off;
            int score;

            if (window > 32)
                window = 32;              /* no gadget needs more than 32 B */

            n = cs_disasm(handle, buf + off, window,
                          (uint64_t)(b->ptr + off), 0, &insn);
            if (n == 0)
                continue;

            /* Walk forward until a terminator or the window/instruction
             * budget runs out.  The first instruction must be something an
             * attacker can actually start a chain with. */
            for (i = 0; i < n && i < ROP_MAX_INSTR; i++) {
                const cs_insn *in = &insn[i];

                if (i == 0) {
                    if (!is_valid_start(in))
                        break;            /* e.g. a bare `ret` - padding */
                    continue;
                }

                if (terminates(in)) {
                    char text[192];

                    score = gadget_score(insn, i + 1);
                    format_gadget(insn, i + 1, text, sizeof(text));

                    found++;
                    if (reported < ROP_MAX_PER_BLOCK) {
                        log_event(ctx->log, ETYPE_ROP_DETECT,
                                  "gadget: %s @ 0x%016llx (score=%d)",
                                  text,
                                  (unsigned long long)(b->ptr + off),
                                  score);
                        if (!sample[0])
                            snprintf(sample, sizeof(sample), "%s", text);
                        reported++;
                    }
                    break;
                }

                if (!is_pop(in) && !is_pivot(in) && !is_useful_reg_op(in))
                    break;                /* unusable instruction in the chain */

                if (is_pad_artifact(in))
                    break;                /* zero-fill padding, not a gadget */
            }

            cs_free(insn, n);
        }

        if (found > 0) {
            b->gadget_count = (uint32_t)found;
            b->hit_mask    |= HIT_ROP;
            b->flags       |= BLK_SUSPICIOUS;

            if (b->tag[0])
                strncat(b->tag, ",ROP", sizeof(b->tag) - strlen(b->tag) - 1);
            else
                strncat(b->tag, "ROP", sizeof(b->tag) - strlen(b->tag) - 1);

            if (blocks_flagged < ROP_MAX_BLOCKS) {
                log_event(ctx->log, ETYPE_ROP_DETECT,
                          "%d gadget(s) in executable block @ 0x%016llx "
                          "size=%llu first=\"%s\"",
                          found,
                          (unsigned long long)b->ptr,
                          (unsigned long long)b->size,
                          sample[0] ? sample : "-");
            }
            blocks_flagged++;
        }
    }

    cs_close(&handle);

    log_event_sev(ctx->log, ETYPE_STATS, SEV_DEBUG,
                  "ROP scan: executable blocks=%d flagged=%d",
                  blocks_scanned, blocks_flagged);
}
