/*
 * tracker_types.h
 * ---------------------------------------------------------------------------
 * Shared, platform-free type definitions for the CoreSight-style real-time
 * memory tracker.
 *
 * This header deliberately depends only on <stdint.h> and <stddef.h> so the
 * exact same definitions compile for:
 *
 *   - Linux   user space  (gcc)
 *   - Windows user space  (x86_64-w64-mingw32-gcc)
 *   - Linux   kernel      (src/kmod mirrors the layout with kernel types)
 *
 * Design rationale (why a fixed 64-byte event?)
 * ---------------------------------------------
 * A real ARM CoreSight implementation streams fixed-size trace packets into a
 * hardware FIFO / trace buffer (ETR/ETF).  We imitate that in software: every
 * event is exactly 64 bytes so the ring buffer can overwrite slots in place
 * without any reallocation, and so one event == one cache line which avoids
 * "false sharing" between the producer and the consumer thread.
 * ---------------------------------------------------------------------------
 */
#ifndef TRACKER_CORE_TYPES_H
#define TRACKER_CORE_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Tunable constants
 * ====================================================================== */

/* Ring buffer capacity (slots).  MUST be a power of two so that the code can
 * replace the expensive modulo (%) with a cheap bitwise AND (mask).
 * 16384 slots * 64 bytes = 1 MiB of event storage. */
#define RING_DEFAULT_SIZE        (1u << 14)

/* Block table capacity (slots).  Power of two, open addressing. */
#define BLOCK_TABLE_DEFAULT_CAP  (1u << 14)

/* Maximum call-stack frames captured when fingerprinting an allocation. */
#define MAX_STACK_DEPTH          32

/* Maximum length of the human readable tag string attached to a block. */
#define MAX_TAG_LEN              64

/* Scheduler cadence: one full cycle every SCAN_INTERVAL_SEC seconds, of which
 * the first RECORD_DURATION_SEC seconds is the "recording window" (events are
 * tagged in-window and get detailed logging), the rest is idle/sleep. */
#define SCAN_INTERVAL_SEC        20u
#define RECORD_DURATION_SEC      3u
#define FIRST_SCAN_DELAY_SEC     1u

/* Shannon entropy above this value is considered "high entropy"
 * (0 = perfectly repetitive, 8 = perfectly random / strong encryption). */
#define ENTROPY_THRESHOLD        7.5

/* Minimum consecutive byte run that counts as a NOP sled / INT3 sled. */
#define NOP_SLED_MIN_RUN         16
#define INT3_SLED_MIN_RUN        16

/* Minimum fraction of printable ASCII characters below which a block is
 * flagged as suspicious (shellcode is mostly non-printable). */
#define PRINTABLE_RATIO_MIN      0.10

/* Per-block byte budget for content scans during one scan phase.  Keeps the
 * scan phase bounded even when many megabytes are tracked. */
#define SCAN_MAX_BYTES_PER_BLOCK (4096u)

/* =========================================================================
 * Memory permission bits (OS neutral)
 * ====================================================================== */

#define PERM_R      0x1u
#define PERM_W      0x2u
#define PERM_X      0x4u
#define PERM_RWX    (PERM_R | PERM_W | PERM_X)

/* =========================================================================
 * Event flags
 * ====================================================================== */

/* Set when the event was pushed while the 3-second recording window was open.
 * Only in-window events receive detailed log lines; out-of-window events are
 * still drained (to keep the ring from overflowing) but only counted. */
#define EVF_IN_WINDOW   0x0001u

/* =========================================================================
 * Block flags (BlockRecord.flags)
 * ====================================================================== */

#define BLK_ACTIVE      0x0001u   /* allocation currently live */
#define BLK_SUSPICIOUS  0x0002u   /* at least one detector fired on it */

/* =========================================================================
 * Detection hit bits (BlockRecord.hit_mask) - bitmask of every rule that
 * fired on this block.  Useful for building a per-block "evidence" summary.
 * ====================================================================== */

#define HIT_RWX           0x0001u
#define HIT_HIGH_ENTROPY  0x0002u
#define HIT_ROP           0x0004u
#define HIT_RET2LIBC      0x0008u
#define HIT_HOOK          0x0010u
#define HIT_UAF           0x0020u
#define HIT_DOUBLE_FREE   0x0040u
#define HIT_OVERFLOW      0x0080u
#define HIT_NOP_SLED      0x0100u
#define HIT_INT3_SLED     0x0200u
#define HIT_LOW_PRINTABLE 0x0400u
#define HIT_PERM_CHANGE   0x0800u

/* =========================================================================
 * Event types - every distinct thing the tracker can report.
 * The numeric values are part of the on-disk log format, so append only.
 * ====================================================================== */

typedef enum EventType {
    ETYPE_NONE          = 0,
    ETYPE_ALLOC         = 1,   /* memory allocation recorded            */
    ETYPE_FREE          = 2,   /* memory freed (lifetime computed)      */
    ETYPE_HOOK_DETECT   = 3,   /* inline hook / GOT tampering check     */
    ETYPE_ROP_DETECT    = 4,   /* ROP gadget confirmed by disassembly   */
    ETYPE_RET2LIBC      = 5,   /* dangerous libc/win function addresses */
    ETYPE_RWX_ALERT     = 6,   /* read-write-execute region detected    */
    ETYPE_HIGH_ENTROPY  = 7,   /* content entropy above threshold       */
    ETYPE_UAF           = 8,   /* use-after-free                        */
    ETYPE_DOUBLE_FREE   = 9,   /* double free                           */
    ETYPE_OVERFLOW      = 10,  /* redzone / heap metadata corruption    */
    ETYPE_PERM_CHANGE   = 11,  /* permission transition (e.g. RW -> RX) */
    ETYPE_NOP_SLED      = 12,  /* long run of 0x90 bytes               */
    ETYPE_INT3_SLED     = 13,  /* long run of 0xCC bytes               */
    ETYPE_LOW_PRINTABLE = 14,  /* mostly non-printable content         */
    ETYPE_SCAN_BEGIN    = 15,  /* scan phase started                   */
    ETYPE_SCAN_END      = 16,  /* scan phase finished + summary        */
    ETYPE_STATS         = 17,  /* periodic statistics                  */
    ETYPE_ERROR         = 18,  /* internal error / unreadable memory   */
    ETYPE__COUNT        = 19
} EventType;

/* Severity levels used for colouring and for log filtering. */
typedef enum Severity {
    SEV_DEBUG    = 0,
    SEV_INFO     = 1,
    SEV_WARN     = 2,
    SEV_ALERT    = 3,
    SEV_CRITICAL = 4
} Severity;

/* =========================================================================
 * TraceEvent - the unit of data stored in the circular buffer.
 * Layout is intentionally identical to the kernel-side event so that a log
 * produced by user space and one produced by the .ko can be correlated.
 *
 * Field-by-field size check (must total 64 bytes):
 *   seq          8
 *   timestamp_ns 8
 *   type         4
 *   flags        2
 *   cpu          2
 *   ptr          8
 *   size         8
 *   pid          4
 *   aux          4
 *   caller_ip    8
 *   stack_hash   8
 *   -------------------
 *   total       64
 * ====================================================================== */

typedef struct TraceEvent {
    uint64_t seq;            /* monotonic event id, assigned at push time  */
    uint64_t timestamp_ns;   /* clock_gettime / ktime_get_ns               */
    uint32_t type;           /* EventType                                  */
    uint16_t flags;          /* EVF_*                                      */
    uint16_t cpu;            /* CPU core (user space: 0)                   */
    uint64_t ptr;            /* address of the affected memory block       */
    uint64_t size;           /* size in bytes (alloc size / block size)    */
    int32_t  pid;            /* process id that triggered the event        */
    int32_t  aux;            /* type-specific payload (perms, entropyx100,
                                gadget count, ...)                         */
    uint64_t caller_ip;      /* return address of the allocating caller    */
    uint64_t stack_hash;     /* FNV-1a fingerprint of the call stack       */
} TraceEvent;

/* =========================================================================
 * BlockRecord - one tracked allocation inside the block hash table.
 * ====================================================================== */

typedef struct BlockRecord {
    uint64_t ptr;            /* block start address (hash key)            */
    uint64_t size;           /* block size in bytes                        */
    uint64_t alloc_time_ns;  /* allocation timestamp                       */
    uint64_t stack_hash;     /* FNV-1a fingerprint of allocation call path */
    double   entropy;        /* Shannon entropy of first 4 KiB (0..8)      */
    uint32_t perms;          /* PERM_* bitmask observed at scan time       */
    uint32_t flags;          /* BLK_*                                      */
    uint32_t hit_mask;       /* HIT_* - every rule that fired              */
    uint32_t gadget_count;   /* ROP gadgets found in this block            */
    uint32_t state;          /* table slot state: 0 empty / 1 live / 2 tomb */
    uint32_t _pad;           /* keep the struct 8-byte aligned             */
    char     tag[MAX_TAG_LEN];/* comma separated tag list, e.g. "RWX,ROP"  */
} BlockRecord;

/* The ring buffer math relies on this being exactly one cache line. */
_Static_assert(sizeof(TraceEvent) == 64,
               "TraceEvent must be exactly 64 bytes (one cache line)");

/* =========================================================================
 * Shared helper prototypes (implemented in src/core/logger.c)
 * ====================================================================== */

/* Return a stable human readable name for an event type, e.g. "[RWX]". */
const char *event_type_name(EventType type);

/* Return a stable human readable name for a severity, e.g. "ALERT". */
const char *severity_name(Severity sev);

/* Map an event type to its default severity. */
Severity event_severity(EventType type);

/* Build a comma separated description of every HIT_* bit in a mask.
 * The result is written into `out` (out_len bytes, always NUL terminated). */
void hit_mask_to_string(uint32_t hit_mask, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* TRACKER_CORE_TYPES_H */
