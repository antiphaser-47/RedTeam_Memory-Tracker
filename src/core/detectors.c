/*
 * detectors.c - scanner registry.
 *
 * The registry is an ordered array of Scanner records.  Order matters:
 *   heap  first  - consumes alloc/free events before anything else looks at
 *                  the block table
 *   rwx   second - refreshes each block's permission bits, which every later
 *                  detector relies on (ROP only scans executable blocks)
 *   content/hook/rop/ret2libc afterwards
 *
 * Detection coverage by stage:
 *   P2: rwx, entropy, hook
 *   P3: + rop (Capstone), ret2libc
 *   P4: + heap (UAF / double free / redzone)
 * ---------------------------------------------------------------------------
 */
#include "detectors.h"
#include "detector_rwx.h"
#include "detector_entropy.h"
#include "detector_hook.h"
#include "detector_rop.h"
#include "detector_ret2libc.h"
#include "detector_heap.h"

static const Scanner k_table[] = {
    { "heap",     scan_heap_on_event,  scan_heap      },
    { "rwx",      scan_rwx_on_event,   scan_rwx       },
    { "entropy",  NULL,                scan_entropy   },
    { "hook",     NULL,                scan_hooks     },
    { "rop",      NULL,                scan_rop       },
    { "ret2libc", NULL,                scan_ret2libc  },
};

const Scanner *detectors_default_table(size_t *count)
{
    if (count)
        *count = sizeof(k_table) / sizeof(k_table[0]);
    return k_table;
}

void detectors_reset(void)
{
    /* Per-detector state that must not leak between self-test runs. */
    hook_reset();
    heap_reset();
}
