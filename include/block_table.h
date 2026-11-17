/*
 * block_table.h
 * ---------------------------------------------------------------------------
 * Open-addressing hash table keyed by the allocation address (pointer).
 *
 * Why not a plain array like the reference implementation?
 * --------------------------------------------------------
 * The original sample kept blocks in a dense array and searched it linearly
 * on every free() - O(n) per operation with n up to 10000.  With a high
 * allocation rate that becomes the bottleneck.  This table gives expected
 * O(1) insert / find / remove via linear probing over a power-of-two
 * capacity, using a murmur-style finaliser as the hash.
 *
 * Slot states:
 *   0 = EMPTY     never used
 *   1 = LIVE      holds a live allocation
 *   2 = TOMBSTONE removed entry; kept so probing does not break, reusable
 * ---------------------------------------------------------------------------
 */
#ifndef TRACKER_CORE_BLOCK_TABLE_H
#define TRACKER_CORE_BLOCK_TABLE_H

#include "tracker_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Slot state constants (BlockRecord.state). */
#define BT_EMPTY     0u
#define BT_LIVE      1u
#define BT_TOMBSTONE 2u

typedef struct BlockTable {
    BlockRecord *slots;   /* slot array, `cap` entries                     */
    uint32_t     cap;     /* capacity, power of two                        */
    uint32_t     mask;    /* cap - 1                                       */
    uint32_t     count;   /* LIVE entries                                  */
    uint32_t     used;    /* LIVE + TOMBSTONE entries (probe load factor)  */
} BlockTable;

/* Allocate the slot array.  `cap` is rounded up to a power of two;
 * pass 0 to use BLOCK_TABLE_DEFAULT_CAP.  0 on success, -1 on OOM. */
int  bt_init(BlockTable *bt, uint32_t cap);

/* Free the slot array.  Safe to call twice. */
void bt_free(BlockTable *bt);

/* Find a live record by address.  Returns NULL when not tracked. */
BlockRecord *bt_find(BlockTable *bt, uint64_t ptr);

/* Find or create the record for `ptr`.
 *  - existing entry  -> returns it unchanged
 *  - new entry       -> slot is zeroed, ptr/flags/state set, counter bumped
 * Returns NULL only when the table is full. */
BlockRecord *bt_insert(BlockTable *bt, uint64_t ptr);

/* Remove the entry for `ptr`.  Returns 1 if something was removed. */
int  bt_remove(BlockTable *bt, uint64_t ptr);

/* Iterate LIVE entries.  Start with *iter = 0; returns NULL when done.
 * Never returns tombstones.  Do not insert/remove while iterating. */
BlockRecord *bt_next(BlockTable *bt, uint32_t *iter);

/* Number of LIVE entries. */
uint32_t bt_count(const BlockTable *bt);

/* Probe stats for tuning: current load factor in percent. */
uint32_t bt_load_percent(const BlockTable *bt);

#ifdef __cplusplus
}
#endif

#endif /* TRACKER_CORE_BLOCK_TABLE_H */
