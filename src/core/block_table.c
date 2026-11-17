/*
 * block_table.c - open-addressing hash table of live allocations.
 *
 * See include/block_table.h for the slot-state model.
 *
 * Hash: murmur3-style finaliser on the pointer.  Allocation addresses are
 * page aligned (low 12 bits often zero), so the high-entropy avalanche step
 * is what keeps the distribution flat - a naive `ptr >> 12` would collide
 * badly for allocations that differ only in the low bits.
 * ---------------------------------------------------------------------------
 */
#include "block_table.h"

#include <stdlib.h>
#include <string.h>

#define BT_FULL_PROBES 64u   /* give up after this many linear probes */

/* murmur3 fmix64 - finaliser used as our pointer hash. */
static uint64_t hash_ptr(uint64_t p)
{
    p ^= p >> 33;
    p *= 0xff51afd7ed558ccdULL;
    p ^= p >> 33;
    p *= 0xc4ceb9fe1a85ec53ULL;
    p ^= p >> 33;
    return p;
}

static uint32_t next_pow2(uint32_t v)
{
    uint32_t p = 1;

    if (v == 0)
        return 1;
    while (p < v) {
        if (p > (1u << 30))
            return p;
        p <<= 1;
    }
    return p;
}

int bt_init(BlockTable *bt, uint32_t cap)
{
    uint32_t slots;

    if (!bt)
        return -1;

    memset(bt, 0, sizeof(*bt));

    slots = next_pow2(cap ? cap : BLOCK_TABLE_DEFAULT_CAP);
    bt->slots = (BlockRecord *)calloc(slots, sizeof(BlockRecord));
    if (!bt->slots)
        return -1;

    bt->cap   = slots;
    bt->mask  = slots - 1;
    bt->count = 0;
    bt->used  = 0;
    return 0;
}

void bt_free(BlockTable *bt)
{
    if (!bt)
        return;
    free(bt->slots);
    bt->slots = NULL;
    bt->cap   = 0;
    bt->mask  = 0;
    bt->count = 0;
    bt->used  = 0;
}

BlockRecord *bt_find(BlockTable *bt, uint64_t ptr)
{
    uint32_t i, probes;

    if (!bt || !bt->slots || ptr == 0)
        return NULL;

    i = (uint32_t)(hash_ptr(ptr) & bt->mask);

    for (probes = 0; probes < BT_FULL_PROBES; probes++) {
        BlockRecord *s = &bt->slots[i];

        if (s->state == BT_EMPTY)
            return NULL;                 /* stop: no live entry here */

        if (s->state == BT_LIVE && s->ptr == ptr)
            return s;

        i = (i + 1) & bt->mask;          /* linear probe */
    }
    return NULL;
}

BlockRecord *bt_insert(BlockTable *bt, uint64_t ptr)
{
    uint32_t i, probes;
    uint32_t first_tomb = UINT32_MAX;
    BlockRecord *existing = NULL;

    if (!bt || !bt->slots || ptr == 0)
        return NULL;

    i = (uint32_t)(hash_ptr(ptr) & bt->mask);

    /* Pass 1: look for the pointer (reuse) or remember the first tombstone
     * we can recycle. */
    for (probes = 0; probes < BT_FULL_PROBES; probes++) {
        BlockRecord *s = &bt->slots[i];

        if (s->state == BT_EMPTY) {
            uint32_t use = (first_tomb != UINT32_MAX) ? first_tomb : i;

            if (first_tomb != UINT32_MAX) {
                /* Reusing a tombstone: slot already counted in `used`. */
                s = &bt->slots[use];
            } else {
                bt->used++;
            }

            memset(s, 0, sizeof(*s));
            s->ptr   = ptr;
            s->flags = BLK_ACTIVE;
            s->state = BT_LIVE;
            bt->count++;
            return s;
        }

        if (s->state == BT_TOMBSTONE) {
            if (first_tomb == UINT32_MAX)
                first_tomb = i;
        } else if (s->ptr == ptr) {
            existing = s;
            break;
        }

        i = (i + 1) & bt->mask;
    }

    if (existing)
        return existing;

    /* Table full (or probe budget exhausted) and we saw a tombstone:
     * recycle it. */
    if (first_tomb != UINT32_MAX) {
        BlockRecord *s = &bt->slots[first_tomb];

        memset(s, 0, sizeof(*s));
        s->ptr   = ptr;
        s->flags = BLK_ACTIVE;
        s->state = BT_LIVE;
        bt->count++;
        return s;
    }

    return NULL;                         /* table full */
}

int bt_remove(BlockTable *bt, uint64_t ptr)
{
    BlockRecord *s = bt_find(bt, ptr);

    if (!s)
        return 0;

    memset(s, 0, sizeof(*s));
    s->state = BT_TOMBSTONE;
    bt->count--;
    return 1;
}

BlockRecord *bt_next(BlockTable *bt, uint32_t *iter)
{
    if (!bt || !bt->slots || !iter)
        return NULL;

    while (*iter < bt->cap) {
        BlockRecord *s = &bt->slots[*iter];
        (*iter)++;
        if (s->state == BT_LIVE)
            return s;
    }
    return NULL;
}

uint32_t bt_count(const BlockTable *bt)
{
    return bt ? bt->count : 0;
}

uint32_t bt_load_percent(const BlockTable *bt)
{
    if (!bt || bt->cap == 0)
        return 0;
    return (uint32_t)((uint64_t)bt->used * 100u / bt->cap);
}
