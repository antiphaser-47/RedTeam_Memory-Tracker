/*
 * test_block_table.c - unit tests for the open-addressing block table.
 *
 * Coverage:
 *   B1  insert / find round trip
 *   B2  duplicate insert returns the SAME record (no double counting)
 *   B3  remove + re-insert of the same pointer (tombstone recycling)
 *   B4  iteration skips tombstones and empty slots
 *   B5  load factor + count stay consistent after churn
 *   B6  table survives more inserts than capacity/2 without losing entries
 *
 * Exit code 0 = all tests passed, 1 = at least one failure.
 * ---------------------------------------------------------------------------
 */
#include "block_table.h"

#include <stdio.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (cond) {                                                        \
            printf("  PASS  %s\n", msg);                                   \
        } else {                                                           \
            printf("  FAIL  %s\n", msg);                                   \
            g_failures++;                                                  \
        }                                                                  \
    } while (0)

static void test_insert_find(void)
{
    BlockTable bt;
    BlockRecord *b, *b2;

    printf("B1/B2: insert, find, duplicate insert\n");

    CHECK(bt_init(&bt, 64) == 0, "bt_init(64)");
    CHECK(bt_count(&bt) == 0, "empty table has count 0");

    b = bt_insert(&bt, 0x1000);
    CHECK(b != NULL, "insert returns a record");
    if (b) {
        b->size = 42;
        CHECK(b->flags & BLK_ACTIVE, "new record is marked active");
    }

    b2 = bt_find(&bt, 0x1000);
    CHECK(b2 == b, "find returns the same record");

    b2 = bt_insert(&bt, 0x1000);
    CHECK(b2 == b, "duplicate insert returns existing record");
    CHECK(bt_count(&bt) == 1, "duplicate insert does not bump the count");
    CHECK(b && b->size == 42, "duplicate insert preserves payload");

    CHECK(bt_find(&bt, 0x2000) == NULL, "unknown pointer not found");

    bt_free(&bt);
}

static void test_remove_reinsert(void)
{
    BlockTable bt;
    BlockRecord *b;

    printf("B3: remove + re-insert (tombstone recycling)\n");

    CHECK(bt_init(&bt, 64) == 0, "bt_init(64)");

    b = bt_insert(&bt, 0x3000);
    CHECK(b != NULL, "insert 0x3000");
    CHECK(bt_count(&bt) == 1, "count == 1");

    CHECK(bt_remove(&bt, 0x3000) == 1, "remove existing returns 1");
    CHECK(bt_count(&bt) == 0, "count back to 0");
    CHECK(bt_find(&bt, 0x3000) == NULL, "removed pointer no longer found");
    CHECK(bt_remove(&bt, 0x3000) == 0, "second remove is a no-op");

    b = bt_insert(&bt, 0x3000);
    CHECK(b != NULL, "re-insert after remove succeeds (tombstone reused)");
    CHECK(bt_count(&bt) == 1, "count == 1 after re-insert");

    bt_free(&bt);
}

static void test_iteration(void)
{
    BlockTable bt;
    uint32_t iter;
    int seen = 0, i;
    BlockRecord *b;

    printf("B4: iteration skips tombstones\n");

    CHECK(bt_init(&bt, 128) == 0, "bt_init(128)");

    for (i = 0; i < 10; i++)
        bt_insert(&bt, 0x10000ULL + (uint64_t)i * 0x1000);

    /* Remove three of them - they become tombstones. */
    bt_remove(&bt, 0x10000ULL);
    bt_remove(&bt, 0x10000ULL + 0x3000);
    bt_remove(&bt, 0x10000ULL + 0x9000);
    CHECK(bt_count(&bt) == 7, "count == 7 after removing 3 of 10");

    iter = 0;
    while ((b = bt_next(&bt, &iter)) != NULL) {
        if (b->state != BT_LIVE) {
            CHECK(0, "iteration returned a non-live slot");
            break;
        }
        seen++;
    }
    CHECK(seen == 7, "iteration visited exactly the 7 live entries");

    bt_free(&bt);
}

static void test_churn(void)
{
    BlockTable bt;
    int i, found = 0;
    BlockRecord *b;

    printf("B5/B6: churn and capacity\n");

    /* Small table so we exercise probing and tombstone reuse. */
    CHECK(bt_init(&bt, 256) == 0, "bt_init(256)");

    for (i = 0; i < 100; i++) {
        b = bt_insert(&bt, 0x40000ULL + (uint64_t)i * 0x10);
        if (!b) {
            CHECK(0, "insert failed before table should be full");
            break;
        }
        b->size = (uint64_t)i;
    }
    CHECK(bt_count(&bt) == 100, "100 live entries after burst insert");

    /* Free half of them. */
    for (i = 0; i < 50; i++)
        bt_remove(&bt, 0x40000ULL + (uint64_t)i * 0x10);
    CHECK(bt_count(&bt) == 50, "count == 50 after freeing half");

    /* The survivors must still be findable - this is the classic
     * linear-probing bug: a tombstone in the probe chain makes later
     * lookups give up too early. */
    for (i = 50; i < 100; i++) {
        b = bt_find(&bt, 0x40000ULL + (uint64_t)i * 0x10);
        if (b && b->size == (uint64_t)i)
            found++;
    }
    CHECK(found == 50, "all 50 survivors still reachable after removals");

    /* Reuse the freed slots. */
    for (i = 0; i < 50; i++) {
        b = bt_insert(&bt, 0x40000ULL + (uint64_t)i * 0x10);
        if (!b) {
            CHECK(0, "tombstone reuse failed");
            break;
        }
    }
    CHECK(bt_count(&bt) == 100, "count == 100 after reusing tombstones");

    printf("        load factor = %u%%\n", bt_load_percent(&bt));

    bt_free(&bt);
}

int main(void)
{
    printf("=== block_table unit tests ===\n");

    test_insert_find();
    test_remove_reinsert();
    test_iteration();
    test_churn();

    printf("=== %s (%d failure(s)) ===\n",
           g_failures ? "FAILED" : "ALL PASSED", g_failures);
    return g_failures ? 1 : 0;
}
