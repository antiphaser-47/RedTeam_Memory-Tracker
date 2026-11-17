/* SPDX-License-Identifier: GPL-2.0 */
/*
 * debugfs_iface.h - the user-facing part of memory_tracker.ko.
 *
 * Everything the operator can see lives under
 *
 *     /sys/kernel/debug/memory_tracker/
 *
 *         stats     read-only counters: probes, ring, live-block table
 *         events    drained trace records, one per line, symbols resolved
 *         clear     write anything to drop the backlog and reset the table
 *         selftest  write anything to push a marker + a real alloc/free pair
 *
 * The `events` file is a seq_file, so reading it costs one ring drain per
 * open() and then streams out of the already-captured snapshot.  That keeps
 * the probe handlers (which only ever write into the ring) completely
 * decoupled from symbol resolution, which is far too expensive to do in IRQ
 * context.
 */
#ifndef TRACKER_DEBUGFS_IFACE_H
#define TRACKER_DEBUGFS_IFACE_H

/* Create /sys/kernel/debug/memory_tracker/{stats,events,clear,selftest}.
 * Returns 0 on success, -errno on failure (nothing is left behind). */
int mt_debugfs_init(void);

/* Remove the directory and wait for in-flight readers.  Safe to call when
 * init never ran. */
void mt_debugfs_exit(void);

#endif /* TRACKER_DEBUGFS_IFACE_H */
