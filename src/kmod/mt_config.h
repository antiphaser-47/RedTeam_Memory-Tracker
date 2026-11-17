/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mt_config.h - tunables shared by the module's translation units.
 *
 * Every variable declared here is defined (and exposed through
 * module_param()) in tracker_kmod.c.  They are deliberately *not* static so
 * that probes.c and debugfs_iface.c can read them without a getter.
 *
 * Load-time overrides look like:
 *     insmod memory_tracker.ko ring_size=32768 oversize_kb=1024 trace_alloc=0
 * and, for the writable ones, at runtime through
 *     echo 0 > /sys/module/memory_tracker/parameters/trace_alloc
 */
#ifndef TRACKER_MT_CONFIG_H
#define TRACKER_MT_CONFIG_H

#include <linux/types.h>

/* Number of slots in each per-CPU ring (rounded up to a power of two). */
extern unsigned int mt_ring_size;

/* log2 of the live-block table slot count, clamped to 10..22. */
extern unsigned int mt_kblock_bits;

/* Allocations at or above this many kilobytes raise KEV_OVERSIZE.
 * 0 disables the check. */
extern unsigned int mt_oversize_kb;

/* Emit an event for every successful allocation.  Very noisy on a busy
 * system - turn off when you only care about the alerts. */
extern bool mt_trace_alloc;

/* Emit an event for every clean release. */
extern bool mt_trace_free;

/* Emit an event for a release of a pointer we never saw allocated.  This is
 * the common case immediately after insmod (everything allocated before the
 * module loaded is unknown), so it is off by default and only counted. */
extern bool mt_trace_unknown;

#endif /* TRACKER_MT_CONFIG_H */
