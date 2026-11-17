// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "memory_tracker: " fmt

/*
 * tracker_kmod.c - module entry point for memory_tracker.ko.
 *
 * This file owns three things and nothing else:
 *
 *   1. the tunables (mt_ring_size, mt_kblock_bits, mt_oversize_kb,
 *      mt_trace_alloc/free/unknown) and their module_param() plumbing, so an
 *      operator can tune the module at insmod time:
 *
 *          insmod memory_tracker.ko ring_size=32768 oversize_kb=1024 \
 *                 trace_alloc=0
 *
 *      or at runtime through /sys/module/memory_tracker/parameters/.
 *
 *   2. the init order, which matters:
 *
 *          kring_init()       - pre-allocate one lock-free ring per CPU.
 *                               Must exist before any probe fires, otherwise
 *                               the very first traced kmalloc() would have
 *                               nowhere to record its event.
 *          kblock_init()      - pre-allocate the live-block table.  Same
 *                               reasoning: probes must never allocate.
 *          probes_register()  - start hooking the allocator.  From here on
 *                               events flow into the structures above.
 *          mt_debugfs_init()  - publish /sys/kernel/debug/memory_tracker so
 *                               the operator can actually read what is being
 *                               collected.
 *
 *      Each step is allowed to fail, and a failure rolls back every step that
 *      already succeeded, in reverse order.  The module either comes up fully
 *      wired or leaves no trace at all.
 *
 *   3. the exit order, which is exactly reversed:
 *
 *          mt_debugfs_init  -> mt_debugfs_exit   (stop readers first)
 *          probes_register  -> probes_unregister (stop the event source)
 *          kblock_init      -> kblock_exit       (free the table)
 *          kring_init       -> kring_exit        (free the rings last)
 *
 *      Stopping the probes before freeing their storage is not optional: a
 *      handler that is still in flight must find valid rings and a valid
 *      table when it runs.  unregister_kprobe()/unregister_kretprobe() wait
 *      for in-flight handlers, so by the time probes_unregister() returns,
 *      nothing can touch the structures we are about to free.
 *
 * Context rules: everything here runs in process context (module load /
 * unload), so sleeping and allocating are fine.  The probe handlers in
 * probes.c are the ones bound by the no-sleep / no-alloc rules.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "mt_config.h"
#include "ring_kernel.h"
#include "kblock.h"
#include "probes.h"
#include "debugfs_iface.h"

/* ------------------------------------------------------------------------ */
/* tunables - defined here, declared in mt_config.h                          */
/* ------------------------------------------------------------------------ */

/* Slots per CPU ring.  Rounded up to a power of two by kring_init(). */
unsigned int mt_ring_size = 16384;
module_param_named(ring_size, mt_ring_size, uint, 0444);
MODULE_PARM_DESC(ring_size,
		 "Trace ring slots per CPU (rounded up to a power of two)");

/* log2 of the live-block table capacity, clamped to 10..22 inside
 * kblock_init().  16 = 65536 slots ≈ 2.5MB, the default. */
unsigned int mt_kblock_bits = 16;
module_param_named(kblock_bits, mt_kblock_bits, uint, 0444);
MODULE_PARM_DESC(kblock_bits,
		 "log2 of live-block table slots, clamped 10..22");

/* Allocations >= this many KiB raise a KEV_OVERSIZE alert.  0 disables. */
unsigned int mt_oversize_kb = 1024;
module_param_named(oversize_kb, mt_oversize_kb, uint, 0444);
MODULE_PARM_DESC(oversize_kb,
		 "Alert on allocations >= this many KiB (0 = disabled)");

/* Emit a KEV_ALLOC event for every successful allocation.  Extremely noisy
 * on a busy system; off means the allocation is still *tracked* (so frees
 * can be classified), only the trace record is skipped. */
bool mt_trace_alloc;
module_param_named(trace_alloc, mt_trace_alloc, bool, 0644);
MODULE_PARM_DESC(trace_alloc, "Emit a trace event for every allocation");

/* Emit a KEV_FREE event for every clean release. */
bool mt_trace_free;
module_param_named(trace_free, mt_trace_free, bool, 0644);
MODULE_PARM_DESC(trace_free, "Emit a trace event for every clean release");

/* Emit a KEV_UNKNOWN_FREE event for a release of a pointer we never saw
 * allocated.  Off by default: right after insmod *every* pre-existing block
 * is unknown, which would flood the log with informational noise. */
bool mt_trace_unknown;
module_param_named(trace_unknown, mt_trace_unknown, bool, 0644);
MODULE_PARM_DESC(trace_unknown,
		 "Emit a trace event for releases of unknown pointers");

/* ------------------------------------------------------------------------ */
/* lifecycle                                                                 */
/* ------------------------------------------------------------------------ */

/* Named mt_tracker_* rather than mt_*: the kernel already has a static
 * inline mt_init(struct maple_tree *) in maple_tree.h and a colliding name
 * would silently break the module_init alias. */
static int __init mt_tracker_init(void)
{
	unsigned int ok = 0, failed = 0;
	int ret;

	pr_info("loading (ring_size=%u, kblock_bits=%u, oversize_kb=%u, "
		"trace_alloc=%d, trace_free=%d, trace_unknown=%d)\n",
		mt_ring_size, mt_kblock_bits, mt_oversize_kb,
		mt_trace_alloc, mt_trace_free, mt_trace_unknown);

	/* Step 1: per-CPU rings.  Must precede the probes. */
	ret = kring_init(mt_ring_size);
	if (ret) {
		pr_err("ring allocation failed (%d)\n", ret);
		return ret;
	}

	/* Step 2: live-block table.  Must precede the probes. */
	ret = kblock_init(mt_kblock_bits);
	if (ret) {
		pr_err("live-block table allocation failed (%d)\n", ret);
		goto err_ring;
	}

	/* Step 3: hook the allocator.  probes_register() tolerates individual
	 * probe failures (partial coverage) and reports them through ok/failed;
	 * it only fails hard when it cannot run at all. */
	ret = probes_register(&ok, &failed);
	if (ret) {
		pr_err("probe registration failed (%d)\n", ret);
		goto err_kblock;
	}
	pr_info("probes registered: %u ok, %u failed\n", ok, failed);
	if (failed)
		pr_warn("partial coverage - see the probe table in "
			"/sys/kernel/debug/memory_tracker/stats\n");

	/* Step 4: publish the debugfs interface. */
	ret = mt_debugfs_init();
	if (ret) {
		pr_err("debugfs setup failed (%d)\n", ret);
		goto err_probes;
	}

	pr_info("ready - interface at /sys/kernel/debug/memory_tracker\n");
	return 0;

	/* Roll back in reverse order.  probes_unregister() waits for in-flight
	 * handlers, so the structures below are quiescent before we free
	 * them. */
err_probes:
	probes_unregister();
err_kblock:
	kblock_exit();
err_ring:
	kring_exit();
	return ret;
}

static void __exit mt_tracker_exit(void)
{
	/* Reverse of init:
	 *   1. remove debugfs  -> no new readers, in-flight ones drained by
	 *      debugfs_remove();
	 *   2. unregister probes -> no new events, in-flight handlers waited
	 *      for by the kprobe infrastructure;
	 *   3. free the live-block table;
	 *   4. free the rings last. */
	mt_debugfs_exit();
	probes_unregister();
	kblock_exit();
	kring_exit();

	pr_info("unloaded\n");
}

module_init(mt_tracker_init);
module_exit(mt_tracker_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("memory-tracker project");
MODULE_DESCRIPTION
	("CoreSight-inspired real-time memory tracker: kprobe/kretprobe "
	 "tracing of kmalloc/kfree with double-free, wrong-free and "
	 "cache-mismatch detection, exported through debugfs");
MODULE_VERSION("1.0");
