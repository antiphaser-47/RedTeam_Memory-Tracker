// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "memory_tracker: " fmt

/*
 * debugfs_iface.c - the operator-facing side of memory_tracker.ko.
 *
 * Layout under /sys/kernel/debug/memory_tracker/
 *
 *   stats     read-only report: ring occupancy, live-block table, probe
 *             counters and the per-symbol registration table.
 *   events    one drained trace record per line, symbols resolved.  The ring
 *             is drained once per open() into a private snapshot and the
 *             snapshot is then sorted by timestamp, so a single read shows a
 *             coherent, globally ordered view even though the writers are
 *             one lock-free ring per CPU.
 *   clear     write anything to discard the unread backlog and empty the
 *             live-block table.  Cumulative counters are *not* touched.
 *   selftest  read it to run an end-to-end self test.  Everything the test
 *             does is safe: the only real allocator call is one kmalloc() and
 *             one matching kfree(); the double-free classification is driven
 *             directly against the live-block table, never against SLUB.
 *
 * Everything here runs in process context, so symbol resolution
 * (sprint_symbol) and memory allocation are allowed.  The probe handlers in
 * probes.c must never do either.
 */
#include "debugfs_iface.h"
#include "ring_kernel.h"
#include "kblock.h"
#include "probes.h"
#include "mt_config.h"

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <linux/sort.h>
#include <linux/kallsyms.h>
#include <linux/timekeeping.h>
#include <linux/sched.h>

/* Records captured by one open() of `events`.  4096 * 64B = 256KB. */
#define MT_DRAIN_MAX	4096u

/* ns value of ktime_get_ns() when this file was initialised - used to turn
 * the raw clock into an uptime figure in `stats`. */
static u64 g_load_ns;

static struct dentry *g_dir;

/* ------------------------------------------------------------------------ */
/* event type names - keep in sync with enum k_event_type in ring_kernel.h   */
/* ------------------------------------------------------------------------ */

static const char * const ev_names[KEV_TYPE_MAX] = {
	[KEV_ALLOC]		= "ALLOC",
	[KEV_FREE]		= "FREE",
	[KEV_DOUBLE_FREE]	= "DOUBLE_FREE",
	[KEV_WRONG_FREE]	= "WRONG_FREE",
	[KEV_CACHE_MISMATCH]	= "CACHE_MISMATCH",
	[KEV_OVERSIZE]		= "OVERSIZE",
	[KEV_UNKNOWN_FREE]	= "UNKNOWN_FREE",
	[KEV_SELFTEST]		= "SELFTEST",
};

static const char *ev_name(u32 type)
{
	if (type < KEV_TYPE_MAX && ev_names[type])
		return ev_names[type];
	return "???";
}

static const char *kbf_name(enum kblock_free_result r)
{
	switch (r) {
	case KBF_OK:		return "KBF_OK";
	case KBF_DOUBLE_FREE:	return "KBF_DOUBLE_FREE";
	case KBF_WRONG_FREE:	return "KBF_WRONG_FREE";
	case KBF_CACHE_MISMATCH:return "KBF_CACHE_MISMATCH";
	case KBF_UNKNOWN_FREE:	return "KBF_UNKNOWN_FREE";
	}
	return "KBF_?";
}

/* ------------------------------------------------------------------------ */
/* stats								    */
/* ------------------------------------------------------------------------ */

static int stats_show(struct seq_file *m, void *v)
{
	struct mt_probe_stats ps;
	struct mt_probe_status st[MT_MAX_PROBE_ROWS];
	unsigned int n = 0, i;
	u64 produced = 0, dropped = 0;
	u32 live = 0, quar = 0, slots = 0, rings = 0;

	probes_stats(&ps);
	probes_status(st, &n);
	kring_totals(&produced, &dropped);
	kring_info(&slots, &rings);
	kblock_counts(&live, &quar);

	seq_puts(m, "memory_tracker.ko - statistics\n");
	seq_puts(m, "================================\n");
	seq_printf(m, "now_ns                 : %llu\n", ktime_get_ns());
	seq_printf(m, "loaded_ns              : %llu\n", g_load_ns);
	seq_printf(m, "uptime_ms              : %llu\n",
		   (ktime_get_ns() - g_load_ns) / 1000000ULL);

	seq_puts(m, "\n[ring]\n");
	seq_printf(m, "slots_per_cpu          : %u\n", slots);
	seq_printf(m, "rings                  : %u\n", rings);
	seq_printf(m, "produced               : %llu\n", produced);
	seq_printf(m, "dropped                : %llu\n", dropped);

	seq_puts(m, "\n[live-block table]\n");
	seq_printf(m, "capacity               : %u\n", kblock_capacity());
	seq_printf(m, "live                   : %u\n", live);
	seq_printf(m, "quarantined            : %u\n", quar);

	seq_puts(m, "\n[probes]\n");
	seq_printf(m, "registered_ok          : %llu\n", ps.probed_ok);
	seq_printf(m, "registration_failed    : %llu\n", ps.probed_failed);
	seq_printf(m, "kretprobe_instances_missed : %llu\n", ps.ret_missed);

	seq_puts(m, "\n[allocation side]\n");
	seq_printf(m, "alloc_seen             : %llu\n", ps.alloc_seen);
	seq_printf(m, "alloc_returned_null    : %llu\n", ps.alloc_null);
	seq_printf(m, "alloc_table_full       : %llu\n", ps.alloc_table_full);
	seq_printf(m, "oversize               : %llu\n", ps.oversize);

	seq_puts(m, "\n[release side]\n");
	seq_printf(m, "free_ok                : %llu\n", ps.free_seen);
	seq_printf(m, "double_free            : %llu\n", ps.double_free);
	seq_printf(m, "wrong_free             : %llu\n", ps.wrong_free);
	seq_printf(m, "cache_mismatch         : %llu\n", ps.cache_mismatch);
	seq_printf(m, "unknown_free           : %llu\n", ps.unknown_free);

	seq_puts(m, "\n[config]\n");
	seq_printf(m, "ring_size (param)      : %u\n", mt_ring_size);
	seq_printf(m, "kblock_bits (param)    : %u\n", mt_kblock_bits);
	seq_printf(m, "oversize_kb            : %u\n", mt_oversize_kb);
	seq_printf(m, "trace_alloc            : %s\n",
		   mt_trace_alloc ? "on" : "off");
	seq_printf(m, "trace_free             : %s\n",
		   mt_trace_free ? "on" : "off");
	seq_printf(m, "trace_unknown          : %s\n",
		   mt_trace_unknown ? "on" : "off");

	seq_puts(m, "\n[probe table]\n");
	seq_printf(m, "  %-34s %-9s %s\n", "symbol", "kind", "status");
	for (i = 0; i < n; i++)
		seq_printf(m, "  %-34s %-9s %s\n",
			   st[i].name ? st[i].name : "?",
			   st[i].is_kretprobe ? "kretprobe" : "kprobe",
			   st[i].ok ? "OK" : "FAILED");
	if (!n)
		seq_puts(m, "  (no probes registered)\n");

	return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_show, inode->i_private);
}

/* ------------------------------------------------------------------------ */
/* events								    */
/* ------------------------------------------------------------------------ */

/*
 * Snapshot taken at open(): the ring is drained into `ev`, the records are
 * sorted by timestamp so the per-CPU rings interleave correctly, and the
 * seq_file then walks the array.  `sym` is a scratch buffer for sprint_symbol
 * (KSYM_SYMBOL_LEN is ~700 bytes, too big to keep on the stack next to
 * seq_printf's own frame).
 */
struct events_view {
	struct k_event *ev;
	u32 count;
	u64 dropped;
	char sym[KSYM_SYMBOL_LEN];
};

static int cmp_ts(const void *a, const void *b)
{
	const struct k_event *ea = a;
	const struct k_event *eb = b;

	if (ea->ts_ns < eb->ts_ns)
		return -1;
	if (ea->ts_ns > eb->ts_ns)
		return 1;
	return 0;
}

static void swap_bytes(void *a, void *b, int size)
{
	char *pa = a;
	char *pb = b;
	char t;

	while (size-- > 0) {
		t = *pa;
		*pa++ = *pb;
		*pb++ = t;
	}
}

static void *ev_start(struct seq_file *m, loff_t *pos)
{
	struct events_view *vw = m->private;

	if (!vw || *pos < 0 || (u64)*pos >= vw->count)
		return NULL;
	return &vw->ev[*pos];
}

static void *ev_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct events_view *vw = m->private;

	(void)p;
	++*pos;
	if (!vw || (u64)*pos >= vw->count)
		return NULL;
	return &vw->ev[*pos];
}

static void ev_stop(struct seq_file *m, void *p)
{
	(void)m;
	(void)p;
}

static int ev_show(struct seq_file *m, void *p)
{
	struct events_view *vw = m->private;
	const struct k_event *ev = p;
	const char *caller = "-";

	if (!vw || !ev)
		return 0;

	if (ev->caller_ip) {
		sprint_symbol(vw->sym, (unsigned long)ev->caller_ip);
		caller = vw->sym;
	}

	seq_printf(m,
		   "ts=%llu type=%s pid=%u cpu=%u ptr=0x%llx size=%llu caller=%s aux=0x%llx flags=0x%x\n",
		   ev->ts_ns, ev_name(ev->type), ev->pid, ev->cpu,
		   ev->ptr, ev->size, caller, ev->aux, ev->flags);
	return 0;
}

static const struct seq_operations events_ops = {
	.start = ev_start,
	.next  = ev_next,
	.stop  = ev_stop,
	.show  = ev_show,
};

static int events_open(struct inode *inode, struct file *file)
{
	struct events_view *vw;
	struct seq_file *m;
	int ret;

	(void)inode;

	vw = kzalloc(sizeof(*vw), GFP_KERNEL);
	if (!vw)
		return -ENOMEM;

	vw->ev = kvmalloc(MT_DRAIN_MAX * sizeof(struct k_event), GFP_KERNEL);
	if (!vw->ev) {
		kfree(vw);
		return -ENOMEM;
	}

	/* Drain before seq_open so the snapshot is fixed for the whole read. */
	vw->count = kring_drain(vw->ev, MT_DRAIN_MAX, &vw->dropped);
	if (vw->count > 1)
		sort(vw->ev, vw->count, sizeof(struct k_event),
		     cmp_ts, swap_bytes);

	ret = seq_open(file, &events_ops);
	if (ret) {
		kvfree(vw->ev);
		kfree(vw);
		return ret;
	}

	m = file->private_data;
	m->private = vw;
	return 0;
}

static int events_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct events_view *vw = m ? m->private : NULL;

	if (vw) {
		kvfree(vw->ev);
		kfree(vw);
		m->private = NULL;
	}
	return seq_release(inode, file);
}

/* ------------------------------------------------------------------------ */
/* clear								    */
/* ------------------------------------------------------------------------ */

static ssize_t clear_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	(void)file;
	(void)buf;
	(void)ppos;

	if (!count)
		return -EINVAL;

	/*
	 * Two independent resets:
	 *   kring_clear()   - consumer cursors jump to the write index, so the
	 *                     unread backlog is discarded and never replayed;
	 *   kblock_reset()  - every slot goes EMPTY, so pointers allocated
	 *                     before the reset are reported as UNKNOWN_FREE
	 *                     afterwards (documented in docs/USAGE.md).
	 * Cumulative counters in probes.c are deliberately left alone.
	 */
	kring_clear();
	kblock_reset();

	return count;
}

/* ------------------------------------------------------------------------ */
/* selftest								    */
/* ------------------------------------------------------------------------ */

static void push_marker(u64 ptr, u64 aux)
{
	struct k_event ev;

	ev.ts_ns     = ktime_get_ns();
	ev.ptr       = ptr;
	ev.size      = 0;
	ev.caller_ip = 0;
	ev.aux       = aux;
	ev.type      = KEV_SELFTEST;
	ev.flags     = KEVF_SELFTEST;
	ev.pid       = (u32)current->pid;
	ev.cpu       = (u32)smp_processor_id();
	kring_push(&ev);
}

/*
 * The test never asks SLUB to double free anything.  It drives
 * kblock_note_free() directly to prove the classifier, then puts the block
 * back into the LIVE state so the real kfree() below classifies as a clean
 * release instead of raising a bogus alert.
 */
static int selftest_show(struct seq_file *m, void *v)
{
	enum kblock_free_result r1, r2;
	struct mt_probe_stats ps;
	unsigned int state = 0;
	void *p;
	int pass = 0, total = 6;
	u64 sz = 0, age = 0;

	(void)v;

	seq_puts(m, "memory_tracker selftest\n");
	seq_puts(m, "=======================\n");

	probes_stats(&ps);

	/* [1] a real allocation must be traced and land in the table. */
	p = kmalloc(128, GFP_KERNEL);
	seq_printf(m, "[1] kmalloc(128)               : %s",
		   p ? "OK" : "FAIL");
	if (p)
		seq_printf(m, " ptr=0x%llx", (u64)(unsigned long)p);
	seq_putc(m, '\n');
	if (p)
		pass++;

	/* [2] the table must know about it and consider it LIVE. */
	if (p && kblock_contains((u64)(unsigned long)p, &state) &&
	    state == KB_LIVE) {
		seq_puts(m, "[2] tracked as LIVE             : OK\n");
		pass++;
	} else {
		seq_puts(m, "[2] tracked as LIVE             : FAIL\n");
	}

	/* [3] first classification through the table = clean release. */
	r1 = p ? kblock_note_free((u64)(unsigned long)p, false, 0,
				  &sz, &age) : KBF_UNKNOWN_FREE;
	seq_printf(m, "[3] first release classified    : %s %s\n",
		   kbf_name(r1), r1 == KBF_OK ? "" : "(expected KBF_OK)");
	if (r1 == KBF_OK)
		pass++;

	/* [4] second classification of the same pointer = double free. */
	r2 = p ? kblock_note_free((u64)(unsigned long)p, false, 0,
				  &sz, &age) : KBF_UNKNOWN_FREE;
	seq_printf(m, "[4] second release classified   : %s %s\n",
		   kbf_name(r2),
		   r2 == KBF_DOUBLE_FREE ? "" : "(expected KBF_DOUBLE_FREE)");
	if (r2 == KBF_DOUBLE_FREE)
		pass++;

	/*
	 * [5] put the block back to LIVE so that the genuine kfree() below
	 *     sees a normal allocation.  Without this the real free would be
	 *     reported as a double free and pollute the alert log.
	 */
	if (p && kblock_note_alloc((u64)(unsigned long)p, 128, 0,
				   KB_KMALLOC) &&
	    kblock_contains((u64)(unsigned long)p, &state) &&
	    state == KB_LIVE) {
		seq_puts(m, "[5] block restored to LIVE      : OK\n");
		pass++;
	} else {
		seq_puts(m, "[5] block restored to LIVE      : FAIL\n");
	}

	/* [6] real release through the kfree() probe + a marker event. */
	if (p) {
		kfree(p);
		push_marker((u64)(unsigned long)p, 0x53454C4654535400ULL);
	}
	if (p && kblock_contains((u64)(unsigned long)p, &state) &&
	    state == KB_QUAR) {
		seq_puts(m, "[6] real kfree quarantined      : OK\n");
		pass++;
	} else {
		seq_puts(m, "[6] real kfree quarantined      : FAIL\n");
	}

	seq_printf(m, "\nprobe counters: alloc_seen=%llu free_ok=%llu double_free=%llu\n",
		   ps.alloc_seen, ps.free_seen, ps.double_free);
	seq_printf(m, "result: %s (%d/%d)\n",
		   pass == total ? "PASS" : "FAIL", pass, total);
	return 0;
}

static int selftest_open(struct inode *inode, struct file *file)
{
	return single_open(file, selftest_show, inode->i_private);
}

/* ------------------------------------------------------------------------ */
/* file operations								    */
/* ------------------------------------------------------------------------ */

static const struct file_operations stats_fops = {
	.owner	 = THIS_MODULE,
	.open	 = stats_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static const struct file_operations events_fops = {
	.owner	 = THIS_MODULE,
	.open	 = events_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = events_release,
};

static const struct file_operations clear_fops = {
	.owner	 = THIS_MODULE,
	.open	 = simple_open,
	.write	 = clear_write,
	.llseek	 = noop_llseek,
};

static const struct file_operations selftest_fops = {
	.owner	 = THIS_MODULE,
	.open	 = selftest_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

/* ------------------------------------------------------------------------ */
/* lifecycle								    */
/* ------------------------------------------------------------------------ */

int mt_debugfs_init(void)
{
	g_load_ns = ktime_get_ns();

	g_dir = debugfs_create_dir("memory_tracker", NULL);
	if (IS_ERR_OR_NULL(g_dir)) {
		int err = g_dir ? PTR_ERR(g_dir) : -ENODEV;

		g_dir = NULL;
		return err;
	}

	debugfs_create_file("stats", 0444, g_dir, NULL, &stats_fops);
	debugfs_create_file("events", 0444, g_dir, NULL, &events_fops);
	debugfs_create_file("clear", 0200, g_dir, NULL, &clear_fops);
	debugfs_create_file("selftest", 0444, g_dir, NULL, &selftest_fops);

	pr_info("debugfs interface at /sys/kernel/debug/memory_tracker\n");
	return 0;
}

void mt_debugfs_exit(void)
{
	if (!g_dir)
		return;
	/* debugfs_remove() waits for active readers, so no seq_file can be
	 * touching a snapshot after this returns. */
	debugfs_remove(g_dir);
	g_dir = NULL;
}
