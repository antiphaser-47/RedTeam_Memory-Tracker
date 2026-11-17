// SPDX-License-Identifier: GPL-2.0
/*
 * probes.c - kprobe / kretprobe handlers for memory_tracker.ko.
 *
 * What is hooked and why
 * ----------------------
 *   allocation side (kretprobe: we need the pointer the allocator *returns*)
 *     __kmalloc_noprof            kmalloc() with a run-time size
 *     __kmalloc_node_noprof       kmalloc_node() / NUMA aware
 *     __kmalloc_cache_noprof      kmalloc() with a compile-time constant size
 *     __kmalloc_cache_node_noprof constant size + node
 *     __kmalloc_large_noprof      objects larger than KMALLOC_MAX_CACHE_SIZE
 *     __kmalloc_large_node_noprof large objects, node aware
 *     kmem_cache_alloc_noprof     explicit kmem_cache_alloc()
 *     kmem_cache_alloc_lru_noprof kmem_cache_alloc_lru() (inode/dentry caches)
 *
 *   release side (plain kprobe: the pointer is an *argument*)
 *     kfree            const void *objp            -> regs->di
 *     kmem_cache_free  struct kmem_cache *s, void *x -> regs->di / regs->si
 *
 * Argument register map (x86-64 System V ABI, probes all sit at function
 * entry so no register has been clobbered yet):
 *     rdi = arg0, rsi = arg1, rdx = arg2, rcx = arg3, rax = return value.
 *
 * Context rules
 * -------------
 * Handlers can run in IRQ context with preemption (and possibly IRQs)
 * disabled.  Therefore:
 *   - never sleep, never call the allocator (kblock_note_alloc() only writes
 *     into a table pre-allocated at init, kring_push() only writes into
 *     pre-allocated slots);
 *   - all locking is raw_spin_lock_irqsave();
 *   - the caller return address is fetched with copy_from_kernel_nofault()
 *     so a bad pointer degrades to "unknown caller" instead of an oops;
 *   - symbol resolution (sprint_symbol) happens *only* in debugfs read
 *     context, never in a handler.
 *
 * Recursion safety
 * ----------------
 * kblock_note_alloc(), kblock_note_free(), kring_push(), ktime_get_ns(),
 * copy_from_kernel_nofault() and kmem_cache_size() contain no path that
 * reaches the __kmalloc family / kfree / kmem_cache_* entry points, so a
 * handler cannot re-enter a probe through its own work.  Anything else that
 * allocates (dmesg, seq_file, ...) happens outside the handlers.
 */
#include "probes.h"
#include "ring_kernel.h"
#include "kblock.h"
#include "mt_config.h"

#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>		/* copy_from_kernel_nofault()	*/
#include <linux/timekeeping.h>		/* ktime_get_ns()		*/

/* ------------------------------------------------------------------------ */
/* counters								    */
/* ------------------------------------------------------------------------ */

static atomic64_t c_alloc_seen;
static atomic64_t c_alloc_null;
static atomic64_t c_alloc_full;
static atomic64_t c_oversize;
static atomic64_t c_free_seen;
static atomic64_t c_double_free;
static atomic64_t c_wrong_free;
static atomic64_t c_cache_mismatch;
static atomic64_t c_unknown_free;
static atomic64_t c_probed_ok;
static atomic64_t c_probed_failed;

/* ------------------------------------------------------------------------ */
/* per-probe bookkeeping							    */
/* ------------------------------------------------------------------------ */

#define MT_MAX_PROBES	MT_MAX_PROBE_ROWS

static struct kretprobe mt_rprobes[MT_MAX_PROBES];
static unsigned int     mt_nr_rprobes;

static struct kprobe    mt_kprobes[MT_MAX_PROBES];
static unsigned int     mt_nr_kprobes;

/* Registration outcome, exported to debugfs so the operator can see which
 * hooks actually landed instead of guessing. */
static struct mt_probe_status mt_status[MT_MAX_PROBES];
static unsigned int           mt_nr_status;

static bool mt_registered;

/* Concurrent instances per probed function.  The allocator nests (page
 * reclaim inside a kmalloc, for example), so leave generous head-room; an
 * overflow is not fatal, it only bumps nmissed and loses some events. */
static int mt_maxactive(void)
{
	return (int)(nr_cpu_ids * 8u + 64u);
}

/* ------------------------------------------------------------------------ */
/* caller address extraction							    */
/* ------------------------------------------------------------------------ */

/*
 * The probed instruction sits at function entry, so the return address to the
 * *caller* is the word the `call` pushed, i.e. the top of the stack.
 *
 * There are two ways a kprobe can be placed, and they disagree about which
 * word that is:
 *
 *   int3 based : the breakpoint replaces the first instruction.  Nothing has
 *                run yet, so (%rsp) is the caller's return address.
 *
 *   ftrace based (CONFIG_KPROBES_ON_FTRACE): the first instruction has been
 *                rewritten into `call ftrace_caller`, which pushed the address
 *                of the *next* instruction of the probed function.  The
 *                caller's return address is then one slot higher, at 8(%rsp).
 *
 * We cannot ask the kernel which mechanism was chosen without poking at
 * private flags, so instead we read both words and discard the one that lands
 * inside the probed function itself (regs->ip is the probed address in both
 * cases).  Two guarded reads, no symbol lookup, safe in IRQ context.
 */
static u64 read_caller(struct pt_regs *regs)
{
	unsigned long w0 = 0, w1 = 0;
	unsigned long lo = instruction_pointer(regs);

	if (copy_from_kernel_nofault(&w0, (const void *)regs->sp, sizeof(w0)))
		return 0;

	/* Top word belongs to the probed function -> ftrace layout. */
	if (w0 >= lo && w0 < lo + 0x80UL) {
		if (copy_from_kernel_nofault(&w1,
					     (const void *)(regs->sp + 8),
					     sizeof(w1)))
			return 0;
		return (u64)w1;
	}
	return (u64)w0;
}

/* ------------------------------------------------------------------------ */
/* event construction								    */
/* ------------------------------------------------------------------------ */

/* Fill in the fields every event shares and hand it to the per-CPU ring. */
static void emit(u32 type, u32 flags, u64 ptr, u64 size, u64 caller, u64 aux)
{
	struct k_event ev;

	ev.ts_ns    = ktime_get_ns();
	ev.ptr      = ptr;
	ev.size     = size;
	ev.caller_ip = caller;
	ev.aux      = aux;
	ev.type     = type;
	ev.flags    = flags;
	ev.pid      = (u32)current->pid;
	ev.cpu      = (u32)smp_processor_id();

	kring_push(&ev);
}

/* ------------------------------------------------------------------------ */
/* allocation side									    */
/* ------------------------------------------------------------------------ */

/* Per-instance payload handed from the entry handler to the return handler.
 * Kept at 32 bytes so a kretprobe instance stays inside one small slab. */
struct alloc_ctx {
	u64 caller;
	u64 size;
	u64 cache;
	u32 kind;	/* KB_KMALLOC / KB_KMEM_CACHE	*/
	u32 pad;
};

static inline struct alloc_ctx *ctx_of(struct kretprobe_instance *ri)
{
	return (struct alloc_ctx *)ri->data;
}

/*
 * Entry handlers.  Each one only knows how to pull its own arguments out of
 * pt_regs; everything downstream is shared.  Returning 0 tells the kernel to
 * keep the instance so the return handler will run.
 *
 * Layouts:
 *   size in rdi                      : __kmalloc[_node|_large[_node]]_noprof
 *   cache in rdi, size in rdx        : __kmalloc_cache_noprof
 *   cache in rdi, size in rcx        : __kmalloc_cache_node_noprof
 *   cache in rdi, size from the cache: kmem_cache_alloc[_lru]_noprof
 */
static int entry_size(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct alloc_ctx *c = ctx_of(ri);

	c->caller = read_caller(regs);
	c->size   = regs->di;
	c->cache  = 0;
	c->kind   = KB_KMALLOC;
	c->pad    = 0;
	return 0;
}

static int entry_cache_rdx(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct alloc_ctx *c = ctx_of(ri);

	c->caller = read_caller(regs);
	c->cache  = regs->di;
	c->size   = regs->dx;
	c->kind   = KB_KMALLOC;	/* kmalloc caches are still kmalloc blocks */
	c->pad    = 0;
	return 0;
}

static int entry_cache_rcx(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct alloc_ctx *c = ctx_of(ri);

	c->caller = read_caller(regs);
	c->cache  = regs->di;
	c->size   = regs->cx;
	c->kind   = KB_KMALLOC;
	c->pad    = 0;
	return 0;
}

static int entry_cache_only(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct alloc_ctx *c = ctx_of(ri);
	struct kmem_cache *s = (struct kmem_cache *)regs->di;

	c->caller = read_caller(regs);
	c->cache  = (u64)s;
	/* The size is not an argument here; ask the cache itself.  This is a
	 * trivial getter (no locking, no allocation) and is safe to call from
	 * a handler. */
	c->size   = s ? (u64)kmem_cache_size(s) : 0;
	c->kind   = KB_KMEM_CACHE;
	c->pad    = 0;
	return 0;
}

/*
 * Return handler, shared by every allocation probe.  The instance payload
 * tells us everything the entry handler could not know about the result.
 */
static int ret_alloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct alloc_ctx *c = ctx_of(ri);
	u64 ptr = regs_return_value(regs);

	if (!ptr) {
		atomic64_inc(&c_alloc_null);
		return 0;
	}

	if (!kblock_note_alloc(ptr, c->size, c->cache, c->kind)) {
		/* Live-block table is full: the event still goes out, it just
		 * will not be matchable against a later free. */
		atomic64_inc(&c_alloc_full);
	}
	atomic64_inc(&c_alloc_seen);

	/* Oversize is an alert, so it is emitted regardless of the trace
	 * switches - the operator asked for it by setting the threshold. */
	if (mt_oversize_kb &&
	    c->size >= (u64)mt_oversize_kb * 1024ULL) {
		atomic64_inc(&c_oversize);
		emit(KEV_OVERSIZE, KEVF_ALERT, ptr, c->size, c->caller,
		     c->cache);
	}

	if (mt_trace_alloc)
		emit(KEV_ALLOC, 0, ptr, c->size, c->caller, c->cache);

	return 0;
}

/* ------------------------------------------------------------------------ */
/* release side									    */
/* ------------------------------------------------------------------------ */

/* Turn a classification from the live-block table into an event. */
static void emit_free_result(enum kblock_free_result res, u64 ptr,
			     u64 size, u64 age, u64 caller, u64 cache)
{
	switch (res) {
	case KBF_OK:
		atomic64_inc(&c_free_seen);
		if (mt_trace_free)
			emit(KEV_FREE, 0, ptr, size, caller, age);
		break;

	case KBF_DOUBLE_FREE:
		atomic64_inc(&c_double_free);
		emit(KEV_DOUBLE_FREE, KEVF_ALERT, ptr, size, caller, age);
		break;

	case KBF_WRONG_FREE:
		atomic64_inc(&c_wrong_free);
		emit(KEV_WRONG_FREE, KEVF_ALERT, ptr, size, caller, cache);
		break;

	case KBF_CACHE_MISMATCH:
		atomic64_inc(&c_cache_mismatch);
		emit(KEV_CACHE_MISMATCH, KEVF_ALERT, ptr, size, caller, cache);
		break;

	case KBF_UNKNOWN_FREE:
	default:
		atomic64_inc(&c_unknown_free);
		if (mt_trace_unknown)
			emit(KEV_UNKNOWN_FREE, 0, ptr, size, caller, 0);
		break;
	}
}

/* kfree(const void *objp) */
static int kp_kfree(struct kprobe *p, struct pt_regs *regs)
{
	u64 ptr = regs->di;
	u64 size = 0, age = 0;
	u64 caller;
	enum kblock_free_result res;

	if (!ptr)
		return 0;

	caller = read_caller(regs);
	res = kblock_note_free(ptr, false, 0, &size, &age);
	emit_free_result(res, ptr, size, age, caller, 0);
	return 0;
}

/* kmem_cache_free(struct kmem_cache *s, void *objp) */
static int kp_cache_free(struct kprobe *p, struct pt_regs *regs)
{
	u64 cache = regs->di;
	u64 ptr   = regs->si;
	u64 size = 0, age = 0;
	u64 caller;
	enum kblock_free_result res;

	if (!ptr)
		return 0;

	caller = read_caller(regs);
	res = kblock_note_free(ptr, true, cache, &size, &age);
	emit_free_result(res, ptr, size, age, caller, cache);
	return 0;
}

/* ------------------------------------------------------------------------ */
/* registration								    */
/* ------------------------------------------------------------------------ */

static void note_status(const char *name, bool kret, int ret)
{
	if (mt_nr_status >= MT_MAX_PROBES)
		return;
	mt_status[mt_nr_status].name        = name;
	mt_status[mt_nr_status].is_kretprobe = kret;
	mt_status[mt_nr_status].ok           = (ret == 0);
	mt_nr_status++;

	if (ret == 0)
		atomic64_inc(&c_probed_ok);
	else
		atomic64_inc(&c_probed_failed);
}

/* Every allocation entry handler writes the same 32-byte payload. */
#define MT_RPROBE(sym, entry)						\
	do {								\
		struct kretprobe *rp = &mt_rprobes[mt_nr_rprobes];	\
		int _ret;						\
									\
		memset(rp, 0, sizeof(*rp));				\
		rp->kp.symbol_name = (sym);				\
		rp->handler        = ret_alloc;				\
		rp->entry_handler  = (entry);				\
		rp->maxactive      = mt_maxactive();			\
		rp->data_size      = sizeof(struct alloc_ctx);		\
		_ret = register_kretprobe(rp);				\
		if (_ret == 0)						\
			mt_nr_rprobes++;				\
		note_status((sym), true, _ret);				\
	} while (0)

#define MT_KPROBE(sym, fn)						\
	do {								\
		struct kprobe *kp = &mt_kprobes[mt_nr_kprobes];		\
		int _ret;						\
									\
		memset(kp, 0, sizeof(*kp));				\
		kp->symbol_name = (sym);				\
		kp->pre_handler = (fn);					\
		_ret = register_kprobe(kp);				\
		if (_ret == 0)						\
			mt_nr_kprobes++;				\
		note_status((sym), false, _ret);			\
	} while (0)

int probes_register(unsigned int *ok, unsigned int *failed)
{
	if (mt_registered)
		goto report;

	/*
	 * Register the release probes *first*.  If any of them fails we still
	 * keep the rest - partial coverage is strictly better than none, and
	 * the status table tells the operator exactly what is missing.
	 */
	MT_KPROBE("kfree", kp_kfree);
	MT_KPROBE("kmem_cache_free", kp_cache_free);

	MT_RPROBE("__kmalloc_noprof",            entry_size);
	MT_RPROBE("__kmalloc_node_noprof",       entry_size);
	MT_RPROBE("__kmalloc_large_noprof",      entry_size);
	MT_RPROBE("__kmalloc_large_node_noprof", entry_size);
	MT_RPROBE("__kmalloc_cache_noprof",      entry_cache_rdx);
	MT_RPROBE("__kmalloc_cache_node_noprof", entry_cache_rcx);
	MT_RPROBE("kmem_cache_alloc_noprof",     entry_cache_only);
	MT_RPROBE("kmem_cache_alloc_lru_noprof", entry_cache_only);

	mt_registered = true;

report:
	if (ok)
		*ok = (unsigned int)atomic64_read(&c_probed_ok);
	if (failed)
		*failed = (unsigned int)atomic64_read(&c_probed_failed);
	return 0;
}

void probes_unregister(void)
{
	unsigned int i;

	if (!mt_registered)
		return;

	/* Reverse order, and tolerate probes that never registered: the
	 * kernel ignores unregister of an unknown kretprobe only if we only
	 * hand back what register_kprobe accepted, which is exactly what the
	 * mt_nr_* counters track. */
	for (i = mt_nr_rprobes; i > 0; i--)
		unregister_kretprobe(&mt_rprobes[i - 1]);
	for (i = mt_nr_kprobes; i > 0; i--)
		unregister_kprobe(&mt_kprobes[i - 1]);

	mt_nr_rprobes = 0;
	mt_nr_kprobes = 0;
	mt_registered = false;
}

void probes_stats(struct mt_probe_stats *out)
{
	unsigned int i;
	s64 missed = 0;

	if (!out)
		return;

	for (i = 0; i < mt_nr_rprobes; i++)
		missed += mt_rprobes[i].nmissed;

	out->alloc_seen       = (u64)atomic64_read(&c_alloc_seen);
	out->alloc_null       = (u64)atomic64_read(&c_alloc_null);
	out->alloc_table_full = (u64)atomic64_read(&c_alloc_full);
	out->oversize         = (u64)atomic64_read(&c_oversize);
	out->free_seen        = (u64)atomic64_read(&c_free_seen);
	out->double_free      = (u64)atomic64_read(&c_double_free);
	out->wrong_free       = (u64)atomic64_read(&c_wrong_free);
	out->cache_mismatch   = (u64)atomic64_read(&c_cache_mismatch);
	out->unknown_free     = (u64)atomic64_read(&c_unknown_free);
	out->probed_ok        = (u64)atomic64_read(&c_probed_ok);
	out->probed_failed    = (u64)atomic64_read(&c_probed_failed);
	out->ret_missed       = (missed > 0) ? (u64)missed : 0;
}

void probes_status(struct mt_probe_status *out, unsigned int *count)
{
	unsigned int i;

	if (count)
		*count = mt_nr_status;
	if (!out)
		return;
	for (i = 0; i < mt_nr_status; i++)
		out[i] = mt_status[i];
}
