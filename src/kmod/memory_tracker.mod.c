#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0xda5bcbd2, "kmem_cache_size" },
	{ 0x07bc7e7e, "sort" },
	{ 0xabd9ccfa, "simple_open" },
	{ 0x24475c71, "noop_llseek" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xa831f1fd, "debugfs_remove" },
	{ 0x9e4d7e38, "seq_putc" },
	{ 0xe0038666, "unregister_kretprobe" },
	{ 0x0b6c7ccc, "const_current_task" },
	{ 0x86632fd6, "_find_next_bit" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0x444885a7, "_raw_spin_unlock_irqrestore" },
	{ 0xb5c51982, "__cpu_possible_mask" },
	{ 0x27683a56, "memset" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xf296206e, "nr_cpu_ids" },
	{ 0xd94f9b73, "sprint_symbol" },
	{ 0x7a093393, "seq_read" },
	{ 0x7ec472ba, "cpu_number" },
	{ 0x7ec472ba, "__preempt_count" },
	{ 0xf1de9e85, "vfree" },
	{ 0x67f7faf9, "param_ops_bool" },
	{ 0x272da60a, "seq_write" },
	{ 0x6eb0b5bc, "__kmalloc_cache_noprof" },
	{ 0x97acb853, "ktime_get" },
	{ 0xd7a59a65, "vzalloc_noprof" },
	{ 0x06396bec, "seq_printf" },
	{ 0xb6377019, "register_kprobe" },
	{ 0xa1b728ae, "debugfs_create_file_full" },
	{ 0xab4fa532, "register_kretprobe" },
	{ 0x4a5d601e, "single_release" },
	{ 0x2de0a194, "unregister_kprobe" },
	{ 0x3769edd9, "seq_open" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0xf1de9e85, "kvfree" },
	{ 0x25596857, "single_open" },
	{ 0xaaac1325, "debugfs_create_dir" },
	{ 0x17e051a9, "__kvmalloc_node_noprof" },
	{ 0x2dcfc42e, "kmalloc_caches" },
	{ 0x67f7faf9, "param_ops_uint" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0x4a5d601e, "seq_release" },
	{ 0xd272d446, "__SCT__preempt_schedule" },
	{ 0xbd03ed67, "this_cpu_off" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0xe2d24a1a, "seq_lseek" },
	{ 0x11f4259a, "_raw_spin_lock_irqsave" },
	{ 0xd272d446, "__fentry__" },
	{ 0xe8213e80, "_printk" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x1b60315e, "copy_from_kernel_nofault" },
	{ 0x80fa37a5, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x90a48d82,
	0xda5bcbd2,
	0x07bc7e7e,
	0xabd9ccfa,
	0x24475c71,
	0xbd03ed67,
	0xa831f1fd,
	0x9e4d7e38,
	0xe0038666,
	0x0b6c7ccc,
	0x86632fd6,
	0xe54e0a6b,
	0x444885a7,
	0xb5c51982,
	0x27683a56,
	0xd272d446,
	0xf296206e,
	0xd94f9b73,
	0x7a093393,
	0x7ec472ba,
	0x7ec472ba,
	0xf1de9e85,
	0x67f7faf9,
	0x272da60a,
	0x6eb0b5bc,
	0x97acb853,
	0xd7a59a65,
	0x06396bec,
	0xb6377019,
	0xa1b728ae,
	0xab4fa532,
	0x4a5d601e,
	0x2de0a194,
	0x3769edd9,
	0xe4de56b4,
	0xf1de9e85,
	0x25596857,
	0xaaac1325,
	0x17e051a9,
	0x2dcfc42e,
	0x67f7faf9,
	0xd710adbf,
	0x4a5d601e,
	0xd272d446,
	0xbd03ed67,
	0xcb8b6ec6,
	0xe2d24a1a,
	0x11f4259a,
	0xd272d446,
	0xe8213e80,
	0xbd03ed67,
	0xd272d446,
	0x1b60315e,
	0x80fa37a5,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__ubsan_handle_out_of_bounds\0"
	"kmem_cache_size\0"
	"sort\0"
	"simple_open\0"
	"noop_llseek\0"
	"random_kmalloc_seed\0"
	"debugfs_remove\0"
	"seq_putc\0"
	"unregister_kretprobe\0"
	"const_current_task\0"
	"_find_next_bit\0"
	"__fortify_panic\0"
	"_raw_spin_unlock_irqrestore\0"
	"__cpu_possible_mask\0"
	"memset\0"
	"__x86_return_thunk\0"
	"nr_cpu_ids\0"
	"sprint_symbol\0"
	"seq_read\0"
	"cpu_number\0"
	"__preempt_count\0"
	"vfree\0"
	"param_ops_bool\0"
	"seq_write\0"
	"__kmalloc_cache_noprof\0"
	"ktime_get\0"
	"vzalloc_noprof\0"
	"seq_printf\0"
	"register_kprobe\0"
	"debugfs_create_file_full\0"
	"register_kretprobe\0"
	"single_release\0"
	"unregister_kprobe\0"
	"seq_open\0"
	"__ubsan_handle_load_invalid_value\0"
	"kvfree\0"
	"single_open\0"
	"debugfs_create_dir\0"
	"__kvmalloc_node_noprof\0"
	"kmalloc_caches\0"
	"param_ops_uint\0"
	"__kmalloc_noprof\0"
	"seq_release\0"
	"__SCT__preempt_schedule\0"
	"this_cpu_off\0"
	"kfree\0"
	"seq_lseek\0"
	"_raw_spin_lock_irqsave\0"
	"__fentry__\0"
	"_printk\0"
	"__ref_stack_chk_guard\0"
	"__stack_chk_fail\0"
	"copy_from_kernel_nofault\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "CF9BAE88C2C5E013AD42151");
