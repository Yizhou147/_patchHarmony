// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>

#include "core.h"
#include "hk.h"
#include "hk_patch.h"
#include "ds.h"
#include "ds_caps.h"
#include "ds_ipcns.h"
#include "ds_ksym.h"
#include "hint.h"
#include "ds_pidns.h"
#include "ds_proc.h"
#include "ds_slot.h"
#include "ds_status.h"
#include "ipc_mqueue_compat.h"

bool droid_lkm_verbose;

module_param_named(verbose, droid_lkm_verbose, bool, 0444);
MODULE_PARM_DESC(verbose, "log every hook entry (on-device crash bisect)");

static bool droid_lkm_mqueue_fs_up;

static const char *const droid_lkm_probe_syms[] = {
	"do_exit",
	"kernel_clone",
	"task_active_pid_ns",
	"find_ge_pid",
	"pid_task",
	"proc_alloc_inum",
	"proc_free_inum",
	"disable_pid_allocation",
	"group_send_sig_info",
	"kernel_wait4",
	"proc_ns_dir_inode_operations",
	"proc_pid_make_inode",
	"pid_dentry_operations",
	"do_mmap",
	"shmem_file_setup",
	"__arm64_sys_unshare",
	"__arm64_sys_clone",
	"__arm64_sys_clone3",
	"__arm64_sys_setns",
	"__arm64_sys_reboot",
	"sys_call_table",
	"create_new_namespaces",
	"copy_namespaces",
	"copy_process",
	"unshare_nsproxy_namespaces",
	"check_unshare_flags",
	"switch_task_namespaces",
};

static void droid_lkm_probe_symbols(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(droid_lkm_probe_syms); i++)
		droid_lkm_dbg("sym %-30s = 0x%lx\n", droid_lkm_probe_syms[i],
			droid_lkm_sym(droid_lkm_probe_syms[i]));
}

static void droid_lkm_mqueue_fs_teardown(void)
{
	if (droid_lkm_mqueue_fs_up) {
		droid_lkm_mqueue_fs_exit();
		droid_lkm_mqueue_fs_up = false;
	}
}

static unsigned long __nocfi droid_lkm_hk_resolve(const char *name)
{
	return droid_lkm_sym(name);
}

/*
 * the write path is chosen once, here. the slot path stores through an alias this
 * module maps itself, and MediaTek kernel protection trips on that store on this
 * device, which is what took it down, so the kernel's own primitive is the path
 * every write takes. the slot_on parameter brings the slot path back for a
 * kernel that allows it
 */
static struct hk_cfg droid_lkm_hk_cfg = {
	.resolve = droid_lkm_hk_resolve,
	.write = hk_write_kernel,
};


MODULE_PARM_DESC(inline_hook, "install inline hooks, off by default");

/*
 * on the Redmi G Pro 27U kernel (MTK MT9655, 5.15.148-android14-11) the offsets
 * run the scan looks for breaks partway, because KALLSYMS_ALL carries per cpu
 * symbols whose relative offset sits outside the image, so a plain scan ends at
 * KALLRECON_NO_OFFSETS. seeding the table address skips that search. the kernel
 * is nokaslr, so the value holds across every boot of one build; offsets=0 gives
 * the scan back on a kernel that does not need the hint.
 */
#define DROID_LKM_DEFAULT_OFFSETS 0xffffffc00911f5a8UL

static unsigned long droid_lkm_offsets = DROID_LKM_DEFAULT_OFFSETS;
module_param_named(offsets, droid_lkm_offsets, ulong, 0444);
MODULE_PARM_DESC(offsets, "runtime address of kallsyms_offsets, 0 to scan for it");

static int __init droid_lkm_init(void)
{
	struct kallrecon_hint hint = { .offsets = droid_lkm_offsets };
	int ret;

	kallrecon_supply(&hint);
	find_kallsyms_base();
	if (!klnum_val || !kallrecon_klp) {
		droid_lkm_err("kallsyms recovery failed (%d)\n",
			      kallrecon_fail_reason());
		droid_lkm_err("  sprint=0x%lx base=0x%lx offs=0x%lx ti=0x%lx names=0x%lx num=%u klnum=%u layout=v%d seqs=0x%lx klp=%ps\n",
			      sprint_addr, kernel_base, kloffs_addr, klindex_addr,
			      klnames_addr, klnum_addr ? *(unsigned int *)klnum_addr : 0,
			      klnum_val, (int)kl_layout, klseqs_addr,
			      kallrecon_klp);
		droid_lkm_err("  probe lookup: kallsyms_lookup_name=0x%lx do_exit=0x%lx _stext=0x%lx\n",
			      kallsyms_name_to_addr("kallsyms_lookup_name"),
			      kallsyms_name_to_addr("do_exit"),
			      kallsyms_name_to_addr("_stext"));
		return -ENODATA;
	}
	droid_lkm_info("loaded, klnum=%u offsets=0x%lx\n", klnum_val,
		       droid_lkm_offsets);

	droid_lkm_info("params: verbose=%d skip_sysvipc=%d skip_do_exit=%d no_fake_ns=%d\n",
		droid_lkm_verbose, droid_lkm_slot_skip_sysvipc(), droid_lkm_pidns_skip_do_exit(),
		droid_lkm_slot_no_fake_ns());
	droid_lkm_probe_symbols();

	ret = droid_lkm_ksym_init();
	if (ret)
		return ret;

	ret = droid_lkm_caps_init();
	if (ret)
		return ret;
	droid_lkm_caps_report();

	ret = droid_lkm_munmap_init();
	if (ret)
		return ret;

	ret = hk_init(&droid_lkm_hk_cfg);
	if (ret) {
		droid_lkm_err("hk_init failed: %d\n", ret);
		return ret;
	}

	ret = droid_lkm_pidns_init();
	if (ret)
		goto err_hk;

	ret = droid_lkm_ipcns_init();
	if (ret)
		goto err_pidns;



	if (droid_lkm_mqueue_fs_init()) {
		droid_lkm_warn("POSIX mqueue disabled (mqueuefs/shim unavailable)\n");
	} else {
		droid_lkm_mqueue_fs_up = true;
	}

	ret = droid_lkm_slot_init();
	if (ret)
		goto err_ipcns;

	ret = droid_lkm_proc_init();
	if (ret)
		goto err_slot;

	ret = droid_lkm_status_init();
	if (ret)
		droid_lkm_warn("NSpid emulation disabled: %d\n", ret);

	droid_lkm_info("ready\n");
	return 0;

err_slot:
	droid_lkm_proc_exit();
	droid_lkm_slot_exit();
err_ipcns:
	droid_lkm_ipcns_exit();

	droid_lkm_mqueue_fs_teardown();
err_pidns:
	droid_lkm_pidns_exit();
err_hk:
	hk_exit();
	return ret;
}

static void __exit droid_lkm_exit(void)
{


	if (droid_lkm_pidns_busy() || droid_lkm_ipcns_busy())
		droid_lkm_warn("live container state at unload; those objects will be leaked\n");

	droid_lkm_status_exit();
	droid_lkm_proc_exit();
	droid_lkm_slot_exit();

	droid_lkm_task_ipc_deferred_run();
	droid_lkm_ipcns_exit();

	droid_lkm_mqueue_fs_teardown();
	droid_lkm_pidns_exit();
	droid_lkm_keepalive_release();
	hk_exit();
	droid_lkm_info("unloaded\n");
}

module_init(droid_lkm_init);
module_exit(droid_lkm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Droidspaces kernel feature shim for stock GKI");
MODULE_AUTHOR("dere3046");
MODULE_VERSION("0.1.0");
