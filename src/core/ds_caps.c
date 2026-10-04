// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/user_namespace.h>

#include "ds.h"
#include "ds_caps.h"

struct droid_lkm_caps droid_lkm_caps;

static unsigned int droid_lkm_caps_parse_version(void)
{
	unsigned int major = 0, minor = 0, patch = 0;
	unsigned long uts = droid_lkm_sym("init_uts_ns");
	char buf[__NEW_UTS_LEN + 1];

	/*
	 * not utsname(): that reads current->nsproxy->uts_ns, so it is only
	 * correct while task_struct and nsproxy member offsets match the headers
	 * this module was built against. uts_namespace carries no configuration
	 * dependent member, so these two offsets are the whole assumption.
	 */
	if (!uts)
		return 0;
	memcpy(buf, (void *)(uts + offsetof(struct uts_namespace, name) +
			     offsetof(struct new_utsname, release)),
	       sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	if (sscanf(buf, "%u.%u.%u", &major, &minor, &patch) < 2)
		return 0;
	return DROID_LKM_VERSION(major, minor, patch);
}

int droid_lkm_caps_init(void)
{
	struct droid_lkm_caps *caps = &droid_lkm_caps;
	void *idmap_none = (void *)droid_lkm_sym("nop_mnt_idmap");

	caps->version = droid_lkm_caps_parse_version();
	if (!caps->version) {
		droid_lkm_err("cannot parse the kernel release, refusing to load\n");
		return -ENODEV;
	}

	if (caps->version < DROID_LKM_VERSION(5, 10, 0)) {
		droid_lkm_err("kernel %u.%u is older than 5.10, refusing to load\n",
			      caps->version >> 16, (caps->version >> 8) & 0xff);
		return -ENODEV;
	}

	/*
	 * the idmap argument replaced the user namespace one in 6.3. the symbol
	 * probe decides when it answers, the version only covers a kernel that
	 * carries neither name.
	 */
	caps->perm_takes_idmap = idmap_none != NULL ||
				 caps->version >= DROID_LKM_VERSION(6, 3, 0);
	caps->idmap_none = idmap_none ? idmap_none : (void *)&init_user_ns;
	/*
	 * do_mmap gained vm_flags in the same generation that moved the locked
	 * unmap entry to do_vmi_munmap, so the symbol answers this one and the
	 * version is not consulted.
	 */
	caps->mmap_takes_vm_flags = droid_lkm_sym("do_vmi_munmap") != 0;
	caps->has_ns_count = caps->version >= DROID_LKM_VERSION(5, 15, 0);
	caps->ctl_takes_table = caps->version < DROID_LKM_VERSION(6, 12, 0);

	/*
	 * a version derived value that contradicts a symbol probe means this
	 * kernel is not one this build knows. loading would install a handler
	 * with the wrong shape and corrupt state, so refuse instead.
	 */
	if (caps->version >= DROID_LKM_VERSION(6, 6, 0) &&
	    !droid_lkm_sym("do_vmi_munmap")) {
		droid_lkm_err("kernel %u.%u has no do_vmi_munmap, refusing to load\n",
			      caps->version >> 16, (caps->version >> 8) & 0xff);
		return -ENODEV;
	}
	if (caps->version < DROID_LKM_VERSION(6, 1, 0) &&
	    !droid_lkm_sym("__do_munmap")) {
		droid_lkm_err("kernel %u.%u has no __do_munmap, refusing to load\n",
			      caps->version >> 16, (caps->version >> 8) & 0xff);
		return -ENODEV;
	}

	return 0;
}

void droid_lkm_caps_report(void)
{
	const struct droid_lkm_caps *caps = &droid_lkm_caps;

	droid_lkm_info("caps: kernel=%u.%u.%u idmap=%d idmap_none=%px vm_flags=%d ns_count=%d ctl_table=%d\n",
		       caps->version >> 16, (caps->version >> 8) & 0xff,
		       caps->version & 0xff, caps->perm_takes_idmap,
		       caps->idmap_none, caps->mmap_takes_vm_flags,
		       caps->has_ns_count, caps->ctl_takes_table);
}
