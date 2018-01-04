/*
 *  Copyright (C) 2017  Red Hat, Inc.
 *
 *  This work is licensed under the terms of the GNU GPL, version 2. See
 *  the COPYING file in the top-level directory.
 */

#include <linux/percpu.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <asm/spec_ctrl.h>
#include <asm/cpufeature.h>

static DEFINE_MUTEX(spec_ctrl_mutex);

enum {
	IBRS_DISABLED,
	/* in host kernel, disabled in guest and userland */
	IBRS_ENABLED,
	/* in host kernel and host userland, disabled in guest */
	IBRS_ENABLED_USER,
	IBRS_MAX = IBRS_ENABLED_USER,
};
static unsigned int ibrs_enabled __read_mostly;
static bool ibpb_enabled __read_mostly;

static void set_spec_ctrl_pcp(bool enable, int flag)
{
	int cpu, val = __this_cpu_read(spec_ctrl_pcp);
	if (enable)
		val |= flag;
	else
		val &= ~flag;
	for_each_possible_cpu(cpu)
		WRITE_ONCE(per_cpu(spec_ctrl_pcp, cpu), val);
}

void set_spec_ctrl_pcp_ibrs(bool enable)
{
	set_spec_ctrl_pcp(enable, SPEC_CTRL_PCP_IBRS);
}

void set_spec_ctrl_pcp_ibrs_user(bool enable)
{
	set_spec_ctrl_pcp(enable, SPEC_CTRL_PCP_IBRS_USER);
}

void set_spec_ctrl_pcp_ibpb(bool enable)
{
	set_spec_ctrl_pcp(enable, SPEC_CTRL_PCP_IBPB);
}

void spec_ctrl_init(struct cpuinfo_x86 *c)
{
	bool implicit_ibpb = false;

	if (c != &boot_cpu_data)
		return;

	if (c->x86_vendor != X86_VENDOR_INTEL &&
	    c->x86_vendor != X86_VENDOR_AMD)
		return;

	/*
	 * On both Intel and AMD, SPEC_CTRL implies IBPB.
	 */
	if (boot_cpu_has(X86_FEATURE_SPEC_CTRL)) {
		setup_force_cpu_cap(X86_FEATURE_IBPB_SUPPORT);
		if (!ibrs_enabled) {
			set_spec_ctrl_pcp_ibrs(true);
			ibrs_enabled = 1;
		}
		printk(KERN_INFO
		       "FEATURE SPEC_CTRL Present\n");
	} else {
		printk(KERN_INFO
		       "FEATURE SPEC_CTRL Not Present\n");
	}

	/*
	 * Some AMD CPUs don't need IBPB or IBRS CPUID bits, because
	 * they can just disable indirect branch predictor
	 * support (MSR 0xc0011021[14]).
	 */
	if (c->x86_vendor == X86_VENDOR_AMD &&
	    !(cpu_has(c, X86_FEATURE_IBPB_SUPPORT) &&
	      cpu_has(c, X86_FEATURE_SPEC_CTRL))) {
		u64 val;

		switch (c->x86) {
		case 0x10:
		case 0x12:
		case 0x16:
			rdmsrl(MSR_F15H_IC_CFG, val);
			val |= MSR_F15H_IC_CFG_DIS_IND;
			wrmsrl(MSR_F15H_IC_CFG, val);
			implicit_ibpb = true;
			break;
		}
	}
	if (boot_cpu_has(X86_FEATURE_IBPB_SUPPORT) || implicit_ibpb) {
		if (boot_cpu_has(X86_FEATURE_IBPB_SUPPORT)) {
			if (!ibpb_enabled) {
				set_spec_ctrl_pcp_ibpb(true);
				ibpb_enabled = 1;
			}
			printk(KERN_INFO "FEATURE IBPB_SUPPORT Present\n");
		} else {
			printk(KERN_INFO "FEATURE IBPB_SUPPORT Implicit\n");
		}
	} else {
		printk(KERN_INFO "FEATURE IBPB_SUPPORT Not Present\n");
	}
}
