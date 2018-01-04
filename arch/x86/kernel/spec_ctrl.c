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

static void spec_ctrl_flush_all_cpus(u32 msr_nr, u64 val)
{
	int cpu;
	get_online_cpus();
	for_each_online_cpu(cpu)
		wrmsrl_on_cpu(cpu, msr_nr, val);
	put_online_cpus();
}

static void flush_all_cpus_ibrs(bool enable)
{
	spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
				 enable ? FEATURE_ENABLE_IBRS : 0);
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

void spec_ctrl_rescan_cpuid(void)
{
	mutex_lock(&spec_ctrl_mutex);
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL ||
	    boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
		/* detect spec ctrl related cpuid additions */
		init_scattered_cpuid_features(&boot_cpu_data);
		spec_ctrl_init(&boot_cpu_data);
	}
	mutex_unlock(&spec_ctrl_mutex);
}

static ssize_t __enabled_read(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos, unsigned int *field)
{
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "%d\n", READ_ONCE(*field));
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ibrs_enabled_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	return __enabled_read(file, user_buf, count, ppos, &ibrs_enabled);
}

static ssize_t ibrs_enabled_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	unsigned int enable;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
		return -EINVAL;

	if (enable > IBRS_MAX)
		return -EINVAL;

	mutex_lock(&spec_ctrl_mutex);
	if (ibrs_enabled == enable)
		goto out_unlock;

	if (!boot_cpu_has(X86_FEATURE_SPEC_CTRL)) {
		count = -ENODEV;
		goto out_unlock;
	}

	if (enable == IBRS_ENABLED) {
		set_spec_ctrl_pcp_ibrs_user(false);
		set_spec_ctrl_pcp_ibrs(true);
	} else {
		set_spec_ctrl_pcp_ibrs(false);
		if (enable == IBRS_DISABLED) {
			set_spec_ctrl_pcp_ibrs_user(false);
			flush_all_cpus_ibrs(false);
		} else {
			WARN_ON(enable != IBRS_ENABLED_USER);
			set_spec_ctrl_pcp_ibrs_user(true);
			flush_all_cpus_ibrs(true);
		}
	}
	WRITE_ONCE(ibrs_enabled, enable);

out_unlock:
	mutex_unlock(&spec_ctrl_mutex);
	return count;
}

static const struct file_operations fops_ibrs_enabled = {
	.read = ibrs_enabled_read,
	.write = ibrs_enabled_write,
	.llseek = default_llseek,
};

static ssize_t ibpb_enabled_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	unsigned int tmp = ibpb_enabled;
	return __enabled_read(file, user_buf, count, ppos, &tmp);
}

static ssize_t ibpb_enabled_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	unsigned int enable;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
		return -EINVAL;

	if (enable > 1)
		return -EINVAL;

	mutex_lock(&spec_ctrl_mutex);
	if (ibpb_enabled == !!enable)
		goto out_unlock;

	if (!boot_cpu_has(X86_FEATURE_IBPB_SUPPORT)) {
		count = -ENODEV;
		goto out_unlock;
	}

	if (enable) {
		set_spec_ctrl_pcp_ibpb(true);
		WRITE_ONCE(ibpb_enabled, true);
	} else {
		set_spec_ctrl_pcp_ibpb(false);
		WRITE_ONCE(ibpb_enabled, false);
	}

out_unlock:
	mutex_unlock(&spec_ctrl_mutex);
	return count;
}

static const struct file_operations fops_ibpb_enabled = {
	.read = ibpb_enabled_read,
	.write = ibpb_enabled_write,
	.llseek = default_llseek,
};

static int __init debugfs_spec_ctrl(void)
{
	debugfs_create_file("ibrs_enabled", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_ibrs_enabled);
	debugfs_create_file("ibpb_enabled", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_ibpb_enabled);
	return 0;
}
late_initcall(debugfs_spec_ctrl);
