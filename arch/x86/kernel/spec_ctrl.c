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

static bool noibrs_cmdline __read_mostly;
static bool ibp_disabled __read_mostly;

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

static void spec_ctrl_sync_all_cpus(u32 msr_nr, u64 val)
{
	int cpu;
	get_online_cpus();
	for_each_online_cpu(cpu)
		wrmsrl_on_cpu(cpu, msr_nr, val);
	put_online_cpus();
}

static void sync_all_cpus_ibrs(bool enable)
{
	spec_ctrl_sync_all_cpus(MSR_IA32_SPEC_CTRL,
				 enable ? FEATURE_ENABLE_IBRS : 0);
}

static void __sync_this_cpu_ibp(void *data)
{
	bool enable = *(bool *)data;
	u64 val;

	/* disable IBP on old CPU families */
	rdmsrl(MSR_F15H_IC_CFG, val);
	if (!enable)
		val |= MSR_F15H_IC_CFG_DIS_IND;
	else
		val &= ~MSR_F15H_IC_CFG_DIS_IND;
	wrmsrl(MSR_F15H_IC_CFG, val);
}

/* enable means IBP should be enabled in the CPU (i.e. fast) */
static void sync_all_cpus_ibp(bool enable)
{
	get_online_cpus();

	__sync_this_cpu_ibp(&enable);

	smp_call_function_many(cpu_online_mask, __sync_this_cpu_ibp,
			       &enable, 1);

	put_online_cpus();
}

static void spec_ctrl_disable_all(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		WRITE_ONCE(per_cpu(spec_ctrl_pcp, cpu), 0);
}

static int __init noibrs(char *str)
{
	noibrs_cmdline = true;

	return 0;
}
early_param("noibrs", noibrs);

static int __init noibpb(char *str)
{
	/* deprecated */
	return 0;
}
early_param("noibpb", noibpb);

static void spec_ctrl_print_features(void)
{
	if (boot_cpu_has(X86_FEATURE_IBP_DISABLE)) {
		printk(KERN_INFO "FEATURE SPEC_CTRL Present (Implicit)\n");
		printk(KERN_INFO "FEATURE IBPB_SUPPORT Present (Implicit)\n");
		return;
	}

	if (cpu_has_spec_ctrl())
		printk(KERN_INFO "FEATURE SPEC_CTRL Present\n");
	else
		printk(KERN_INFO "FEATURE SPEC_CTRL Not Present\n");

	if (boot_cpu_has(X86_FEATURE_IBPB_SUPPORT))
		printk(KERN_INFO "FEATURE IBPB_SUPPORT Present\n");
	else
		printk(KERN_INFO "FEATURE IBPB_SUPPORT Not Present\n");
}

static void spec_ctrl_enable(void)
{
	if (boot_cpu_has(X86_FEATURE_IBP_DISABLE) && !noibrs_cmdline) {
		/* default enabled */
		ibp_disabled = true;
		return;
	}

	WARN_ON(cpu_has_spec_ctrl() && !boot_cpu_has(X86_FEATURE_IBPB_SUPPORT));

	if (cpu_has_spec_ctrl() && !noibrs_cmdline)
		set_spec_ctrl_pcp_ibrs(true);
}

void spec_ctrl_cpu_init(void)
{
	if (boot_cpu_has(X86_FEATURE_IBP_DISABLE)) {
		bool enabled = !ibp_disabled;
		__sync_this_cpu_ibp(&enabled);
		return;
	}

	if (ibrs_enabled() == IBRS_ENABLED_USER)
		native_wrmsrl(MSR_IA32_SPEC_CTRL, FEATURE_ENABLE_IBRS);
}

static void spec_ctrl_reinit_all_cpus(void)
{
	if (boot_cpu_has(X86_FEATURE_IBP_DISABLE)) {
		sync_all_cpus_ibp(!ibrs_enabled());
		return;
	}

	if (ibrs_enabled() == IBRS_ENABLED_USER)
		sync_all_cpus_ibrs(true);
	else if (ibrs_enabled() == IBRS_DISABLED)
		sync_all_cpus_ibrs(false);
}

void spec_ctrl_init(void)
{
	spec_ctrl_print_features();
	spec_ctrl_enable();
}

void spec_ctrl_rescan_cpuid(void)
{
	bool old_spec, old_ibpb;
	int cpu;

	if (boot_cpu_has(X86_FEATURE_IBP_DISABLE))
		return;

	mutex_lock(&spec_ctrl_mutex);
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL ||
	    boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {

		old_spec = boot_cpu_has(X86_FEATURE_SPEC_CTRL);
		old_ibpb = boot_cpu_has(X86_FEATURE_IBPB_SUPPORT);

		/* detect spec ctrl related cpuid additions */
		init_scattered_cpuid_features(&boot_cpu_data);

		/* if there were no spec ctrl related changes, we're done */
		if (old_spec == boot_cpu_has(X86_FEATURE_SPEC_CTRL) &&
		    old_ibpb == boot_cpu_has(X86_FEATURE_IBPB_SUPPORT))
			goto done;

		/*
		 * The SPEC_CTRL and IBPB_SUPPORT cpuid bits may have
		 * just been set in the boot_cpu_data, transfer them
		 * to the per-cpu data too.
		 */
		if (cpu_has_spec_ctrl())
			for_each_online_cpu(cpu)
				set_cpu_cap(&cpu_data(cpu),
					    X86_FEATURE_SPEC_CTRL);
		if (boot_cpu_has(X86_FEATURE_IBPB_SUPPORT))
			for_each_online_cpu(cpu)
				set_cpu_cap(&cpu_data(cpu),
					    X86_FEATURE_IBPB_SUPPORT);

		/*
		 * Re-execute the v2 mitigation logic based on any new CPU
		 * features.  Note that any debugfs-based changes the user may
		 * have made will be overwritten, because new features are now
		 * available, so any previous changes may no longer be
		 * relevant.  Go back to the defaults unless they're overridden
		 * by the cmdline.
		 */
		spec_ctrl_disable_all();
		spec_ctrl_enable();
		spec_ctrl_reinit_all_cpus();
	}
done:
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
	unsigned int enabled = ibrs_enabled();

	if (ibp_disabled)
		enabled = IBRS_ENABLED_USER;

	return __enabled_read(file, user_buf, count, ppos, &enabled);
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
	if ((!ibp_disabled && enable == ibrs_enabled()) ||
	    (ibp_disabled && enable == IBRS_ENABLED_USER))
		goto out_unlock;

	if (boot_cpu_has(X86_FEATURE_IBP_DISABLE)) {
		if (enable == IBRS_ENABLED) {
			count = -EINVAL;
			goto out_unlock;
		} else {
			if (enable == IBRS_DISABLED) {
				sync_all_cpus_ibp(true);
				ibp_disabled = false;
			} else {
				WARN_ON(enable != IBRS_ENABLED_USER);
				sync_all_cpus_ibp(false);
				ibp_disabled = true;
			}
		}
		goto out_unlock;
	}

	if (!cpu_has_spec_ctrl()) {
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
			sync_all_cpus_ibrs(false);
		} else {
			WARN_ON(enable != IBRS_ENABLED_USER);
			set_spec_ctrl_pcp_ibrs_user(true);
			sync_all_cpus_ibrs(true);
		}
	}

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
	unsigned int enabled = ibpb_enabled();

	if (ibp_disabled)
		enabled = 1;

	return __enabled_read(file, user_buf, count, ppos, &enabled);
}

static const struct file_operations fops_ibpb_enabled = {
	.read = ibpb_enabled_read,
	.llseek = default_llseek,
};

static int __init debugfs_spec_ctrl(void)
{
	debugfs_create_file("ibrs_enabled", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_ibrs_enabled);
	debugfs_create_file("ibpb_enabled", S_IRUSR,
			    arch_debugfs_dir, NULL, &fops_ibpb_enabled);
	return 0;
}
late_initcall(debugfs_spec_ctrl);
