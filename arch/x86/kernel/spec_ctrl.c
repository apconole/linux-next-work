/*
 *  Copyright (C) 2017  Red Hat, Inc.
 *
 *  This work is licensed under the terms of the GNU GPL, version 2. See
 *  the COPYING file in the top-level directory.
 */

#include <linux/percpu.h>
#include <asm/spec_ctrl.h>

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

void set_spec_ctrl_pcp_ibpb(bool enable)
{
	set_spec_ctrl_pcp(enable, SPEC_CTRL_PCP_IBPB);
}
