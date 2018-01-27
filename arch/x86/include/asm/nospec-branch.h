/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NOSPEC_BRANCH_H__
#define __NOSPEC_BRANCH_H__

#include <asm/alternative.h>
#include <asm/alternative-asm.h>
#include <asm/cpufeatures.h>
#include <asm/spec_ctrl.h>
#include <asm/percpu.h>
#include <asm/nops.h>
#include <asm/jump_label.h>

/* The Spectre V2 mitigation variants */
enum spectre_v2_mitigation {
	SPECTRE_V2_NONE,
	SPECTRE_V2_IBRS,
	SPECTRE_V2_IBRS_ALWAYS,
	SPECTRE_V2_IBP_DISABLED,
};

void __spectre_v2_select_mitigation(void);
void spectre_v2_print_mitigation(void);

#endif /* __NOSPEC_BRANCH_H__ */
