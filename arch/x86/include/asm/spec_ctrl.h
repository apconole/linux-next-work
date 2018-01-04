#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#define SPEC_CTRL_PCP_IBRS	(1<<0)
#define SPEC_CTRL_PCP_IBPB	(1<<1)

#ifdef __ASSEMBLY__

#include <asm/msr-index.h>

.macro ENABLE_IBRS
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	pushq %rax
	pushq %rcx
	pushq %rdx
	movl $MSR_IA32_SPEC_CTRL, %ecx
	movl $0, %edx
	movl $FEATURE_ENABLE_IBRS, %eax
	wrmsr
	popq %rdx
	popq %rcx
	popq %rax

.Lskip_\@:
.endm

.macro ENABLE_IBRS_CLOBBER
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	movl $MSR_IA32_SPEC_CTRL, %ecx
	movl $0, %edx
	movl $FEATURE_ENABLE_IBRS, %eax
	wrmsr

.Lskip_\@:
.endm

.macro ENABLE_IBRS_SAVE_AND_CLOBBER save_reg:req
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	movl $MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	movl %eax, \save_reg

	movl $0, %edx
	movl $FEATURE_ENABLE_IBRS, %eax
	wrmsr

.Lskip_\@:
.endm

.macro DISABLE_IBRS
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	pushq %rax
	pushq %rcx
	pushq %rdx
	movl $MSR_IA32_SPEC_CTRL, %ecx
	movl $0, %edx
	movl $0, %eax
	wrmsr
	popq %rdx
	popq %rcx
	popq %rax

.Lskip_\@:
.endm

.macro RESTORE_IBRS_CLOBBER save_reg:req
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	cmpl $FEATURE_ENABLE_IBRS, \save_reg
	je .Lskip_\@

	movl $MSR_IA32_SPEC_CTRL, %ecx
	movl $0, %edx
	movl \save_reg, %eax
	wrmsr

.Lskip_\@:
.endm

.macro DISABLE_IBRS_CLOBBER
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	movl $MSR_IA32_SPEC_CTRL, %ecx
	movl $0, %edx
	movl $0, %eax
	wrmsr

.Lskip_\@:
.endm

#if 0 /* unused */
.macro SET_IBPB
	testl $SPEC_CTRL_PCP_IBPB, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	pushq %rax
	pushq %rcx
	pushq %rdx
	movl $MSR_IA32_PRED_CMD, %ecx
	movl $0, %edx
	movl $FEATURE_SET_IBPB, %eax
	wrmsr
	popq %rdx
	popq %rcx
	popq %rax

.Lskip_\@:
.endm
#endif

#else /* __ASSEMBLY__ */

#include <linux/ptrace.h>
#include <asm/microcode.h>

extern void set_spec_ctrl_pcp_ibrs(bool enable);
extern void set_spec_ctrl_pcp_ibpb(bool enable);

static inline void spec_ctrl_enable_ibrs(void)
{
	if (static_cpu_has(X86_FEATURE_SPEC_CTRL)) {
		if (__this_cpu_read(spec_ctrl_pcp) & SPEC_CTRL_PCP_IBRS)
			native_wrmsrl(MSR_IA32_SPEC_CTRL, FEATURE_ENABLE_IBRS);
	}
}

static inline void spec_ctrl_disable_ibrs(void)
{
	if (static_cpu_has(X86_FEATURE_SPEC_CTRL)) {
		if (__this_cpu_read(spec_ctrl_pcp) & SPEC_CTRL_PCP_IBRS)
			native_wrmsrl(MSR_IA32_SPEC_CTRL, 0);
	}
}

static inline void __spec_ctrl_ibpb(void)
{
	native_wrmsrl(MSR_IA32_PRED_CMD, FEATURE_SET_IBPB);
}

static inline void spec_ctrl_ibpb(void)
{
	if (static_cpu_has(X86_FEATURE_IBPB_SUPPORT)) {
		if (__this_cpu_read(spec_ctrl_pcp) & SPEC_CTRL_PCP_IBPB)
			__spec_ctrl_ibpb();
	}
}

static inline void spec_ctrl_ibpb_if_different_creds(struct task_struct *next)
{
	struct task_struct *prev = current;

	if (static_cpu_has(X86_FEATURE_IBPB_SUPPORT)) {
		if (__this_cpu_read(spec_ctrl_pcp) & SPEC_CTRL_PCP_IBPB && next &&
		    ___ptrace_may_access(next, NULL, prev, PTRACE_MODE_IBPB))
			__spec_ctrl_ibpb();
	}
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
