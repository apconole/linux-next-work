/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NOSPEC_BRANCH_H__
#define __NOSPEC_BRANCH_H__

#include <asm/alternative.h>
#include <asm/alternative-asm.h>
#include <asm/cpufeatures.h>
#include <asm/percpu.h>
#include <asm/nops.h>
#include <asm/jump_label.h>

#ifdef __ASSEMBLY__

/*
 * These are the bare retpoline primitives for indirect jmp and call.
 * Do not use these directly; they only exist to make the ALTERNATIVE
 * invocation below less ugly.
 */
.macro RETPOLINE_JMP reg:req
	call	.Ldo_rop_\@
.Lspec_trap_\@:
	pause
	jmp	.Lspec_trap_\@
.Ldo_rop_\@:
	mov	\reg, (%_ASM_SP)
	ret
.endm

/*
 * This is a wrapper around RETPOLINE_JMP so the called function in reg
 * returns to the instruction after the macro.
 */
.macro RETPOLINE_CALL reg:req
	jmp	.Ldo_call_\@
.Ldo_retpoline_jmp_\@:
	RETPOLINE_JMP \reg
.Ldo_call_\@:
	call	.Ldo_retpoline_jmp_\@
.endm

.macro __JMP_NOSPEC reg:req
	661: RETPOLINE_JMP \reg; 662:
	.pushsection .altinstr_replacement, "ax"
	663: lfence; jmp *\reg; 664:
	.popsection
	.pushsection .altinstructions, "a"
	altinstruction_entry 661b, 663b, X86_FEATURE_RETPOLINE_AMD, 662b-661b, 664b-663b
	.popsection
.endm

.macro __CALL_NOSPEC reg:req
	661: RETPOLINE_CALL \reg; 662:
	.pushsection .altinstr_replacement, "ax"
	663: lfence; call *\reg; 664:
	.popsection
	.pushsection .altinstructions, "a"
	altinstruction_entry 661b, 663b, X86_FEATURE_RETPOLINE_AMD, 662b-661b, 664b-663b
	.popsection
.endm

/*
 * JMP_NOSPEC and CALL_NOSPEC macros can be used instead of a simple
 * indirect jmp/call which may be susceptible to the Spectre variant 2
 * attack.
 */
.macro JMP_NOSPEC reg:req
	STATIC_JUMP .Lretp_\@, retp_enabled_key
	jmp *\reg

.Lretp_\@:
	__JMP_NOSPEC \reg
.endm

.macro CALL_NOSPEC reg:req
	STATIC_JUMP .Lretp_\@, retp_enabled_key
	call *\reg
	jmp	.Ldone_\@

.Lretp_\@:
	__CALL_NOSPEC \reg

.Ldone_\@:
.endm

#else /* __ASSEMBLY__ */

#if defined(CONFIG_X86_64) && defined(RETPOLINE)
/*
 * Since the inline asm uses the %V modifier which is only in newer GCC,
 * the 64-bit one is dependent on RETPOLINE not CONFIG_RETPOLINE.
 */
#define CALL_NOSPEC						\
	"call __x86_indirect_thunk_%V[thunk_target]\n"
#define THUNK_TARGET(addr) [thunk_target] "r" (addr)

#else /* No retpoline for C / inline asm */
# define CALL_NOSPEC "call *%[thunk_target]\n"
# define THUNK_TARGET(addr) [thunk_target] "rm" (addr)
#endif

/* The Spectre V2 mitigation variants */
enum spectre_v2_mitigation {
	SPECTRE_V2_NONE,
	SPECTRE_V2_RETPOLINE_MINIMAL,
	SPECTRE_V2_RETPOLINE_NO_IBPB,
	SPECTRE_V2_RETPOLINE_SKYLAKE,
	SPECTRE_V2_RETPOLINE_UNSAFE_MODULE,
	SPECTRE_V2_RETPOLINE,
	SPECTRE_V2_IBRS,
	SPECTRE_V2_IBRS_ALWAYS,
	SPECTRE_V2_IBP_DISABLED,
};

void __spectre_v2_select_mitigation(void);
void spectre_v2_print_mitigation(void);

static inline bool retp_compiler(void)
{
#ifdef RETPOLINE
	return true;
#else
	return false;
#endif

#endif /* __ASSEMBLY__ */
#endif /* __NOSPEC_BRANCH_H__ */
