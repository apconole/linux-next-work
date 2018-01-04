#ifdef CONFIG_KAISER

/* KAISER PGDs are 8k.  Flip bit 12 to switch between the two halves: */
#define KAISER_SWITCH_MASK (1<<PAGE_SHIFT)

.macro ADJUST_KERNEL_CR3 reg:req
	/* Clear "KAISER bit", point CR3 at kernel pagetables: */
	andq	$(~KAISER_SWITCH_MASK), \reg
.endm

.macro ADJUST_USER_CR3 reg:req
	/* Move CR3 up a page to the user page tables: */
	orq	$(KAISER_SWITCH_MASK), \reg
.endm

.macro SWITCH_TO_KERNEL_CR3 scratch_reg:req
	mov	%cr3, \scratch_reg
	ADJUST_KERNEL_CR3 \scratch_reg
	mov	\scratch_reg, %cr3
.endm

.macro SWITCH_TO_USER_CR3 scratch_reg:req
	mov	%cr3, \scratch_reg
	ADJUST_USER_CR3 \scratch_reg
	mov	\scratch_reg, %cr3
.endm

.macro SAVE_AND_SWITCH_TO_KERNEL_CR3 scratch_reg:req save_reg:req
	movq	%cr3, %r\scratch_reg
	movq	%r\scratch_reg, \save_reg
	/*
	 * Is the switch bit zero?  This means the address is
	 * up in real KAISER patches in a moment.
	 */
	testq	$(KAISER_SWITCH_MASK), %r\scratch_reg
	jz	.Ldone_\@

	ADJUST_KERNEL_CR3 %r\scratch_reg
	movq	%r\scratch_reg, %cr3

.Ldone_\@:
.endm

.macro RESTORE_CR3 save_reg:req
	/*
	 * The CR3 write could be avoided when not changing its value,
	 * but would require a CR3 read *and* a scratch register.
	 */
	movq	\save_reg, %cr3
.endm

#else /* CONFIG_KAISER=n: */

.macro SWITCH_TO_KERNEL_CR3 scratch_reg:req
.endm
.macro SWITCH_TO_USER_CR3 scratch_reg:req
.endm
.macro SAVE_AND_SWITCH_TO_KERNEL_CR3 scratch_reg:req save_reg:req
.endm
.macro RESTORE_CR3 save_reg:req
.endm

#endif
