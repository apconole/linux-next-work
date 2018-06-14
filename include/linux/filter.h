/*
 * Linux Socket Filter Data Structures
 */
#ifndef __LINUX_FILTER_H__
#define __LINUX_FILTER_H__

#include <linux/atomic.h>
#include <linux/compat.h>
#include <uapi/linux/filter.h>
#include <asm/cacheflush.h>
#include <uapi/linux/bpf.h>
#ifndef __GENKSYMS__
#include <net/xdp.h>
#include <net/sch_generic.h>
#endif

#ifdef CONFIG_COMPAT
/*
 * A struct sock_filter is architecture independent.
 */
struct compat_sock_fprog {
	u16		len;
	compat_uptr_t	filter;		/* struct sock_filter * */
};
#endif

struct bpf_binary_header {
	unsigned int pages;
	u8 image[];
};

struct sk_buff;
struct sock;
struct bpf_prog_aux;
struct xdp_buff;

/* ArgX, context and stack frame pointer register positions. Note,
 * Arg1, Arg2, Arg3, etc are used as argument mappings of function
 * calls in BPF_CALL instruction.
 */
#define BPF_REG_ARG1	BPF_REG_1
#define BPF_REG_ARG2	BPF_REG_2
#define BPF_REG_ARG3	BPF_REG_3
#define BPF_REG_ARG4	BPF_REG_4
#define BPF_REG_ARG5	BPF_REG_5
#define BPF_REG_CTX	BPF_REG_6
#define BPF_REG_FP	BPF_REG_10

/* Additional register mappings for converted user programs. */
#define BPF_REG_A	BPF_REG_0
#define BPF_REG_X	BPF_REG_7
#define BPF_REG_TMP	BPF_REG_8

/* BPF program can access up to 512 bytes of stack space. */
#define MAX_BPF_STACK	512

/* Helper macros for filter block array initializers. */

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Endianess conversion, cpu_to_{l,b}e(), {l,b}e_to_cpu() */

#define BPF_ENDIAN(TYPE, DST, LEN)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_END | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = LEN })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

#define BPF_PSEUDO_MAP_FD	1

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

/* Short form of mov based on type, BPF_X: dst_reg = src_reg, BPF_K: dst_reg = imm32 */

#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */

#define BPF_LD_IND(SIZE, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,	\
		.dst_reg = 0,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Function call */

#define BPF_EMIT_CALL(FUNC)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((FUNC) - __bpf_call_base) })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

#define bytes_to_bpf_size(bytes)				\
({								\
	int bpf_size = -EINVAL;					\
								\
	if (bytes == sizeof(u8))				\
		bpf_size = BPF_B;				\
	else if (bytes == sizeof(u16))				\
		bpf_size = BPF_H;				\
	else if (bytes == sizeof(u32))				\
		bpf_size = BPF_W;				\
	else if (bytes == sizeof(u64))				\
		bpf_size = BPF_DW;				\
								\
	bpf_size;						\
})

struct bpf_prog {
	u16			pages;		/* Number of allocated pages */
	kmemcheck_bitfield_begin(meta);
	u16			jited:1,	/* Is our filter JIT'ed? */
				gpl_compatible:1, /* Is filter GPL compatible? */
				cb_access:1,	/* Is control block accessed? */
				dst_needed:1;	/* Do we need dst entry? */
	kmemcheck_bitfield_end(meta);
	u32			len;		/* Number of filter blocks */
	enum bpf_prog_type	type;		/* Type of BPF program */
	struct bpf_prog_aux	*aux;		/* Auxiliary fields */
	struct sock_fprog_kern	*orig_prog;	/* Original BPF program */
	unsigned int		(*bpf_func)(const struct sk_buff *skb,
					    const struct bpf_insn *filter);
	/* Instructions for interpreter */
	union {
		struct sock_filter	insns[0];
		struct bpf_insn		insnsi[0];
	};
};

struct sk_filter
{
	atomic_t		refcnt;
	unsigned int         	len;	/* Number of filter blocks */
	unsigned int		(*bpf_func)(const struct sk_buff *skb,
					    const struct sock_filter *filter);
	struct rcu_head		rcu;
	struct sock_filter     	insns[0];
};

#define BPF_PROG_RUN(filter, ctx)  (*filter->bpf_func)(ctx, filter->insnsi)

static inline unsigned int bpf_prog_size(unsigned int proglen)
{
	return max(sizeof(struct bpf_prog),
		   offsetof(struct bpf_prog, insns[proglen]));
}

#define bpf_classic_proglen(fprog) (fprog->len * sizeof(fprog->filter[0]))

#ifdef CONFIG_DEBUG_SET_MODULE_RONX
static inline void bpf_prog_lock_ro(struct bpf_prog *fp)
{
	set_memory_ro((unsigned long)fp, fp->pages);
}

static inline void bpf_prog_unlock_ro(struct bpf_prog *fp)
{
	set_memory_rw((unsigned long)fp, fp->pages);
}
#else
static inline void bpf_prog_lock_ro(struct bpf_prog *fp)
{
}

static inline void bpf_prog_unlock_ro(struct bpf_prog *fp)
{
}
#endif /* CONFIG_DEBUG_SET_MODULE_RONX */

/* compute the linear packet data range [data, data_end) which
 * will be accessed by cls_bpf and act_bpf programs
 */
static inline unsigned int sk_filter_len(const struct sk_filter *fp)
{
	return fp->len * sizeof(struct sock_filter) + sizeof(*fp);
}

static inline void bpf_compute_data_end(struct sk_buff *skb)
{
	return;
}

int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap);
static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
{
	return sk_filter_trim_cap(sk, skb, 1);
}

extern unsigned int sk_run_filter(const struct sk_buff *skb,
				  const struct sock_filter *filter);
extern int sk_unattached_filter_create(struct sk_filter **pfp,
				       struct sock_fprog *fprog);
extern void sk_unattached_filter_destroy(struct sk_filter *fp);
extern int sk_attach_filter(struct sock_fprog *fprog, struct sock *sk);
extern int sk_detach_filter(struct sock *sk);
extern int sk_chk_filter(struct sock_filter *filter, unsigned int flen);
extern int sk_get_filter(struct sock *sk, struct sock_filter __user *filter, unsigned len);
extern void sk_decode_filter(struct sock_filter *filt, struct sock_filter *to);

u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog *fp, int *err);
void bpf_prog_free(struct bpf_prog *fp);

static inline u32 bpf_prog_run_xdp(const struct bpf_prog *prog,
				   struct xdp_buff *xdp)
{
	return 0;
}

static inline void bpf_warn_invalid_xdp_action(u32 act)
{
	return;
}


int xdp_do_redirect(struct net_device *dev,
		    struct xdp_buff *xdp,
		    struct bpf_prog *prog);
void xdp_do_flush_map(void);

struct bpf_prog *bpf_prog_alloc(unsigned int size, gfp_t gfp_extra_flags);
struct bpf_prog *bpf_prog_realloc(struct bpf_prog *fp_old, unsigned int size,
				  gfp_t gfp_extra_flags);
void __bpf_prog_free(struct bpf_prog *fp);

static inline void bpf_prog_unlock_free(struct bpf_prog *fp)
{
	bpf_prog_unlock_ro(fp);
	__bpf_prog_free(fp);
}

struct bpf_prog *bpf_patch_insn_single(struct bpf_prog *prog, u32 off,
				       const struct bpf_insn *patch, u32 len);

typedef void (*bpf_jit_fill_hole_t)(void *area, unsigned int size);

struct bpf_binary_header *
bpf_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
		     unsigned int alignment,
		     bpf_jit_fill_hole_t bpf_fill_ill_insns);
void bpf_jit_binary_free(struct bpf_binary_header *hdr);

#ifdef CONFIG_BPF_JIT
#include <stdarg.h>
#include <linux/linkage.h>
#include <linux/printk.h>

void bpf_jit_compile(struct sk_filter *fp);
void bpf_jit_free(struct sk_filter *fp);

void trace_bpf_jit_compile(struct bpf_prog *fp);
void trace_bpf_jit_free(struct bpf_prog *fp);

struct bpf_prog *trace_bpf_int_jit_compile(struct bpf_prog *prog);

static inline void bpf_jit_dump(unsigned int flen, unsigned int proglen,
				u32 pass, void *image)
{
	pr_err("flen=%u proglen=%u pass=%u image=%p\n",
	       flen, proglen, pass, image);
	if (image)
		print_hex_dump(KERN_ERR, "JIT code: ", DUMP_PREFIX_ADDRESS,
			       16, 1, image, proglen, false);
}
#define SK_RUN_FILTER(FILTER, SKB) (*FILTER->bpf_func)(SKB, FILTER->insns)
#else
static inline void bpf_jit_compile(struct sk_filter *fp)
{
}
static inline void bpf_jit_free(struct sk_filter *fp)
{
}
#define SK_RUN_FILTER(FILTER, SKB) sk_run_filter(SKB, FILTER->insns)
#endif

void *trace_bpf_internal_load_pointer_neg_helper(const struct sk_buff *skb,
						 int k, unsigned int size);

static inline void *bpf_load_pointer(const struct sk_buff *skb, int k,
				     unsigned int size, void *buffer)
{
	if (k >= 0)
		return skb_header_pointer(skb, k, size, buffer);

	return trace_bpf_internal_load_pointer_neg_helper(skb, k, size);
}

static inline int bpf_tell_extensions(void)
{
	return SKF_AD_MAX;
}

enum {
	BPF_S_RET_K = 1,
	BPF_S_RET_A,
	BPF_S_ALU_ADD_K,
	BPF_S_ALU_ADD_X,
	BPF_S_ALU_SUB_K,
	BPF_S_ALU_SUB_X,
	BPF_S_ALU_MUL_K,
	BPF_S_ALU_MUL_X,
	BPF_S_ALU_DIV_X,
	BPF_S_ALU_MOD_K,
	BPF_S_ALU_MOD_X,
	BPF_S_ALU_AND_K,
	BPF_S_ALU_AND_X,
	BPF_S_ALU_OR_K,
	BPF_S_ALU_OR_X,
	BPF_S_ALU_XOR_K,
	BPF_S_ALU_XOR_X,
	BPF_S_ALU_LSH_K,
	BPF_S_ALU_LSH_X,
	BPF_S_ALU_RSH_K,
	BPF_S_ALU_RSH_X,
	BPF_S_ALU_NEG,
	BPF_S_LD_W_ABS,
	BPF_S_LD_H_ABS,
	BPF_S_LD_B_ABS,
	BPF_S_LD_W_LEN,
	BPF_S_LD_W_IND,
	BPF_S_LD_H_IND,
	BPF_S_LD_B_IND,
	BPF_S_LD_IMM,
	BPF_S_LDX_W_LEN,
	BPF_S_LDX_B_MSH,
	BPF_S_LDX_IMM,
	BPF_S_MISC_TAX,
	BPF_S_MISC_TXA,
	BPF_S_ALU_DIV_K,
	BPF_S_LD_MEM,
	BPF_S_LDX_MEM,
	BPF_S_ST,
	BPF_S_STX,
	BPF_S_JMP_JA,
	BPF_S_JMP_JEQ_K,
	BPF_S_JMP_JEQ_X,
	BPF_S_JMP_JGE_K,
	BPF_S_JMP_JGE_X,
	BPF_S_JMP_JGT_K,
	BPF_S_JMP_JGT_X,
	BPF_S_JMP_JSET_K,
	BPF_S_JMP_JSET_X,
	/* Ancillary data */
	BPF_S_ANC_PROTOCOL,
	BPF_S_ANC_PKTTYPE,
	BPF_S_ANC_IFINDEX,
	BPF_S_ANC_NLATTR,
	BPF_S_ANC_NLATTR_NEST,
	BPF_S_ANC_MARK,
	BPF_S_ANC_QUEUE,
	BPF_S_ANC_HATYPE,
	BPF_S_ANC_RXHASH,
	BPF_S_ANC_CPU,
	BPF_S_ANC_ALU_XOR_X,
	BPF_S_ANC_SECCOMP_LD_W,
	BPF_S_ANC_VLAN_TAG,
	BPF_S_ANC_VLAN_TAG_PRESENT,
	BPF_S_ANC_PAY_OFFSET,
};

#endif /* __LINUX_FILTER_H__ */
