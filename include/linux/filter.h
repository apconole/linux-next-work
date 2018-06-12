/*
 * Linux Socket Filter Data Structures
 */
#ifndef __LINUX_FILTER_H__
#define __LINUX_FILTER_H__

#include <linux/atomic.h>
#include <linux/compat.h>
#include <uapi/linux/filter.h>
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

struct bpf_prog
{
	struct bpf_prog_aux	*aux;	/* Auxiliary fields */
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

int bpf_prog_select_runtime(struct bpf_prog *fp);

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

#ifdef CONFIG_BPF_JIT
#include <stdarg.h>
#include <linux/linkage.h>
#include <linux/printk.h>

extern void bpf_jit_compile(struct sk_filter *fp);
extern void bpf_jit_free(struct sk_filter *fp);

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
