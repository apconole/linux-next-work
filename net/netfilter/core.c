/* netfilter.c: look after the filters for various protocols.
 * Heavily influenced by the old firewall.c by David Bonn and Alan Cox.
 *
 * Thanks to Rob `CmdrTaco' Malda for not influencing this code in any
 * way.
 *
 * Rusty Russell (C)2000 -- This code is GPL.
 * Patrick McHardy (c) 2006-2012
 */
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <net/protocol.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv6.h>
#include <linux/inetdevice.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "nf_internals.h"

static DEFINE_MUTEX(afinfo_mutex);

const struct nf_afinfo __rcu *nf_afinfo[NFPROTO_NUMPROTO] __read_mostly;
EXPORT_SYMBOL(nf_afinfo);
const struct nf_ipv6_ops __rcu *nf_ipv6_ops __read_mostly;
EXPORT_SYMBOL_GPL(nf_ipv6_ops);

DEFINE_PER_CPU(bool, nf_skb_duplicated);
EXPORT_SYMBOL_GPL(nf_skb_duplicated);

int nf_register_afinfo(const struct nf_afinfo *afinfo)
{
	mutex_lock(&afinfo_mutex);
	RCU_INIT_POINTER(nf_afinfo[afinfo->family], afinfo);
	mutex_unlock(&afinfo_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(nf_register_afinfo);

void nf_unregister_afinfo(const struct nf_afinfo *afinfo)
{
	mutex_lock(&afinfo_mutex);
	RCU_INIT_POINTER(nf_afinfo[afinfo->family], NULL);
	mutex_unlock(&afinfo_mutex);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(nf_unregister_afinfo);

#ifdef HAVE_JUMP_LABEL
struct static_key nf_hooks_needed[NFPROTO_NUMPROTO][NF_MAX_HOOKS];
EXPORT_SYMBOL(nf_hooks_needed);
#endif

static DEFINE_MUTEX(nf_hook_mutex);
#define nf_entry_dereference(e) \
	rcu_dereference_protected(e, lockdep_is_held(&nf_hook_mutex))

struct nf_hook_entries *allocate_hook_entries_size(size_t num)
{
	return kmalloc(sizeof(struct nf_hook_entries) +
		       sizeof(struct nf_hook_entry) * num, GFP_KERNEL);
}

static void release_nf_hook_entries(struct rcu_head *head)
{
	struct nf_hook_entries *entries = container_of(head,
						       struct nf_hook_entries,
						       rcu);
	kfree(entries);
}

static int nf_hook_entries_grow(struct nf_hook_entries **new, const struct nf_hook_entries *old, const struct nf_hook_entry *insert)
{
	size_t hook_entries = 1;
	size_t i, j;
	if (old)
		hook_entries += old->num_hook_entries;

	WARN_ON(!insert);

	*new = allocate_hook_entries_size(hook_entries);
	if (!*new)
		return -ENOMEM;

	(*new)->num_hook_entries = hook_entries;
	for (i = 0, j = 0; i < hook_entries; i++) {
		struct nf_hook_entry *assigned;
		const struct nf_hook_entry *hook_entry = insert;

		if (likely(old)) {
			WARN_ON(!(insert->orig_ops));
			if (j < old->num_hook_entries &&
			    nf_hook_entry_priority(hook_entry) >
			    nf_hook_entry_priority(&(old->hooks[j]))) {
				WARN_ON(!(old->hooks[j].orig_ops));
				hook_entry = &(old->hooks[j++]);
			}
		}
		assigned = (struct nf_hook_entry *)&((*new)->hooks[i]);
		*assigned = *hook_entry;
		assigned->next = NULL;
		if (i) {
			struct nf_hook_entry *prev =
				(struct nf_hook_entry *)&((*new)->hooks[i-1]);

			rcu_assign_pointer(prev->next, assigned);
		}
	}
	init_rcu_head(&((*new)->rcu));
	return 0;
}

static int nf_hook_entries_shrink(struct nf_hook_entries **new, const struct nf_hook_entries *old, const struct nf_hook_entry *remove)
{
	const struct nf_hook_entry *hook_entry;
	size_t hook_entries = 0;
	size_t i;

	if (old && old->num_hook_entries) {
		hook_entries = old->num_hook_entries - 1;

		/* there's a strange problem we could get - remove is not
		 * in the old->hooks array.  So need to make sure we check
		 * that it's valid */
		rcu_read_lock();
		for_each_nf_hook_entry(old->hooks, hook_entry) {
			if (nf_hook_entry_ops(hook_entry) ==
			    nf_hook_entry_ops(remove))
				break;

			if (hook_entry->hook == remove->hook)
				break;
		}
		rcu_read_unlock();
		if (!hook_entry) {
			WARN(1, "Completely missing!?  probably broken");
			return -ENOENT;
		}
	}

	if (!hook_entries) {
		*new = NULL;
		return 0;
	}

	*new = allocate_hook_entries_size(hook_entries);
	if (WARN_ON(!*new))
		return -ENOMEM;

	i = 0;
	rcu_read_lock();
	for_each_nf_hook_entry(old->hooks, hook_entry) {
		struct nf_hook_entry *assigned;

		if (nf_hook_entry_ops(hook_entry) ==
		    nf_hook_entry_ops(remove))
			continue;

		assigned = (struct nf_hook_entry *)&((*new)->hooks[i]);
		*assigned = *hook_entry;
		assigned->next = NULL;
		if (i) {
			struct nf_hook_entry *prev =
				(struct nf_hook_entry *)&((*new)->hooks[i-1]);

			rcu_assign_pointer(prev->next, assigned);
		}
		i++;
	}
	rcu_read_unlock();
	(*new)->num_hook_entries = hook_entries;
	init_rcu_head(&((*new)->rcu));
	return 0;
}


static struct nf_hook_entries __rcu **nf_hook_entry_head(struct net *net, const struct nf_hook_ops *reg)
{
	if (reg->pf != NFPROTO_NETDEV)
		return net->nf.hooks[reg->pf]+reg->hooknum;

#ifdef CONFIG_NETFILTER_INGRESS
	if (reg->hooknum == NF_NETDEV_INGRESS) {
		if (reg->dev && dev_net(reg->dev) == net)
			return &reg->dev->nf_hooks_ingress;
	}
#endif
	return NULL;
}

int nf_register_net_hook(struct net *net, const struct nf_hook_ops *reg)
{
	struct nf_hook_entries __rcu **pp, *p, *new_hooks;
	const struct nf_hook_entry *old;
	struct nf_hook_entry entry;
	int ret;

	if (reg->pf == NFPROTO_NETDEV) {
#ifndef CONFIG_NETFILTER_INGRESS
		if (reg->hooknum == NF_NETDEV_INGRESS)
			return -EOPNOTSUPP;
#endif
		if (reg->hooknum != NF_NETDEV_INGRESS ||
		    !reg->dev || dev_net(reg->dev) != net)
			return -EINVAL;
	}

	pp = nf_hook_entry_head(net, reg);
	if (!pp)
		return -EINVAL;

	nf_hook_entry_init(&entry, reg);

	rcu_read_lock();
	mutex_lock(&nf_hook_mutex);
	p = nf_entry_dereference(*pp);
	ret = nf_hook_entries_grow(&new_hooks, p, &entry);
	if (!ret)
		rcu_assign_pointer(*pp, new_hooks);
	mutex_unlock(&nf_hook_mutex);
	rcu_read_unlock();

	if (ret)
		return ret;
#ifdef CONFIG_NETFILTER_INGRESS
	if (reg->pf == NFPROTO_NETDEV && reg->hooknum == NF_NETDEV_INGRESS)
		net_inc_ingress_queue();
#endif
#ifdef HAVE_JUMP_LABEL
	static_key_slow_inc(&nf_hooks_needed[reg->pf][reg->hooknum]);
#endif
	synchronize_net();
	/* for now, drop all nf queue entries */
	rcu_read_lock();
	for_each_nf_hook_entry(likely(p) ? p->hooks : NULL, old)
		nf_queue_nf_hook_drop(net, old);
	rcu_read_unlock();
	synchronize_net();
	if (likely(p))
		call_rcu(&p->rcu, release_nf_hook_entries);
	return 0;
}
EXPORT_SYMBOL(nf_register_net_hook);

void nf_unregister_net_hook(struct net *net, const struct nf_hook_ops *reg)
{
	struct nf_hook_entries __rcu **pp, *p, *new_hooks;
	const struct nf_hook_entry *old;
	struct nf_hook_entry removed;

	pp = nf_hook_entry_head(net, reg);
	if (WARN_ON_ONCE(!pp))
		return;

	nf_hook_entry_init(&removed, reg);
	rcu_read_lock();
	mutex_lock(&nf_hook_mutex);
	p = nf_entry_dereference(*pp);
	if (!p || nf_hook_entries_shrink(&new_hooks, p, &removed)) {
		mutex_unlock(&nf_hook_mutex);
		rcu_read_unlock();
		WARN(1, "nf_unregister_net_hook: hook not found!\n");
		return;
	}
	rcu_assign_pointer(*pp, new_hooks);
	mutex_unlock(&nf_hook_mutex);
	rcu_read_unlock();

#ifdef CONFIG_NETFILTER_INGRESS
	if (reg->pf == NFPROTO_NETDEV && reg->hooknum == NF_NETDEV_INGRESS)
		net_dec_ingress_queue();
#endif
#ifdef HAVE_JUMP_LABEL
	static_key_slow_dec(&nf_hooks_needed[reg->pf][reg->hooknum]);
#endif
	synchronize_net();
	/* for now, drop all nf queue entries */
	/* other cpu might still process nfqueue verdict that used reg */
	rcu_read_lock();
	for_each_nf_hook_entry(p->hooks, old)
		nf_queue_nf_hook_drop(net, old);
	rcu_read_unlock();
	synchronize_net();
	call_rcu(&p->rcu, release_nf_hook_entries);
}
EXPORT_SYMBOL(nf_unregister_net_hook);

int nf_register_net_hooks(struct net *net, const struct nf_hook_ops *reg,
			  unsigned int n)
{
	unsigned int i;
	int err = 0;

	for (i = 0; i < n; i++) {
		err = nf_register_net_hook(net, &reg[i]);
		if (err)
			goto err;
	}
	return err;

err:
	if (i > 0)
		nf_unregister_net_hooks(net, reg, i);
	return err;
}
EXPORT_SYMBOL(nf_register_net_hooks);

void nf_unregister_net_hooks(struct net *net, const struct nf_hook_ops *reg,
			     unsigned int n)
{
	while (n-- > 0)
		nf_unregister_net_hook(net, &reg[n]);
}
EXPORT_SYMBOL(nf_unregister_net_hooks);

static LIST_HEAD(nf_hook_list);

static int _nf_register_hook(struct nf_hook_ops *reg)
{
	struct net *net, *last;
	int ret;

	for_each_net(net) {
		ret = nf_register_net_hook(net, reg);
		if (ret && ret != -ENOENT)
			goto rollback;
	}
	list_add_tail(&reg->list, &nf_hook_list);

	return 0;
rollback:
	last = net;
	for_each_net(net) {
		if (net == last)
			break;
		nf_unregister_net_hook(net, reg);
	}
	return ret;
}

int nf_register_hook(struct nf_hook_ops *reg)
{
	int ret;

	rtnl_lock();
	ret = _nf_register_hook(reg);
	rtnl_unlock();

	return ret;
}
EXPORT_SYMBOL(nf_register_hook);

static void _nf_unregister_hook(struct nf_hook_ops *reg)
{
	struct net *net;

	list_del(&reg->list);
	for_each_net(net)
		nf_unregister_net_hook(net, reg);
}

void nf_unregister_hook(struct nf_hook_ops *reg)
{
	rtnl_lock();
	_nf_unregister_hook(reg);
	rtnl_unlock();
}
EXPORT_SYMBOL(nf_unregister_hook);

int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	unsigned int i;
	int err = 0;

	for (i = 0; i < n; i++) {
		err = nf_register_hook(&reg[i]);
		if (err)
			goto err;
	}
	return err;

err:
	if (i > 0)
		nf_unregister_hooks(reg, i);
	return err;
}
EXPORT_SYMBOL(nf_register_hooks);

/* Caller MUST take rtnl_lock() */
int _nf_register_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	unsigned int i;
	int err = 0;

	for (i = 0; i < n; i++) {
		err = _nf_register_hook(&reg[i]);
		if (err)
			goto err;
	}
	return err;

err:
	if (i > 0)
		_nf_unregister_hooks(reg, i);
	return err;
}
EXPORT_SYMBOL(_nf_register_hooks);

void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	while (n-- > 0)
		nf_unregister_hook(&reg[n]);
}
EXPORT_SYMBOL(nf_unregister_hooks);

/* Caller MUST take rtnl_lock */
void _nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	while (n-- > 0)
		_nf_unregister_hook(&reg[n]);
}
EXPORT_SYMBOL(_nf_unregister_hooks);

/* Returns 1 if okfn() needs to be executed by the caller,
 * -EPERM for NF_DROP, 0 otherwise.  Caller must hold rcu_read_lock. */
int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state,
		 struct nf_hook_entry *entry)
{
	struct nf_hook_entry *hook;
	unsigned int verdict;
	int ret;

	for_each_nf_hook_entry(entry, hook) {
		verdict = nf_hook_entry_hookfn(hook, skb, state);
		switch (verdict & NF_VERDICT_MASK) {
		case NF_ACCEPT:
			break;
		case NF_DROP:
			kfree_skb(skb);
			ret = NF_DROP_GETERR(verdict);
			if (ret == 0)
				ret = -EPERM;
			return ret;
		case NF_QUEUE:
			ret = nf_queue(skb, state, &entry, verdict);
			if (ret == 1 && entry)
				continue;
			return ret;
		default:
			/* Implicit handling for NF_STOLEN, as well as any other
			 * non conventional verdicts.
			 */
			return 0;
		}
	}

	return 1;
}
EXPORT_SYMBOL(nf_hook_slow);


int skb_make_writable(struct sk_buff *skb, unsigned int writable_len)
{
	if (writable_len > skb->len)
		return 0;

	/* Not exclusive use of packet?  Must copy. */
	if (!skb_cloned(skb)) {
		if (writable_len <= skb_headlen(skb))
			return 1;
	} else if (skb_clone_writable(skb, writable_len))
		return 1;

	if (writable_len <= skb_headlen(skb))
		writable_len = 0;
	else
		writable_len -= skb_headlen(skb);

	return !!__pskb_pull_tail(skb, writable_len);
}
EXPORT_SYMBOL(skb_make_writable);

/* This needs to be compiled in any case to avoid dependencies between the
 * nfnetlink_queue code and nf_conntrack.
 */
struct nfnl_ct_hook __rcu *nfnl_ct_hook __read_mostly;
EXPORT_SYMBOL_GPL(nfnl_ct_hook);

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
/* This does not belong here, but locally generated errors need it if connection
   tracking in use: without this, connection may not be in hash table, and hence
   manufactured ICMP or RST packets will not be associated with it. */
void (*ip_ct_attach)(struct sk_buff *, const struct sk_buff *)
		__rcu __read_mostly;
EXPORT_SYMBOL(ip_ct_attach);

void nf_ct_attach(struct sk_buff *new, const struct sk_buff *skb)
{
	void (*attach)(struct sk_buff *, const struct sk_buff *);

	if (skb->nfct) {
		rcu_read_lock();
		attach = rcu_dereference(ip_ct_attach);
		if (attach)
			attach(new, skb);
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(nf_ct_attach);

void (*nf_ct_destroy)(struct nf_conntrack *) __rcu __read_mostly;
EXPORT_SYMBOL(nf_ct_destroy);

void nf_conntrack_destroy(struct nf_conntrack *nfct)
{
	void (*destroy)(struct nf_conntrack *);

	rcu_read_lock();
	destroy = rcu_dereference(nf_ct_destroy);
	BUG_ON(destroy == NULL);
	destroy(nfct);
	rcu_read_unlock();
}
EXPORT_SYMBOL(nf_conntrack_destroy);

/* Built-in default zone used e.g. by modules. */
const struct nf_conntrack_zone nf_ct_zone_dflt = {
	.id	= NF_CT_DEFAULT_ZONE_ID,
	.dir	= NF_CT_DEFAULT_ZONE_DIR,
};
EXPORT_SYMBOL_GPL(nf_ct_zone_dflt);
#endif /* CONFIG_NF_CONNTRACK */

#ifdef CONFIG_NF_NAT_NEEDED
void (*nf_nat_decode_session_hook)(struct sk_buff *, struct flowi *);
EXPORT_SYMBOL(nf_nat_decode_session_hook);
#endif

static int nf_register_hook_list(struct net *net)
{
	struct nf_hook_ops *elem;
	int ret;

	rtnl_lock();
	list_for_each_entry(elem, &nf_hook_list, list) {
		ret = nf_register_net_hook(net, elem);
		if (ret && ret != -ENOENT)
			goto out_undo;
	}
	rtnl_unlock();
	return 0;

out_undo:
	list_for_each_entry_continue_reverse(elem, &nf_hook_list, list)
		nf_unregister_net_hook(net, elem);
	rtnl_unlock();
	return ret;
}

static void nf_unregister_hook_list(struct net *net)
{
	struct nf_hook_ops *elem;

	rtnl_lock();
	list_for_each_entry(elem, &nf_hook_list, list)
		nf_unregister_net_hook(net, elem);
	rtnl_unlock();
}

static int __net_init netfilter_net_init(struct net *net)
{
	int i, h, ret;

	for (i = 0; i < ARRAY_SIZE(net->nf.hooks); i++) {
		for (h = 0; h < NF_MAX_HOOKS; h++)
			RCU_INIT_POINTER(net->nf.hooks[i][h], NULL);
	}

#ifdef CONFIG_PROC_FS
	net->nf.proc_netfilter = proc_net_mkdir(net, "netfilter",
						net->proc_net);
	if (!net->nf.proc_netfilter) {
		if (!net_eq(net, &init_net))
			pr_err("cannot create netfilter proc entry");

		return -ENOMEM;
	}
#endif
	ret = nf_register_hook_list(net);
	if (ret)
		remove_proc_entry("netfilter", net->proc_net);

	return ret;
}

static void __net_exit netfilter_net_exit(struct net *net)
{
	nf_unregister_hook_list(net);
	remove_proc_entry("netfilter", net->proc_net);
}

static struct pernet_operations netfilter_net_ops = {
	.init = netfilter_net_init,
	.exit = netfilter_net_exit,
};

int __init netfilter_init(void)
{
	int ret;

	ret = register_pernet_subsys(&netfilter_net_ops);
	if (ret < 0)
		goto err;

	ret = netfilter_log_init();
	if (ret < 0)
		goto err_pernet;

	return 0;
err_pernet:
	unregister_pernet_subsys(&netfilter_net_ops);
err:
	return ret;
}
