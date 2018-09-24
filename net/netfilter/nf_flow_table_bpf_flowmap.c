/* Copyright (c) 2018 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#include <linux/bpf.h>
#include <net/xdp.h>
#include <linux/filter.h>
#include <trace/events/xdp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_flow_table.h>

struct flow_map_internal {
	struct bpf_map map;
	struct list_head list;
	struct nf_flowtable net_flow_table;
};

struct flow_map_key {
	struct flow_offload_tuple flow_offload;
	char dir_hint;
};

struct flow_map_value {
	struct flow_offload offloaded_flow;
};

static DEFINE_SPINLOCK(flow_map_list_lock);
static LIST_HEAD(flow_map_list);

static struct bpf_map *flow_map_alloc(union bpf_attr *attr)
{
	struct flow_map_internal *fmap_ret;
	u64 cost;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return ERR_PTR(-EPERM);

	if (attr->max_entries == 0 ||
	    attr->key_size != sizeof(struct flow_map_key) ||
	    attr->value_size != sizeof(struct flow_map_value))
		return ERR_PTR(-EINVAL);

	fmap_ret = kzalloc(sizeof(*fmap_ret), GFP_USER);
	if (!fmap_ret)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&fmap_ret->map, attr);
	cost = (u64)fmap_ret->map.max_entries * sizeof(struct flow_offload);
	if (cost >= U32_MAX - PAGE_SIZE) {
		kfree(&fmap_ret);
		return ERR_PTR(-ENOMEM);
	}

	fmap_ret->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	/* if map size is larger than memlock limit, reject it early */
	if ((err = bpf_map_precharge_memlock(fmap_ret->map.pages))) {
		kfree(&fmap_ret);
		return ERR_PTR(err);
	}

	nf_flow_table_init(&fmap_ret->net_flow_table);
	spin_lock(&flow_map_list_lock);
	list_add_tail_rcu(&fmap_ret->list, &flow_map_list);
	spin_unlock(&flow_map_list_lock);

	return &fmap_ret->map;
}

static void flow_map_free(struct bpf_map *map)
{
	struct flow_map_internal *fmap = container_of(map,
						      struct flow_map_internal,
						      map);


	spin_lock(&flow_map_list_lock);
	list_del_rcu(&fmap->list);
	spin_unlock(&flow_map_list_lock);

	nf_flow_table_free(&fmap->net_flow_table);
	synchronize_rcu();

	kfree(fmap);
}

static int flow_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return 0;
}



const struct bpf_map_ops flow_map_ops = {
	.map_alloc = flow_map_alloc,
	.map_free = flow_map_free,
	.map_get_next_key = flow_map_get_next_key,
	.map_check_btf = map_check_no_btf,
};

static int __init flow_map_init(void)
{
	bpf_map_insert_ops(BPF_MAP_TYPE_FLOWMAP, &flow_map_ops);
	return 0;
}

module_init(flow_map_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aaron Conole <aconole@bytheb.org>");
