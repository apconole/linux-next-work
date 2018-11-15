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
	struct nf_flowtable net_flow_table;
};

static void flow_map_init_from_attr(struct bpf_map *map, union bpf_attr *attr)
{
	map->map_type = attr->map_type;
	map->key_size = attr->key_size;
	map->value_size = attr->value_size;
	map->max_entries = attr->max_entries;
	map->map_flags = attr->map_flags;
	map->numa_node = bpf_map_attr_numa_node(attr);
}


static struct bpf_map *flow_map_alloc(union bpf_attr *attr)
{
	struct flow_map_internal *fmap_ret;
	u64 cost;
	int err;

	printk("Call to create bpf map.\n");
	if (!capable(CAP_NET_ADMIN))
		return ERR_PTR(-EPERM);

	if (attr->max_entries == 0 ||
	    attr->key_size != sizeof(struct bpf_flow_map) ||
	    attr->value_size != sizeof(struct bpf_flow_map))
		return ERR_PTR(-EINVAL);

	fmap_ret = kzalloc(sizeof(*fmap_ret), GFP_USER);
	if (!fmap_ret)
		return ERR_PTR(-ENOMEM);

	flow_map_init_from_attr(&fmap_ret->map, attr);
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

	memset(&fmap_ret->net_flow_table, 0, sizeof(fmap_ret->net_flow_table));
	fmap_ret->net_flow_table.flags |= NF_FLOWTABLE_F_HW;
	nf_flow_table_init(&fmap_ret->net_flow_table);

	return &fmap_ret->map;
}

static void flow_map_free(struct bpf_map *map)
{
	struct flow_map_internal *fmap = container_of(map,
						      struct flow_map_internal,
						      map);

	nf_flow_table_free(&fmap->net_flow_table);
	synchronize_rcu();
	kfree(fmap);
}

static void *flow_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct flow_map_internal *fmap = container_of(map,
						      struct flow_map_internal, map);
	struct bpf_flow_map *internal_key = (struct bpf_flow_map *)key;
	struct flow_offload_tuple_rhash *hash_ret;
	struct flow_offload_tuple lookup_key;

	/* first, attempt the original direction */
	memcpy(&lookup_key.src_v6, internal_key->flow.ipv6_src, sizeof(lookup_key.src_v6));
	memcpy(&lookup_key.dst_v6, internal_key->flow.ipv6_dst, sizeof(lookup_key.dst_v6));
	lookup_key.src_port = ntohs(internal_key->flow.sport);
	lookup_key.dst_port = ntohs(internal_key->flow.dport);

	printk("Lookup addr_proto: %x", internal_key->flow.addr_proto);
	if (internal_key->flow.addr_proto == htons(ETH_P_IP))
		lookup_key.l3proto = AF_INET;
	else if (internal_key->flow.addr_proto == htons(ETH_P_IPV6))
		lookup_key.l3proto = AF_INET6;
	else
		return NULL;

	lookup_key.l4proto = (u8)internal_key->flow.ip_proto;
	lookup_key.iifidx = internal_key->ifindex;

	printk("Flow offload lookup: %d:%d -> %d:%d, %u, %u\n",
	       lookup_key.src_v4.s_addr, lookup_key.src_port,
	       lookup_key.dst_v4.s_addr, lookup_key.dst_port,
	       lookup_key.l3proto, lookup_key.l4proto);
	hash_ret = flow_offload_lookup(&fmap->net_flow_table, &lookup_key);
	if (!hash_ret) {
		memcpy(&lookup_key.src_v6, internal_key->flow.ipv6_src,
		       sizeof(lookup_key.src_v6));
		memcpy(&lookup_key.dst_v6, internal_key->flow.ipv6_dst,
		       sizeof(lookup_key.dst_v6));
		lookup_key.src_port = internal_key->flow.dport;
		lookup_key.dst_port = internal_key->flow.sport;
		lookup_key.dir = 1;
		hash_ret = flow_offload_lookup(&fmap->net_flow_table,
					       &lookup_key);
	}

	if (!hash_ret) {
		printk("No flow found, but table is: %d\n",
		       atomic_read(&fmap->net_flow_table.rhashtable.nelems));
		return NULL;
	}

	return key;
}

static int flow_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return 0;
}

static int flow_map_check_no_btf(const struct bpf_map *map,
				 const struct btf_type *key_type,
				 const struct btf_type *value_type)
{
	return -ENOTSUPP;
}

const struct bpf_map_ops flow_map_ops = {
	.map_alloc = flow_map_alloc,
	.map_free = flow_map_free,
	.map_get_next_key = flow_map_get_next_key,
	.map_lookup_elem = flow_map_lookup_elem,
	.map_check_btf = flow_map_check_no_btf,
};

static int __init flow_map_init(void)
{
	bpf_map_insert_ops(BPF_MAP_TYPE_FLOWMAP, &flow_map_ops);
	return 0;
}

module_init(flow_map_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aaron Conole <aconole@bytheb.org>");
