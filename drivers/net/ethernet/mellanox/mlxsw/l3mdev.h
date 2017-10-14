#ifndef __MLXSW_L3MDEV_H__
#define __MLXSW_L3MDEV_H__

/* VRF is missing in RHEL */

static inline u32 l3mdev_fib_table(const struct net_device *dev)
{
       return 0;
}

#endif
