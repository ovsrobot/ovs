/*
 * Copyright (c) 2020 Nokia, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/module.h>

#include <net/bareudp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/udp.h>
#include <net/xfrm.h>

#include "datapath.h"
#include "vport.h"
#include "vport-netdev.h"

static struct vport_ops ovs_bareudp_vport_ops;
/**
 * struct bareudp_port - Keeps track of open UDP ports
 * @dst_port: destination port.
 * @payload_ethertype: ethertype of the l3 traffic tunnelled
 */
struct bareudp_port {
	u16 dst_port;
	u16 payload_ethertype;
};

static inline struct bareudp_port *bareudp_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

static int bareudp_get_options(const struct vport *vport,
		struct sk_buff *skb)
{
	struct bareudp_port *bareudp_port = bareudp_vport(vport);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, bareudp_port->dst_port))
		return -EMSGSIZE;

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_PAYLOAD_ETHERTYPE, bareudp_port->dst_port))
		return -EMSGSIZE;

	return 0;
}

static const struct nla_policy exts_policy[OVS_BAREUDP_EXT_MAX + 1] = {
        [OVS_BAREUDP_EXT_MULTIPROTO_MODE]     = { .type = NLA_FLAG, },
};

static int bareudp_configure_exts(struct vport *vport, struct nlattr *attr,
		struct bareudp_conf *conf)
{
	struct nlattr *exts[OVS_BAREUDP_EXT_MAX + 1];
	int err;

	if (nla_len(attr) < sizeof(struct nlattr))
		return -EINVAL;

	err = nla_parse_nested_deprecated(exts, OVS_BAREUDP_EXT_MAX, attr,
			exts_policy, NULL);
	if (err < 0)
		return err;

	if (exts[OVS_BAREUDP_EXT_MULTIPROTO_MODE])
		conf->multi_proto_mode = true;

	return 0;
}


static struct vport *bareudp_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct bareudp_port *bareudp_port;
	struct net_device *dev;
	struct vport *vport;
	struct bareudp_conf conf;
	struct nlattr *a;
	u16 ethertype;
	u16 dst_port;
	int err;

	if (!options) {
		err = -EINVAL;
		goto error;
	}

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
	if (a && nla_len(a) == sizeof(u16)) {
		dst_port = nla_get_u16(a);
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto error;
	}

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_PAYLOAD_ETHERTYPE);
	if (a && nla_len(a) == sizeof(u16)) {
		ethertype = nla_get_u16(a);
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto error;
	}

	vport = ovs_vport_alloc(sizeof(struct bareudp_port),
				&ovs_bareudp_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_EXTENSION);
	if (a) {
		err = bareudp_configure_exts(vport, a, &conf);
		if (err) {
			ovs_vport_free(vport);
			goto error;
		}
	}

	bareudp_port = bareudp_vport(vport);
	bareudp_port->dst_port = dst_port;
	bareudp_port->payload_ethertype = ethertype;

	conf.ethertype = htons(ethertype);
	conf.port = htons(dst_port);

	rtnl_lock();
	dev = bareudp_dev_create(net, parms->name, NET_NAME_USER, &conf);
	if (IS_ERR(dev)) {
		rtnl_unlock();
		ovs_vport_free(vport);
		return ERR_CAST(dev);
	}

	err = dev_change_flags(dev, dev->flags | IFF_UP, NULL);
	if (err < 0) {
		rtnl_delete_link(dev);
		rtnl_unlock();
		ovs_vport_free(vport);
		goto error;
	}

	rtnl_unlock();
	return vport;
error:
	return ERR_PTR(err);
}

static struct vport *bareudp_create(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = bareudp_tnl_create(parms);
	if (IS_ERR(vport))
		return vport;

	return ovs_netdev_link(vport, parms->name);
}

static struct vport_ops ovs_bareudp_vport_ops = {
	.type		= OVS_VPORT_TYPE_BAREUDP,
	.create		= bareudp_create,
	.destroy	= ovs_netdev_tunnel_destroy,
	.get_options	= bareudp_get_options,
#ifndef USE_UPSTREAM_TUNNEL
	.fill_metadata_dst = bareudp_fill_metadata_dst,
#endif
	.send		= bareudp_xmit,
};

static int __init ovs_bareudp_tnl_init(void)
{
	return ovs_vport_ops_register(&ovs_bareudp_vport_ops);
}

static void __exit ovs_bareudp_tnl_exit(void)
{
	ovs_vport_ops_unregister(&ovs_bareudp_vport_ops);
}

module_init(ovs_bareudp_tnl_init);
module_exit(ovs_bareudp_tnl_exit);

MODULE_DESCRIPTION("OVS: Bareudp switching port");
MODULE_LICENSE("GPL");
MODULE_ALIAS("vport-type-6");
