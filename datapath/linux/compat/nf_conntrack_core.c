#include <linux/types.h>
#include <linux/version.h>
#include <net/ip.h>
#include <net/ipv6.h>

#ifndef HAVE_NF_CT_ZONE_INIT

#include <net/netfilter/nf_conntrack_zones.h>

/* Built-in default zone used e.g. by modules. */
const struct nf_conntrack_zone nf_ct_zone_dflt = {
	.id	= NF_CT_DEFAULT_ZONE_ID,
	.dir	= NF_CT_DEFAULT_ZONE_DIR,
};

#endif /* HAVE_NF_CT_ZONE_INIT */

#ifndef HAVE_NF_CT_INVERT_TUPLE_TAKES_L3PROTO
static int ipv4_get_l4proto(const struct sk_buff *skb, unsigned int nhoff,
			    u_int8_t *protonum)
{
	int dataoff = -1;
	const struct iphdr *iph;
	struct iphdr _iph;

	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (!iph)
		return -1;

	/* Conntrack defragments packets, we might still see fragments
	 * inside ICMP packets though.
	 */
	if (iph->frag_off & htons(IP_OFFSET))
		return -1;

	dataoff = nhoff + (iph->ihl << 2);
	*protonum = iph->protocol;

	/* Check bogus IP headers */
	if (dataoff > skb->len) {
		pr_debug("bogus IPv4 packet: nhoff %u, ihl %u, skblen %u\n",
			 nhoff, iph->ihl << 2, skb->len);
		return -1;
	}
	return dataoff;
}

#if IS_ENABLED(CONFIG_IPV6)
static int ipv6_get_l4proto(const struct sk_buff *skb, unsigned int nhoff,
			    u8 *protonum)
{
	int protoff = -1;
	unsigned int extoff = nhoff + sizeof(struct ipv6hdr);
	__be16 frag_off;
	u8 nexthdr;

	if (skb_copy_bits(skb, nhoff + offsetof(struct ipv6hdr, nexthdr),
			  &nexthdr, sizeof(nexthdr)) != 0) {
		pr_debug("can't get nexthdr\n");
		return -1;
	}
	protoff = ipv6_skip_exthdr(skb, extoff, &nexthdr, &frag_off);
	/*
	 * (protoff == skb->len) means the packet has not data, just
	 * IPv6 and possibly extensions headers, but it is tracked anyway
	 */
	if (protoff < 0 || (frag_off & htons(~0x7)) != 0) {
		pr_debug("can't find proto in pkt\n");
		return -1;
	}

	*protonum = nexthdr;
	return protoff;
}
#endif

int rpl_get_l4proto(const struct sk_buff *skb,
		    unsigned int nhoff, u8 pf, u8 *l4num)
{
	switch (pf) {
	case NFPROTO_IPV4:
		return ipv4_get_l4proto(skb, nhoff, l4num);
#if IS_ENABLED(CONFIG_IPV6)
	case NFPROTO_IPV6:
		return ipv6_get_l4proto(skb, nhoff, l4num);
#endif
	default:
		*l4num = 0;
		break;
	}
	return -1;
}
#endif /* HAVE_NF_CT_INVERT_TUPLE_TAKES_L3PROTO */
