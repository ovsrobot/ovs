/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "tnl-neigh-cache.h"

#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <stdlib.h>

#include "bitmap.h"
#include "cmap.h"
#include "coverage.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "errno.h"
#include "flow.h"
#include "netdev.h"
#include "ovs-thread.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/ofpbuf.h"
#include "seq.h"
#include "socket-util.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "smap.h"

VLOG_DEFINE_THIS_MODULE(tnl_neigh_cache);

/* In seconds */
#define NEIGH_ENTRY_DEFAULT_IDLE_TIME  (15 * 60)
#define NUD_VALID (NUD_PERMANENT|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)

struct tnl_neigh_entry {
    struct cmap_node cmap_node;
    struct in6_addr ip;
    struct eth_addr mac;
    time_t expires;             /* Expiration time. */
    char br_name[IFNAMSIZ];
    bool event;
};

enum tnl_neigh_nlmsg_op {
    TNL_NEIGH_NLMSG_ADD = 1,
    TNL_NEIGH_NLMSG_DEL,
};

struct tnl_neigh_nlmsg {
    struct in6_addr ip;
    struct eth_addr mac;
    char br_name[IFNAMSIZ];
    enum tnl_neigh_nlmsg_op op;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
static struct cmap table = CMAP_INITIALIZER;
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct nln_notifier *neigh_notifier = NULL;
static struct nln *neigh_nln = NULL;
static struct tnl_neigh_nlmsg tnmsg;

static int tnl_neigh_event_parse(struct ofpbuf *, struct tnl_neigh_nlmsg *);
static void tnl_neigh_event_change(const struct tnl_neigh_nlmsg *, void *);

static uint32_t
tnl_neigh_hash(const struct in6_addr *ip)
{
    return hash_bytes(ip->s6_addr, 16, 0);
}

static struct tnl_neigh_entry *
tnl_neigh_lookup__(const char br_name[IFNAMSIZ], const struct in6_addr *dst)
{
    struct tnl_neigh_entry *neigh;
    uint32_t hash;

    hash = tnl_neigh_hash(dst);
    CMAP_FOR_EACH_WITH_HASH (neigh, cmap_node, hash, &table) {
        if (ipv6_addr_equals(&neigh->ip, dst) &&
            !strcmp(neigh->br_name, br_name) && !neigh->event) {
            if (neigh->expires <= time_now()) {
                return NULL;
            }

            neigh->expires = time_now() + NEIGH_ENTRY_DEFAULT_IDLE_TIME;
            return neigh;
        }
    }

    /* To check whether neigh entry available which learned from system. */
    CMAP_FOR_EACH_WITH_HASH (neigh, cmap_node, hash, &table) {
        if (ipv6_addr_equals(&neigh->ip, dst) &&
            neigh->event) {
            return neigh;
        }
    }

    return NULL;
}

int
tnl_neigh_lookup(const char br_name[IFNAMSIZ], const struct in6_addr *dst,
                 struct eth_addr *mac)
{
    struct tnl_neigh_entry *neigh;
    int res = ENOENT;

    neigh = tnl_neigh_lookup__(br_name, dst);
    if (neigh) {
        *mac = neigh->mac;
        res = 0;
    }
    return res;
}

static void
neigh_entry_free(struct tnl_neigh_entry *neigh)
{
    free(neigh);
}

static void
tnl_neigh_delete(struct tnl_neigh_entry *neigh)
{
    uint32_t hash = tnl_neigh_hash(&neigh->ip);
    cmap_remove(&table, &neigh->cmap_node, hash);
    ovsrcu_postpone(neigh_entry_free, neigh);
}

static void
tnl_neigh_set_nolock(const char name[IFNAMSIZ], const struct in6_addr *dst,
                     const struct eth_addr mac, bool event)
{
    struct tnl_neigh_entry *neigh = tnl_neigh_lookup__(name, dst);
    if (neigh) {
        if (eth_addr_equals(neigh->mac, mac)) {
            neigh->expires = time_now() + NEIGH_ENTRY_DEFAULT_IDLE_TIME;
            return;
        }
        tnl_neigh_delete(neigh);
    }
    seq_change(tnl_conf_seq);

    neigh = xmalloc(sizeof *neigh);
    neigh->ip = *dst;
    neigh->mac = mac;
    neigh->event = event;
    neigh->expires = time_now() + NEIGH_ENTRY_DEFAULT_IDLE_TIME;
    ovs_strlcpy(neigh->br_name, name, sizeof neigh->br_name);
    cmap_insert(&table, &neigh->cmap_node, tnl_neigh_hash(&neigh->ip));
}

static void
tnl_neigh_unset_nolock(const char name[IFNAMSIZ], const struct in6_addr *dst)
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    CMAP_FOR_EACH (neigh, cmap_node, &table) {
        if (!strcmp(neigh->br_name, name) &&
            ipv6_addr_equals(&neigh->ip, dst) && neigh->event) {
            tnl_neigh_delete(neigh);
            changed = true;
        }
    }

    if (changed) {
        seq_change(tnl_conf_seq);
    }
}

static void
tnl_neigh_set__(const char name[IFNAMSIZ], const struct in6_addr *dst,
                const struct eth_addr mac)
{
    ovs_mutex_lock(&mutex);
    tnl_neigh_set_nolock(name, dst, mac, false);
    ovs_mutex_unlock(&mutex);
}

static void
tnl_arp_set(const char name[IFNAMSIZ], ovs_be32 dst,
            const struct eth_addr mac)
{
    struct in6_addr dst6 = in6_addr_mapped_ipv4(dst);
    tnl_neigh_set__(name, &dst6, mac);
}

static int
tnl_arp_snoop(const struct flow *flow, struct flow_wildcards *wc,
              const char name[IFNAMSIZ])
{
    /* Snoop normal ARP replies and gratuitous ARP requests/replies only */
    if (!is_arp(flow)
        || (!is_garp(flow, wc) &&
            FLOW_WC_GET_AND_MASK_WC(flow, wc, nw_proto) != ARP_OP_REPLY)
        || eth_addr_is_zero(FLOW_WC_GET_AND_MASK_WC(flow, wc, arp_sha))) {
        return EINVAL;
    }

    tnl_arp_set(name, FLOW_WC_GET_AND_MASK_WC(flow, wc, nw_src), flow->arp_sha);
    return 0;
}

static int
tnl_nd_snoop(const struct flow *flow, struct flow_wildcards *wc,
             const char name[IFNAMSIZ])
{
    if (!is_nd(flow, wc) || flow->tp_src != htons(ND_NEIGHBOR_ADVERT)) {
        return EINVAL;
    }
    /* - RFC4861 says Neighbor Advertisements sent in response to unicast Neighbor
     *   Solicitations SHOULD include the Target link-layer address. However, Linux
     *   doesn't. So, the response to Solicitations sent by OVS will include the
     *   TLL address and other Advertisements not including it can be ignored.
     * - OVS flow extract can set this field to zero in case of packet parsing errors.
     *   For details refer miniflow_extract()*/
    if (eth_addr_is_zero(FLOW_WC_GET_AND_MASK_WC(flow, wc, arp_tha))) {
        return EINVAL;
    }

    memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
    memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
    memset(&wc->masks.nd_target, 0xff, sizeof wc->masks.nd_target);

    tnl_neigh_set__(name, &flow->nd_target, flow->arp_tha);
    return 0;
}

int
tnl_neigh_snoop(const struct flow *flow, struct flow_wildcards *wc,
                const char name[IFNAMSIZ])
{
    int res;
    res = tnl_arp_snoop(flow, wc, name);
    if (res != EINVAL) {
        return res;
    }
    return tnl_nd_snoop(flow, wc, name);
}

void
tnl_neigh_cache_run(void)
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        if (!neigh->event && neigh->expires <= time_now()) {
            tnl_neigh_delete(neigh);
            changed = true;
        }
    }

    if (neigh_nln) {
        nln_run(neigh_nln);
    }

    ovs_mutex_unlock(&mutex);

    if (changed) {
        seq_change(tnl_conf_seq);
    }
}

void
tnl_neigh_cache_wait(void)
{
    ovs_mutex_lock(&mutex);
    if (neigh_nln) {
        nln_wait(neigh_nln);
    }
    ovs_mutex_unlock(&mutex);
}

void
tnl_neigh_flush(const char br_name[IFNAMSIZ])
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH (neigh, cmap_node, &table) {
        if (!strcmp(neigh->br_name, br_name)) {
            tnl_neigh_delete(neigh);
            changed = true;
        }
    }
    ovs_mutex_unlock(&mutex);

    if (changed) {
        seq_change(tnl_conf_seq);
    }
}

static void
tnl_neigh_flush__(bool event)
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH (neigh, cmap_node, &table) {
        if (!event || neigh->event) {
            tnl_neigh_delete(neigh);
            changed = true;
        }
    }
    ovs_mutex_unlock(&mutex);
    if (changed) {
        seq_change(tnl_conf_seq);
    }
}

static void
tnl_neigh_cache_flush(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    tnl_neigh_flush__(false);
    unixctl_command_reply(conn, "OK");
}

static int
lookup_any(const char *host_name, struct in6_addr *address)
{
    if (addr_is_ipv6(host_name)) {
        return lookup_ipv6(host_name, address);
    } else {
        int r;
        struct in_addr ip;
        r = lookup_ip(host_name, &ip);
        if (r == 0) {
            in6_addr_set_mapped_ipv4(address, ip.s_addr);
        }
        return r;
    }
    return ENOENT;
}

static void
tnl_neigh_cache_add(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[], void *aux OVS_UNUSED)
{
    const char *br_name = argv[1];
    struct eth_addr mac;
    struct in6_addr ip6;

    if (lookup_any(argv[2], &ip6) != 0) {
        unixctl_command_reply_error(conn, "bad IP address");
        return;
    }

    if (!eth_addr_from_string(argv[3], &mac)) {
        unixctl_command_reply_error(conn, "bad MAC address");
        return;
    }

    tnl_neigh_set__(br_name, &ip6, mac);
    unixctl_command_reply(conn, "OK");
}

static void
tnl_neigh_cache_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct tnl_neigh_entry *neigh;

    ds_put_cstr(&ds, "IP                                            MAC                 Bridge\n");
    ds_put_cstr(&ds, "==========================================================================\n");
    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        int start_len, need_ws;

        start_len = ds.length;
        ipv6_format_mapped(&neigh->ip, &ds);

        need_ws = INET6_ADDRSTRLEN - (ds.length - start_len);
        ds_put_char_multiple(&ds, ' ', need_ws);

        ds_put_format(&ds, ETH_ADDR_FMT"   %s",
                      ETH_ADDR_ARGS(neigh->mac), neigh->br_name);
        if (!neigh->event && neigh->expires <= time_now()) {
            ds_put_format(&ds, " STALE");
        }
        ds_put_char(&ds, '\n');

    }
    ovs_mutex_unlock(&mutex);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static int
tnl_neigh_event_parse(struct ofpbuf *buf, struct tnl_neigh_nlmsg *change)
{
    static const struct nl_policy policy[] = {
        [NDA_DST] = { .type = NL_A_UNSPEC,
                      .min_len = sizeof(struct in_addr),
                      .optional = false, },
        [NDA_LLADDR] = { .type = NL_A_UNSPEC,
                         .min_len = ETH_ALEN,
                         .optional = true, },
    };

    struct nlattr *attrs[ARRAY_SIZE(policy)];
    const struct nlmsghdr *nlmsg = buf->data;
    const struct ndmsg *ndm;
    char namebuf[IFNAMSIZ];
    bool parsed;
    struct in6_addr addr;

    /* Process RTM_NEWNEIGH or RTM_DELNEIGH events only. */
    if (nlmsg->nlmsg_type != RTM_NEWNEIGH &&
        nlmsg->nlmsg_type != RTM_DELNEIGH) {
        return 0;
    }

    ndm = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *ndm);
    if (ndm->ndm_family != AF_INET &&
        ndm->ndm_family != AF_INET6) {
        return 0;
    }

    parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
                             policy, attrs, ARRAY_SIZE(policy));
    if (!parsed) {
        VLOG_DBG_RL(&rl, "The tnl neigh event parse failed");
        return 0;
    }

    if (!if_indextoname(ndm->ndm_ifindex, namebuf)) {
        return 0;
    }

    memset(change, 0, sizeof *change);
    ovs_strlcpy(change->br_name, namebuf, sizeof change->br_name);

    if (ndm->ndm_family == AF_INET) {
        const ovs_be32 *ip4;
        ip4 = nl_attr_get_unspec(attrs[NDA_DST], sizeof *ip4);
        addr = in6_addr_mapped_ipv4(*ip4);
    } else {
        const struct in6_addr *ip6;
        ip6 = nl_attr_get_unspec(attrs[NDA_DST], sizeof *ip6);
        addr = *ip6;
    }

    change->ip = addr;
    change->op = TNL_NEIGH_NLMSG_DEL;
    if (nlmsg->nlmsg_type == RTM_NEWNEIGH) {
        /* If neigh entry was not ready,  will not cache it. */
        if (!(ndm->ndm_state & NUD_VALID) || !attrs[NDA_LLADDR]) {
            return 0;
        }

        const struct eth_addr *mac;
        mac = nl_attr_get_unspec(attrs[NDA_LLADDR], ETH_ALEN);
        change->mac = *mac;
        change->op = TNL_NEIGH_NLMSG_ADD;
    }

    return RTNLGRP_NEIGH;
}

static void
tnl_neigh_event_change(const struct tnl_neigh_nlmsg *change,
                       void *aux OVS_UNUSED)
{
    if (!change) {
        return;
    }

    switch (change->op) {
        case TNL_NEIGH_NLMSG_ADD:
            VLOG_DBG("Add neigh entry: %s "ETH_ADDR_FMT,
                     change->br_name, ETH_ADDR_ARGS(change->mac));
            tnl_neigh_set_nolock(change->br_name, &change->ip,
                                 change->mac, true);
            break;
        case TNL_NEIGH_NLMSG_DEL:
        {
            char ip[INET6_ADDRSTRLEN];

            ipv6_string_mapped(ip, &change->ip);
            VLOG_DBG("Del neigh entry: %s %s", change->br_name, ip);
            tnl_neigh_unset_nolock(change->br_name, &change->ip);
            break;
        }
        default:
            VLOG_ERR_RL(&rl, "The message ops of neigh netlink is unknown");
            break;
    }
}

static void
tnl_neigh_event_uninit(void)
{
    if (neigh_notifier) {
        nln_notifier_destroy(neigh_notifier);
        neigh_notifier = NULL;
    }

    if (neigh_nln) {
        nln_destroy(neigh_nln);
        neigh_nln = NULL;
    }
}

static int
tnl_neigh_event_init(void)
{
    neigh_nln = nln_create(NETLINK_ROUTE,
                           (nln_parse_func *) tnl_neigh_event_parse,
                           &tnmsg);
    if (!neigh_nln) {
        return -1;
    }

    neigh_notifier =
        nln_notifier_create(neigh_nln, RTNLGRP_NEIGH,
                            (nln_notify_func *) tnl_neigh_event_change,
                            NULL);
    if (!neigh_notifier) {
        tnl_neigh_event_uninit();
        return -1;
    }

    return 0;
}

static int
tnl_neigh_event_dump(void)
{
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf request, reply, buf;
    struct nl_dump dump;
    struct ndmsg *ndmsg;

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, sizeof *ndmsg, RTM_GETNEIGH,
                        NLM_F_REQUEST | NLM_F_DUMP);

    ndmsg = ofpbuf_put_zeros(&request, sizeof *ndmsg);
    ndmsg->ndm_family = AF_UNSPEC;

    nl_dump_start(&dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    while (nl_dump_next(&dump, &reply, &buf)) {
        struct tnl_neigh_nlmsg msg;

        if (tnl_neigh_event_parse(&reply, &msg)) {
            tnl_neigh_event_change(&msg, NULL);
        }
    }
    ofpbuf_uninit(&buf);
    return nl_dump_done(&dump);
}

void
tnl_neigh_event_enabled(const struct smap *ovs_other_config)
{
    int err;

    if (smap_get_bool(ovs_other_config, "tnl-neigh-event-enabled", false)) {
        if (neigh_nln || neigh_notifier) {
            return;
        }

        err = tnl_neigh_event_init();
        if (err) {
            VLOG_ERR("Can't create nln handle or notifier for neighboring subsystem");
            return;
        }

        err = tnl_neigh_event_dump();
        if (err) {
            tnl_neigh_event_uninit();
            VLOG_ERR("Can't dump neigh entries");
            return;
        }
    } else {
        if (!neigh_nln && !neigh_notifier) {
            return;
        }
        tnl_neigh_flush__(true);
        tnl_neigh_event_uninit();
    }
}

void
tnl_neigh_cache_init(void)
{
    unixctl_command_register("tnl/arp/show", "", 0, 0, tnl_neigh_cache_show, NULL);
    unixctl_command_register("tnl/arp/set", "BRIDGE IP MAC", 3, 3, tnl_neigh_cache_add, NULL);
    unixctl_command_register("tnl/arp/flush", "", 0, 0, tnl_neigh_cache_flush, NULL);
    unixctl_command_register("tnl/neigh/show", "", 0, 0, tnl_neigh_cache_show, NULL);
    unixctl_command_register("tnl/neigh/set", "BRIDGE IP MAC", 3, 3, tnl_neigh_cache_add, NULL);
    unixctl_command_register("tnl/neigh/flush", "", 0, 0, tnl_neigh_cache_flush, NULL);
}
