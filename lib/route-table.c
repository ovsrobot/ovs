/*
 * Copyright (c) 2011, 2012, 2013, 2014, 2017 Nicira, Inc.
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

#include "route-table.h"

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "coverage.h"
#include "hash.h"
#include "netdev.h"
#include "netlink.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "openvswitch/ofpbuf.h"
#include "ovs-router.h"
#include "packets.h"
#include "rtnetlink.h"
#include "tnl-ports.h"
#include "openvswitch/vlog.h"

/* Linux 2.6.36 added RTA_MARK, so define it just in case we're building with
 * old headers.  (We can't test for it with #ifdef because it's an enum.) */
#define RTA_MARK 16

VLOG_DEFINE_THIS_MODULE(route_table);

COVERAGE_DEFINE(route_table_dump);

static struct ovs_mutex route_table_mutex = OVS_MUTEX_INITIALIZER;
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

/* Global change number for route-table, which should be incremented
 * every time route_table_reset() is called.  */
static uint64_t rt_change_seq;

static struct nln *nln = NULL;
static struct route_table_msg rtmsg;
static struct nln_notifier *route_notifier = NULL;
static struct nln_notifier *route6_notifier = NULL;
static struct nln_notifier *name_notifier = NULL;

static bool route_table_valid = false;

static void route_table_reset(void);
static void route_table_handle_msg(const struct route_table_msg *,
                                   void *);
static void route_table_change(const struct route_table_msg *, void *);
static void route_map_clear(void);

static void name_table_init(void);
static void name_table_change(const struct rtnetlink_change *, void *);

uint64_t
route_table_get_change_seq(void)
{
    return rt_change_seq;
}

/* Users of the route_table module should register themselves with this
 * function before making any other route_table function calls. */
void
route_table_init(void)
    OVS_EXCLUDED(route_table_mutex)
{
    ovs_mutex_lock(&route_table_mutex);
    ovs_assert(!nln);
    ovs_assert(!route_notifier);
    ovs_assert(!route6_notifier);

    ovs_router_init();
    nln = nln_create(NULL, NETLINK_ROUTE,
                     route_table_parse, &rtmsg);

    route_notifier =
        nln_notifier_create(nln, RTNLGRP_IPV4_ROUTE,
                            (nln_notify_func *) route_table_change, NULL);
    route6_notifier =
        nln_notifier_create(nln, RTNLGRP_IPV6_ROUTE,
                            (nln_notify_func *) route_table_change, NULL);

    route_table_reset();
    name_table_init();

    ovs_mutex_unlock(&route_table_mutex);
}

/* Run periodically to update the locally maintained routing table. */
void
route_table_run(void)
    OVS_EXCLUDED(route_table_mutex)
{
    ovs_mutex_lock(&route_table_mutex);
    if (nln) {
        rtnetlink_run();
        nln_run(nln);

        if (!route_table_valid) {
            route_table_reset();
        }
    }
    ovs_mutex_unlock(&route_table_mutex);
}

/* Causes poll_block() to wake up when route_table updates are required. */
void
route_table_wait(void)
    OVS_EXCLUDED(route_table_mutex)
{
    ovs_mutex_lock(&route_table_mutex);
    if (nln) {
        rtnetlink_wait();
        nln_wait(nln);
    }
    ovs_mutex_unlock(&route_table_mutex);
}

bool
route_table_dump_one_table(
    char *netns,
    unsigned char id,
    void (*handle_msg)(const struct route_table_msg *, void *),
    void *data)
{
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf request, reply, buf;
    struct rtmsg *rq_msg;
    bool filtered = true;
    struct nl_dump dump;

    ofpbuf_init(&request, 0);

    nl_msg_put_nlmsghdr(&request, sizeof *rq_msg, RTM_GETROUTE, NLM_F_REQUEST);

    rq_msg = ofpbuf_put_zeros(&request, sizeof *rq_msg);
    rq_msg->rtm_family = AF_UNSPEC;
    rq_msg->rtm_table = RT_TABLE_UNSPEC;

    nl_msg_put_u32(&request, RTA_TABLE, id);

    nl_dump_start(netns, &dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    while (nl_dump_next(&dump, &reply, &buf)) {
        struct route_table_msg msg;

        if (route_table_parse(&reply, &msg)) {
            struct nlmsghdr *nlmsghdr = nl_msg_nlmsghdr(&reply);

            /* Older kernels do not support filtering. */
            if (!(nlmsghdr->nlmsg_flags & NLM_F_DUMP_FILTERED)) {
                filtered = false;
            }
            (*handle_msg)(&msg, data);
        }
    }
    ofpbuf_uninit(&buf);
    nl_dump_done(&dump);

    return filtered;
}

static void
route_table_reset(void)
{
    unsigned char tables[] = {
        RT_TABLE_DEFAULT,
        RT_TABLE_MAIN,
        RT_TABLE_LOCAL,
    };

    route_map_clear();
    netdev_get_addrs_list_flush();
    route_table_valid = true;
    rt_change_seq++;

    COVERAGE_INC(route_table_dump);

    for (size_t i = 0; i < ARRAY_SIZE(tables); i++) {
        if (!route_table_dump_one_table(NULL, tables[i],
                                        route_table_handle_msg,
                                        NULL)) {
            /* Got unfiltered reply, no need to dump further. */
            break;
        }
    }
}

static bool
route_table_add_nexthop(struct route_table_msg *change,
                        bool ipv4,
                        struct nlattr *nl_gw,
                        uint32_t ifindex)
{
    ovs_assert(change->rd.n_nexthops < MAX_ROUTE_DATA_NEXTHOP);

    struct route_data_nexthop *nh = &change->rd.nexthops[
            change->rd.n_nexthops];

    if (nl_gw) {
        if (ipv4) {
            ovs_be32 gw;
            gw = nl_attr_get_be32(nl_gw);
            in6_addr_set_mapped_ipv4(&nh->rta_gw, gw);
        } else {
            nh->rta_gw = nl_attr_get_in6_addr(nl_gw);
        }
    }

    nh->ifindex = ifindex;
    if (ifindex && !if_indextoname(ifindex, nh->ifname)) {
        int error = errno;

        VLOG_DBG_RL(&rl, "Could not find interface name[%u]: %s",
                    ifindex, ovs_strerror(error));
        if (error == ENXIO) {
            change->relevant = false;
        } else {
            return 0;
        }
    }
    change->rd.n_nexthops++;
    return 1;
}


/* The following function uses the RTNH defines of rtnetlink.h
 * As these rely on casts from char * to struct rtnexthop * clang will issue
 * a warning about alignment even though the defines will ensure that the data
 * is alligned. */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#endif

static bool
route_table_parse_multipath(struct route_table_msg *change,
                            struct nlattr *multipath,
                            bool ipv4)
{
    static const struct nl_policy policy[] = {
        [RTA_GATEWAY] = { .type = NL_A_U32, .optional = true },
    };

    static const struct nl_policy policy6[] = {
        [RTA_GATEWAY] = { .type = NL_A_IPV6, .optional = true },
    };

    struct nlattr *attrs[ARRAY_SIZE(policy)];

    size_t len = RTA_PAYLOAD((struct rtattr *) multipath);
    struct rtnexthop *rtnh = RTA_DATA(multipath);

    while (len >= sizeof(*rtnh) && len >= rtnh->rtnh_len &&
           change->rd.n_nexthops < MAX_ROUTE_DATA_NEXTHOP) {

        bool parsed;

        struct ofpbuf buf;
        ofpbuf_use_const(&buf, RTNH_DATA(rtnh),
                         rtnh->rtnh_len - sizeof(*rtnh));
        if (ipv4) {
            parsed = nl_policy_parse(&buf, 0, policy, attrs,
                                     ARRAY_SIZE(policy));
        } else {
            parsed = nl_policy_parse(&buf, 0, policy6, attrs,
                                     ARRAY_SIZE(policy6));
        }

        if (!parsed) {
            VLOG_DBG_RL(&rl, "received unparseable rtnetlink route message");
            return 0;
        }

        if (!route_table_add_nexthop(change, ipv4, attrs[RTA_GATEWAY],
                                     rtnh->rtnh_ifindex)) {
            return 0;
        }

        len -= RTNH_ALIGN(rtnh->rtnh_len);
        rtnh = RTNH_NEXT(rtnh);
    }

    return 1;
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/* Return RTNLGRP_IPV4_ROUTE or RTNLGRP_IPV6_ROUTE on success, 0 on parse
 * error. */
int
route_table_parse(struct ofpbuf *buf, void *change_)
{
    struct route_table_msg *change = change_;
    bool parsed, ipv4 = false;

    static const struct nl_policy policy[] = {
        [RTA_DST] = { .type = NL_A_U32, .optional = true  },
        [RTA_OIF] = { .type = NL_A_U32, .optional = true },
        [RTA_GATEWAY] = { .type = NL_A_U32, .optional = true },
        [RTA_MARK] = { .type = NL_A_U32, .optional = true },
        [RTA_PREFSRC] = { .type = NL_A_U32, .optional = true },
        [RTA_TABLE] = { .type = NL_A_U32, .optional = true },
        [RTA_PRIORITY] = { .type = NL_A_U32, .optional = true },
        [RTA_MULTIPATH] = { .type = NL_A_NESTED, .optional = true },
    };

    static const struct nl_policy policy6[] = {
        [RTA_DST] = { .type = NL_A_IPV6, .optional = true },
        [RTA_OIF] = { .type = NL_A_U32, .optional = true },
        [RTA_MARK] = { .type = NL_A_U32, .optional = true },
        [RTA_GATEWAY] = { .type = NL_A_IPV6, .optional = true },
        [RTA_PREFSRC] = { .type = NL_A_IPV6, .optional = true },
        [RTA_TABLE] = { .type = NL_A_U32, .optional = true },
        [RTA_PRIORITY] = { .type = NL_A_U32, .optional = true },
        [RTA_MULTIPATH] = { .type = NL_A_NESTED, .optional = true },
    };

    struct nlattr *attrs[ARRAY_SIZE(policy)];
    const struct rtmsg *rtm;

    rtm = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *rtm);

    if (rtm->rtm_family == AF_INET) {
        parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
                                 policy, attrs, ARRAY_SIZE(policy));
        ipv4 = true;
    } else if (rtm->rtm_family == AF_INET6) {
        parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
                                 policy6, attrs, ARRAY_SIZE(policy6));
    } else {
        VLOG_DBG_RL(&rl, "received non AF_INET rtnetlink route message");
        return 0;
    }

    if (parsed) {
        const struct nlmsghdr *nlmsg;
        uint32_t table_id;

        nlmsg = buf->data;

        memset(change, 0, sizeof *change);
        change->relevant = true;

        if (rtm->rtm_scope == RT_SCOPE_NOWHERE) {
            change->relevant = false;
        }

        if (rtm->rtm_type != RTN_UNICAST &&
            rtm->rtm_type != RTN_LOCAL) {
            change->relevant = false;
        }

        table_id = rtm->rtm_table;
        if (attrs[RTA_TABLE]) {
            table_id = nl_attr_get_u32(attrs[RTA_TABLE]);
        }
        /* Do not consider changes in non-standard routing tables. */
        if (table_id
            && table_id != RT_TABLE_DEFAULT
            && table_id != RT_TABLE_MAIN
            && table_id != RT_TABLE_LOCAL) {
            change->relevant = false;
         }
        change->rd.rta_table_id = table_id;

        change->nlmsg_type     = nlmsg->nlmsg_type;
        change->rd.rtm_dst_len = rtm->rtm_dst_len + (ipv4 ? 96 : 0);
        change->rd.local = rtm->rtm_type == RTN_LOCAL;
        change->rd.plen = rtm->rtm_dst_len;
        change->rd.rtm_protocol = rtm->rtm_protocol;

        if (attrs[RTA_DST]) {
            if (ipv4) {
                ovs_be32 dst;
                dst = nl_attr_get_be32(attrs[RTA_DST]);
                in6_addr_set_mapped_ipv4(&change->rd.rta_dst, dst);
            } else {
                change->rd.rta_dst = nl_attr_get_in6_addr(attrs[RTA_DST]);
            }
        } else if (ipv4) {
            in6_addr_set_mapped_ipv4(&change->rd.rta_dst, 0);
        }
        if (attrs[RTA_PREFSRC]) {
            if (ipv4) {
                ovs_be32 prefsrc;
                prefsrc = nl_attr_get_be32(attrs[RTA_PREFSRC]);
                in6_addr_set_mapped_ipv4(&change->rd.rta_prefsrc, prefsrc);
            } else {
                change->rd.rta_prefsrc =
                    nl_attr_get_in6_addr(attrs[RTA_PREFSRC]);
            }
        }
        if (attrs[RTA_MARK]) {
            change->rd.mark = nl_attr_get_u32(attrs[RTA_MARK]);
        }
        if (attrs[RTA_PRIORITY]) {
            change->rd.rta_priority = nl_attr_get_u32(attrs[RTA_PRIORITY]);
        }

        if (attrs[RTA_GATEWAY] || attrs[RTA_OIF]) {
            uint32_t ifindex = 0;
            if (attrs[RTA_OIF]) {
                ifindex = nl_attr_get_u32(attrs[RTA_OIF]);
            }
            if (!route_table_add_nexthop(change, ipv4, attrs[RTA_GATEWAY],
                                         ifindex)) {
                return 0;
            }
        } else if (attrs[RTA_MULTIPATH]) {
            if (!route_table_parse_multipath(change,
                                             attrs[RTA_MULTIPATH], ipv4)) {
                return 0;
            }
        }
    } else {
        VLOG_DBG_RL(&rl, "received unparseable rtnetlink route message");
        return 0;
    }

    /* Success. */
    return ipv4 ? RTNLGRP_IPV4_ROUTE : RTNLGRP_IPV6_ROUTE;
}

static void
route_table_change(const struct route_table_msg *change OVS_UNUSED,
                   void *aux OVS_UNUSED)
{
    if (!change || change->relevant) {
        route_table_valid = false;
    }
}

static void
route_table_handle_msg(const struct route_table_msg *change,
                       void *data OVS_UNUSED)
{
    if (change->relevant && change->nlmsg_type == RTM_NEWROUTE) {
        const struct route_data *rd = &change->rd;

        ovs_router_insert(rd->mark, &rd->rta_dst, rd->rtm_dst_len,
                          rd->local, rd->nexthops[0].ifname,
                          &rd->nexthops[0].rta_gw, &rd->rta_prefsrc);
    }
}

static void
route_map_clear(void)
{
    ovs_router_flush();
}

bool
route_table_fallback_lookup(const struct in6_addr *ip6_dst OVS_UNUSED,
                            char name[] OVS_UNUSED,
                            struct in6_addr *gw6)
{
    *gw6 = in6addr_any;
    return false;
}


/* name_table . */

static void
name_table_init(void)
{
    name_notifier = rtnetlink_notifier_create(name_table_change, NULL);
}


static void
name_table_change(const struct rtnetlink_change *change,
                  void *aux OVS_UNUSED)
{
    if (change && change->irrelevant) {
        return;
    }

    /* Changes to interface status can cause routing table changes that some
     * versions of the linux kernel do not advertise for some reason. */
    route_table_valid = false;

    if (change && change->nlmsg_type == RTM_DELLINK) {
        if (change->ifname) {
            tnl_port_map_delete_ipdev(change->ifname);
        }
    }
}
