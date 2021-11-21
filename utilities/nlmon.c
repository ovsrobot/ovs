/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stddef.h>
#include <linux/rtnetlink.h>
#include<linux/if_ether.h>
#include <getopt.h>
#include "netlink.h"
#include "netlink-socket.h"
#include "netnsid.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/poll-loop.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "nlmon.h"

#define MAX_TYPE_LEN 25

typedef int (*GRP_handler)(void *);

int nlmon_link(void *);
int nlmon_tc(void *);

static void print_usage(void);
static void nl_parse_tc_opts(struct nlattr *);
static void parse_rtattr_flags(struct rtattr **, int,
                struct rtattr *, int, unsigned short);
static void nl_parse_tc_acts(struct rtattr *);
static void nl_parse_tc_act(struct rtattr *);

static const struct {
    enum rtnetlink_groups gr_id;
    const char * gr_name;
    GRP_handler handler;
} known_groups[] = {
    { RTNLGRP_LINK, "link", nlmon_link},
    { RTNLGRP_TC, "tc", nlmon_tc},
    /* keep new groups above */
    { RTNLGRP_NONE, NULL, NULL }
};

static const struct nl_policy rtnlgrp_TC_policy[] = {
    [TCA_KIND] = { .type = NL_A_STRING, .optional = false, },
    [TCA_OPTIONS] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_CHAIN] = { .type = NL_A_U32, .optional = true, },
};

static const struct nl_policy rtnlgrp_link_policy[] = {
    [IFLA_IFNAME] = { .type = NL_A_STRING, .optional = false },
    [IFLA_MASTER] = { .type = NL_A_U32, .optional = true },
};

static const struct nl_policy tca_flower_policy[] = {
    [TCA_FLOWER_CLASSID] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_INDEV] = { .type = NL_A_STRING, .max_len = IFNAMSIZ,
                           .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_TYPE] = { .type = NL_A_U16, .optional = false, },
    [TCA_FLOWER_KEY_ARP_SIP] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ARP_TIP] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ARP_SHA] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN,
                                 .optional = true, },
    [TCA_FLOWER_KEY_ARP_THA] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN,
                                 .optional = true, },
    [TCA_FLOWER_KEY_ARP_OP] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_ARP_SIP_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ARP_TIP_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ARP_SHA_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ARP_THA_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ARP_OP_MASK] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_FLAGS] = { .type = NL_A_U32, .optional = false, },
    [TCA_FLOWER_ACT] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_FLOWER_KEY_IP_PROTO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST] = {.type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_MPLS_TTL] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_MPLS_TC] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_MPLS_BOS] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_MPLS_LABEL] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_PRIO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ETH_TYPE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_ENC_KEY_ID] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_DST] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK] = { .type = NL_A_U32,
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_DST_MASK] = { .type = NL_A_U32,
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_DST] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK] = { .type = NL_A_UNSPEC,
                                           .min_len = sizeof(struct in6_addr),
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_DST_MASK] = { .type = NL_A_UNSPEC,
                                           .min_len = sizeof(struct in6_addr),
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_UDP_DST_PORT] = { .type = NL_A_U16,
                                          .optional = true, },
    [TCA_FLOWER_KEY_FLAGS] = { .type = NL_A_BE32, .optional = true, },
    [TCA_FLOWER_KEY_FLAGS_MASK] = { .type = NL_A_BE32, .optional = true, },
    [TCA_FLOWER_KEY_IP_TTL] = { .type = NL_A_U8,
                                .optional = true, },
    [TCA_FLOWER_KEY_IP_TTL_MASK] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_IP_TOS] = { .type = NL_A_U8,
                                .optional = true, },
    [TCA_FLOWER_KEY_IP_TOS_MASK] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_TCP_FLAGS] = { .type = NL_A_U16,
                                   .optional = true, },
    [TCA_FLOWER_KEY_TCP_FLAGS_MASK] = { .type = NL_A_U16,
                                        .optional = true, },
    [TCA_FLOWER_KEY_CVLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CVLAN_PRIO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_CVLAN_ETH_TYPE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IP_TOS] = { .type = NL_A_U8,
                                    .optional = true, },
    [TCA_FLOWER_KEY_ENC_IP_TOS_MASK] = { .type = NL_A_U8,
                                         .optional = true, },
    [TCA_FLOWER_KEY_ENC_IP_TTL] = { .type = NL_A_U8,
                                    .optional = true, },
    [TCA_FLOWER_KEY_ENC_IP_TTL_MASK] = { .type = NL_A_U8,
                                         .optional = true, },
    [TCA_FLOWER_KEY_ENC_OPTS] = { .type = NL_A_NESTED, .optional = true, },
    [TCA_FLOWER_KEY_ENC_OPTS_MASK] = { .type = NL_A_NESTED,
                                       .optional = true, },
    [TCA_FLOWER_KEY_CT_STATE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CT_STATE_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CT_ZONE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CT_ZONE_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CT_MARK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_CT_MARK_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_CT_LABELS] = { .type = NL_A_U128, .optional = true, },
    [TCA_FLOWER_KEY_CT_LABELS_MASK] = { .type = NL_A_U128,
                                        .optional = true, },
    [TCA_FLOWER_KEY_ICMPV4_CODE] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_ICMPV4_CODE_MASK] = { .type = NL_A_U8,
                                          .optional = true, },
    [TCA_FLOWER_KEY_ICMPV4_TYPE] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_ICMPV4_TYPE_MASK] = { .type = NL_A_U8,
                                          .optional = true, },
    [TCA_FLOWER_KEY_ICMPV6_CODE] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_ICMPV6_CODE_MASK] = { .type = NL_A_U8,
                                          .optional = true, },
    [TCA_FLOWER_KEY_ICMPV6_TYPE] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_ICMPV6_TYPE_MASK] = { .type = NL_A_U8,
                                          .optional = true, },
};

int
main(int argc, char *argv[])
{

    char type[MAX_TYPE_LEN];
    int rc;
    enum rtnetlink_groups gr_id = RTNLGRP_LINK;
    enum vlog_level level = VLL_DBG;

    set_program_name(argv[0]);

    for (;;) {
        int c, optidx = 0;
        static struct option long_opts[] = {
                { "type", 1, 0, 't' },
                { "log-level", 1, 0, 'l' },
                { "help", 0, 0, 'h' },
                { 0, 0, 0, 0 }
        };

        c = getopt_long(argc, argv, "t:l:h", long_opts, &optidx);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 't':
            ovs_strzcpy(type, optarg, MAX_TYPE_LEN - 1);
            break;
        case 'l':
            if (strcmp("info", optarg) == 0) {
                level = VLL_INFO;
            } else if (strcmp("err", optarg) == 0) {
                level = VLL_ERR;
            }
            break;
        default:
            print_usage();
            break;
        }
    }

    vlog_set_levels(NULL, VLF_ANY_DESTINATION, level);

    for (int i = 0; known_groups[i].gr_id != RTNLGRP_NONE; i++) {
        if (strcmp(type, known_groups[i].gr_name) == 0) {
            gr_id = known_groups[i].gr_id;
            rc = known_groups[i].handler(&gr_id);
            goto out;
        }
    }

    /* no group found call default group */
    rc = nlmon_link(&gr_id);

out:
    return rc;
}

static void
init_socket(struct nl_sock **sk, enum rtnetlink_groups *gid)
{
    int error;

    error = nl_sock_create(NETLINK_ROUTE, sk);
    if (error) {
        ovs_fatal(error, "could not create rtnetlink socket");
    }

    error = nl_sock_join_mcgroup(*sk, *gid);
    if (error) {
        ovs_fatal(error, "could not join RTNLGRP_LINK multicast group");
    }
    nl_sock_listen_all_nsid(*sk, true);
}

int nlmon_link(void * args)
{
    uint64_t buf_stub[4096 / 64];
    struct nl_sock *sock;
    int nsid;
    struct ofpbuf buf;
    int error;

    init_socket(&sock, (enum rtnetlink_groups *) args);
    ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
    for (;;) {
        error = nl_sock_recv(sock, &buf, &nsid, false);
        if (error == EAGAIN) {
            /* Nothing to do. */
        } else if (error == ENOBUFS) {
            ovs_error(0, "network monitor socket overflowed");
        } else if (error) {
            ovs_fatal(error, "error on network monitor socket");
        } else {
            struct iff_flag {
                unsigned int flag;
                const char *name;
            };

            static const struct iff_flag flags[] = {
                { IFF_UP, "UP", },
                { IFF_BROADCAST, "BROADCAST", },
                { IFF_DEBUG, "DEBUG", },
                { IFF_LOOPBACK, "LOOPBACK", },
                { IFF_POINTOPOINT, "POINTOPOINT", },
                { IFF_NOTRAILERS, "NOTRAILERS", },
                { IFF_RUNNING, "RUNNING", },
                { IFF_NOARP, "NOARP", },
                { IFF_PROMISC, "PROMISC", },
                { IFF_ALLMULTI, "ALLMULTI", },
                { IFF_MASTER, "MASTER", },
                { IFF_SLAVE, "SLAVE", },
                { IFF_MULTICAST, "MULTICAST", },
                { IFF_PORTSEL, "PORTSEL", },
                { IFF_AUTOMEDIA, "AUTOMEDIA", },
                { IFF_DYNAMIC, "DYNAMIC", },
            };

            struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_link_policy)];
            struct nlmsghdr *nlh;
            struct ifinfomsg *iim;
            int i;

            nlh = ofpbuf_at(&buf, 0, NLMSG_HDRLEN);
            iim = ofpbuf_at(&buf, NLMSG_HDRLEN, sizeof *iim);
            if (!iim) {
                ovs_error(0, "received bad rtnl message (no ifinfomsg)");
                continue;
            }

            if (!nl_policy_parse(&buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                                 rtnlgrp_link_policy,
                                 attrs, ARRAY_SIZE(rtnlgrp_link_policy))) {
                ovs_error(0, "received bad rtnl message (policy)");
                continue;
            }
            printf("netdev %s changed (%s):\n",
                   nl_attr_get_string(attrs[IFLA_IFNAME]),
                   (nlh->nlmsg_type == RTM_NEWLINK ? "RTM_NEWLINK"
                    : nlh->nlmsg_type == RTM_DELLINK ? "RTM_DELLINK"
                    : nlh->nlmsg_type == RTM_GETLINK ? "RTM_GETLINK"
                    : nlh->nlmsg_type == RTM_SETLINK ? "RTM_SETLINK"
                    : "other"));
            printf("  flags:");
            for (i = 0; i < ARRAY_SIZE(flags); i++) {
                if (iim->ifi_flags & flags[i].flag) {
                    printf(" %s", flags[i].name);
                }
            }
            printf("\n");
            if (netnsid_is_remote(nsid)) {
                printf("  netns id: %d\n", nsid);
            } else {
                printf("  netns id: local\n");
            }
            if (attrs[IFLA_MASTER]) {
                uint32_t idx = nl_attr_get_u32(attrs[IFLA_MASTER]);
                char ifname[IFNAMSIZ];
                if (!if_indextoname(idx, ifname)) {
                    strcpy(ifname, "unknown");
                }
                printf("  master=%"PRIu32" (%s)\n", idx, ifname);
            }
        }

        nl_sock_wait(sock, POLLIN);
        poll_block();
    }
}

int nlmon_tc(void * args)
{
    uint64_t buf_stub[4096];
    struct nl_sock *sock;
    struct ofpbuf buf;
    int nsid, error;
    __u16 f_proto = 0;
    __u32 f_prio = 0;

    init_socket(&sock, (enum rtnetlink_groups *) args);

    ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
    for (;;) {
        error = nl_sock_recv(sock, &buf, &nsid, false);
        if (error == EAGAIN) {
            /* Nothing to do. */
        } else if (error == ENOBUFS) {
            ovs_error(0, "network monitor socket overflowed");
        } else if (error) {
            ovs_fatal(error, "error on network monitor socket");
        } else {
            struct nlmsghdr *nlh;
            struct tcmsg *tc;
            struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_TC_policy)];

            nlh = (struct nlmsghdr *) ofpbuf_at(&buf, 0, NLMSG_HDRLEN);
            tc = (struct tcmsg *) ofpbuf_at(&buf, NLMSG_HDRLEN, sizeof *tc);
            if (!tc) {
                ovs_error(0, "received bad TC message (no TC header)");
                continue;
            }
            /* TODO ADD: monitoring via dev name option */
            if (nlh->nlmsg_type != RTM_NEWTFILTER) {
                /* ignore Delete and Get filter messages */
                continue;
            }
            if (!nl_policy_parse(&buf, NLMSG_HDRLEN + sizeof(struct tcmsg),
                                 rtnlgrp_TC_policy,
                                 attrs, ARRAY_SIZE(rtnlgrp_TC_policy))) {
                ovs_error(0, "received bad rtnl message (policy)");
                continue;
            }

            printf("filter ifindex %d nsid ", tc->tcm_ifindex);
            if (nsid < 0) {
                printf("local ");
            } else {
                printf("%u ", nsid);
            }

            f_proto = TC_H_MIN(tc->tcm_info);
            f_prio = TC_H_MAJ(tc->tcm_info) >> 16;

            if (f_proto) {
                printf("protocol 0x%x ", ntohs(f_proto));
            }
            if (f_prio) {
                printf("pref %u ", f_prio);
            }

            if (attrs[TCA_KIND]) {
                printf("%s ", nl_attr_get_string(attrs[TCA_KIND]));
            }
            if (attrs[TCA_CHAIN]) {
                printf("chain %u ", nl_attr_get_u32(attrs[TCA_CHAIN]));
            }
            if (tc->tcm_handle) {
                printf("handle 0x%x ", tc->tcm_handle);
            }
            printf("\n");
            if (attrs[TCA_OPTIONS]) {
                nl_parse_tc_opts(attrs[TCA_OPTIONS]);
            } else {
                ovs_error(0, "BAD TC options");
            }
        }

        nl_sock_wait(sock, POLLIN);
        poll_block();
    }


    return 0;
}

static void nl_parse_tc_opts(struct nlattr * nlattr)
{
    struct nlattr *attrs[ARRAY_SIZE(tca_flower_policy)];
    struct ds str_filter = DS_EMPTY_INITIALIZER;
    unsigned char * tmp_str;
    __u8 tmp_u8 = 0;
    __u16 tmp_u16 = 0;
    __u32 tmp_u32 = 0;
    int i;
    char buf[256];

    if (!nl_parse_nested(nlattr, tca_flower_policy,
                         attrs, ARRAY_SIZE(tca_flower_policy))) {
        ovs_error(0, "failed to parse flower classifier options");
        return ;
    }

    for (i = 0; i < ARRAY_SIZE(tca_flower_policy); i++) {
        if (!nl_attr_get_flag(attrs[i])) {
            continue;
        }
        switch (attrs[i]->nla_type) {
        case TCA_FLOWER_CLASSID:
            ds_put_format(&str_filter, "  classid:%u\n",
                             nl_attr_get_u32(attrs[i]));
            break;
        case TCA_FLOWER_INDEV:
            ds_put_format(&str_filter, "  indev:%s\n",
                            nl_attr_get_string(attrs[i]));
            break;
        case TCA_FLOWER_KEY_ETH_DST:
            if (nl_attr_get_size(attrs[i]) == ETH_ALEN) {
                ds_put_cstr(&str_filter, "  dst_mac:");
                tmp_str = (unsigned char *) nl_attr_get(attrs[i]);
                ds_put_format(&str_filter, "%02x", tmp_str[0]);
                for (int j = 1; j < ETH_ALEN; j++) {
                    ds_put_format(&str_filter, ":%02x", tmp_str[j]);
                }
                ds_put_cstr(&str_filter, "\n");
            }
            break;
        case TCA_FLOWER_KEY_ETH_SRC:
            if (nl_attr_get_size(attrs[i]) == ETH_ALEN) {
                ds_put_cstr(&str_filter, "  src_mac:");
                tmp_str = (unsigned char *) nl_attr_get(attrs[i]);
                ds_put_format(&str_filter, "%02x", tmp_str[0]);
                for (int j = 1; j < ETH_ALEN; j++) {
                    ds_put_format(&str_filter, ":%02x", tmp_str[j]);
                }
                ds_put_cstr(&str_filter, "\n");
            }
            break;
        case TCA_FLOWER_KEY_ETH_TYPE:
             tmp_u16 = nl_attr_get_u16(attrs[i]);
             ds_put_cstr(&str_filter, "  eth_type:");
             if (tmp_u16 == htons(ETH_P_IP)) {
                 ds_put_cstr(&str_filter, "ipv4\n");
             } else if (tmp_u16 == htons(ETH_P_IPV6)) {
                 ds_put_cstr(&str_filter, "ipv6\n");
            } else if (tmp_u16 == htons(ETH_P_ARP)) {
                 ds_put_cstr(&str_filter, "arp\n");
            } else if (tmp_u16 == htons(ETH_P_RARP)) {
                 ds_put_cstr(&str_filter, "rarp\n");
            } else {
                 ds_put_format(&str_filter, "%04x\n", ntohs(tmp_u16));
            }
            break;
        case TCA_FLOWER_KEY_IP_PROTO:
            tmp_u8 = nl_attr_get_u8(attrs[i]);
            ds_put_cstr(&str_filter, "  ip_proto:");
            switch (tmp_u8) {
            case IPPROTO_TCP:
                ds_put_cstr(&str_filter, "tcp\n");
                break;
            case IPPROTO_UDP:
                ds_put_cstr(&str_filter, "udp\n");
                break;
            case IPPROTO_SCTP:
                ds_put_cstr(&str_filter, "sctp\n");
                break;
            case IPPROTO_ICMP:
                ds_put_cstr(&str_filter, "icmp\n");
                break;
            case IPPROTO_ICMPV6:
                ds_put_cstr(&str_filter, "icmpv6\n");
                break;
            default:
                ds_put_format(&str_filter, "%02x\n", tmp_u8);
            }
            break;
        case TCA_FLOWER_KEY_IPV4_SRC:
        case TCA_FLOWER_KEY_IPV6_SRC:
            if (tmp_u16 == htons(ETH_P_IP)) {
                inet_ntop(AF_INET, nl_attr_get(attrs[i]), buf, 256);
            } else if (tmp_u16 == htons(ETH_P_IPV6)) {
                inet_ntop(AF_INET6, nl_attr_get(attrs[i]), buf, 256);
            } else {
                continue;
            }
            ds_put_format(&str_filter, "  src_ip:%s\n", buf);
            break;
        case TCA_FLOWER_KEY_IPV4_DST:
        case TCA_FLOWER_KEY_IPV6_DST:
            if (tmp_u16 == htons(ETH_P_IP)) {
                inet_ntop(AF_INET, nl_attr_get(attrs[i]), buf, 256);
            } else if (tmp_u16 == htons(ETH_P_IPV6)) {
                inet_ntop(AF_INET6, nl_attr_get(attrs[i]), buf, 256);
            } else {
                continue;
            }
            ds_put_format(&str_filter, "  dst_ip:%s\n", buf);
            break;
        case TCA_FLOWER_KEY_TCP_SRC:
        case TCA_FLOWER_KEY_UDP_SRC:
        case TCA_FLOWER_KEY_SCTP_SRC:
            tmp_u16 = ntohs(nl_attr_get_u16(attrs[i]));
            ds_put_format(&str_filter, "  src_port:%u\n", tmp_u16);
        break;
        case TCA_FLOWER_KEY_TCP_DST:
        case TCA_FLOWER_KEY_UDP_DST:
        case TCA_FLOWER_KEY_SCTP_DST:
            tmp_u16 = ntohs(nl_attr_get_u16(attrs[i]));
            ds_put_format(&str_filter, "  dst_port:%u\n", tmp_u16);
        break;
        case TCA_FLOWER_FLAGS:
            tmp_u32 = nl_attr_get_u32(attrs[i]);
            ds_put_cstr(&str_filter, "  filter-flags:[");
            if (tmp_u32 & TCA_CLS_FLAGS_SKIP_HW) {
                ds_put_cstr(&str_filter, "skip-hw, ");
            }
            if (tmp_u32 & TCA_CLS_FLAGS_SKIP_SW) {
                ds_put_cstr(&str_filter, "skip-sw, ");
            }
            if (tmp_u32 & TCA_CLS_FLAGS_IN_HW) {
                ds_put_cstr(&str_filter, "in-hw, ");
            }
            if (tmp_u32 & TCA_CLS_FLAGS_NOT_IN_HW) {
                ds_put_cstr(&str_filter, "not-in-hw, ");
            }
            ds_truncate(&str_filter, str_filter.length - 2);
            ds_put_cstr(&str_filter, "]\n");
            if (nl_attr_get_flag(attrs[TCA_FLOWER_IN_HW_COUNT])) {
                tmp_u32 = nl_attr_get_u32(attrs[TCA_FLOWER_IN_HW_COUNT]);
                ds_put_format(&str_filter, "  in-hw-count : %u\n", tmp_u32);
            }
            break;
        default:
            continue;
        }
    }

    printf("%s", ds_cstr(&str_filter));
    if (attrs[TCA_FLOWER_ACT]) {
        nl_parse_tc_acts((struct rtattr *) attrs[TCA_FLOWER_ACT]);
    }

    ds_destroy(&str_filter);
}

static void nl_parse_tc_acts(struct rtattr *rta){
    struct rtattr *tb[33];
    int i;

    parse_rtattr_flags(tb, 33, RTA_DATA(rta), RTA_PAYLOAD(rta),
                           NLA_F_NESTED);

    for (i = 0; i < 33; i++) {
        if (tb[i]) {
            nl_parse_tc_act(tb[i]);
        }
    }
}

static void nl_parse_tc_act(struct rtattr *rta){
    struct rtattr *tb[33];

    parse_rtattr_flags(tb, 33, RTA_DATA(rta), RTA_PAYLOAD(rta),
                           NLA_F_NESTED);

    if (tb[1] == NULL) {
        fprintf(stderr, "NULL Action!\n");
        return;
    }

    printf("act name = %s\n", (char *) RTA_DATA(tb[1]));

}
static void parse_rtattr_flags(struct rtattr *tb[], int max,
                struct rtattr *rta, int len, unsigned short flags) {
    unsigned short type;

    memset(tb, 0, sizeof(struct rtattr *) * max);
    while (RTA_OK(rta, len)) {
        type = rta->rta_type & ~flags;
        if ((type <= max) && (!tb[type])) {
            tb[type] = rta;
        }
        rta = RTA_NEXT(rta, len);
    }
    if (len) {
        fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
                len, rta->rta_len);
    }
}

static void print_usage(void)
{
        int i;

        printf(
        "Usage: nlmon [OPTION] \n"
        "\n"
        "Options\n"
        " -t, --type=group_type netlink group type\n"
        " -l, --log-level={info,err,dbg} set output log level (Default dbg)\n"
        " -h, --help            Show this help.\n"
        "\n"
        );
        printf("Known groups(Default group - link):");
        for (i = 0; known_groups[i].gr_id != RTNLGRP_NONE; i++) {
            printf(" [%s],", known_groups[i].gr_name);
        }
        printf("\n");
        exit(0);
}

