/*
 * Copyright (c) 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef ROUTE_TABLE_H
#define ROUTE_TABLE_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "openvswitch/list.h"
#include "openvswitch/types.h"

struct route_data_nexthop {
    struct ovs_list nexthop_node;

    sa_family_t family;
    struct in6_addr addr;
    char ifname[IFNAMSIZ]; /* Interface name. */
};

struct route_data {
    struct ovs_list nexthops;

    /* Copied from struct rtmsg. */
    unsigned char rtm_dst_len;
    unsigned char rtm_protocol;
    bool local;

    /* Extracted from Netlink attributes. */
    struct in6_addr rta_dst; /* 0 if missing. */
    struct in6_addr rta_prefsrc; /* 0 if missing. */
    uint32_t mark;
    uint32_t rta_table_id; /* 0 if missing. */
    uint32_t rta_priority; /* 0 if missing. */
};

/* A digested version of a route message sent down by the kernel to indicate
 * that a route has changed. */
struct route_table_msg {
    bool relevant;        /* Should this message be processed? */
    int nlmsg_type;       /* e.g. RTM_NEWROUTE, RTM_DELROUTE. */
    struct route_data rd; /* Data parsed from this message. */
};

uint64_t route_table_get_change_seq(void);
void route_table_init(void);
void route_table_run(void);
void route_table_wait(void);
bool route_table_fallback_lookup(const struct in6_addr *ip6_dst,
                                 char name[],
                                 struct in6_addr *gw6);
bool route_table_dump_one_table(
    uint32_t id,
    void (*handle_msg)(const struct route_table_msg *, void *),
    void *data);
#endif /* route-table.h */
