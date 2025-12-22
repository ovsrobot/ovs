/*
 * Copyright (c) 2009, 2015 Nicira, Inc.
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

#ifndef RTNETLINK_LINK_H
#define RTNETLINK_LINK_H 1

#include <stdbool.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>

#include "openvswitch/types.h"

struct ofpbuf;
struct nln_notifier;

/* These functions are Linux specific, so they should be used directly only by
 * Linux-specific code. */

/* Linux 2.6.35 introduced IFLA_STATS64 and rtnl_link_stats64.
 *
 * Tests for rtnl_link_stats64 don't seem to consistently work, e.g. on
 * 2.6.32-431.29.2.el6.x86_64 (see report at
 * https://mail.openvswitch.org/pipermail/ovs-dev/2014-October/291521.html).
 * Maybe if_link.h is not self-contained on those kernels.  It is easiest to
 * unconditionally define a replacement. */
#ifndef IFLA_STATS64
#define IFLA_STATS64 23
#endif
#define rtnl_link_stats64 rpl_rtnl_link_stats64
struct rtnl_link_stats64 {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_errors;
    uint64_t tx_errors;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint64_t multicast;
    uint64_t collisions;

    uint64_t rx_length_errors;
    uint64_t rx_over_errors;
    uint64_t rx_crc_errors;
    uint64_t rx_frame_errors;
    uint64_t rx_fifo_errors;
    uint64_t rx_missed_errors;

    uint64_t tx_aborted_errors;
    uint64_t tx_carrier_errors;
    uint64_t tx_fifo_errors;
    uint64_t tx_heartbeat_errors;
    uint64_t tx_window_errors;

    uint64_t rx_compressed;
    uint64_t tx_compressed;
};

/* A digested version of an rtnetlink_link message sent down by the kernel to
 * indicate that a network device's status (link or address) has been changed.
 */
struct rtnetlink_change {
    /* Copied from struct nlmsghdr. */
    int nlmsg_type;             /* e.g. RTM_NEWLINK, RTM_DELLINK. */

    /* Common attributes. */
    int if_index;               /* Index of network device. */
    const char *ifname;         /* Name of network device. */

    /* Network device link status. */
    int master_ifindex;         /* Ifindex of datapath master (0 if none). */
    int mtu;                    /* Current MTU. */
    struct eth_addr mac;
    unsigned int ifi_flags;     /* Flags of network device. */
    bool irrelevant;            /* Some events, notably wireless extensions,
                                   don't really indicate real netdev change
                                   that OVS should care about. */

    /* Network device address status. */
    /* xxx To be added when needed. */

    /* Link bonding info. */
    const char *primary;        /* Kind of primary (NULL if not primary). */
    const char *sub;            /* Kind of subordinate (NULL if not sub). */

    struct rtnl_link_stats64 *stats64; /* Optional storage for IFLA_STATS64. */
    struct rtnl_link_stats *stats;     /* Optional storage for IFLA_STATS. */
    enum {
        RTNL_LINK_NO_STATS = 0,
        RTNL_LINK_STATS64,
        RTNL_LINK_STATS,
    } stats_present;                    /* Flag indicating what kind of stats
                                           where present in the message. */
};

/* Function called to report that a netdev has changed.  'change' describes the
 * specific change.  It may be null if the buffer of change information
 * overflowed, in which case the function must assume that every device may
 * have changed.  'aux' is as specified in the call to
 * rtnetlink_notifier_register().  */
typedef
void rtnetlink_notify_func(const struct rtnetlink_change *change, int nsid,
                           void *aux);

bool rtnetlink_type_is_rtnlgrp_link(uint16_t type);
bool rtnetlink_type_is_rtnlgrp_addr(uint16_t type);
bool rtnetlink_parse(struct ofpbuf *buf, struct rtnetlink_change *change);
struct nln_notifier *
rtnetlink_notifier_create(rtnetlink_notify_func *, void *aux);
void rtnetlink_notifier_destroy(struct nln_notifier *);
void rtnetlink_run(void);
void rtnetlink_wait(void);
void rtnetlink_report_link(void);
#endif /* rtnetlink.h */
