/*
 * Copyright (c) 2009, 2014 Nicira, Inc.
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

#undef NDEBUG

#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>

#include "netlink-notifier.h"
#include "ovstest.h"
#include "packets.h"
#include "route-table.h"

static void
test_lib_route_table_handle_msg(const struct route_table_msg *change,
                                void *data OVS_UNUSED)
{
    const struct route_data *rd = &change->rd;
    const struct route_data_nexthop *rdnh;
    struct ds rta_dst = DS_EMPTY_INITIALIZER;
    struct ds rta_prefsrc = DS_EMPTY_INITIALIZER;
    struct ds nexthop_addr = DS_EMPTY_INITIALIZER;

    ipv6_format_addr(&change->rd.rta_dst, &rta_dst);
    ipv6_format_addr(&change->rd.rta_prefsrc, &rta_prefsrc);
    printf("relevant: %d nlmsg_type: %d rtm_dst_len: %u rtm_protocol: %u "
           "local: %d rta_dst: %s rta_prefsrc: %s mark: %"PRIu32" "
           "rta_table_id: %"PRIu32" rta_priority: %"PRIu32"\n",
           change->relevant, change->nlmsg_type,
           rd->rtm_dst_len, rd->rtm_protocol, rd->local,
           ds_cstr(&rta_dst), ds_cstr(&rta_prefsrc),
           rd->mark, rd->rta_table_id, rd->rta_priority);

    LIST_FOR_EACH (rdnh, nexthop_node, &rd->nexthops) {
        ds_clear(&nexthop_addr);
        ipv6_format_addr(&rdnh->addr, &nexthop_addr);
        printf("    rta_dst: %s nexthop family: %d addr: %s ifname: %s\n",
               ds_cstr(&rta_dst), rdnh->family, ds_cstr(&nexthop_addr),
               rdnh->ifname);
    }
    ds_destroy(&rta_dst);
    ds_destroy(&rta_prefsrc);
    ds_destroy(&nexthop_addr);
}

static void
test_lib_route_table_dump(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    route_table_dump_one_table(RT_TABLE_MAIN,
                               test_lib_route_table_handle_msg,
                               NULL);
}

static void
test_lib_route_table_change(struct route_table_msg *change,
                            void *aux OVS_UNUSED)
{
    test_lib_route_table_handle_msg(change, NULL);
    route_data_destroy(&change->rd);
}

static struct nln *nln = NULL;
static struct nln_notifier *route_notifier = NULL;
static struct nln_notifier *route6_notifier = NULL;
static struct route_table_msg rtmsg;

static void
test_lib_route_table_monitor(int argc, char *argv[])
{
    if (argc != 2) {
        printf("usage: ovstest %s 'ip route add ...'\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const char *cmd = argv[1];

    nln = nln_create(NETLINK_ROUTE, route_table_parse, &rtmsg);

    route_notifier =
        nln_notifier_create(nln, RTNLGRP_IPV4_ROUTE,
                            (nln_notify_func *) test_lib_route_table_change,
                            NULL);
    route6_notifier =
        nln_notifier_create(nln, RTNLGRP_IPV6_ROUTE,
                            (nln_notify_func *) test_lib_route_table_change,
                            NULL);
    nln_run(nln);
    nln_wait(nln);
    int rc = system(cmd);
    if (rc) {
        exit(rc);
    }
    nln_run(nln);
}

OVSTEST_REGISTER("test-lib-route-table-dump", test_lib_route_table_dump);
OVSTEST_REGISTER("test-lib-route-table-monitor", test_lib_route_table_monitor);
