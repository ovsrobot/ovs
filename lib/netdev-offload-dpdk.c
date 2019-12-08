/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2019 Mellanox Technologies, Ltd.
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

#include <rte_flow.h>

#include "cmap.h"
#include "dpif-netdev.h"
#include "netdev-offload-provider.h"
#include "netdev-provider.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_dpdk);
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(100, 5);

/* Thread-safety
 * =============
 *
 * Below API is NOT thread safe in following terms:
 *
 *  - The caller must be sure that none of these functions will be called
 *    simultaneously.  Even for different 'netdev's.
 *
 *  - The caller must be sure that 'netdev' will not be destructed/deallocated.
 *
 *  - The caller must be sure that 'netdev' configuration will not be changed.
 *    For example, simultaneous call of 'netdev_reconfigure()' for the same
 *    'netdev' is forbidden.
 *
 * For current implementation all above restrictions could be fulfilled by
 * taking the datapath 'port_mutex' in lib/dpif-netdev.c.  */

/*
 * A mapping from ufid to dpdk rte_flow.
 */
static struct cmap ufid_to_rte_flow = CMAP_INITIALIZER;
static struct ovs_mutex ufid_map_mutex = OVS_MUTEX_INITIALIZER;

struct ufid_to_rte_flow_data {
    struct cmap_node node;
    ovs_u128 ufid;
    struct rte_flow *rte_flow;
};

/* Find rte_flow with @ufid. */
static struct rte_flow *
ufid_to_rte_flow_find(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data->rte_flow;
        }
    }

    return NULL;
}

static inline void
ufid_to_rte_flow_associate(const ovs_u128 *ufid,
                           struct rte_flow *rte_flow)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data = xzalloc(sizeof *data);

    /*
     * We should not simply overwrite an existing rte flow.
     * We should have deleted it first before re-adding it.
     * Thus, if following assert triggers, something is wrong:
     * the rte_flow is not destroyed.
     */
    ovs_assert(ufid_to_rte_flow_find(ufid) == NULL);

    data->ufid = *ufid;
    data->rte_flow = rte_flow;

    cmap_insert(&ufid_to_rte_flow,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

static inline void
ufid_to_rte_flow_disassociate(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            cmap_remove(&ufid_to_rte_flow,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            ovsrcu_postpone(free, data);
            return;
        }
    }

    VLOG_WARN("ufid "UUID_FMT" is not associated with an rte flow\n",
              UUID_ARGS((struct uuid *) ufid));
}

/*
 * To avoid individual xrealloc calls for each new element, a 'curent_max'
 * is used to keep track of current allocated number of elements. Starts
 * by 8 and doubles on each xrealloc call.
 */
struct flow_patterns {
    struct rte_flow_item *items;
    int cnt;
    int current_max;
};

struct flow_actions {
    struct rte_flow_action *actions;
    int cnt;
    int current_max;
};

static void
add_flow_pattern(struct flow_patterns *patterns, enum rte_flow_item_type type,
                 const void *spec, const void *mask)
{
    int cnt = patterns->cnt;

    if (cnt == 0) {
        patterns->current_max = 8;
        patterns->items = xcalloc(patterns->current_max,
                                  sizeof *patterns->items);
    } else if (cnt == patterns->current_max) {
        patterns->current_max *= 2;
        patterns->items = xrealloc(patterns->items, patterns->current_max *
                                   sizeof *patterns->items);
    }

    patterns->items[cnt].type = type;
    patterns->items[cnt].spec = spec;
    patterns->items[cnt].mask = mask;
    patterns->items[cnt].last = NULL;
    patterns->cnt++;
}

static void
add_flow_action(struct flow_actions *actions, enum rte_flow_action_type type,
                const void *conf)
{
    int cnt = actions->cnt;

    if (cnt == 0) {
        actions->current_max = 8;
        actions->actions = xcalloc(actions->current_max,
                                   sizeof *actions->actions);
    } else if (cnt == actions->current_max) {
        actions->current_max *= 2;
        actions->actions = xrealloc(actions->actions, actions->current_max *
                                    sizeof *actions->actions);
    }

    actions->actions[cnt].type = type;
    actions->actions[cnt].conf = conf;
    actions->cnt++;
}

static void
free_flow_patterns(struct flow_patterns *patterns)
{
    int i;

    for (i = 0; i < patterns->cnt; i++) {
        if (patterns->items[i].spec) {
            free((void *)patterns->items[i].spec);
        }
        if (patterns->items[i].mask) {
            free((void *)patterns->items[i].mask);
        }
    }
    free(patterns->items);
    patterns->items = NULL;
    patterns->cnt = 0;
}

static void
free_flow_actions(struct flow_actions *actions)
{
    int i;

    for (i = 0; i < actions->cnt; i++) {
        if (actions->actions[i].conf) {
            free((void *)actions->actions[i].conf);
        }
    }
    free(actions->actions);
    actions->actions = NULL;
    actions->cnt = 0;
}

static int
parse_flow_match(struct flow_patterns *patterns,
                 const struct match *match)
{
    uint8_t *next_proto_mask = NULL;
    uint8_t proto = 0;

    /* Eth */
    if (!eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        struct rte_flow_item_eth *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        memcpy(&spec->dst, &match->flow.dl_dst, sizeof spec->dst);
        memcpy(&spec->src, &match->flow.dl_src, sizeof spec->src);
        spec->type = match->flow.dl_type;

        memcpy(&mask->dst, &match->wc.masks.dl_dst, sizeof mask->dst);
        memcpy(&mask->src, &match->wc.masks.dl_src, sizeof mask->src);
        mask->type = match->wc.masks.dl_type;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, spec, mask);
    } else {
        /*
         * If user specifies a flow (like UDP flow) without L2 patterns,
         * OVS will at least set the dl_type. Normally, it's enough to
         * create an eth pattern just with it. Unluckily, some Intel's
         * NIC (such as XL710) doesn't support that. Below is a workaround,
         * which simply matches any L2 pkts.
         */
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);
    }

    /* VLAN */
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        struct rte_flow_item_vlan *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->tci = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        mask->tci = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* Match any protocols. */
        mask->inner_type = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VLAN, spec, mask);
    }

    /* IP v4 */
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        struct rte_flow_item_ipv4 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.type_of_service = match->flow.nw_tos;
        spec->hdr.time_to_live    = match->flow.nw_ttl;
        spec->hdr.next_proto_id   = match->flow.nw_proto;
        spec->hdr.src_addr        = match->flow.nw_src;
        spec->hdr.dst_addr        = match->flow.nw_dst;

        mask->hdr.type_of_service = match->wc.masks.nw_tos;
        mask->hdr.time_to_live    = match->wc.masks.nw_ttl;
        mask->hdr.next_proto_id   = match->wc.masks.nw_proto;
        mask->hdr.src_addr        = match->wc.masks.nw_src;
        mask->hdr.dst_addr        = match->wc.masks.nw_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4, spec, mask);

        /* Save proto for L4 protocol setup. */
        proto = spec->hdr.next_proto_id &
                mask->hdr.next_proto_id;
        next_proto_mask = &mask->hdr.next_proto_id;
    }

    if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        VLOG_DBG("L4 Protocol (%u) not supported", proto);
        return -1;
    }

    if ((match->wc.masks.tp_src && match->wc.masks.tp_src != OVS_BE16_MAX) ||
        (match->wc.masks.tp_dst && match->wc.masks.tp_dst != OVS_BE16_MAX)) {
        return -1;
    }

    if (proto == IPPROTO_TCP) {
        struct rte_flow_item_tcp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port  = match->flow.tp_src;
        spec->hdr.dst_port  = match->flow.tp_dst;
        spec->hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        spec->hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        mask->hdr.src_port  = match->wc.masks.tp_src;
        mask->hdr.dst_port  = match->wc.masks.tp_dst;
        mask->hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        mask->hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TCP, spec, mask);

        /* proto == TCP and ITEM_TYPE_TCP, thus no need for proto match. */
        if (next_proto_mask) {
            *next_proto_mask = 0;
        }
    } else if (proto == IPPROTO_UDP) {
        struct rte_flow_item_udp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP, spec, mask);

        /* proto == UDP and ITEM_TYPE_UDP, thus no need for proto match. */
        if (next_proto_mask) {
            *next_proto_mask = 0;
        }
    } else if (proto == IPPROTO_SCTP) {
        struct rte_flow_item_sctp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_SCTP, spec, mask);

        /* proto == SCTP and ITEM_TYPE_SCTP, thus no need for proto match. */
        if (next_proto_mask) {
            *next_proto_mask = 0;
        }
    } else if (proto == IPPROTO_ICMP) {
        struct rte_flow_item_icmp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.icmp_type = (uint8_t) ntohs(match->flow.tp_src);
        spec->hdr.icmp_code = (uint8_t) ntohs(match->flow.tp_dst);

        mask->hdr.icmp_type = (uint8_t) ntohs(match->wc.masks.tp_src);
        mask->hdr.icmp_code = (uint8_t) ntohs(match->wc.masks.tp_dst);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ICMP, spec, mask);

        /* proto == ICMP and ITEM_TYPE_ICMP, thus no need for proto match. */
        if (next_proto_mask) {
            *next_proto_mask = 0;
        }
    }

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    return 0;
}

static void
add_flow_mark_rss_actions(struct flow_actions *actions,
                          uint32_t flow_mark,
                          struct netdev *netdev)
{
    struct rte_flow_action_mark *mark;
    struct action_rss_data {
        struct rte_flow_action_rss conf;
        uint16_t queue[0];
    } *rss_data;
    int i;

    mark = xzalloc(sizeof *mark);

    mark->id = flow_mark;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);

    rss_data = xmalloc(sizeof *rss_data +
                       netdev_n_rxq(netdev) * sizeof rss_data->queue[0]);
    *rss_data = (struct action_rss_data) {
        .conf = (struct rte_flow_action_rss) {
            .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
            .level = 0,
            .types = 0,
            .queue_num = netdev_n_rxq(netdev),
            .queue = rss_data->queue,
            .key_len = 0,
            .key  = NULL
        },
    };

    /* Override queue array with default. */
    for (i = 0; i < netdev_n_rxq(netdev); i++) {
       rss_data->queue[i] = i;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, &rss_data->conf);

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
}

static struct rte_flow *
netdev_offload_dpdk_mark_rss(struct flow_patterns *patterns,
                             struct netdev *netdev,
                             uint32_t flow_mark)
{
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    const struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0
    };
    struct rte_flow_error error;
    struct rte_flow *flow;

    add_flow_mark_rss_actions(&actions, flow_mark, netdev);

    flow = netdev_dpdk_rte_flow_create(netdev, &flow_attr,
                                       patterns->items,
                                       actions.actions, &error);

    if (!flow) {
        VLOG_ERR("%s: Failed to create flow: %s (%u)\n",
                 netdev_get_name(netdev), error.message, error.type);
    }

    free_flow_actions(&actions);
    return flow;
}

static void
add_count_action(struct flow_actions *actions)
{
    struct rte_flow_action_count *count = xzalloc(sizeof *count);

    count->shared = 0;
    /* Each flow has a single count action, so no need of id */
    count->id = 0;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_COUNT, count);
}

static int
add_port_id_action(struct flow_actions *actions,
                   struct netdev *outdev)
{
    struct rte_flow_action_port_id *port_id = xzalloc(sizeof *port_id);
    int outdev_id;

    outdev_id = netdev_dpdk_get_port_id(outdev);
    if (outdev_id < 0) {
        return -1;
    }
    port_id->id = outdev_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_PORT_ID, port_id);
    return 0;
}

static int
add_output_action(struct netdev *netdev,
                  struct flow_actions *actions,
                  const struct nlattr *nla,
                  struct offload_info *info)
{
    struct netdev *outdev;
    odp_port_t port;
    int ret = 0;

    port = nl_attr_get_odp_port(nla);
    outdev = netdev_ports_get(port, info->dpif_class);
    if (outdev == NULL) {
        VLOG_DBG_RL(&error_rl,
                    "Cannot find netdev for odp port %d", port);
        return -1;
    }
    if (!netdev_flow_api_equals(netdev, outdev) ||
        add_port_id_action(actions, outdev)) {
        VLOG_DBG_RL(&error_rl,
                    "Output to %s cannot be offloaded",
                    netdev_get_name(outdev));
        ret = -1;
    }
    netdev_close(outdev);
    return ret;
}

struct set_action_info {
    const uint8_t *value, *mask;
    const uint8_t size;
    uint8_t *spec;
    const int attr;
};

static int
add_set_flow_action(struct flow_actions *actions,
                    struct set_action_info *sa_info_arr,
                    size_t sa_info_arr_size)
{
    int field, i;

    for (field = 0; field < sa_info_arr_size; field++) {
        if (sa_info_arr[field].mask) {
            /* DPDK does not support partially masked set actions. In such
             * case, fail the offload.
             */
            if (sa_info_arr[field].mask[0] != 0x00 &&
                sa_info_arr[field].mask[0] != 0xFF) {
                VLOG_DBG_RL(&error_rl,
                            "Partial mask is not supported");
                return -1;
            }

            for (i = 1; i < sa_info_arr[field].size; i++) {
                if (sa_info_arr[field].mask[i] !=
                    sa_info_arr[field].mask[i - 1]) {
                    VLOG_DBG_RL(&error_rl,
                                "Partial mask is not supported");
                    return -1;
                }
            }

            if (sa_info_arr[field].mask[0] == 0x00) {
                /* mask bytes are all 0 - no rewrite action required */
                continue;
            }
        }

        memcpy(sa_info_arr[field].spec, sa_info_arr[field].value,
               sa_info_arr[field].size);
        add_flow_action(actions, sa_info_arr[field].attr,
                        sa_info_arr[field].spec);
    }

    return 0;
}

/* Mask is at the midpoint of the data. */
#define get_mask(a, type) ((const type *)(const void *)(a + 1) + 1)

#define SA_INFO(_field, _spec, _attr) { \
    .value = (uint8_t *)&key->_field, \
    .mask = (masked) ? (uint8_t *)&mask->_field : NULL, \
    .size = sizeof key->_field, \
    .spec = (uint8_t *)&_spec, \
    .attr = _attr }

static int
parse_set_actions(struct flow_actions *actions,
                  const struct nlattr *set_actions,
                  const size_t set_actions_len,
                  bool masked)
{
    const struct nlattr *sa;
    unsigned int sleft;

    NL_ATTR_FOR_EACH_UNSAFE (sa, sleft, set_actions, set_actions_len) {
        if (nl_attr_type(sa) == OVS_KEY_ATTR_ETHERNET) {
            const struct ovs_key_ethernet *key = nl_attr_get(sa);
            const struct ovs_key_ethernet *mask = masked ?
                get_mask(sa, struct ovs_key_ethernet) : NULL;
            struct rte_flow_action_set_mac *src = xzalloc(sizeof *src);
            struct rte_flow_action_set_mac *dst = xzalloc(sizeof *dst);
            struct set_action_info sa_info_arr[] = {
                SA_INFO(eth_src, src->mac_addr[0],
                        RTE_FLOW_ACTION_TYPE_SET_MAC_SRC),
                SA_INFO(eth_dst, dst->mac_addr[0],
                        RTE_FLOW_ACTION_TYPE_SET_MAC_DST),
            };

            if (add_set_flow_action(actions, sa_info_arr,
                                    ARRAY_SIZE(sa_info_arr))) {
                return -1;
            }
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_IPV4) {
            const struct ovs_key_ipv4 *key = nl_attr_get(sa);
            const struct ovs_key_ipv4 *mask = masked ?
                get_mask(sa, struct ovs_key_ipv4) : NULL;
            struct rte_flow_action_set_ipv4 *src = xzalloc(sizeof *src);
            struct rte_flow_action_set_ipv4 *dst = xzalloc(sizeof *dst);
            struct rte_flow_action_set_ttl *ttl = xzalloc(sizeof *ttl);
            struct set_action_info sa_info_arr[] = {
                SA_INFO(ipv4_src, src->ipv4_addr,
                        RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC),
                SA_INFO(ipv4_dst, dst->ipv4_addr,
                        RTE_FLOW_ACTION_TYPE_SET_IPV4_DST),
                SA_INFO(ipv4_ttl, ttl->ttl_value,
                        RTE_FLOW_ACTION_TYPE_SET_TTL),
            };

            if (mask && (mask->ipv4_proto || mask->ipv4_tos ||
                mask->ipv4_frag)) {
                VLOG_DBG_RL(&error_rl, "Unsupported IPv4 set action");
                return -1;
            }

            if (add_set_flow_action(actions, sa_info_arr,
                                    ARRAY_SIZE(sa_info_arr))) {
                return -1;
            }
        } else {
            VLOG_DBG_RL(&error_rl,
                        "Unsupported set action type=%d", nl_attr_type(sa));
            return -1;
        }
    }

    return 0;
}

static int
parse_flow_actions(struct netdev *netdev,
                   struct flow_actions *actions,
                   struct nlattr *nl_actions,
                   size_t nl_actions_len,
                   struct offload_info *info)
{
    struct nlattr *nla;
    size_t left;

    add_count_action(actions);
    NL_ATTR_FOR_EACH_UNSAFE (nla, left, nl_actions, nl_actions_len) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            if (!(left <= NLA_ALIGN(nla->nla_len)) ||
                add_output_action(netdev, actions, nla, info )) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_SET ||
                   nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED) {
            const struct nlattr *set_actions = nl_attr_get(nla);
            const size_t set_actions_len = nl_attr_get_size(nla);
            bool masked = nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED;

            if (parse_set_actions(actions, set_actions, set_actions_len,
                                  masked)) {
                return -1;
            }
        } else {
            VLOG_DBG_RL(&error_rl,
                        "Unsupported action type %d", nl_attr_type(nla));
            return -1;
        }
    }

    if (nl_actions_len == 0) {
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_DROP, NULL);
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    return 0;
}

static struct rte_flow *
netdev_offload_dpdk_actions(struct netdev *netdev,
                            struct flow_patterns *patterns,
                            struct nlattr *nl_actions,
                            size_t actions_len,
                            struct offload_info *info)
{
    const struct rte_flow_attr flow_attr = { .ingress = 1, .transfer = 1 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    int ret;

    ret = parse_flow_actions(netdev, &actions, nl_actions, actions_len, info);
    if (ret) {
        goto out;
    }
    flow = netdev_dpdk_rte_flow_create(netdev, &flow_attr, patterns->items,
                                       actions.actions, &error);
    if (!flow) {
        VLOG_ERR("%s: Failed to create flow: %s (%u)\n",
                 netdev_get_name(netdev), error.message, error.type);
    }
    if (flow && info->actions_offloaded) {
        *info->actions_offloaded = true;
    }
out:
    free_flow_actions(&actions);
    return flow;
}

static int
netdev_offload_dpdk_add_flow(struct netdev *netdev,
                             const struct match *match,
                             struct nlattr *nl_actions OVS_UNUSED,
                             size_t actions_len OVS_UNUSED,
                             const ovs_u128 *ufid,
                             struct offload_info *info)
{
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct rte_flow *flow;
    int ret = 0;

    ret = parse_flow_match(&patterns, match);
    if (ret) {
        ret = -1;
        goto out;
    }

    flow = netdev_offload_dpdk_actions(netdev, &patterns, nl_actions,
                                       actions_len, info);
    if (!flow) {
        /* if we failed to offload the rule actions fallback to mark rss
         * actions.
         */
        flow = netdev_offload_dpdk_mark_rss(&patterns, netdev, info->flow_mark);
    }

    if (!flow) {
        ret = -1;
        goto out;
    }
    ufid_to_rte_flow_associate(ufid, flow);
    VLOG_DBG("%s: installed flow %p by ufid "UUID_FMT"\n",
             netdev_get_name(netdev), flow, UUID_ARGS((struct uuid *)ufid));

out:
    free_flow_patterns(&patterns);
    return ret;
}

/*
 * Check if any unsupported flow patterns are specified.
 */
static int
netdev_offload_dpdk_validate_flow(const struct match *match)
{
    struct match match_zero_wc;
    const struct flow *masks = &match->wc.masks;

    /* Create a wc-zeroed version of flow. */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    if (!is_all_zeros(&match_zero_wc.flow.tunnel,
                      sizeof match_zero_wc.flow.tunnel)) {
        goto err;
    }

    if (masks->metadata || masks->skb_priority ||
        masks->pkt_mark || masks->dp_hash) {
        goto err;
    }

    /* recirc id must be zero. */
    if (match_zero_wc.flow.recirc_id) {
        goto err;
    }

    if (masks->ct_state || masks->ct_nw_proto ||
        masks->ct_zone  || masks->ct_mark     ||
        !ovs_u128_is_zero(masks->ct_label)) {
        goto err;
    }

    if (masks->conj_id || masks->actset_output) {
        goto err;
    }

    /* Unsupported L2. */
    if (!is_all_zeros(masks->mpls_lse, sizeof masks->mpls_lse)) {
        goto err;
    }

    /* Unsupported L3. */
    if (masks->ipv6_label || masks->ct_nw_src || masks->ct_nw_dst     ||
        !is_all_zeros(&masks->ipv6_src,    sizeof masks->ipv6_src)    ||
        !is_all_zeros(&masks->ipv6_dst,    sizeof masks->ipv6_dst)    ||
        !is_all_zeros(&masks->ct_ipv6_src, sizeof masks->ct_ipv6_src) ||
        !is_all_zeros(&masks->ct_ipv6_dst, sizeof masks->ct_ipv6_dst) ||
        !is_all_zeros(&masks->nd_target,   sizeof masks->nd_target)   ||
        !is_all_zeros(&masks->nsh,         sizeof masks->nsh)         ||
        !is_all_zeros(&masks->arp_sha,     sizeof masks->arp_sha)     ||
        !is_all_zeros(&masks->arp_tha,     sizeof masks->arp_tha)) {
        goto err;
    }

    /* If fragmented, then don't HW accelerate - for now. */
    if (match_zero_wc.flow.nw_frag) {
        goto err;
    }

    /* Unsupported L4. */
    if (masks->igmp_group_ip4 || masks->ct_tp_src || masks->ct_tp_dst) {
        goto err;
    }

    return 0;

err:
    VLOG_ERR("cannot HW accelerate this flow due to unsupported protocols");
    return -1;
}

static int
netdev_offload_dpdk_destroy_flow(struct netdev *netdev,
                                 const ovs_u128 *ufid,
                                 struct rte_flow *rte_flow)
{
    struct rte_flow_error error;
    int ret;

    ovs_mutex_lock(&ufid_map_mutex);

    ret = netdev_dpdk_rte_flow_destroy(netdev, rte_flow, &error);
    if (ret == 0) {
        ufid_to_rte_flow_disassociate(ufid);
        VLOG_DBG("%s: removed rte flow %p associated with ufid " UUID_FMT "\n",
                 netdev_get_name(netdev), rte_flow,
                 UUID_ARGS((struct uuid *)ufid));
    } else {
        VLOG_ERR("%s: Failed to destroy flow: %s (%u)\n",
                 netdev_get_name(netdev), error.message, error.type);
    }

    ovs_mutex_unlock(&ufid_map_mutex);
    return ret;
}

static int
netdev_offload_dpdk_flow_put(struct netdev *netdev, struct match *match,
                             struct nlattr *actions, size_t actions_len,
                             const ovs_u128 *ufid, struct offload_info *info,
                             struct dpif_flow_stats *stats)
{
    struct rte_flow *rte_flow;
    int ret;

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    rte_flow = ufid_to_rte_flow_find(ufid);
    if (rte_flow) {
        ret = netdev_offload_dpdk_destroy_flow(netdev, ufid, rte_flow);
        if (ret < 0) {
            return ret;
        }
    }

    ret = netdev_offload_dpdk_validate_flow(match);
    if (ret < 0) {
        return ret;
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return netdev_offload_dpdk_add_flow(netdev, match, actions,
                                        actions_len, ufid, info);
}

static int
netdev_offload_dpdk_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats)
{
    struct rte_flow *rte_flow = ufid_to_rte_flow_find(ufid);

    if (!rte_flow) {
        return -1;
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return netdev_offload_dpdk_destroy_flow(netdev, ufid, rte_flow);
}

static int
netdev_offload_dpdk_init_flow_api(struct netdev *netdev)
{
    return netdev_dpdk_flow_api_supported(netdev) ? 0 : EOPNOTSUPP;
}

static int
netdev_offload_dpdk_flow_get(struct netdev *netdev,
                             struct match *match OVS_UNUSED,
                             struct nlattr **actions OVS_UNUSED,
                             const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats,
                             struct dpif_flow_attrs *attrs OVS_UNUSED,
                             struct ofpbuf *buf OVS_UNUSED)
{
    struct rte_flow_query_count query = { .reset = 1 };
    struct rte_flow_error error;
    struct rte_flow *rte_flow;
    int ret = 0;

    ovs_mutex_lock(&ufid_map_mutex);
    rte_flow = ufid_to_rte_flow_find(ufid);
    if (!rte_flow) {
        ret = -1;
        goto out;
    }

    memset(stats, 0, sizeof *stats);
    ret = netdev_dpdk_rte_flow_query(netdev, rte_flow, &query, &error);
    if (ret) {
        VLOG_DBG_RL(&error_rl,
                    "%s: Failed to query ufid "UUID_FMT" flow: %p\n",
                    netdev_get_name(netdev), UUID_ARGS((struct uuid *)ufid),
                    rte_flow);
        ret = -1;
        goto out;
    }
    stats->n_packets += (query.hits_set) ? query.hits : 0;
    stats->n_bytes += (query.bytes_set) ? query.bytes : 0;

out:
    ovs_mutex_unlock(&ufid_map_mutex);
    return ret;
}

const struct netdev_flow_api netdev_offload_dpdk = {
    .type = "dpdk_flow_api",
    .flow_put = netdev_offload_dpdk_flow_put,
    .flow_del = netdev_offload_dpdk_flow_del,
    .init_flow_api = netdev_offload_dpdk_init_flow_api,
    .flow_get = netdev_offload_dpdk_flow_get,
};
