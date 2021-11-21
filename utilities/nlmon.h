/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017
 * Nicira, Inc.
 * Copyright (c) 2016 Mellanox Technologies, Ltd.
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

#ifndef NLMON_H
#define NLMON_H 1

/*
 * Flower classifier:
 * This are a kernel definition of the TC flower attributes
 * since we are not sure that the kernel header are always available
 * added them here.
 * */

enum {
        TCA_FLOWER_UNSPEC,
        TCA_FLOWER_CLASSID,
        TCA_FLOWER_INDEV,
        TCA_FLOWER_ACT,
        TCA_FLOWER_KEY_ETH_DST,
        TCA_FLOWER_KEY_ETH_DST_MASK,
        TCA_FLOWER_KEY_ETH_SRC,
        TCA_FLOWER_KEY_ETH_SRC_MASK,
        TCA_FLOWER_KEY_ETH_TYPE,
        TCA_FLOWER_KEY_IP_PROTO,
        TCA_FLOWER_KEY_IPV4_SRC,
        TCA_FLOWER_KEY_IPV4_SRC_MASK,
        TCA_FLOWER_KEY_IPV4_DST,
        TCA_FLOWER_KEY_IPV4_DST_MASK,
        TCA_FLOWER_KEY_IPV6_SRC,
        TCA_FLOWER_KEY_IPV6_SRC_MASK,
        TCA_FLOWER_KEY_IPV6_DST,
        TCA_FLOWER_KEY_IPV6_DST_MASK,
        TCA_FLOWER_KEY_TCP_SRC,
        TCA_FLOWER_KEY_TCP_DST,
        TCA_FLOWER_KEY_UDP_SRC,
        TCA_FLOWER_KEY_UDP_DST,
        TCA_FLOWER_FLAGS,
        TCA_FLOWER_KEY_VLAN_ID,
        TCA_FLOWER_KEY_VLAN_PRIO,
        TCA_FLOWER_KEY_VLAN_ETH_TYPE,

        TCA_FLOWER_KEY_ENC_KEY_ID,
        TCA_FLOWER_KEY_ENC_IPV4_SRC,
        TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,
        TCA_FLOWER_KEY_ENC_IPV4_DST,
        TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,
        TCA_FLOWER_KEY_ENC_IPV6_SRC,
        TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK,
        TCA_FLOWER_KEY_ENC_IPV6_DST,
        TCA_FLOWER_KEY_ENC_IPV6_DST_MASK,

        TCA_FLOWER_KEY_TCP_SRC_MASK,
        TCA_FLOWER_KEY_TCP_DST_MASK,
        TCA_FLOWER_KEY_UDP_SRC_MASK,
        TCA_FLOWER_KEY_UDP_DST_MASK,
        TCA_FLOWER_KEY_SCTP_SRC_MASK,
        TCA_FLOWER_KEY_SCTP_DST_MASK,

        TCA_FLOWER_KEY_SCTP_SRC,
        TCA_FLOWER_KEY_SCTP_DST,

        TCA_FLOWER_KEY_ENC_UDP_SRC_PORT,
        TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK,
        TCA_FLOWER_KEY_ENC_UDP_DST_PORT,
        TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK,

        TCA_FLOWER_KEY_FLAGS,
        TCA_FLOWER_KEY_FLAGS_MASK,

        TCA_FLOWER_KEY_ICMPV4_CODE,
        TCA_FLOWER_KEY_ICMPV4_CODE_MASK,
        TCA_FLOWER_KEY_ICMPV4_TYPE,
        TCA_FLOWER_KEY_ICMPV4_TYPE_MASK,
        TCA_FLOWER_KEY_ICMPV6_CODE,
        TCA_FLOWER_KEY_ICMPV6_CODE_MASK,
        TCA_FLOWER_KEY_ICMPV6_TYPE,
        TCA_FLOWER_KEY_ICMPV6_TYPE_MASK,

        TCA_FLOWER_KEY_ARP_SIP,
        TCA_FLOWER_KEY_ARP_SIP_MASK,
        TCA_FLOWER_KEY_ARP_TIP,
        TCA_FLOWER_KEY_ARP_TIP_MASK,
        TCA_FLOWER_KEY_ARP_OP,
        TCA_FLOWER_KEY_ARP_OP_MASK,
        TCA_FLOWER_KEY_ARP_SHA,
        TCA_FLOWER_KEY_ARP_SHA_MASK,
        TCA_FLOWER_KEY_ARP_THA,
        TCA_FLOWER_KEY_ARP_THA_MASK,

        TCA_FLOWER_KEY_MPLS_TTL,
        TCA_FLOWER_KEY_MPLS_BOS,
        TCA_FLOWER_KEY_MPLS_TC,
        TCA_FLOWER_KEY_MPLS_LABEL,

        TCA_FLOWER_KEY_TCP_FLAGS,
        TCA_FLOWER_KEY_TCP_FLAGS_MASK,
        TCA_FLOWER_KEY_IP_TOS,
        TCA_FLOWER_KEY_IP_TOS_MASK,
        TCA_FLOWER_KEY_IP_TTL,
        TCA_FLOWER_KEY_IP_TTL_MASK,

        TCA_FLOWER_KEY_CVLAN_ID,
        TCA_FLOWER_KEY_CVLAN_PRIO,
        TCA_FLOWER_KEY_CVLAN_ETH_TYPE,

        TCA_FLOWER_KEY_ENC_IP_TOS,
        TCA_FLOWER_KEY_ENC_IP_TOS_MASK,
        TCA_FLOWER_KEY_ENC_IP_TTL,
        TCA_FLOWER_KEY_ENC_IP_TTL_MASK,

        TCA_FLOWER_KEY_ENC_OPTS,
        TCA_FLOWER_KEY_ENC_OPTS_MASK,

        TCA_FLOWER_IN_HW_COUNT,

        TCA_FLOWER_KEY_PORT_SRC_MIN,
        TCA_FLOWER_KEY_PORT_SRC_MAX,
        TCA_FLOWER_KEY_PORT_DST_MIN,
        TCA_FLOWER_KEY_PORT_DST_MAX,

        TCA_FLOWER_KEY_CT_STATE,
        TCA_FLOWER_KEY_CT_STATE_MASK,
        TCA_FLOWER_KEY_CT_ZONE,
        TCA_FLOWER_KEY_CT_ZONE_MASK,
        TCA_FLOWER_KEY_CT_MARK,
        TCA_FLOWER_KEY_CT_MARK_MASK,
        TCA_FLOWER_KEY_CT_LABELS,
        TCA_FLOWER_KEY_CT_LABELS_MASK,

        __TCA_FLOWER_MAX,
};

#define TCA_FLOWER_MAX (__TCA_FLOWER_MAX - 1)

/* tca flags definitions */
#define TCA_CLS_FLAGS_SKIP_HW   (1 << 0) /* don't offload filter to HW */
#define TCA_CLS_FLAGS_SKIP_SW   (1 << 1) /* don't use filter in SW */
#define TCA_CLS_FLAGS_IN_HW     (1 << 2) /* filter is offloaded to HW */
#define TCA_CLS_FLAGS_NOT_IN_HW (1 << 3) /* filter isn't offloaded to HW */

#define TC_H_MAJ_MASK (0xFFFF0000U)
#define TC_H_MIN_MASK (0x0000FFFFU)
#define TC_H_MAJ(h) ((h)&TC_H_MAJ_MASK)
#define TC_H_MIN(h) ((h)&TC_H_MIN_MASK)
#define TC_H_MAKE(maj,min) (((maj)&TC_H_MAJ_MASK)|((min)&TC_H_MIN_MASK))

#endif /* nlmon.h */
