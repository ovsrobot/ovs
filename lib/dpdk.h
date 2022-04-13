/*
 * Copyright (c) 2016 Nicira, Inc.
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

#ifndef DPDK_H
#define DPDK_H

#include <stdbool.h>
#include <stdint.h>

#ifdef DPDK_NETDEV

#include <rte_config.h>
#include <rte_lcore.h>

#define NON_PMD_CORE_ID LCORE_ID_ANY

#else

#define NON_PMD_CORE_ID UINT32_MAX

#endif /* DPDK_NETDEV */

/*
 * need to reserve tons of extra space in the mbufs so we can align the
 * DMA addresses to 4KB.
 * The minimum mbuf size is limited to avoid scatter behaviour and drop in
 * performance for standard Ethernet MTU.
 */
#define ETHER_HDR_MAX_LEN           (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN \
                                     + (2 * VLAN_HEADER_LEN))
#define MTU_TO_FRAME_LEN(mtu)       ((mtu) + RTE_ETHER_HDR_LEN + \
                                     RTE_ETHER_CRC_LEN)
#define MTU_TO_MAX_FRAME_LEN(mtu)   ((mtu) + ETHER_HDR_MAX_LEN)
#define FRAME_LEN_TO_MTU(frame_len) ((frame_len)                    \
                                     - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN)
#define NETDEV_DPDK_MBUF_ALIGN      1024
#define NETDEV_DPDK_MAX_PKT_LEN     9728

struct smap;
struct ovsrec_open_vswitch;

void dpdk_init(const struct smap *ovs_other_config);
bool dpdk_attach_thread(unsigned cpu);
void dpdk_detach_thread(void);
const char *dpdk_get_vhost_sock_dir(void);
bool dpdk_vhost_iommu_enabled(void);
bool dpdk_vhost_postcopy_enabled(void);
bool dpdk_per_port_memory(void);
bool dpdk_available(void);
void print_dpdk_version(void);
void dpdk_status(const struct ovsrec_open_vswitch *);
uint32_t dpdk_buf_size(int mtu);

#endif /* dpdk.h */
