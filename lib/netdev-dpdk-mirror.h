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

#ifndef NETDEV_DPDK_MIRROR_H
#define NETDEV_DPDK_MIRROR_H

#include "openvswitch/types.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
    mirror_data_find, /* find the mirror-data allocated */
    mirror_data_add, /* add a new mirror_param data int DB */
    mirror_data_rem, /* remove a mirror_param from the DB */
} mirror_data_op;

typedef int (*rte_mirror_scan_fn)(struct rte_mbuf *pkt, void *user_param);
typedef enum {
    mirror_port, /* port mirror */
    mirror_flow_mac, /* flow mirror according to source mac */
    mirror_flow_custom,  /* flow mirror according to a callback scn */
    mirror_invalid,      /* invalid mirror_type */
} rte_mirror_type;

typedef union {
    const struct rte_eth_rxtx_callback *pmd;
    struct rte_eth_rxtx_callback *direct;
} mirror_fn_cb;

struct mirror_param {
    uint16_t dst_port_id;
    uint16_t dst_vlan_id;
    rte_spinlock_t *locks;
    int n_src_queue;
    int n_dst_queue;
    struct rte_mbuf **pkt_buf;
    mirror_fn_cb *mirror_cb;
    unsigned int max_burst_size;
    rte_mirror_scan_fn custom_scan;
    rte_mirror_type mirror_type;
    unsigned int extra_data_size;
    void *extra_data; /* extra mirror parameter */
};

struct mirror_offload_port {
    uint32_t dev_id;
    struct mirror_param rx;
    struct mirror_param tx;
};

bool netdev_port_started(uint16_t port_id, uint32_t *num_tx_queue);
int netdev_get_portid_from_addr(const char *pci_addr_str, uint16_t *port_id);
int netdev_tunnel_port_setup(uint16_t portid, uint32_t *num_queue);

void netdev_mirror_data_proc(uint32_t dev_id, mirror_data_op op,
    int tx, struct mirror_param *in_param,
    struct mirror_offload_port **out_param);
void netdev_mirror_cb_set(struct mirror_param *data, uint16_t port_id,
    int pmd, int tx);
int netdev_eth_register_mirror(uint16_t src_port,
    struct mirror_param *param, int tx_cb);
int netdev_eth_unregister_mirror(uint16_t src_port, int tx_cb);

#ifdef  __cplusplus
}
#endif

#endif /* netdev-dpdk-mirror.h */
