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
#include <rte_ethdev.h>

#include "netdev-dpdk-mirror.h"
#include "openvswitch/vlog.h"
#include "openvswitch/dynamic-string.h"
#include "util.h"

#define MAC_ADDR_MAP           0x0000FFFFFFFFFFFFULL
#define is_mac_addr_match(a,b) (((a^b)&MAC_ADDR_MAP) == 0)
#define INIT_MIRROR_DB_SIZE    8
#define INVALID_DEVICE_ID      0xFFFFFFFF

VLOG_DEFINE_THIS_MODULE(netdev_dpdk_mirror);

/* port/flow mirror database management routines */
/*
 * The below API is for port/flow mirror offloading which uses a different DPDK
 * interface as rte-flow.
 */
static int mirror_port_db_size = 0;
static int mirror_port_used = 0;
static struct mirror_offload_port *mirror_port_db = NULL;

static void
netdev_mirror_db_init(struct mirror_offload_port *db, int size)
{
    int i;

    for (i = 0; i < size; i++) {
        db[i].dev_id = INVALID_DEVICE_ID;
        memset(&db[i].rx, 0, sizeof(struct mirror_param));
        memset(&db[i].tx, 0, sizeof(struct mirror_param));
    }
}

/* Double the db size when it runs out of space */
static int
netdev_mirror_db_resize(void)
{
    int new_size = mirror_port_db_size << 1;
    struct mirror_offload_port *new_db = xmalloc(
        sizeof(struct mirror_offload_port)*new_size);

    memcpy(new_db, mirror_port_db, sizeof(struct mirror_offload_port)
        *mirror_port_db_size);
    netdev_mirror_db_init(&new_db[mirror_port_db_size], mirror_port_db_size);
    mirror_port_db_size = new_size;
    mirror_port_db = new_db;

    return 0;
}


static struct mirror_offload_port*
netdev_mirror_data_find(uint32_t dev_id)
{
    int i;

    if (mirror_port_db == NULL) {
        return NULL;
    }

    for (i = 0; i < mirror_port_db_size; i++) {
        if (dev_id == mirror_port_db[i].dev_id) {
            return &mirror_port_db[i];
        }
    }
    return NULL;
}

static struct mirror_offload_port*
netdev_mirror_data_add(uint32_t dev_id, int tx,
    struct mirror_param *new_param)
{
    struct mirror_offload_port *target = NULL;
    int i;

    if (!mirror_port_db) {
        mirror_port_db_size = INIT_MIRROR_DB_SIZE;
        mirror_port_db = xmalloc(sizeof(struct mirror_offload_port)*
            mirror_port_db_size);
        netdev_mirror_db_init(mirror_port_db, mirror_port_db_size);
    }
    target = netdev_mirror_data_find(dev_id);
    if (target) {
        if (tx) {
            if (target->tx.mirror_cb) {
                VLOG_ERR("Attempt to add ingress mirror offloading"
                    " on port, %d, while one is outstanding\n", dev_id);
                return target;
            }

            memcpy(&target->tx, new_param, sizeof(*new_param));
        } else {
            if (target->rx.mirror_cb) {
                VLOG_ERR("Attempt to add egress mirror offloading"
                    " on port, %d, while one is outstanding\n", dev_id);
                return target;
            }

            memcpy(&target->rx, new_param, sizeof(struct mirror_param));
        }
    } else {
        struct mirror_param *param;
        /* find an unused spot on db */
        for (i = 0; i < mirror_port_db_size; i++) {
            if (mirror_port_db[i].dev_id == INVALID_DEVICE_ID) {
                break;
            }
        }
        if (i == mirror_port_db_size && netdev_mirror_db_resize()) {
                return NULL;
        }

        param = tx ? &mirror_port_db[i].tx : &mirror_port_db[i].rx;
        memcpy(param, new_param, sizeof(struct mirror_param));

        target = &mirror_port_db[i];
        target->dev_id = dev_id;
        mirror_port_used ++;
    }
    return target;
}

static void
netdev_mirror_data_remove(uint32_t dev_id, int tx) {
    struct mirror_offload_port *target = netdev_mirror_data_find(dev_id);

    if (!target) {
        VLOG_ERR("Attempt to remove unsaved port, %d, %s callback\n",
        dev_id, tx?"tx": "rx");
    }

    if (tx) {
        memset(&target->tx, 0, sizeof(struct mirror_param));
    } else {
        memset(&target->rx, 0, sizeof(struct mirror_param));
    }

    if ((target->rx.mirror_cb == NULL) &&
        (target->tx.mirror_cb == NULL)) {
        target->dev_id = INVALID_DEVICE_ID;
        mirror_port_used --;
        /* release port mirror db memory when there
         * is no outstanding port mirror offloading
         * configuration
         */
        if (mirror_port_used == 0) {
            free(mirror_port_db);
            mirror_port_db = NULL;
            mirror_port_db_size = 0;
        }
    }
}

void
netdev_mirror_data_proc(uint32_t dev_id, mirror_data_op op,
    int tx, struct mirror_param *in_param,
    struct mirror_offload_port **out_param)
{
    switch (op) {
    case mirror_data_find:
        *out_param = netdev_mirror_data_find(dev_id);
        break;
    case mirror_data_add:
        *out_param = netdev_mirror_data_add(dev_id, tx, in_param);
        break;
    case mirror_data_rem:
        netdev_mirror_data_remove(dev_id, tx);
        break;
    }
}

/* port/flow mirror traffic processors */
static inline uint16_t
netdev_custom_mirror_offload_cb(uint16_t qidx, struct rte_mbuf **pkts,
    uint16_t nb_pkts, void *user_params)
{
    struct mirror_param *data = user_params;
    uint16_t i, dst_qidx, match_count = 0;
    uint16_t pkt_trans;
    uint16_t dst_port_id = data->dst_port_id;
    uint16_t dst_vlan_id = data->dst_vlan_id;
    struct rte_mbuf **pkt_buf = &data->pkt_buf[qidx * data->max_burst_size];

    if (nb_pkts == 0) {
        return 0;
    }

    if (nb_pkts > data->max_burst_size) {
        VLOG_ERR("Per-flow batch size, %d, exceeds maximum limit\n", nb_pkts);
        return 0;
    }

    for (i = 0; i < nb_pkts; i++) {
        if (data->custom_scan(pkts[i], user_params)) {
            pkt_buf[match_count] = pkts[i];
            pkt_buf[match_count]->ol_flags |= PKT_TX_VLAN_PKT;
            pkt_buf[match_count]->vlan_tci = dst_vlan_id;
            rte_mbuf_refcnt_update(pkt_buf[match_count], 1);
            match_count++;
        }
    }

    dst_qidx = (data->n_dst_queue > qidx)?qidx:(data->n_dst_queue -1);

    rte_spinlock_lock(&data->locks[dst_qidx]);
    pkt_trans = rte_eth_tx_burst(dst_port_id, dst_qidx, pkt_buf, match_count);
    rte_spinlock_unlock(&data->locks[dst_qidx]);

    for (i = 0; i < match_count; i++) {
        pkt_buf[i]->ol_flags &= ~PKT_TX_VLAN_PKT;
    }

    while (unlikely (pkt_trans < match_count)) {
        rte_pktmbuf_free(pkt_buf[pkt_trans]);
        pkt_trans++;
    }

    return nb_pkts;
}

static inline uint16_t
netdev_flow_mirror_offload_cb(uint16_t qidx, struct rte_mbuf **pkts,
    uint16_t nb_pkts, void *user_params, uint32_t offset)
{
    struct mirror_param *data = user_params;
    uint16_t i, dst_qidx, match_count = 0;
    uint16_t pkt_trans;
    uint16_t dst_port_id = data->dst_port_id;
    uint16_t dst_vlan_id = data->dst_vlan_id;
    uint64_t target_addr = *(uint64_t *) data->extra_data;
    struct rte_mbuf **pkt_buf = &data->pkt_buf[qidx * data->max_burst_size];

    if (nb_pkts == 0) {
        return 0;
    }

    if (nb_pkts > data->max_burst_size) {
        VLOG_ERR("Per-flow batch size, %d, exceeds maximum limit\n", nb_pkts);
        return 0;
    }

    for (i = 0; i < nb_pkts; i++) {
        uint64_t *dst_mac_addr =
            rte_pktmbuf_mtod_offset(pkts[i], void *, offset);
        if (is_mac_addr_match(target_addr, (*dst_mac_addr))) {
            pkt_buf[match_count] = pkts[i];
            pkt_buf[match_count]->ol_flags |= PKT_TX_VLAN_PKT;
            pkt_buf[match_count]->vlan_tci = dst_vlan_id;
            rte_mbuf_refcnt_update(pkt_buf[match_count], 1);
            match_count ++;
        }
    }

    dst_qidx = (data->n_dst_queue > qidx) ? qidx : (data->n_dst_queue -1);

    rte_spinlock_lock(&data->locks[dst_qidx]);
    pkt_trans = rte_eth_tx_burst(dst_port_id, dst_qidx, pkt_buf, match_count);
    rte_spinlock_unlock(&data->locks[dst_qidx]);

    for (i = 0; i < match_count; i++) {
        pkt_buf[i]->ol_flags &= ~PKT_TX_VLAN_PKT;
    }

    while (unlikely (pkt_trans < match_count)) {
        rte_pktmbuf_free(pkt_buf[pkt_trans]);
        pkt_trans++;
    }

    return nb_pkts;
}

static inline uint16_t
netdev_port_mirror_offload_cb(uint16_t qidx, struct rte_mbuf **pkts,
    uint16_t nb_pkts, void *user_params)
{
    struct mirror_param *data = user_params;
    uint16_t i, dst_qidx;
    uint16_t pkt_trans;
    uint16_t dst_port_id = data->dst_port_id;
    uint16_t dst_vlan_id = data->dst_vlan_id;

    if (nb_pkts == 0) {
        return 0;
    }

    for (i = 0; i < nb_pkts; i++) {
        pkts[i]->ol_flags |= PKT_TX_VLAN_PKT;
        pkts[i]->vlan_tci = dst_vlan_id;
        rte_mbuf_refcnt_update(pkts[i], 1);
    }

    dst_qidx = (data->n_dst_queue > qidx) ? qidx : (data->n_dst_queue -1);

    rte_spinlock_lock(&data->locks[dst_qidx]);
    pkt_trans = rte_eth_tx_burst(dst_port_id, dst_qidx, pkts, nb_pkts);
    rte_spinlock_unlock(&data->locks[dst_qidx]);

    for (i = 0; i < nb_pkts; i++) {
        pkts[i]->ol_flags &= ~PKT_TX_VLAN_PKT;
    }

    while (unlikely (pkt_trans < nb_pkts)) {
        rte_pktmbuf_free(pkts[pkt_trans]);
        pkt_trans++;
    }

    return nb_pkts;
}

static inline uint16_t
netdev_rx_custom_mirror_offload_cb(uint16_t port_id OVS_UNUSED,
    uint16_t qidx, struct rte_mbuf **pkts, uint16_t nb_pkts,
    uint16_t maxi_pkts OVS_UNUSED, void *user_params)
{
    return netdev_custom_mirror_offload_cb(qidx, pkts, nb_pkts, user_params);
}

static inline uint16_t
netdev_tx_custom_mirror_offload_cb(uint16_t port_id OVS_UNUSED,
    uint16_t qidx, struct rte_mbuf **pkts, uint16_t nb_pkts,
    void *user_params)
{
    return netdev_custom_mirror_offload_cb(qidx, pkts, nb_pkts, user_params);
}

static inline uint16_t
netdev_rx_flow_mirror_offload_cb(uint16_t port_id OVS_UNUSED,
    uint16_t qidx, struct rte_mbuf **pkts, uint16_t nb_pkts,
    uint16_t maxi_pkts OVS_UNUSED, void *user_params)
{
    return netdev_flow_mirror_offload_cb(qidx, pkts, nb_pkts, user_params, 0);
}

static inline uint16_t
netdev_tx_flow_mirror_offload_cb(uint16_t port_id OVS_UNUSED,
    uint16_t qidx, struct rte_mbuf **pkts, uint16_t nb_pkts,
    void *user_params)
{
    return netdev_flow_mirror_offload_cb(qidx, pkts, nb_pkts, user_params, 6);
}

static inline uint16_t
netdev_rx_port_mirror_offload_cb(uint16_t port_id OVS_UNUSED,
    uint16_t qidx, struct rte_mbuf **pkts, uint16_t nb_pkts,
    uint16_t max_pkts OVS_UNUSED, void *user_params)
{
    return netdev_port_mirror_offload_cb(qidx, pkts, nb_pkts, user_params);
}

static inline uint16_t
netdev_tx_port_mirror_offload_cb(uint16_t port_id OVS_UNUSED,
    uint16_t qidx, struct rte_mbuf **pkts, uint16_t nb_pkts,
    void *user_params)
{
    return netdev_port_mirror_offload_cb(qidx, pkts, nb_pkts, user_params);
}

static rte_rx_callback_fn
netdev_mirror_rx_cb(rte_mirror_type mirror_type)
{
    switch (mirror_type) {
    case mirror_port:
        return netdev_rx_port_mirror_offload_cb;
    case mirror_flow_mac:
        return netdev_rx_flow_mirror_offload_cb;
    case mirror_flow_custom:
        return netdev_rx_custom_mirror_offload_cb;
    case mirror_invalid:
        return NULL;
    }
    VLOG_ERR("Un-supported mirror type\n");
    return NULL;
}

static rte_tx_callback_fn
netdev_mirror_tx_cb(rte_mirror_type mirror_type)
{
    switch (mirror_type) {
    case mirror_port:
        return netdev_tx_port_mirror_offload_cb;
    case mirror_flow_mac:
        return netdev_tx_flow_mirror_offload_cb;
        break;
    case mirror_flow_custom:
        return netdev_tx_custom_mirror_offload_cb;
    case mirror_invalid:
        return NULL;
    }
    VLOG_ERR("Un-supported mirror type\n");
    return NULL;
}

void
netdev_mirror_cb_set(struct mirror_param *data, uint16_t port_id,
    int pmd_cb, int tx)
{
    unsigned int qid;

    data->pkt_buf = NULL;
    if (data->extra_data_size) {
        data->pkt_buf = xmalloc(sizeof(mirror_fn_cb)*data->max_burst_size *
            data->n_src_queue);
    }

    data->mirror_cb = xmalloc(sizeof(struct rte_eth_rxtx_callback *)
        * data->n_src_queue);
    for (qid = 0; qid < data->n_src_queue; qid++) {
        if (pmd_cb) {
            if (tx) {
                data->mirror_cb[qid].pmd = rte_eth_add_tx_callback(port_id,
                    qid, netdev_mirror_tx_cb(data->mirror_type), data);
            } else {
                data->mirror_cb[qid].pmd = rte_eth_add_rx_callback(port_id,
                    qid, netdev_mirror_rx_cb(data->mirror_type), data);
            }
        } else {
            struct rte_eth_rxtx_callback *rxtx_cb =
                xmalloc(sizeof(struct rte_eth_rxtx_callback));

            data->mirror_cb[qid].direct = rxtx_cb;
            rxtx_cb->next = NULL;
            rxtx_cb->param = data;

            if (tx) {
                rxtx_cb->fn.tx = netdev_mirror_tx_cb(data->mirror_type);
            } else {
                rxtx_cb->fn.rx = netdev_mirror_rx_cb(data->mirror_type);
            }
        }
    }
}

/* port/flow mirroring device (port) register/un-registe routines */
int
netdev_eth_register_mirror(uint16_t src_port, struct mirror_param *param,
    int tx_cb)
{
    struct mirror_offload_port *port_info = NULL;
    struct mirror_param *data;

    netdev_mirror_data_proc(src_port, mirror_data_add, tx_cb, param,
        &port_info);
    if (!port_info) {
        return -1;
    }

    data = tx_cb ? &port_info->tx : &port_info->rx;
    netdev_mirror_cb_set(data, src_port, 1, tx_cb);

    return 0;
}

int
netdev_eth_unregister_mirror(uint16_t src_port, int tx_cb)
{
    /* release both cb and pkt_buf */
    unsigned int i;
    struct mirror_offload_port *port_info = NULL;
    struct mirror_param *data;

    netdev_mirror_data_proc(src_port, mirror_data_find, tx_cb, NULL,
        &port_info);
    if (port_info == NULL) {
        VLOG_ERR("Source port %d is not on outstanding port mirror db\n",
            src_port);
        return -1;
    }
    data = tx_cb ? &port_info->tx : &port_info->rx;

    for (i = 0; i < data->n_src_queue; i++) {
        if (data->mirror_cb[i].pmd) {
            if (tx_cb) {
                rte_eth_remove_tx_callback(src_port, i,
                    data->mirror_cb[i].pmd);
            } else {
                rte_eth_remove_rx_callback(src_port, i,
                    data->mirror_cb[i].pmd);
            }
        }
        data->mirror_cb[i].pmd = NULL;
    }
    free(data->mirror_cb);

    if (data->pkt_buf) {
        free(data->pkt_buf);
        data->pkt_buf = NULL;
    }

    if (data->extra_data) {
        free(data->extra_data);
        data->extra_data = NULL;
        data->extra_data_size = 0;
    }

    netdev_mirror_data_proc(src_port, mirror_data_rem, tx_cb, NULL, NULL);
    return 0;
}
