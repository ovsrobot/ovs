/*
 * Copyright (c) 2025 Red Hat, Inc.
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

 #ifndef DPIF_OFFLOAD_RTE_FLOW_PRIVATE_H
 #define DPIF_OFFLOAD_RTE_FLOW_PRIVATE_H

/* Forward declarations of private structures. */
struct dpif_offload_rte_flow;

/* DPIF offload RTE flow implementation-specific functions.
 * These should only be used by the associated netdev offload provider,
 * i.e., netdev-offload-dpdk. */
unsigned int rte_flow_offload_thread_id(void);
struct netdev *dpif_offload_rte_get_netdev(struct dpif_offload_rte_flow *,
                                           odp_port_t port_no);
void dpif_offload_rte_traverse_ports(
    const struct dpif_offload_rte_flow *offload,
    bool (*cb)(struct netdev *, odp_port_t, void *), void *aux);

#endif /* DPIF_OFFLOAD_RTE_FLOW_PRIVATE_H */
