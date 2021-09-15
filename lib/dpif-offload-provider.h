/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef DPIF_OFFLOAD_PROVIDER_H
#define DPIF_OFFLOAD_PROVIDER_H

#include "dp-packet.h"
#include "netlink-protocol.h"
#include "openvswitch/packets.h"
#include "openvswitch/types.h"

struct dpif;

/* When offloading sample action, userspace creates a unique ID to map
 * sFlow action and tunnel info and passes this ID to datapath instead
 * of the sFlow info. Datapath will send this ID and sampled packet to
 * userspace. Using the ID, userspace can recover the sFlow info and send
 * sampled packet to the right sFlow monitoring host.
 */
struct dpif_sflow_attr {
    const struct nlattr *action;    /* SFlow action. */
    const struct nlattr *userdata;  /* Struct user_action_cookie. */
    struct flow_tnl *tunnel;        /* Tunnel info. */
    ovs_u128 ufid;                  /* Flow ufid. */
};

/* Parse the specific dpif message to sFlow. So OVS can process it. */
struct dpif_offload_sflow {
    struct dp_packet packet;            /* Packet data. */
    uint32_t iifindex;                  /* Input ifindex. */
    const struct dpif_sflow_attr *attr; /* SFlow attribute. */
};

/* Datapath interface offload structure, to be defined by each implementation
 * of a datapath interface.
 */
struct dpif_offload_api {
    /* Called when the dpif provider is registered and right after dpif
     * provider init function. */
    void (*init)(void);

    /* Free all dpif offload resources. */
    void (*destroy)(void);

    /* Arranges for the poll loop for an upcall handler to wake up when psample
     * has a message queued to be received. */
    void (*sflow_recv_wait)(void);

    /* Polls for an upcall from psample for an upcall handler.
     * Return 0 for success. */
    int (*sflow_recv)(struct dpif_offload_sflow *sflow);
};

void dpif_offload_sflow_recv_wait(const struct dpif *dpif);
int dpif_offload_sflow_recv(const struct dpif *dpif,
                            struct dpif_offload_sflow *sflow);

#ifdef __linux__
extern const struct dpif_offload_api dpif_offload_netlink;
#endif

#endif /* DPIF_OFFLOAD_PROVIDER_H */
