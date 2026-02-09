/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

#ifndef OVS_DOCA_H
#define OVS_DOCA_H

#include <config.h>

struct ovsrec_open_vswitch;
struct smap;

#ifdef DOCA_NETDEV

#include <doca_dev.h>
#include <doca_flow.h>

#include "dp-packet.h"
#include "ovs-thread.h"
#include "util.h"

#define AUX_QUEUE 0
#define OVS_DOCA_MAX_OFFLOAD_QUEUES 1
#define OVS_DOCA_QUEUE_DEPTH 32
#define OVS_DOCA_ENTRY_PROCESS_TIMEOUT_US 1000

/* Estimated maximum number of megaflows */
#define OVS_DOCA_MAX_MEGAFLOWS_COUNTERS (1 << 19)

#define OVS_DOCA_MAX_PIPE_NAME_LEN 128

struct netdev_doca_esw_ctx;

struct ovs_doca_offload_queue {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        unsigned int n_waiting_entries;
    );
};

struct ovs_doca_flow_actions {
    struct doca_flow_actions d;
    uint32_t mark;
};
BUILD_ASSERT_DECL(offsetof(struct ovs_doca_flow_actions, d) == 0);

struct ovs_doca_flow_match {
    struct doca_flow_match d;
};
BUILD_ASSERT_DECL(offsetof(struct ovs_doca_flow_match, d) == 0);

doca_error_t
ovs_doca_complete_queue_esw(struct netdev_doca_esw_ctx *esw,
                            unsigned int qid,
                            bool sync);

doca_error_t
ovs_doca_add_entry(struct netdev *netdev,
                   unsigned int qid,
                   struct doca_flow_pipe *pipe,
                   const struct ovs_doca_flow_match *match,
                   const struct ovs_doca_flow_actions *actions,
                   const struct doca_flow_monitor *monitor,
                   const struct doca_flow_fwd *fwd,
                   uint32_t flags,
                   struct doca_flow_pipe_entry **pentry);

doca_error_t
ovs_doca_remove_entry(struct netdev_doca_esw_ctx *esw,
                      unsigned int qid, uint32_t flags,
                      struct doca_flow_pipe_entry **entry);

void
ovs_doca_destroy_pipe(struct doca_flow_pipe **ppipe);

int
ovs_doca_pipe_create(struct netdev *netdev,
                     struct ovs_doca_flow_match *match,
                     struct ovs_doca_flow_match *match_mask,
                     struct doca_flow_monitor *monitor,
                     struct ovs_doca_flow_actions *actions,
                     struct ovs_doca_flow_actions *actions_mask,
                     struct doca_flow_action_desc *desc,
                     struct doca_flow_fwd *fwd,
                     struct doca_flow_fwd *fwd_miss,
                     uint32_t nr_entries,
                     bool is_egress, bool is_root,
                     uint64_t queues_bitmap,
                     const char *pipe_str,
                     struct doca_flow_pipe **pipe);

doca_error_t
ovs_doca_pipe_cfg_allow_queues(struct doca_flow_pipe_cfg *cfg,
                               uint64_t queues_bitmap);

unsigned int
ovs_doca_max_counters(void);

#endif /* DOCA_NETDEV */

void ovs_doca_init(const struct smap *ovs_other_config);
void print_doca_version(void);
void ovs_doca_status(const struct ovsrec_open_vswitch *);

#endif /* OVS_DOCA_H */
