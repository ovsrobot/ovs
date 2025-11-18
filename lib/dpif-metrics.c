/*
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "dpif-metrics.h"

#include "coverage.h"
#include "ct-dpif.h"
#include "dpif.h"
#include "metrics.h"
#include "sset.h"

METRICS_SUBSYSTEM(dpif);

static void
do_foreach_dpif(metrics_visitor_cb callback,
                struct metrics_visitor *visitor,
                struct metrics_node *node,
                struct metrics_label *labels,
                size_t n OVS_UNUSED)
{
    struct sset types;
    const char *type;

    sset_init(&types);
    dp_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        struct dpif *dpif;
        struct sset names;
        const char *name;

        sset_init(&names);
        dp_enumerate_names(type, &names);
        SSET_FOR_EACH (name, &names) {
            if (!dpif_open(name, type, &dpif)) {
                visitor->it = dpif;
                if (labels[0].key) {
                    labels[0].value = dpif_name(dpif);
                }
                callback(visitor, node);
                dpif_close(dpif);
            }
        }
        sset_destroy(&names);
    }
    sset_destroy(&types);
}

METRICS_FOREACH(dpif, foreach_dpif, do_foreach_dpif, "datapath");
METRICS_FOREACH(dpif, foreach_dpif_nolabel, do_foreach_dpif, NULL);

static bool
ct_stats_supported(void *dpif)
{
    uint32_t u32;

    return ct_dpif_get_nconns(dpif, &u32) == 0;
}

METRICS_IF(foreach_dpif, if_ct_stats_supported, ct_stats_supported);

enum {
    CT_DPIF_METRICS_N_CONNECTIONS,
    CT_DPIF_METRICS_CONNECTION_LIMIT,
    CT_DPIF_METRICS_TCP_SEQ_CHK,
};

static void
ct_dpif_read_value(double *values, void *_dpif)
{
    struct dpif *dpif = _dpif;
    bool tcp_seq_chk;
    uint32_t u32;

    ct_dpif_get_nconns(dpif, &u32);
    values[CT_DPIF_METRICS_N_CONNECTIONS] = u32;

    ct_dpif_get_maxconns(dpif, &u32);
    values[CT_DPIF_METRICS_CONNECTION_LIMIT] = u32;

    ct_dpif_get_tcp_seq_chk(dpif, &tcp_seq_chk);
    values[CT_DPIF_METRICS_TCP_SEQ_CHK] = tcp_seq_chk ? 1 : 0;
}

METRICS_ENTRIES(if_ct_stats_supported, ct_dpif_entries,
        "datapath", ct_dpif_read_value,
    [CT_DPIF_METRICS_N_CONNECTIONS] = METRICS_GAUGE(n_connections,
        "Number of tracked connections."),
    [CT_DPIF_METRICS_CONNECTION_LIMIT] = METRICS_GAUGE(connection_limit,
        "Maximum number of connections allowed."),
    [CT_DPIF_METRICS_TCP_SEQ_CHK] = METRICS_GAUGE(tcp_seq_chk,
        "The TCP sequence checking mode: disabled(0) or enabled(1)."),
);

void
dpif_metrics_register(void)
{
    METRICS_REGISTER(ct_dpif_entries);
}
