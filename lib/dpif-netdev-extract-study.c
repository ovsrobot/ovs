/*
 * Copyright (c) 2021 Intel.
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
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "dpif-netdev-private-thread.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"

VLOG_DEFINE_THIS_MODULE(dpif_mfex_extract_study);

static atomic_uint32_t mfex_study_pkts_count = MFEX_MAX_PKT_COUNT;

/* Struct to hold miniflow study stats. */
struct study_stats {
    uint32_t pkt_count;
    uint32_t pkt_inner_count;
    uint32_t impl_hitcount[MFEX_IMPL_MAX];
    uint32_t impl_inner_hitcount[MFEX_IMPL_MAX];
};

/* Define per thread data to hold the study stats. */
DEFINE_PER_THREAD_MALLOCED_DATA(struct study_stats *, study_stats);

/* Allocate per thread PMD pointer space for study_stats. */
static inline struct study_stats *
mfex_study_get_study_stats_ptr(void)
{
    struct study_stats *stats = study_stats_get();
    if (OVS_UNLIKELY(!stats)) {
        stats = xzalloc(sizeof *stats);
        study_stats_set_unsafe(stats);
    }
    return stats;
}

int
mfex_set_study_pkt_cnt(uint32_t pkt_cmp_count, const char *name)
{
    struct dpif_miniflow_extract_impl *miniflow_funcs;
    miniflow_funcs = dpif_mfex_impl_info_get();

    /* If the packet count is set and implementation called is study then
     * set packet counter to requested number else return -EINVAL.
     */
    if ((strcmp(miniflow_funcs[MFEX_IMPL_STUDY].name, name) == 0) &&
        (pkt_cmp_count != 0)) {

        atomic_store_relaxed(&mfex_study_pkts_count, pkt_cmp_count);
        return 0;
    }

    return -EINVAL;
}

/* Reset stats so that the study function can be called again for the next
 * traffic type and an optimal function pointer can be chosen.
 */
static inline void
mfex_reset_stats(uint32_t *impls_hitcount, uint32_t *pkt_cnt) {
    memset(impls_hitcount, 0, sizeof(uint32_t) * MFEX_IMPL_MAX);
    *pkt_cnt = 0;
}

static inline void
mfex_study_select_best_impls(struct dpif_miniflow_extract_impl *mfex_funcs,
                             uint32_t pkt_cnt, uint32_t *impls_arr,
                             atomic_uintptr_t *pmd_func, char *name)
{

    uint32_t best_func_index = MFEX_IMPL_START_IDX;
    uint32_t max_hits = 0;

    for (int i = MFEX_IMPL_START_IDX; i < MFEX_IMPL_MAX; i++) {
        if (impls_arr[i] > max_hits) {
            max_hits = impls_arr[i];
            best_func_index = i;
        }
    }

    /* If at least 50% of the packets hit the implementation,
     * enable that implementation.
     */
    if (max_hits >= (mfex_study_pkts_count / 2)) {
        atomic_store_relaxed(pmd_func,
                    (uintptr_t) mfex_funcs[best_func_index].extract_func);
        VLOG_INFO("MFEX %s study chose impl %s: (hits %u/%u pkts)",
                  name, mfex_funcs[best_func_index].name, max_hits, pkt_cnt);
    } else {
        /* Set the implementation to null for default miniflow. */
        atomic_store_relaxed(pmd_func,
                    (uintptr_t) mfex_funcs[MFEX_IMPL_SCALAR].extract_func);
        VLOG_INFO("Not enough packets matched (%u/%u), disabling"
                  " optimized MFEX.", max_hits, pkt_cnt);
    }

    /* In debug mode show stats for all the counters. */
    if (VLOG_IS_DBG_ENABLED()) {
        for (int i = MFEX_IMPL_START_IDX; i < MFEX_IMPL_MAX; i++) {
                VLOG_DBG("MFEX study results for implementation %s:"
                         " (hits %u/%u pkts)", mfex_funcs[i].name,
                         impls_arr[i], pkt_cnt);
        }
    }
}

uint32_t
mfex_study_traffic(struct dp_packet_batch *packets,
                   struct netdev_flow_key *keys,
                   uint32_t keys_size, odp_port_t in_port,
                   struct dp_netdev_pmd_thread *pmd_handle,
                   bool md_is_valid)
{
    uint32_t hitmask = 0;
    uint32_t mask = 0;
    uint32_t study_cnt_pkts;
    struct dp_netdev_pmd_thread *pmd = pmd_handle;
    struct dpif_miniflow_extract_impl *miniflow_funcs;
    struct study_stats *stats = mfex_study_get_study_stats_ptr();
    miniflow_funcs = dpif_mfex_impl_info_get();
    atomic_read_relaxed(&mfex_study_pkts_count, &study_cnt_pkts);

    /* Run traffic optimized miniflow_extract to collect the hitmask
     * to be compared after certain packets have been hit to choose
     * the best miniflow_extract version for that traffic.
     */
    for (int i = MFEX_IMPL_START_IDX; i < MFEX_IMPL_MAX; i++) {
        if (!miniflow_funcs[i].available) {
            continue;
        }

        hitmask = miniflow_funcs[i].extract_func(packets, keys, keys_size,
                                                 in_port, pmd_handle,
                                                 md_is_valid);
        if (!md_is_valid) {
            stats->impl_hitcount[i] += count_1bits(hitmask);
        } else {
            stats->impl_inner_hitcount[i] += count_1bits(hitmask);
        }

        /* If traffic is not classified then we dont overwrite the keys
         * array in minfiflow implementations so its safe to create a
         * mask for all those packets whose miniflow have been created.
         */
        mask |= hitmask;
    }

    /* Choose the best miniflow extract implementation to use for inner
     * and outer packets separately.
     */
    if (!md_is_valid) {
        stats->pkt_count += dp_packet_batch_size(packets);

        if (stats->pkt_count >= study_cnt_pkts) {
            char name[] = "outer";
            mfex_study_select_best_impls(miniflow_funcs, stats->pkt_count,
                             stats->impl_hitcount,
                             (void *)&pmd->miniflow_extract_opt, name);
            mfex_reset_stats(stats->impl_hitcount, &stats->pkt_count);
        }

    } else {
        stats->pkt_inner_count += dp_packet_batch_size(packets);

        if (stats->pkt_inner_count >= study_cnt_pkts) {
            char name[] = "inner";
            mfex_study_select_best_impls(miniflow_funcs,
                             stats->pkt_inner_count,
                             stats->impl_inner_hitcount,
                             (void *)&pmd->miniflow_extract_inner_opt, name);
            mfex_reset_stats(stats->impl_inner_hitcount,
                             &stats->pkt_inner_count);
        }
    }
    return mask;
}
