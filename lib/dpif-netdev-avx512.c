/*
 * Copyright (c) 2020 Intel.
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

#ifdef __x86_64__
/* Sparse cannot handle the AVX512 instructions */
#if !defined(__CHECKER__)

#include <config.h>

#include "dpif-netdev.h"
#include "dpif-netdev-perf.h"

#include "dpif-netdev-private.h"
#include "dpif-netdev-private-dpcls.h"
#include "dpif-netdev-private-flow.h"
#include "dpif-netdev-private-thread.h"
#include "dpif-netdev-private-hwol.h"

#include "dp-packet.h"
#include "netdev.h"

#include "immintrin.h"

/* Structure to contain per-packet metadata that must be attributed to the
 * dp netdev flow. This is unfortunate to have to track per packet, however
 * it's a bit awkward to maintain them in a performant way. This structure
 * helps to keep two variables on a single cache line per packet.
 */
struct pkt_flow_meta {
    uint16_t bytes;
    uint16_t tcp_flags;
};

/* Structure of heap allocated memory for DPIF internals. */
struct dpif_userdata {
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)
        struct netdev_flow_key keys[NETDEV_MAX_BURST];
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)
        struct netdev_flow_key *key_ptrs[NETDEV_MAX_BURST];
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)
        struct pkt_flow_meta pkt_meta[NETDEV_MAX_BURST];
};

int32_t
dp_netdev_input_outer_avx512(struct dp_netdev_pmd_thread *pmd,
                             struct dp_packet_batch *packets,
                             odp_port_t in_port)
{
    /* Allocate DPIF userdata. */
    if (OVS_UNLIKELY(!pmd->netdev_input_func_userdata)) {
        pmd->netdev_input_func_userdata =
                xmalloc_pagealign(sizeof(struct dpif_userdata));
    }

    struct dpif_userdata *ud = pmd->netdev_input_func_userdata;
    struct netdev_flow_key *keys = ud->keys;
    struct netdev_flow_key **key_ptrs = ud->key_ptrs;
    struct pkt_flow_meta *pkt_meta = ud->pkt_meta;

    /* Stores the computed output: a rule pointer for each packet */
    /* The AVX512 DPIF implementation handles rules in a way that is optimized
     * for reducing data-movement between HWOL/EMC/SMC and DPCLS. This is
     * achieved by separating the rule arrays. Bitmasks are kept for each
     * packet, indicating if it matched in the HWOL/EMC/SMC array or DPCLS
     * array. Later the two arrays are merged by AVX-512 expand instructions.
     */
    struct dpcls_rule *rules[NETDEV_MAX_BURST];
    struct dpcls_rule *dpcls_rules[NETDEV_MAX_BURST];
    uint32_t dpcls_key_idx = 0;

    for (uint32_t i = 0; i < NETDEV_MAX_BURST; i += 8) {
        _mm512_storeu_si512(&rules[i], _mm512_setzero_si512());
        _mm512_storeu_si512(&dpcls_rules[i], _mm512_setzero_si512());
    }

    /* Prefetch each packet's metadata */
    const size_t batch_size = dp_packet_batch_size(packets);
    for (int i = 0; i < batch_size; i++) {
        struct dp_packet *packet = packets->packets[i];
        OVS_PREFETCH(dp_packet_data(packet));
        pkt_metadata_prefetch_init(&packet->md);
    }

    /* Check if EMC or SMC are enabled */
    struct dfc_cache *cache = &pmd->flow_cache;
    const uint32_t emc_enabled = pmd->ctx.emc_insert_min != 0;
    const uint32_t smc_enabled = pmd->ctx.smc_enable_db;

    uint32_t emc_hits = 0;
    uint32_t smc_hits = 0;

    /* a 1 bit in this mask indidcates a hit, so no DPCLS lookup on the pkt. */
    uint32_t hwol_emc_smc_hitmask = 0;

    /* Perform first packet interation */
    uint32_t lookup_pkts_bitmask = (1ULL << batch_size) - 1;
    uint32_t iter = lookup_pkts_bitmask;
    while (iter) {
        uint32_t i = __builtin_ctz(iter);
        iter = _blsr_u64(iter);

        /* Get packet pointer from bitmask and packet md */
        struct dp_packet *packet = packets->packets[i];
        pkt_metadata_init(&packet->md, in_port);

        struct dp_netdev_flow *f = NULL;

        /* Check for partial hardware offload mark */
        uint32_t mark;
        if (dp_packet_has_flow_mark(packet, &mark)) {
            f = mark_to_flow_find(pmd, mark);
            if (f) {
                rules[i] = &f->cr;

                /* This is nasty - instead of using the HWOL provided flow,
                 * parse the packet data anyway to find the location of the TCP
                 * header to extract the TCP flags for the rule.
                 */
                pkt_meta[i].tcp_flags = parse_tcp_flags(packet);

                pkt_meta[i].bytes = dp_packet_size(packet);
                hwol_emc_smc_hitmask |= (1 << i);
                continue;
            }
        }

        /* Do miniflow extract into keys */
        struct netdev_flow_key *key = &keys[i];
        miniflow_extract(packet, &key->mf);

        /* Cache TCP and byte values for all packets */
        pkt_meta[i].bytes = dp_packet_size(packet);
        pkt_meta[i].tcp_flags = miniflow_get_tcp_flags(&key->mf);

        key->len = netdev_flow_key_size(miniflow_n_values(&key->mf));
        key->hash = dpif_netdev_packet_get_rss_hash_orig_pkt(packet, &key->mf);

        if (emc_enabled) {
            f = emc_lookup(&cache->emc_cache, key);

            if (f) {
                rules[i] = &f->cr;
                emc_hits++;
                hwol_emc_smc_hitmask |= (1 << i);
                continue;
            }
        };

        if (smc_enabled && !f) {
            f = smc_lookup_single(pmd, packet, key);
            if (f) {
                rules[i] = &f->cr;
                smc_hits++;
                hwol_emc_smc_hitmask |= (1 << i);
                continue;
            }
        }

        /* The flow pointer was not found in HWOL/EMC/SMC, so add it to the
         * dpcls input keys array for batch lookup later.
         */
        key_ptrs[dpcls_key_idx] = &keys[i];
        dpcls_key_idx++;
    }


    /* DPCLS handles any packets missed by HWOL/EMC/SMC. It operates on the
     * key_ptrs[] for input miniflows to match, storing results in the
     * dpcls_rules[] array.
     */
    if (dpcls_key_idx > 0) {
        struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
        if (OVS_UNLIKELY(!cls)) {
            return -1;
        }
        int any_miss = !dpcls_lookup(cls,
                                    (const struct netdev_flow_key **) key_ptrs,
                                    dpcls_rules, dpcls_key_idx, NULL);
        if (OVS_UNLIKELY(any_miss)) {
            return -1;
        }

        /* Merge DPCLS rules and HWOL/EMC/SMC rules. */
        uint32_t dpcls_idx = 0;
        for (int i = 0; i < NETDEV_MAX_BURST; i += 8) {
            /* Indexing here is somewhat complicated due to DPCLS output rule
             * load index depending on the hitmask of HWOL/EMC/SMC. More
             * packets from HWOL/EMC/SMC bitmask means less DPCLS rules are
             * used.
             */
            __m512i v_cache_rules = _mm512_loadu_si512(&rules[i]);
            __m512i v_merged_rules =
                        _mm512_mask_expandloadu_epi64(v_cache_rules,
                                                      ~hwol_emc_smc_hitmask,
                                                      &dpcls_rules[dpcls_idx]);
            _mm512_storeu_si512(&rules[i], v_merged_rules);

            /* Update DPCLS load index and bitmask for HWOL/EMC/SMC hits.
             * There are 8 output pointer per register, subtract the
             * HWOL/EMC/SMC lanes equals the number of DPCLS rules consumed.
             */
            uint32_t hitmask_FF = (hwol_emc_smc_hitmask & 0xFF);
            dpcls_idx += 8 - __builtin_popcountll(hitmask_FF);
            hwol_emc_smc_hitmask = (hwol_emc_smc_hitmask >> 8);
        }
    }

    /* At this point we don't return error anymore, so commit stats here. */
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_RECV, batch_size);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_EXACT_HIT, emc_hits);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SMC_HIT, smc_hits);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_HIT,
                            dpcls_key_idx);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_LOOKUP,
                            dpcls_key_idx);

    /* Initialize the "Action Batch" for each flow handled below. */
    struct dp_packet_batch action_batch;
    action_batch.trunc = 0;
    action_batch.do_not_steal = false;

    while (lookup_pkts_bitmask) {
        uint32_t rule_pkt_idx = __builtin_ctz(lookup_pkts_bitmask);
        uint64_t needle = (uintptr_t) rules[rule_pkt_idx];

        /* Parallel compare 8 flow* 's to the needle, create a bitmask. */
        uint32_t batch_bitmask = 0;
        for (uint32_t j = 0; j < NETDEV_MAX_BURST; j += 8) {
            /* Pre-calculate store addr */
            uint32_t num_pkts_in_batch = __builtin_popcountll(batch_bitmask);
            void *store_addr = &action_batch.packets[num_pkts_in_batch];

            /* Search for identical flow* in burst, update bitmask. */
            __m512i v_needle = _mm512_set1_epi64(needle);
            __m512i v_hay = _mm512_loadu_si512(&rules[j]);
            __mmask8 k_cmp_bits = _mm512_cmpeq_epi64_mask(v_needle, v_hay);
            uint32_t cmp_bits = k_cmp_bits;
            batch_bitmask |= cmp_bits << j;

            /* Compress & Store the batched packets. */
            struct dp_packet **packets_ptrs = &packets->packets[j];
            __m512i v_pkt_ptrs = _mm512_loadu_si512(packets_ptrs);
            _mm512_mask_compressstoreu_epi64(store_addr, cmp_bits, v_pkt_ptrs);
        }

        /* Strip all packets in this batch from the lookup_pkts_bitmask. */
        lookup_pkts_bitmask &= (~batch_bitmask);
        action_batch.count = __builtin_popcountll(batch_bitmask);

        /* Loop over all packets in this batch, to gather the byte and tcp_flag
         * values, and pass them to the execute function. It would be nice to
         * optimize this away, however it is not easy to refactor in dpif.
         */
        uint32_t bytes = 0;
        uint16_t tcp_flags = 0;
        uint32_t bitmask_iter = batch_bitmask;
        for (int i = 0; i < action_batch.count; i++) {
            uint32_t idx = __builtin_ctzll(bitmask_iter);
            bitmask_iter = _blsr_u64(bitmask_iter);

            bytes += pkt_meta[idx].bytes;
            tcp_flags |= pkt_meta[idx].tcp_flags;
        }

        dp_netdev_batch_execute(pmd, &action_batch, rules[rule_pkt_idx],
                                bytes, tcp_flags);
    }

    return 0;
}

#endif
#endif
