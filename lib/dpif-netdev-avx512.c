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

#include "dp-packet.h"
#include "netdev.h"

#include "immintrin.h"


/* Structure to contain per-packet metadata that must be attributed to the
 * dp netdev flow. This is unfortunate to have to track per packet, however
 * its a bit difficult awkward to maintain them in a performant way. This
 * structure helps to keep two variables on a single cache line per packet.
 */
struct pkt_flow_meta {
    uint16_t bytes;
    uint16_t tcp_flags;
};

int32_t
dp_netdev_input_outer_avx512_probe(void)
{
    int avx512f_available = dpdk_get_cpu_has_isa("x86_64", "avx512f");
    int bmi2_available = dpdk_get_cpu_has_isa("x86_64", "bmi2");
    printf("here: avx512f %d, bmi2 %d\n", avx512f_available, bmi2_available);
    if (!avx512f_available || !bmi2_available) {
        return 0;
    }
    return 1;
}

int32_t
dp_netdev_input_outer_avx512(struct dp_netdev_pmd_thread *pmd,
                             struct dp_packet_batch *packets,
                             odp_port_t in_port)
{
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)struct netdev_flow_key keys_impl[NETDEV_MAX_BURST+1];
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)struct netdev_flow_key *key_ptrs[NETDEV_MAX_BURST];
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)struct pkt_flow_meta pkt_meta[NETDEV_MAX_BURST];

    /* Temporary pointers to the above stack allocated arrays due to the
     * dpcls_lookup() function signature taking pointers, not linear flow_keys.
     */
    ssize_t blocks_offset = offsetof(struct netdev_flow_key, buf);
    struct netdev_flow_key *keys = (void *)(((char *)keys_impl) + (64-blocks_offset));
    for (int i = 0; i < NETDEV_MAX_BURST; i++) {
         key_ptrs[i] = &keys[i];
    }

    /* Stores the computed output: a rule pointer for each packet */
    struct dpcls_rule *rules[NETDEV_MAX_BURST];
    for (uint32_t i = 0; i < NETDEV_MAX_BURST; i += 8) {
        _mm512_storeu_si512(&rules[i], _mm512_setzero_si512());
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
    uint32_t emc_hits = 0;

    /* Perform first packet interation */
    uint32_t lookup_pkts_bitmask = (1ULL << batch_size) - 1;
    uint32_t iter = lookup_pkts_bitmask;
    while (iter) {
        uint32_t i = __builtin_ctz(iter);
        iter = _blsr_u64(iter);

        /* Initialize packet md and do miniflow extract */
        struct dp_packet *packet = packets->packets[i];
        pkt_metadata_init(&packet->md, in_port);
        struct netdev_flow_key *key = &keys[i];
        miniflow_extract(packet, &key->mf);
        key->len = count_1bits(key->mf.map.bits[0] + key->mf.map.bits[1]);
        key->hash = dpif_netdev_packet_get_rss_hash_orig_pkt(packet, &key->mf);

        if (emc_enabled) {
           struct dp_netdev_flow *f = emc_lookup(&cache->emc_cache, key);
           if (f) {
               rules[i] = &f->cr;
               emc_hits++;
               // TODO: remove this EMC hit from the dpcls lookup bitmask
           }
        };

        /* Cache TCP and byte values for packets */
        pkt_meta[i].bytes = dp_packet_size(packet);
        pkt_meta[i].tcp_flags = miniflow_get_tcp_flags(&key->mf);
    }

    struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_UNLIKELY(!cls)) {
        return -1;
    }

    int any_miss = !dpcls_lookup(cls, (const struct netdev_flow_key **)key_ptrs,
                                rules, batch_size, NULL);
    if (OVS_UNLIKELY(any_miss)) {
        return -1;
    }

    /* At this point we don't return error anymore, so commit stats here */
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_EXACT_HIT, emc_hits);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_RECV, batch_size);

    uint32_t wild_hit = batch_size - emc_hits;
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_HIT, wild_hit);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_LOOKUP, wild_hit);

    /* Initialize the "Action Batch" for each flow handled below */
    struct dp_packet_batch action_batch;
    action_batch.trunc = 0;
    action_batch.do_not_steal = false;

    while (lookup_pkts_bitmask) {
        uint32_t rule_pkt_idx = __builtin_ctz(lookup_pkts_bitmask);
        uint64_t needle = (uintptr_t)rules[rule_pkt_idx];

        /* Parallel compare 8 flow* 's to the needle, create a bitmask */
        __mmask32 batch_bitmask = 0;
        for(uint32_t j = 0; j < NETDEV_MAX_BURST; j += 8) {
            /* Pre-calculate store addr */
            uint32_t num_pkts_in_batch = __builtin_popcountll(batch_bitmask);
            void *store_addr = &action_batch.packets[num_pkts_in_batch];

            /* Search for identical flow* in burst, update bitmask */
            __m512i v_needle = _mm512_maskz_set1_epi64(-1, needle);
            __m512i v_hay = _mm512_loadu_si512(&rules[j]);
            uint16_t cmp_bits = _mm512_cmpeq_epi64_mask(v_needle, v_hay);
            batch_bitmask |= cmp_bits << j;

            /* Compress & Store the batched packets */
            struct dp_packet **packets_ptrs = &packets->packets[j];
            __m512i v_pkt_ptrs = _mm512_loadu_si512(packets_ptrs);
            _mm512_mask_compressstoreu_epi64(store_addr, cmp_bits, v_pkt_ptrs);
        }

        /* Strip all packets in this batch from the lookup_pkts_bitmask */
        lookup_pkts_bitmask &= (~batch_bitmask);
        action_batch.count = __builtin_popcountll(batch_bitmask);

        /* Loop over all packets in this batch, to gather the byte and tcp_flag
         * values, and pass them to the execute function. It would be nice to
         * optimize this away, however it is not easy to refactor in dpif.
         */
        uint32_t bytes = 0;
        uint16_t tcp_flags = 0;
        uint32_t bitmask_iter = batch_bitmask;
        for(int i = 0; i < action_batch.count; i++) {
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
