/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef DPIF_NETDEV_H
#define DPIF_NETDEV_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dpif.h"
#include "openvswitch/types.h"
#include "dp-packet.h"
#include "packets.h"
#include "cmap.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { DP_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

bool dpif_is_netdev(const struct dpif *);

#define NR_QUEUE   1
#define NR_PMD_THREADS 1

/* forward declaration for lookup_func typedef */
struct dpcls_subtable;
struct dpcls_rule;

/* must be public as it is intantiated in subtable struct below */
struct netdev_flow_key {
    uint32_t hash;       /* Hash function differs for different users. */
    uint32_t len;        /* Length of the following miniflow (incl. map). */
    struct miniflow mf;
    uint64_t buf[FLOW_MAX_PACKET_U64S];
};

/* A rule to be inserted to the classifier. */
struct dpcls_rule {
    struct cmap_node cmap_node;   /* Within struct dpcls_subtable 'rules'. */
    struct netdev_flow_key *mask; /* Subtable's mask. */
    struct netdev_flow_key flow;  /* Matching key. */
    /* 'flow' must be the last field, additional space is allocated here. */
};

/** Lookup function for a subtable in the dpcls. This function is called
 * by each subtable with an array of packets, and a bitmask of packets to
 * perform the lookup on. Using a function pointer gives flexibility to
 * optimize the lookup function based on subtable properties and the
 * CPU instruction set available at runtime.
 */
typedef uint32_t (*dpcls_subtable_lookup_func)(struct dpcls_subtable *subtable,
                uint32_t keys_map, const struct netdev_flow_key *keys[],
                struct dpcls_rule **rules);

/** Prototype for generic lookup func, using same code path as before */
uint32_t
dpcls_subtable_lookup_generic(struct dpcls_subtable *subtable,
                              uint32_t keys_map,
                              const struct netdev_flow_key *keys[],
                              struct dpcls_rule **rules);

/* A set of rules that all have the same fields wildcarded. */
struct dpcls_subtable {
    /* The fields are only used by writers. */
    struct cmap_node cmap_node OVS_GUARDED; /* Within dpcls 'subtables_map'. */

    /* These fields are accessed by readers. */
    struct cmap rules;           /* Contains "struct dpcls_rule"s. */
    uint32_t hit_cnt;            /* Number of match hits in subtable in current
                                    optimization interval. */

    /* the lookup function to use for this subtable. If there is a known
     * property of the subtable (eg: only 3 bits of miniflow metadata is
     * used for the lookup) then this can point at an optimized version of
     * the lookup function for this particular subtable. */
    dpcls_subtable_lookup_func lookup_func;

    struct netdev_flow_key mask; /* Wildcards for fields (const). */
    /* 'mask' must be the last field, additional space is allocated here. */
};

/* Iterate through netdev_flow_key TNL u64 values specified by 'FLOWMAP'. */
#define NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(VALUE, KEY, FLOWMAP)   \
    MINIFLOW_FOR_EACH_IN_FLOWMAP(VALUE, &(KEY)->mf, FLOWMAP)

/* Iterate all bits set in the *rle_unit*, lookup the block of metadata based
 * on the packet miniflow, and compare it for "matching" the rule, using the
 * subtable mask in the process. Note that the pointers passed in to this
 * function are already adjusted for the unit offset. */
static inline int32_t
dpcls_verify_unit(const uint64_t rle_unit, const uint64_t pkt_unit,
                  const uint64_t *rle, const uint64_t *msk,
                  const uint64_t *pkt)
{
    int match_fail = 0;
    int linear_idx = 0;

    uint64_t iter = rle_unit;
    while (iter) {
        uint64_t low_bit = iter & (-iter);
        iter &= ~(low_bit);

        uint64_t low_mask = low_bit - 1;
        uint64_t bits = (low_mask & pkt_unit);
        uint64_t blk_idx = __builtin_popcountll(bits);

        /* Take packet, mask bits away, compare against rule.
         * Results in 1 for matching, so ! to invert to fail */
        match_fail |= !((pkt[blk_idx] & msk[linear_idx]) == rle[linear_idx]);
        linear_idx++;
    }

    return match_fail;
}

/* match rule and target (aka packet), to understand if the rule applies to
 * this packet. The actual miniflow-unit iteration is performed in
 * the *dpcls_verify_unit* function, this just wraps the two unit calls */
static inline int
dpcls_rule_matches_key(const struct dpcls_rule *rule,
                       const struct netdev_flow_key *target)
{
    /* retrieve the "block" pointers for the packet, rule and subtable mask */
    const uint64_t *rle_blocks = miniflow_get_values(&rule->flow.mf);
    const uint64_t *msk_blocks = miniflow_get_values(&rule->mask->mf);
    const uint64_t *pkt_blocks = miniflow_get_values(&target->mf);

    /* fetch the rule bits to iterate */
    const uint64_t rle_u0 = rule->flow.mf.map.bits[0];
    const uint64_t rle_u1 = rule->flow.mf.map.bits[1];

    /* fetch the packet bits to navigate the packet's miniflow block indexes */
    const uint64_t pkt_u0 = target->mf.map.bits[0];
    const uint64_t pkt_u1 = target->mf.map.bits[1];

    /* calculate where u1 starts by finding total size of u0 */
    int rle_u0_pop = __builtin_popcountll(rle_u0);
    int pkt_u0_pop = __builtin_popcountll(pkt_u0);

    int fail = 0;
    /* call verify_unit for both units. This has multiple advantages:
     * 1) Each while() loop gets its own branch predictor entry - improves hits
     * 2) Compiler can re-shuffle instructions as it likes, also between iters
     * 3) Simpler popcount() approach means less branches in general
     */
    fail |= dpcls_verify_unit(rle_u0, pkt_u0, &rle_blocks[0], &msk_blocks[0], &pkt_blocks[0]);
    fail |= dpcls_verify_unit(rle_u1, pkt_u1, &rle_blocks[rle_u0_pop], &msk_blocks[rle_u0_pop],
                              &pkt_blocks[pkt_u0_pop]);

    /* return 1 if matches, 0 on fail */
    return fail == 0;
}

#ifdef  __cplusplus
}
#endif

#endif /* netdev.h */
