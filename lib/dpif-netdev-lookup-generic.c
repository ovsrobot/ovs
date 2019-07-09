/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2019 Intel Corporation.
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
#include "dpif-netdev.h"

#include "bitmap.h"
#include "cmap.h"

#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-provider.h"
#include "flow.h"
#include "packets.h"
#include "pvector.h"

VLOG_DEFINE_THIS_MODULE(dpif_lookup_generic);

/* netdev_flow_key_flatten_unit:
 * Given a packet, table and mf_masks, this function iterates over each bit
 * set in the subtable, and calculates the appropriate metadata to store in the
 * blocks_scratch[].
 *
 * The results of the blocks_scratch[] can be used for hashing, and later for
 * verification of if a rule matches the given packet.
 */
static inline void
netdev_flow_key_flatten_unit(const uint64_t *pkt_blocks,
                             const uint64_t *tbl_blocks,
                             const uint64_t *mf_masks,
                             uint64_t *blocks_scratch,
                             const uint64_t pkt_mf_bits,
                             const uint32_t count)
{
    uint32_t i;
    for (i = 0; i < count; i++) {
        uint64_t mf_mask = mf_masks[i];
        /* Calculate the block index for the packet metadata */
        uint64_t idx_bits = mf_mask & pkt_mf_bits;
        const uint32_t pkt_idx = count_1bits(idx_bits);

        /* check if the packet has the subtable miniflow bit set. If yes, the
         * block at the above pkt_idx will be stored, otherwise it is masked
         * out to be zero.
         */
        uint64_t pkt_has_mf_bit = (mf_mask + 1) & pkt_mf_bits;
        uint64_t no_bit = ((!pkt_has_mf_bit) > 0) - 1;

        /* mask packet block by table block, and mask to zero if packet
         * doesn't actually contain this block of metadata
         */
        blocks_scratch[i] = pkt_blocks[pkt_idx] & tbl_blocks[i] & no_bit;
    }
}

/* netdev_flow_key_flatten:
 * This function takes a packet, and subtable and writes an array of uint64_t
 * blocks. The blocks contain the metadata that the subtable matches on, in
 * the same order as the subtable, allowing linear iteration over the blocks.
 *
 * To calculate the blocks contents, the netdev_flow_key_flatten_unit function
 * is called twice, once for each "unit" of the miniflow. This call can be
 * inlined by the compiler for performance.
 *
 * Note that the u0_count and u1_count variables can be compile-time constants,
 * allowing the loop in the inlined flatten_unit() function to be compile-time
 * unrolled, or possibly removed totally by unrolling by the loop iterations.
 * The compile time optimizations enabled by this design improves performance.
 */
static inline void
netdev_flow_key_flatten(const struct netdev_flow_key *key,
                        const struct netdev_flow_key *mask,
                        const uint64_t *mf_masks,
                        uint64_t *blocks_scratch,
                        const uint32_t u0_count,
                        const uint32_t u1_count)
{
    /* load mask from subtable, mask with packet mf, popcount to get idx */
    const uint64_t *pkt_blocks = miniflow_get_values(&key->mf);
    const uint64_t *tbl_blocks = miniflow_get_values(&mask->mf);

    /* packet miniflow bits to be masked by pre-calculated mf_masks */
    const uint64_t pkt_bits_u0 = key->mf.map.bits[0];
    const uint32_t pkt_bits_u0_pop = count_1bits(pkt_bits_u0);
    const uint64_t pkt_bits_u1 = key->mf.map.bits[1];

    /* Unit 0 flattening */
    netdev_flow_key_flatten_unit(&pkt_blocks[0],
                                 &tbl_blocks[0],
                                 &mf_masks[0],
                                 &blocks_scratch[0],
                                 pkt_bits_u0,
                                 u0_count);

    /* Unit 1 flattening:
     * Move the pointers forward in the arrays based on u0 offsets, NOTE:
     * 1) pkt blocks indexed by actual popcount of u0, which is NOT always
     *    the same as the amount of bits set in the subtable.
     * 2) mf_masks, tbl_block and blocks_scratch are all "flat" arrays, so
     *    the index is always u0_count.
     */
    netdev_flow_key_flatten_unit(&pkt_blocks[pkt_bits_u0_pop],
                                 &tbl_blocks[u0_count],
                                 &mf_masks[u0_count],
                                 &blocks_scratch[u0_count],
                                 pkt_bits_u1,
                                 u1_count);
}

static inline uint64_t
netdev_rule_matches_key(const struct dpcls_rule *rule,
                        const uint32_t mf_bits_total,
                        const uint64_t *blocks_scratch)
{
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);
    const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);

    uint64_t not_match = 0;
    for (int i = 0; i < mf_bits_total; i++) {
        not_match |= (blocks_scratch[i] & maskp[i]) != keyp[i];
    }

    /* invert result to show match as 1 */
    return !not_match;
}

/* const prop version of the function: note that mf bits total and u0 are
 * explicitly passed in here, while they're also available at runtime from the
 * subtable pointer. By making them compile time, we enable the compiler to
 * unroll loops and flatten out code-sequences based on the knowledge of the
 * mf_bits_* compile time values. This results in improved performance.
 */
static inline uint32_t ALWAYS_INLINE
lookup_generic_impl(struct dpcls_subtable *subtable,
                    uint64_t *blocks_scratch,
                    uint32_t keys_map,
                    const struct netdev_flow_key *keys[],
                    struct dpcls_rule **rules,
                    const uint32_t bit_count_u0,
                    const uint32_t bit_count_u1)
{
    const uint32_t n_pkts = count_1bits(keys_map);
    ovs_assert(NETDEV_MAX_BURST >= n_pkts);
    uint32_t hashes[NETDEV_MAX_BURST];

    const uint32_t bit_count_total = bit_count_u0 + bit_count_u1;
    uint64_t *mf_masks = subtable->mf_masks;
    int i;

    /* Flatten the packet metadata into the blocks_scratch[] using subtable */
    ULLONG_FOR_EACH_1(i, keys_map) {
            netdev_flow_key_flatten(keys[i],
                                    &subtable->mask,
                                    mf_masks,
                                    &blocks_scratch[i * bit_count_total],
                                    bit_count_u0,
                                    bit_count_u1);
    }

    /* Hash the now linearized blocks of packet metadata */
    ULLONG_FOR_EACH_1(i, keys_map) {
         uint32_t hash = 0;
         uint32_t i_off = i * bit_count_total;
         for (int h = 0; h < bit_count_total; h++) {
             hash = hash_add64(hash, blocks_scratch[i_off + h]);
         }
         hashes[i] = hash_finish(hash, bit_count_total * 8);
    }

    /* Lookup: this returns a bitmask of packets where the hash table had
     * an entry for the given hash key. Presence of a hash key does not
     * guarantee matching the key, as there can be hash collisions.
     */
    uint32_t found_map;
    const struct cmap_node *nodes[NETDEV_MAX_BURST];
    found_map = cmap_find_batch(&subtable->rules, keys_map, hashes, nodes);

    /* Verify that packet actually matched rule. If not found, a hash
     * collision has taken place, so continue searching with the next node.
     */
    ULLONG_FOR_EACH_1(i, found_map) {
        struct dpcls_rule *rule;

        CMAP_NODE_FOR_EACH (rule, cmap_node, nodes[i]) {
            const uint32_t cidx = i * bit_count_total;
            uint32_t match = netdev_rule_matches_key(rule, bit_count_total,
                                                     &blocks_scratch[cidx]);

            if (OVS_LIKELY(match)) {
                rules[i] = rule;
                subtable->hit_cnt++;
                goto next;
            }
        }

        /* None of the found rules was a match.  Clear the i-th bit to
         * search for this key in the next subtable. */
        ULLONG_SET0(found_map, i);
    next:
        ;                     /* Keep Sparse happy. */
    }

    return found_map;
}

/* Generic - use runtime provided mf bits */
uint32_t
dpcls_subtable_lookup_generic(struct dpcls_subtable *subtable,
                              uint64_t *blocks_scratch,
                              uint32_t keys_map,
                              const struct netdev_flow_key *keys[],
                              struct dpcls_rule **rules)
{
    /* Here the runtime subtable->mf_bits counts are used, which forces the
     * compiler to iterate normal for() loops. Due to this limitation in the
     * compilers available optimizations, this function has lower performance
     * than the below specialized functions.
     */
    return lookup_generic_impl(subtable, blocks_scratch, keys_map, keys, rules,
                               subtable->mf_bits_set_unit0,
                               subtable->mf_bits_set_unit1);
}

static uint32_t
dpcls_subtable_lookup_mf_u0w5_u1w1(struct dpcls_subtable *subtable,
                                   uint64_t *blocks_scratch,
                                   uint32_t keys_map,
                                   const struct netdev_flow_key *keys[],
                                   struct dpcls_rule **rules)
{
    /* hard coded bit counts - enables compile time loop unrolling, and
     * generating of optimized code-sequences due to loop unrolled code.
     */
    return lookup_generic_impl(subtable, blocks_scratch, keys_map, keys, rules,
                               5, 1);
}

static uint32_t
dpcls_subtable_lookup_mf_u0w4_u1w1(struct dpcls_subtable *subtable,
                                   uint64_t *blocks_scratch,
                                   uint32_t keys_map,
                                   const struct netdev_flow_key *keys[],
                                   struct dpcls_rule **rules)
{
    return lookup_generic_impl(subtable, blocks_scratch, keys_map, keys, rules,
                               4, 1);
}

static uint32_t
dpcls_subtable_lookup_mf_u0w4_u1w0(struct dpcls_subtable *subtable,
                                   uint64_t *blocks_scratch,
                                   uint32_t keys_map,
                                   const struct netdev_flow_key *keys[],
                                   struct dpcls_rule **rules)
{
    return lookup_generic_impl(subtable, blocks_scratch, keys_map, keys, rules,
                               4, 0);
}

/* Probe function to lookup an available specialized function.
 * If capable to run the requested miniflow fingerprint, this function returns
 * the most optimal implementation for that miniflow fingerprint.
 * @retval FunctionAddress A valid function to handle the miniflow bit pattern
 * @retval 0 The requested miniflow is not supported here, NULL is returned
 */
dpcls_subtable_lookup_func
dpcls_subtable_generic_probe(uint32_t u0_bits, uint32_t u1_bits)
{
    dpcls_subtable_lookup_func f = NULL;

    if (u0_bits == 5 && u1_bits == 1) {
        f = dpcls_subtable_lookup_mf_u0w5_u1w1;
    } else if (u0_bits == 4 && u1_bits == 1) {
        f = dpcls_subtable_lookup_mf_u0w4_u1w1;
    } else if (u0_bits == 4 && u1_bits == 0) {
        f = dpcls_subtable_lookup_mf_u0w4_u1w0;
    }

    if (f) {
        VLOG_INFO("Subtable using Generic Optimized for u0 %d, u1 %d\n",
                  u0_bits, u1_bits);
    }
    return f;
}
