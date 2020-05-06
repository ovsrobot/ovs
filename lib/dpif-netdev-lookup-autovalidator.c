/*
 * Copyright (c) 2020 Intel Corporation.
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
#include "dpif-netdev-private.h"
#include "dpif-netdev-lookup.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_lookup_autovalidator);

/* This file implements an automated validator for subtable search
 * implementations. It compares the results of the generic scalar search result
 * with ISA optimized implementations.
 *
 * Note the goal is *NOT* to test the *specialized* versions of subtables, as
 * the compiler performs the specialization - and we rely on the correctness of
 * the compiler to not break those specialized variantes.
 *
 * The goal is to ensure identical results of the different implementations,
 * despite that the implementations may have different methods to get those
 * results.
 *
 * Example: AVX-512 ISA uses different instructions and algorithm to the scalar
 * implementation, however the results (rules[] output) must be the same.
 */

static uint32_t
dpcls_subtable_autovalidator(struct dpcls_subtable *subtable,
                             uint32_t keys_map,
                             const struct netdev_flow_key *keys[],
                             struct dpcls_rule **rules_good)
{
    const uint32_t u0_bit_count = subtable->mf_bits_set_unit0;
    const uint32_t u1_bit_count = subtable->mf_bits_set_unit1;

    /* Scalar generic - the "known correct" version */
    dpcls_subtable_lookup_func lookup_good;
    lookup_good = dpcls_subtable_generic_probe(u0_bit_count, u1_bit_count);

    /* Run actual scalar implemenation to get known good results */
    uint32_t matches_good = lookup_good(subtable, keys_map, keys, rules_good);

    /* Now compare all other implementations against known good results.
     * Note we start iterating from array[2], as 0 is autotester, and 1 is
     * the known-good scalar implementation.
     */
    /* TODO: use BUILD_BUG_ON to check for i = 2 being correct? */

    struct dpcls_subtable_lookup_info_t *lookup_funcs;
    int32_t lookup_func_count = dpcls_subtable_lookup_info_get(&lookup_funcs);
    if (lookup_func_count < 0) {
        VLOG_ERR("failed to get lookup subtable function implementations\n");
        return 0;
    }

    for (int i = 1; i < lookup_func_count; i++) {
        dpcls_subtable_lookup_func lookup_func;
        lookup_func = lookup_funcs[i].probe(u0_bit_count,
                            u1_bit_count);

        /* If its probe returns a function, then test it */
        if (lookup_func) {
            struct dpcls_rule *rules_test[NETDEV_MAX_BURST];
            size_t rules_size = sizeof(struct dpcls_rule *) * NETDEV_MAX_BURST;
            memset(rules_test, 0, rules_size);
            uint32_t matches_test = lookup_func(subtable, keys_map, keys,
                                                rules_test);

            /* Ensure same packets matched against subtable */
            if (matches_good != matches_test) {
                VLOG_ERR("matches_good %d != matches_test %d for func %s\n",
                         matches_good, matches_test, lookup_funcs[i].name);
            }

            /* Ensure rules matched are the same for scalar / others */
            int j;
            ULLONG_FOR_EACH_1 (j, matches_test) {
                ovs_assert(rules_good[j] == rules_test[j]);
            }
        }
    }

    return matches_good;
}

dpcls_subtable_lookup_func
dpcls_subtable_autovalidator_probe(uint32_t u0 OVS_UNUSED,
                                   uint32_t u1 OVS_UNUSED)
{
    /* Always return the same validator tester, it works for all subtables */
    return dpcls_subtable_autovalidator;
}
