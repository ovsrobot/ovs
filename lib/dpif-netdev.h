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

#include "cmap.h"
#include "dpif.h"
#include "openvswitch/types.h"
#include "dp-packet.h"
#include "packets.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { DP_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

bool dpif_is_netdev(const struct dpif *);

#define NR_QUEUE   1
#define NR_PMD_THREADS 1

/* Forward declaration for lookup_func typedef. */
struct dpcls_subtable;
struct dpcls_rule;

/* Must be public as it is instantiated in subtable struct below. */
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

/* Lookup function for a subtable in the dpcls. This function is called
 * by each subtable with an array of packets, and a bitmask of packets to
 * perform the lookup on. Using a function pointer gives flexibility to
 * optimize the lookup function based on subtable properties and the
 * CPU instruction set available at runtime.
 */
typedef
uint32_t (*dpcls_subtable_lookup_func)(struct dpcls_subtable *subtable,
                                       uint64_t *blocks_scratch,
                                       uint32_t keys_map,
                                       const struct netdev_flow_key *keys[],
                                       struct dpcls_rule **rules);

/* Prototype for generic lookup func, using same code path as before. */
uint32_t
dpcls_subtable_lookup_generic(struct dpcls_subtable *subtable,
                              uint64_t *blocks_scratch,
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

    /* The lookup function to use for this subtable. From a technical point of
     * view, this is just an implementation of mutliple dispatch. The attribute
     * used to identify the ideal function is the miniflow fingerprint that the
     * subtable matches on. The miniflow "bits" are used to select the actual
     * dpcls lookup implementation at subtable creation time.
     */
    uint8_t mf_bits_set_unit0;
    uint8_t mf_bits_set_unit1;

    /* the lookup function to use for this subtable. If there is a known
     * property of the subtable (eg: only 3 bits of miniflow metadata is
     * used for the lookup) then this can point at an optimized version of
     * the lookup function for this particular subtable. */
    dpcls_subtable_lookup_func lookup_func;

    /* caches the masks to match a packet to, reducing runtime calculations */
    uint64_t *mf_masks;

    struct netdev_flow_key mask; /* Wildcards for fields (const). */
    /* 'mask' must be the last field, additional space is allocated here. */
};

/* Iterate through netdev_flow_key TNL u64 values specified by 'FLOWMAP'. */
#define NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(VALUE, KEY, FLOWMAP)   \
    MINIFLOW_FOR_EACH_IN_FLOWMAP (VALUE, &(KEY)->mf, FLOWMAP)

void
netdev_flow_key_gen_masks(const struct netdev_flow_key *tbl,
                          uint64_t *mf_masks,
                          const uint32_t mf_bits_u0,
                          const uint32_t mf_bits_u1);

bool dpcls_rule_matches_key(const struct dpcls_rule *rule,
                            const struct netdev_flow_key *target);


#ifdef  __cplusplus
}
#endif

#endif /* netdev.h */
