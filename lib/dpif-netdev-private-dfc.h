/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
 * Copyright (c) 2019, 2020, 2021 Intel Corporation.
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

#ifndef DPIF_NETDEV_PRIVATE_DFC_H
#define DPIF_NETDEV_PRIVATE_DFC_H 1

#include <stdbool.h>
#include <stdint.h>

#include "dpif.h"
#include "dpif-netdev-private-dpcls.h"
#include "dpif-netdev-private-flow.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* EMC cache and SMC cache compose the datapath flow cache (DFC)
 *
 * Exact match cache for frequently used flows
 *
 * The cache uses a 32-bit hash of the packet (which can be the RSS hash) to
 * search its entries for a miniflow that matches exactly the miniflow of the
 * packet. It stores the 'dpcls_rule' (rule) that matches the miniflow.
 *
 * A cache entry holds a reference to its 'dp_netdev_flow'.
 *
 * A miniflow with a given hash can be in one of EM_FLOW_HASH_SEGS different
 * entries. The 32-bit hash is split into EM_FLOW_HASH_SEGS values (each of
 * them is EM_FLOW_HASH_SHIFT bits wide and the remainder is thrown away). Each
 * value is the index of a cache entry where the miniflow could be.
 *
 *
 * Signature match cache (SMC)
 *
 * This cache stores a 16-bit signature for each flow without storing keys, and
 * stores the corresponding 16-bit flow_table index to the 'dp_netdev_flow'.
 * Each flow thus occupies 32bit which is much more memory efficient than EMC.
 * SMC uses a set-associative design that each bucket contains
 * SMC_ENTRY_PER_BUCKET number of entries.
 * Since 16-bit flow_table index is used, if there are more than 2^16
 * dp_netdev_flow, SMC will miss them that cannot be indexed by a 16-bit value.
 *
 *
 * Thread-safety
 * =============
 *
 * Each pmd_thread has its own private exact match cache.
 * If dp_netdev_input is not called from a pmd thread, a mutex is used.
 */

#define EM_FLOW_HASH_SHIFT 13
#define EM_FLOW_HASH_ENTRIES (1u << EM_FLOW_HASH_SHIFT)
#define EM_FLOW_HASH_MASK (EM_FLOW_HASH_ENTRIES - 1)
#define EM_FLOW_HASH_SEGS 2

/* SMC uses a set-associative design. A bucket contains a set of entries that
 * a flow item can occupy. For now, it uses one hash function rather than two
 * as for the EMC design. */
#define SMC_ENTRY_PER_BUCKET 4
#define SMC_ENTRIES (1u << 20)
#define SMC_BUCKET_CNT (SMC_ENTRIES / SMC_ENTRY_PER_BUCKET)
#define SMC_MASK (SMC_BUCKET_CNT - 1)

/* Default EMC insert probability is 1 / DEFAULT_EM_FLOW_INSERT_INV_PROB */
#define DEFAULT_EM_FLOW_INSERT_INV_PROB 100
#define DEFAULT_EM_FLOW_INSERT_MIN (UINT32_MAX /                     \
                                    DEFAULT_EM_FLOW_INSERT_INV_PROB)

/* Forward declaration for SMC function prototype. */
struct dp_netdev_pmd_thread;

struct emc_entry {
    struct dp_netdev_flow *flow;
    struct netdev_flow_key key;   /* key.hash used for emc hash value. */
};

struct emc_cache {
    struct emc_entry entries[EM_FLOW_HASH_ENTRIES];
    int sweep_idx;                /* For emc_cache_slow_sweep(). */
};

struct smc_bucket {
    uint16_t sig[SMC_ENTRY_PER_BUCKET];
    uint16_t flow_idx[SMC_ENTRY_PER_BUCKET];
};

/* Signature match cache, differentiate from EMC cache */
struct smc_cache {
    struct smc_bucket buckets[SMC_BUCKET_CNT];
};

struct dfc_cache {
    struct emc_cache emc_cache;
    struct smc_cache smc_cache;
};

/* Iterate in the exact match cache through every entry that might contain a
 * miniflow with hash 'HASH'. */
#define EMC_FOR_EACH_POS_WITH_HASH(EMC, CURRENT_ENTRY, HASH)                 \
    for (uint32_t i__ = 0, srch_hash__ = (HASH);                             \
         (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ & EM_FLOW_HASH_MASK], \
         i__ < EM_FLOW_HASH_SEGS;                                            \
         i__++, srch_hash__ >>= EM_FLOW_HASH_SHIFT)

static inline bool
emc_entry_alive(struct emc_entry *ce)
{
    return ce->flow && !ce->flow->dead;
}

static inline void
emc_clear_entry(struct emc_entry *ce)
{
    if (ce->flow) {
        dp_netdev_flow_unref(ce->flow);
        ce->flow = NULL;
    }
}

static inline void
smc_clear_entry(struct smc_bucket *b, int idx)
{
    b->flow_idx[idx] = UINT16_MAX;
}

static inline void
emc_cache_init(struct emc_cache *flow_cache)
{
    int i;

    flow_cache->sweep_idx = 0;
    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        flow_cache->entries[i].flow = NULL;
        flow_cache->entries[i].key.hash = 0;
        flow_cache->entries[i].key.len = sizeof(struct miniflow);
        flowmap_init(&flow_cache->entries[i].key.mf.map);
    }
}

static inline void
smc_cache_init(struct smc_cache *smc_cache)
{
    int i, j;
    for (i = 0; i < SMC_BUCKET_CNT; i++) {
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
            smc_cache->buckets[i].flow_idx[j] = UINT16_MAX;
        }
    }
}

static inline void
dfc_cache_init(struct dfc_cache *flow_cache)
{
    emc_cache_init(&flow_cache->emc_cache);
    smc_cache_init(&flow_cache->smc_cache);
}

static inline void
emc_cache_uninit(struct emc_cache *flow_cache)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        emc_clear_entry(&flow_cache->entries[i]);
    }
}

static inline void
smc_cache_uninit(struct smc_cache *smc)
{
    int i, j;

    for (i = 0; i < SMC_BUCKET_CNT; i++) {
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
            smc_clear_entry(&(smc->buckets[i]), j);
        }
    }
}

static inline void
dfc_cache_uninit(struct dfc_cache *flow_cache)
{
    smc_cache_uninit(&flow_cache->smc_cache);
    emc_cache_uninit(&flow_cache->emc_cache);
}

/* Check and clear dead flow references slowly (one entry at each
 * invocation).  */
static inline void
emc_cache_slow_sweep(struct emc_cache *flow_cache)
{
    struct emc_entry *entry = &flow_cache->entries[flow_cache->sweep_idx];

    if (!emc_entry_alive(entry)) {
        emc_clear_entry(entry);
    }
    flow_cache->sweep_idx = (flow_cache->sweep_idx + 1) & EM_FLOW_HASH_MASK;
}

/* Used to compare 'netdev_flow_key' in the exact match cache to a miniflow.
 * The maps are compared bitwise, so both 'key->mf' and 'mf' must have been
 * generated by miniflow_extract. */
static inline bool
emc_flow_key_equal_mf(const struct netdev_flow_key *key,
                         const struct miniflow *mf)
{
    return !memcmp(&key->mf, mf, key->len);
}

static inline struct dp_netdev_flow *
emc_lookup(struct emc_cache *cache, const struct netdev_flow_key *key)
{
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) {
        if (current_entry->key.hash == key->hash
            && emc_entry_alive(current_entry)
            && emc_flow_key_equal_mf(&current_entry->key, &key->mf)) {

            /* We found the entry with the 'key->mf' miniflow */
            return current_entry->flow;
        }
    }

    return NULL;
}

struct dp_netdev_flow *
smc_lookup_single(struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet *packet,
                  struct netdev_flow_key *key);

#ifdef  __cplusplus
}
#endif

#endif /* dpif-netdev-private-dfc.h */
