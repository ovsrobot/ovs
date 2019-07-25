/* Copyright (c) 2019 Nicira, Inc.
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
#include "datapath-config.h"

#include "cmap.h"
#include "ct-dpif.h"
#include "dpif.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(datapath_config);

struct ct_timeout_policy {
    struct uuid uuid;
    unsigned int last_used_seqno;
    unsigned int last_updated_seqno;
    struct ct_dpif_timeout_policy cdtp;
    struct cmap_node node;          /* Element in struct datapath's
                                     * "ct_timeout_policies" cmap. */
};

struct ct_zone {
    uint16_t id;
    unsigned int last_used_seqno;
    struct uuid tp_uuid;            /* uuid that identifies a timeout policy in
                                     * struct datapaths's "ct_tps cmap. */
    struct cmap_node node;          /* Element in struct datapath's "ct_zones"
                                     * cmap. */
};

struct datapath {
    char *type;                     /* Datapath type. */
    char *dpif_backer_name;
    const struct ovsrec_datapath *cfg;

    struct hmap_node node;          /* In 'all_datapaths'. */
    struct cmap ct_zones;           /* "struct ct_zone"s indexed by zone id. */
    struct cmap ct_tps;             /* "struct ct_timeout_policy"s indexed by
                                     * uuid. */
};

/* All datapaths, indexed by type. */
static struct hmap all_datapaths = HMAP_INITIALIZER(&all_datapaths);

static void ct_zone_destroy(struct datapath *, struct ct_zone *);
static void ct_timeout_policy_destroy(struct datapath *,
                                      struct ct_timeout_policy *,
                                      struct dpif *);

static struct datapath *
datapath_lookup(const char *type)
{
    struct datapath *dp;

    HMAP_FOR_EACH_WITH_HASH (dp, node, hash_string(type, 0), &all_datapaths) {
        if (!strcmp(dp->type, type)) {
            return dp;
        }
    }
    return NULL;
}

static void
datapath_clear_timeout_policy(struct datapath *dp)
{
    struct ct_dpif_timeout_policy *tp;
    struct dpif *dpif;
    void *state;
    int err;

    dpif_open(dp->dpif_backer_name, dp->type, &dpif);
    if (!dpif) {
        return;
    }

    err = ct_dpif_timeout_policy_dump_start(dpif, &state);
    if (err) {
        return ;
    }

    while (!(err = ct_dpif_timeout_policy_dump_next(dpif, state, &tp))) {
        ct_dpif_del_timeout_policy(dpif, tp->id);
        free(tp);
    }

    ct_dpif_timeout_policy_dump_done(dpif, state);
    dpif_close(dpif);
}

static struct datapath *
datapath_create(const struct ovsrec_datapath *dp_cfg, const char *type)
{
    struct datapath *dp;

    ovs_assert(!datapath_lookup(type));
    dp = xzalloc(sizeof *dp);

    dp->type = xstrdup(type);
    dp->dpif_backer_name = xasprintf("ovs-%s", type);
    dp->cfg = dp_cfg;

    cmap_init(&dp->ct_zones);
    cmap_init(&dp->ct_tps);

    datapath_clear_timeout_policy(dp);
    hmap_insert(&all_datapaths, &dp->node, hash_string(dp->type, 0));
    return dp;
}

static void
datapath_destroy(struct datapath *dp)
{
    struct ct_zone *zone;
    struct ct_timeout_policy *tp;
    struct dpif *dpif;

    if (dp) {
        CMAP_FOR_EACH (zone, node, &dp->ct_zones) {
            ct_zone_destroy(dp, zone);
        }

        dpif_open(dp->dpif_backer_name, dp->type, &dpif);

        CMAP_FOR_EACH (tp, node, &dp->ct_tps) {
            ct_timeout_policy_destroy(dp, tp, dpif);
        }

        dpif_close(dpif);
        hmap_remove(&all_datapaths, &dp->node);
        cmap_destroy(&dp->ct_zones);
        cmap_destroy(&dp->ct_tps);
        free(dp->type);
        free(dp->dpif_backer_name);
        free(dp);
    }
}

static void
add_del_datapaths(const struct ovsrec_open_vswitch *cfg)
{
    struct datapath *dp, *next;
    struct shash_node *node;
    struct shash new_dp;
    size_t i;

    /* Collect new datapaths' type. */
    shash_init(&new_dp);
    for (i = 0; i < cfg->n_datapaths; i++) {
        const struct ovsrec_datapath *dp_cfg = cfg->value_datapaths[i];
        char *key = cfg->key_datapaths[i];

        if (!strcmp(key, "system") || !strcmp(key, "netdev")) {
            shash_add(&new_dp, key, dp_cfg);
        } else {
            VLOG_WARN("Unsupported dpatapath type %s\n", key);
        }
    }

    /* Get rid of deleted datapath. */
    HMAP_FOR_EACH_SAFE (dp, next, node, &all_datapaths) {
        dp->cfg = shash_find_data(&new_dp, dp->type);
        if (!dp->cfg) {
            datapath_destroy(dp);
        }
    }

    /* Add new datapaths */
    SHASH_FOR_EACH (node, &new_dp) {
        const struct ovsrec_datapath *dp_cfg = node->data;
        if (!datapath_lookup(node->name)) {
            datapath_create(dp_cfg, node->name);
        }
    }

    shash_destroy(&new_dp);
}

static struct ct_zone *
ct_zone_lookup(struct cmap *ct_zones, uint16_t zone_id)
{
    struct ct_zone *zone;

    CMAP_FOR_EACH_WITH_HASH (zone, node, hash_int(zone_id, 0), ct_zones) {
        if (zone->id == zone_id) {
            return zone;
        }
    }
    return NULL;
}

static struct ct_zone *
ct_zone_alloc(uint16_t zone_id)
{
    struct ct_zone *zone;

    zone = xzalloc(sizeof *zone);
    zone->id = zone_id;

    return zone;
}

static void
ct_zone_destroy(struct datapath *dp, struct ct_zone *zone)
{
    cmap_remove(&dp->ct_zones, &zone->node, hash_int(zone->id, 0));
    ovsrcu_postpone(free, zone);
}

static struct ct_timeout_policy *
ct_timeout_policy_lookup(struct cmap *ct_tps, struct uuid *uuid)
{
    struct ct_timeout_policy *tp;

    CMAP_FOR_EACH_WITH_HASH (tp, node, uuid_hash(uuid), ct_tps) {
        if (uuid_equals(&tp->uuid, uuid)) {
            return tp;
        }
    }
    return NULL;
}

static struct ct_timeout_policy *
ct_timeout_policy_alloc(struct ovsrec_ct_timeout_policy *tp_cfg,
                        unsigned int idl_seqno)
{
    struct ct_timeout_policy *tp;
    size_t i;

    tp = xzalloc(sizeof *tp);
    tp->uuid = tp_cfg->header_.uuid;
    for (i = 0; i < tp_cfg->n_timeouts; i++) {
        ct_dpif_set_timeout_policy_attr_by_name(&tp->cdtp,
            tp_cfg->key_timeouts[i], tp_cfg->value_timeouts[i]);
    }
    tp->cdtp.id = idl_seqno;
    tp->last_updated_seqno = idl_seqno;

    return tp;
}

static bool
ct_timeout_policy_update(struct ovsrec_ct_timeout_policy *tp_cfg,
                         struct ct_timeout_policy *tp,
                         unsigned int idl_seqno)
{
    size_t i;
    bool changed = false;

    for (i = 0; i < tp_cfg->n_timeouts; i++) {
        changed |= ct_dpif_set_timeout_policy_attr_by_name(&tp->cdtp,
                        tp_cfg->key_timeouts[i], tp_cfg->value_timeouts[i]);
    }
    if (changed) {
        tp->last_updated_seqno = idl_seqno;
    }
    return changed;
}

static void
ct_timeout_policy_destroy(struct datapath *dp, struct ct_timeout_policy *tp,
                          struct dpif *dpif)
{
    cmap_remove(&dp->ct_tps, &tp->node, uuid_hash(&tp->uuid));
    if (dpif) {
        ct_dpif_del_timeout_policy(dpif, tp->cdtp.id);
    }
    ovsrcu_postpone(free, tp);
}

static void
datapath_update_ct_zone_config(struct datapath *dp, struct dpif *dpif,
                               unsigned int idl_seqno)
{
    const struct ovsrec_datapath *dp_cfg = dp->cfg;
    struct ovsrec_ct_timeout_policy *tp_cfg;
    struct ovsrec_ct_zone *zone_cfg;
    struct ct_timeout_policy *tp;
    struct ct_zone *zone;
    uint16_t zone_id;
    bool new_zone;
    size_t i;

    for (i = 0; i < dp_cfg->n_ct_zones; i++) {
        /* Update ct_zone config */
        zone_cfg = dp_cfg->value_ct_zones[i];
        zone_id = dp_cfg->key_ct_zones[i];
        zone = ct_zone_lookup(&dp->ct_zones, zone_id);
        if (!zone) {
            new_zone = true;
            zone = ct_zone_alloc(zone_id);
        } else {
            new_zone = false;
        }
        zone->last_used_seqno = idl_seqno;

        /* Update timeout policy */
        tp_cfg = zone_cfg->timeout_policy;
        tp = ct_timeout_policy_lookup(&dp->ct_tps, &tp_cfg->header_.uuid);
        if (!tp) {
            tp = ct_timeout_policy_alloc(tp_cfg, idl_seqno);
            cmap_insert(&dp->ct_tps, &tp->node, uuid_hash(&tp->uuid));
            if (dpif) {
                ct_dpif_add_timeout_policy(dpif, false, &tp->cdtp);
            }
        } else {
            if (ct_timeout_policy_update(tp_cfg, tp, idl_seqno)) {
                if (dpif) {
                    ct_dpif_add_timeout_policy(dpif, false, &tp->cdtp);
                }
            }
        }
        tp->last_used_seqno = idl_seqno;

        /* Update default timeout policy */
        if (!zone_id && tp->last_updated_seqno == idl_seqno) {
            ct_dpif_add_timeout_policy(dpif, true, &tp->cdtp);
        }

        /* Link zone with new timeout policy */
        zone->tp_uuid = tp_cfg->header_.uuid;
        if (new_zone) {
            cmap_insert(&dp->ct_zones, &zone->node, hash_int(zone_id, 0));
        }
    }
}

void
reconfigure_datapath(const struct ovsrec_open_vswitch *cfg,
                     unsigned int idl_seqno)
{
    struct ct_timeout_policy *tp;
    struct ct_zone *zone;
    struct datapath *dp;
    struct dpif *dpif;

    add_del_datapaths(cfg);
    HMAP_FOR_EACH (dp, node, &all_datapaths) {
        dpif_open(dp->dpif_backer_name, dp->type, &dpif);

        datapath_update_ct_zone_config(dp, dpif, idl_seqno);

        /* Garbage colleciton */
        CMAP_FOR_EACH (zone, node, &dp->ct_zones) {
            if (zone->last_used_seqno != idl_seqno) {
                ct_zone_destroy(dp, zone);
            }
        }
        CMAP_FOR_EACH (tp, node, &dp->ct_tps) {
            if (tp->last_used_seqno != idl_seqno) {
                ct_timeout_policy_destroy(dp, tp, dpif);
            }
        }

        dpif_close(dpif);
    }
}

void
destroy_all_datapaths(void)
{
    struct datapath *dp, *next_dp;

    HMAP_FOR_EACH_SAFE (dp, next_dp, node, &all_datapaths) {
        datapath_destroy(dp);
    }
}

/* If timeout policy is found in datapath '*dp_type' and in 'zone',
 * sets timeout policy id in '*tp_id' and returns true. Otherwise,
 * returns false. */
bool
datapath_get_zone_timeout_policy_id(const char *dp_type, uint16_t zone,
                                    uint32_t *tp_id)
{
    struct datapath *dp;
    struct ct_zone *ct_zone;
    struct ct_timeout_policy *ct_tp;

    dp = datapath_lookup(dp_type);
    if (!dp) {
        return false;
    }

    ct_zone = ct_zone_lookup(&dp->ct_zones, zone);
    if (!ct_zone) {
        return false;
    }

    ct_tp = ct_timeout_policy_lookup(&dp->ct_tps, &ct_zone->tp_uuid);
    if (!ct_tp) {
        return false;
    }

    *tp_id = ct_tp->cdtp.id;
    return true;
}
