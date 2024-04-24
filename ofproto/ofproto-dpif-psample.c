/*
 * Copyright (c) 2024 Red Hat, Inc.
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
#include "ofproto-dpif-psample.h"

#include "dpif.h"
#include "hash.h"
#include "ofproto.h"
#include "openvswitch/hmap.h"
#include "openvswitch/thread.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(psample);

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

struct psample_exporter {
    uint32_t group_id;
    uint32_t collector_set_id;
    uint64_t n_packets;
    uint64_t n_bytes;
};

struct psample_exporter_map_node {
    struct hmap_node node;
    struct psample_exporter exporter;
};

struct dpif_psample {
    struct hmap exporters_map;     /* Contains psample_exporter_map_node. */

    struct ovs_refcount ref_cnt;
};

/* Exporter handling */
static void
dpif_psample_clear(struct dpif_psample *ps) OVS_REQUIRES(mutex)
{
    struct psample_exporter_map_node *node;

    HMAP_FOR_EACH_POP (node, node, &ps->exporters_map) {
        free(node);
    }
}

static struct psample_exporter_map_node*
dpif_psample_new_exporter_node(struct dpif_psample *ps,
                               const struct ofproto_psample_options *options)
    OVS_REQUIRES(mutex)
{
    struct psample_exporter_map_node *node;
    node = xzalloc(sizeof *node);
    node->exporter.collector_set_id = options->collector_set_id;
    node->exporter.group_id = options->group_id;
    hmap_insert(&ps->exporters_map, &node->node,
                hash_int(options->collector_set_id, 0));
    return node;
}

static struct psample_exporter_map_node*
dpif_psample_find_exporter_node(const struct dpif_psample *ps,
                                const uint32_t collector_set_id)
    OVS_REQUIRES(mutex)
{
    struct psample_exporter_map_node *node;
    HMAP_FOR_EACH_WITH_HASH (node, node,
                             hash_int(collector_set_id, 0),
                             &ps->exporters_map) {
        if (node->exporter.collector_set_id == collector_set_id) {
            return node;
        }
    }
    return NULL;
}

/* Configuration. */

/* Sets the psample configuration.
 * Returns true if the configuration has changed. */
bool
dpif_psample_set_options(struct dpif_psample *ps,
                         const struct ovs_list *options_list)
OVS_EXCLUDED(mutex)
{
    struct ofproto_psample_options *options;
    struct psample_exporter_map_node *node;
    bool changed = false;

    ovs_mutex_lock(&mutex);

    /* psample exporters do not hold any runtime memory so we do not need to
     * be extra careful at detecting which exporter changed and which did
     * not. As soon as we detect any change we can just recreate them all. */
    LIST_FOR_EACH(options, list_node, options_list) {
        node = dpif_psample_find_exporter_node(ps, options->collector_set_id);
        if (!node ||
            node->exporter.collector_set_id != options->collector_set_id ||
            node->exporter.group_id != options->group_id) {
            changed = true;
            break;
        }
    }
    changed |= (hmap_count(&ps->exporters_map) != ovs_list_size(options_list));

    if (changed) {
        dpif_psample_clear(ps);
        LIST_FOR_EACH(options, list_node, options_list) {
            dpif_psample_new_exporter_node(ps, options);
        }
    }

    ovs_mutex_unlock(&mutex);

    return changed;
}

/* Returns the group_id of the exporter with the given collector_set_id, if it
 * exists. */
bool
dpif_psample_get_group_id(struct dpif_psample *ps, uint32_t collector_set_id,
                          uint32_t *group_id) OVS_EXCLUDED(mutex)
{

    struct psample_exporter_map_node *node;
    bool found = false;

    ovs_mutex_lock(&mutex);
    node = dpif_psample_find_exporter_node(ps, collector_set_id);
    if (node) {
        found = true;
        *group_id = node->exporter.group_id;
    }
    ovs_mutex_unlock(&mutex);
    return found;
}

void
dpif_psample_credit_stats(struct dpif_psample *ps, uint32_t collector_set_id,
                          const struct dpif_flow_stats *stats)
OVS_EXCLUDED(mutex)
{
    struct psample_exporter_map_node *node;

    ovs_mutex_lock(&mutex);
    node = dpif_psample_find_exporter_node(ps, collector_set_id);
    if (node) {
        node->exporter.n_packets += stats->n_packets;
        node->exporter.n_bytes += stats->n_bytes;
    }
    ovs_mutex_unlock(&mutex);
}


/* Creation and destruction. */
struct dpif_psample *
dpif_psample_create(void)
{
    struct dpif_psample *ps;
    ps = xzalloc(sizeof *ps);
    hmap_init(&ps->exporters_map);
    ovs_refcount_init(&ps->ref_cnt);
    return ps;
}

static void
dpif_psample_destroy(struct dpif_psample *ps) OVS_EXCLUDED(mutex)
{
    if (ps) {
        ovs_mutex_lock(&mutex);
        dpif_psample_clear(ps);
        free(ps);
        ovs_mutex_unlock(&mutex);
    }
}

/* Reference counting. */
struct dpif_psample*
dpif_psample_ref(const struct dpif_psample *ps_)
{
    struct dpif_psample *ps = CONST_CAST(struct dpif_psample*, ps_);
    if (ps) {
        ovs_refcount_ref(&ps->ref_cnt);
    }
    return ps;
}

void
dpif_psample_unref(struct dpif_psample *ps) OVS_EXCLUDED(mutex)
{
    if (ps && ovs_refcount_unref_relaxed(&ps->ref_cnt) == 1) {
        dpif_psample_destroy(ps);
    }
}
