/*
 * Copyright (c) 2025 Red Hat, Inc.
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

#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "dpif-provider.h"
#include "id-fpool.h"
#include "netdev-provider.h"
#include "unixctl.h"
#include "util.h"
#include "vswitch-idl.h"

#include "openvswitch/dynamic-string.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload);

static struct vlog_rate_limit rl_dbg = VLOG_RATE_LIMIT_INIT(100, 100);

static struct ovs_mutex dpif_offload_mutex = OVS_MUTEX_INITIALIZER;
static struct shash dpif_offload_classes \
    OVS_GUARDED_BY(dpif_offload_mutex) = \
    SHASH_INITIALIZER(&dpif_offload_classes);
static struct shash dpif_offload_providers \
    OVS_GUARDED_BY(dpif_offload_mutex) = \
    SHASH_INITIALIZER(&dpif_offload_providers);

static const struct dpif_offload_class *base_dpif_offload_classes[] = {
#if defined(__linux__)
    &dpif_offload_tc_class,
#endif
#ifdef DPDK_NETDEV
    &dpif_offload_dpdk_class,
#endif
    /* If you add an offload class to this structure, make sure you also
     * update the dpif_offload_provider_priority_list below. */
    &dpif_offload_dummy_class,
    &dpif_offload_dummy_x_class,
};

static char *dpif_offload_provider_priority_list = "tc,dpdk,dummy,dummy_x";
static atomic_bool dpif_offload_global_enabled = false;
static atomic_bool dpif_offload_rebalance_policy = false;
static struct smap port_order_cfg = SMAP_INITIALIZER(&port_order_cfg);

static int
dpif_offload_register_provider__(const struct dpif_offload_class *class)
    OVS_REQUIRES(dpif_offload_mutex)
{
    int error;

    if (shash_find(&dpif_offload_classes, class->type)) {
        VLOG_WARN("attempted to register duplicate dpif offload class: %s",
                  class->type);
        return EEXIST;
    }

    if (!class->supported_dpif_types) {
        VLOG_WARN("attempted to register a dpif offload class without any "
                  "supported dpifs: %s", class->type);
        return EINVAL;
    }

    error = class->init ? class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize %s dpif offload class: %s",
                  class->type, ovs_strerror(error));
        return error;
    }

    shash_add(&dpif_offload_classes, class->type, class);
    return 0;
}

static int
dpif_offload_register_provider(const struct dpif_offload_class *class)
{
    int error;

    ovs_mutex_lock(&dpif_offload_mutex);
    error = dpif_offload_register_provider__(class);
    ovs_mutex_unlock(&dpif_offload_mutex);

    return error;
}

static void
dpif_offload_show_classes(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    const struct shash_node **list;
    struct ds ds;

    ds_init(&ds);
    ovs_mutex_lock(&dpif_offload_mutex);

    list = shash_sort(&dpif_offload_classes);
    for (size_t i = 0; i < shash_count(&dpif_offload_classes); i++) {
        const struct dpif_offload_class *class = list[i]->data;

        if (i == 0) {
            ds_put_cstr(&ds, "Offload Class     Supported dpif class(es)\n");
            ds_put_cstr(&ds, "----------------  ------------------------\n");
        }

        ds_put_format(&ds, "%-16s  ", list[i]->name);

        for (size_t j = 0; class->supported_dpif_types[j] != NULL; j++) {
            ds_put_format(&ds, "%*s%s\n", j == 0 ? 0 : 18, "",
                          class->supported_dpif_types[j]);
        }
    }

    ovs_mutex_unlock(&dpif_offload_mutex);
    free(list);

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

void
dp_offload_initialize(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (!ovsthread_once_start(&once)) {
        return;
    }

    unixctl_command_register("dpif/offload/classes", NULL, 0, 0,
                             dpif_offload_show_classes, NULL);

    for (int i = 0; i < ARRAY_SIZE(base_dpif_offload_classes); i++) {
        ovs_assert(base_dpif_offload_classes[i]->open
                   && base_dpif_offload_classes[i]->close
                   && base_dpif_offload_classes[i]->can_offload
                   && base_dpif_offload_classes[i]->port_add
                   && base_dpif_offload_classes[i]->port_dump_start
                   && base_dpif_offload_classes[i]->port_dump_next
                   && base_dpif_offload_classes[i]->port_dump_done
                   && base_dpif_offload_classes[i]->get_netdev);

        ovs_assert((base_dpif_offload_classes[i]->flow_dump_create &&
                    base_dpif_offload_classes[i]->flow_dump_next &&
                    base_dpif_offload_classes[i]->flow_dump_destroy &&
                    base_dpif_offload_classes[i]->flow_dump_thread_create &&
                    base_dpif_offload_classes[i]->flow_dump_thread_destroy) ||
                   (!base_dpif_offload_classes[i]->flow_dump_create &&
                    !base_dpif_offload_classes[i]->flow_dump_next &&
                    !base_dpif_offload_classes[i]->flow_dump_destroy &&
                    !base_dpif_offload_classes[i]->flow_dump_thread_create &&
                    !base_dpif_offload_classes[i]->flow_dump_thread_destroy));

        dpif_offload_register_provider(base_dpif_offload_classes[i]);
    }
    ovsthread_once_done(&once);
}

static struct dp_offload*
dpif_offload_get_dp_offload(const struct dpif *dpif)
{
    return ovsrcu_get(struct dp_offload *, &dpif->dp_offload);
}

static int
dpif_offload_attach_provider_to_dp_offload__(struct dp_offload *dp_offload,
                                             struct dpif_offload *offload)
{
    struct ovs_list *providers_list = &dp_offload->offload_providers;
    struct dpif_offload *offload_entry;

    LIST_FOR_EACH (offload_entry, dpif_list_node, providers_list) {
        if (offload_entry == offload || !strcmp(offload->name,
                                                offload_entry->name)) {
            return EEXIST;
        }
    }

    ovs_list_push_back(providers_list, &offload->dpif_list_node);
    return 0;
}

static int
dpif_offload_attach_provider_to_dp_offload(struct dp_offload *dp_offload,
                                           struct dpif_offload *offload)
{
    int error;

    ovs_assert(dp_offload);

    error = dpif_offload_attach_provider_to_dp_offload__(dp_offload, offload);
    return error;
}

static int
dpif_offload_attach_dp_offload(struct dpif *dpif,
                               struct dp_offload *dp_offload)
    OVS_REQUIRES(dpif_offload_mutex)
{
    ovsrcu_set(&dpif->dp_offload, dp_offload);
    ovs_refcount_ref(&dp_offload->ref_cnt);
    return 0;
}

static int
dpif_offload_attach_providers_(struct dpif *dpif)
    OVS_REQUIRES(dpif_offload_mutex)
{
    struct ovs_list provider_list = OVS_LIST_INITIALIZER(&provider_list);
    const char *dpif_type_str = dpif_normalize_type(dpif_type(dpif));
    struct dp_offload *dp_offload;
    struct dpif_offload *offload;
    struct shash_node *node;
    char *tokens, *saveptr;

    /* Allocate and attach dp_offload to dpif. */
    dp_offload = xmalloc(sizeof *dp_offload);
    dp_offload->dpif_name = xstrdup(dpif_name(dpif));
    ovs_mutex_init_recursive(&dp_offload->offload_mutex);
    ovs_refcount_init(&dp_offload->ref_cnt);
    ovs_list_init(&dp_offload->offload_providers);
    shash_add(&dpif_offload_providers, dp_offload->dpif_name, dp_offload);

    /* Open all the providers supporting this dpif type. */
    SHASH_FOR_EACH (node, &dpif_offload_classes) {
        const struct dpif_offload_class *class = node->data;

        for (size_t i = 0; class->supported_dpif_types[i] != NULL; i++) {
            if (!strcmp(class->supported_dpif_types[i], dpif_type_str)) {
                int error = class->open(class, dpif, &offload);
                if (error) {
                    VLOG_WARN("failed to initialize dpif offload provider "
                              "%s for %s: %s",
                              class->type, dpif_name(dpif),
                              ovs_strerror(error));
                } else {
                    ovs_list_push_back(&provider_list,
                                       &offload->dpif_list_node);
                }
                break;
            }
        }
    }

    /* Attach all the providers based on the priority list. */
    tokens = xstrdup(dpif_offload_provider_priority_list);

    for (char *name = strtok_r(tokens, ",", &saveptr);
         name;
         name = strtok_r(NULL, ",", &saveptr)) {

        LIST_FOR_EACH_SAFE (offload, dpif_list_node, &provider_list) {

            if (!strcmp(name, offload->class->type)) {
                int error;

                ovs_list_remove(&offload->dpif_list_node);
                error = dpif_offload_attach_provider_to_dp_offload(dp_offload,
                                                                   offload);
                if (error) {
                    VLOG_WARN(
                        "failed to add dpif offload provider %s to %s: %s",
                        offload->class->type, dpif_name(dpif),
                        ovs_strerror(error));

                    offload->class->close(offload);
                }
                break;
            }
        }
    }
    free(tokens);

    /* Add remaining entries in order. */
    LIST_FOR_EACH_SAFE (offload, dpif_list_node, &provider_list) {
        int error;

        ovs_list_remove(&offload->dpif_list_node);
        error = dpif_offload_attach_provider_to_dp_offload(dp_offload,
                                                           offload);
        if (error) {
            VLOG_WARN("failed to add dpif offload provider %s to %s: %s",
                      offload->class->type, dpif_name(dpif),
                      ovs_strerror(error));

            offload->class->close(offload);
        }
    }

    /* Attach dp_offload to dpif. */
    ovsrcu_set(&dpif->dp_offload, dp_offload);

    return 0;
}

int
dpif_offload_attach_providers(struct dpif *dpif)
{
    struct dp_offload *dp_offload;
    int rc;

    ovs_mutex_lock(&dpif_offload_mutex);

    dp_offload = shash_find_data(&dpif_offload_providers, dpif_name(dpif));
    if (dp_offload) {
        rc = dpif_offload_attach_dp_offload(dpif, dp_offload);
    } else {
        rc = dpif_offload_attach_providers_(dpif);
    }

    ovs_mutex_unlock(&dpif_offload_mutex);
    return rc;
}

static void
dpif_offload_free_dp_offload_rcu(struct dp_offload *dp_offload)
{
    struct dpif_offload *offload_entry;

    /* We need to use the safe variant here as we removed the entry, and the
     * close API will free() it. */
    LIST_FOR_EACH_SAFE (offload_entry, dpif_list_node,
                        &dp_offload->offload_providers)
    {
        char *name = offload_entry->name;

        ovs_list_remove(&offload_entry->dpif_list_node);
        offload_entry->class->close(offload_entry);
        ovsrcu_postpone(free, name);
    }

    /* Free remaining resources. */
    ovs_mutex_destroy(&dp_offload->offload_mutex);
    free(dp_offload->dpif_name);
    free(dp_offload);
}

void
dpif_offload_detach_providers(struct dpif *dpif)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);

    if (dp_offload) {
        /* Take dpif_offload_mutex so that, if dp_offload->ref_cnt falls to
         * zero, we can't get a new reference to 'dp_offload' through the
         * 'dpif_offload_providers' shash. */
        ovs_mutex_lock(&dpif_offload_mutex);
        if (ovs_refcount_unref_relaxed(&dp_offload->ref_cnt) == 1) {
            shash_find_and_delete(&dpif_offload_providers,
                                  dp_offload->dpif_name);
            ovsrcu_postpone(dpif_offload_free_dp_offload_rcu, dp_offload);
        }
         ovs_mutex_unlock(&dpif_offload_mutex);
         ovsrcu_set(&dpif->dp_offload, NULL);
    }
}

void
dpif_offload_set_config(struct dpif *dpif, const struct smap *other_cfg)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    struct dpif_offload *offload;

    if (!dp_offload) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->set_config) {
            offload->class->set_config(offload, other_cfg);
        }
    }
}


void
dpif_offload_init(struct dpif_offload *offload,
                  const struct dpif_offload_class *class,
                  struct dpif *dpif)
{
    ovs_assert(offload && class && dpif);

    offload->class = class;
    offload->name = xasprintf("%s[%s]", class->type, dpif_name(dpif));
}

const char *
dpif_offload_name(const struct dpif_offload *offload)
{
    return offload->name;
}

const char *
dpif_offload_class_type(const struct dpif_offload *offload)
{
    return offload->class->type;
}

bool
dpif_offload_get_debug(const struct dpif_offload *offload, struct ds *ds,
                       struct json *json)
{
    if (!offload->class->get_debug) {
        return false;
    }

    offload->class->get_debug(offload, ds, json);
    return true;
}

bool
dpif_offload_is_offload_enabled(void)
{
    bool enabled;

    atomic_read_relaxed(&dpif_offload_global_enabled, &enabled);
    return enabled;
}

bool
dpif_offload_is_offload_rebalance_policy_enabled(void)
{
    bool enabled;

    atomic_read_relaxed(&dpif_offload_rebalance_policy, &enabled);
    return enabled;
}

void
dpif_offload_set_netdev_offload(struct netdev *netdev,
                                struct dpif_offload *offload)
{
    ovsrcu_set(&netdev->dpif_offload, offload);
}

static bool
dpif_offload_try_port_add(struct dpif_offload *offload, struct netdev *netdev,
                          odp_port_t port_no)
{
    if (offload->class->can_offload(offload, netdev)) {
        int err = offload->class->port_add(offload, netdev, port_no);
        if (!err) {
            VLOG_DBG("netdev %s added to dpif-offload provider %s",
                     netdev_get_name(netdev), dpif_offload_name(offload));
            return true;
        } else {
            VLOG_ERR("Failed adding netdev %s to dpif-offload provider "
                     "%s, error %s",
                     netdev_get_name(netdev), dpif_offload_name(offload),
                     ovs_strerror(err));
        }
    } else {
        VLOG_DBG("netdev %s failed can_offload for dpif-offload provider %s",
                 netdev_get_name(netdev), dpif_offload_name(offload));
    }
    return false;
}

void
dpif_offload_port_add(struct dpif *dpif, struct netdev *netdev,
                      odp_port_t port_no)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    const char *port_priority = smap_get(&port_order_cfg,
                                         netdev_get_name(netdev));
    struct dpif_offload *offload;

    if (!dp_offload) {
        return;
    }

    if (port_priority) {
        char *tokens = xstrdup(port_priority);
        char *saveptr;

        VLOG_DBG("for netdev %s using port priority %s",
                 netdev_get_name(netdev), port_priority);

        for (char *name = strtok_r(tokens, ",", &saveptr);
             name;
             name = strtok_r(NULL, ",", &saveptr)) {
            bool provider_added = false;

            if (!strcmp("none", name)) {
                break;
            }

            LIST_FOR_EACH (offload, dpif_list_node,
                           &dp_offload->offload_providers) {
                if (!strcmp(name, offload->class->type)) {

                    provider_added = dpif_offload_try_port_add(offload, netdev,
                                                               port_no);
                    break;
                }
            }

            if (provider_added) {
                break;
            }
        }
        free(tokens);
    } else {
        LIST_FOR_EACH (offload, dpif_list_node,
                       &dp_offload->offload_providers) {
            if (dpif_offload_try_port_add(offload, netdev, port_no)) {
                break;
            }
        }
    }
}

void
dpif_offload_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    struct dpif_offload *offload;

    if (!dp_offload) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        int err = offload->class->port_del(offload, port_no);
        if (err) {
            VLOG_ERR("Failed deleting port_no %d from dpif-offload provider "
                     "%s, error %s", port_no, dpif_offload_name(offload),
                     ovs_strerror(err));
        }
    }
}

void
dpif_offload_port_set_config(struct dpif *dpif, odp_port_t port_no,
                             const struct smap *cfg)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    struct dpif_offload *offload;

    if (!dp_offload) {
        return;
    }
    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->port_set_config) {
            offload->class->port_set_config(offload, port_no, cfg);
        }
    }
}

struct dpif_offload *
dpif_offload_port_offloaded_by(const struct dpif *dpif, odp_port_t port_no)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    struct dpif_offload *offload, *offload_return = NULL;

    if (!dp_offload || !dpif_offload_is_offload_enabled()) {
        return NULL;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->get_netdev(offload, port_no)) {
            offload_return = offload;
            break;
        }
    }

    return offload_return;
}

void
dpif_offload_dump_start(struct dpif_offload_dump *dump,
                        const struct dpif *dpif)
{
    memset(dump, 0, sizeof *dump);
    dump->dpif = dpif;
}

bool
dpif_offload_dump_next(struct dpif_offload_dump *dump,
                       struct dpif_offload **offload)
{
    struct dp_offload *dp_offload;

    if (!offload || !dump || dump->error) {
        return false;
    }

    dp_offload = dpif_offload_get_dp_offload(dump->dpif);
    if (!dp_offload) {
        return false;
    }

    if (dump->state) {
        /* In theory, list entries should not be removed. However, in case
         * someone calls this during destruction and the node has disappeared,
         * we will return EIDRM (Identifier removed). */
        struct dpif_offload *offload_entry = NULL;

        LIST_FOR_EACH (offload_entry, dpif_list_node,
                       &dp_offload->offload_providers) {
            if (offload_entry == dump->state) {
                if (ovs_list_back(&dp_offload->offload_providers)
                    == &offload_entry->dpif_list_node) {
                        dump->error = EOF;
                } else {
                    *offload = CONTAINER_OF(
                        offload_entry->dpif_list_node.next,
                        struct dpif_offload, dpif_list_node);

                    dump->state = *offload;
                }
                break;
            }
        }

        if (!offload_entry) {
            dump->error = EIDRM;
        }
    } else {
        /* Get the first entry in the list. */
        if (!ovs_list_is_empty(&dp_offload->offload_providers)) {
            *offload = CONTAINER_OF(
                ovs_list_front(&dp_offload->offload_providers),
                struct dpif_offload, dpif_list_node);

            dump->state = *offload;
        } else {
            dump->error = EOF;
        }
    }

    return !dump->error;
}

int
dpif_offload_dump_done(struct dpif_offload_dump *dump)
{
    return dump->error == EOF ? 0 : dump->error;
}

void
dpif_offload_set_global_cfg(const struct ovsrec_open_vswitch *cfg)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    const struct smap *other_cfg = &cfg->other_config;
    const char *priority;

    /* The 'hw-offload-priority' parameter can only be set at startup,
     * any successive change needs a restart. */
    priority = smap_get(other_cfg, "hw-offload-priority");

    if (ovsthread_once_start(&init_once)) {
        /* Initialize the dpif-offload layer in case it's not yet initialized
         * at the first invocation of setting the configuration. */
        dp_offload_initialize();

        /* If priority is not set keep the default value. */
        if (priority) {
            char *tokens = xstrdup(priority);
            char *saveptr;

            dpif_offload_provider_priority_list = xstrdup(priority);

            /* Log a warning for unknown offload providers. */
            for (char *name = strtok_r(tokens, ",", &saveptr);
                 name;
                 name = strtok_r(NULL, ",", &saveptr)) {

                if (!shash_find(&dpif_offload_classes, name)) {
                    VLOG_WARN("'hw-offload-priority' configuration has an "
                              "unknown type; %s", name);
                }
            }
            free(tokens);
        }
        ovsthread_once_done(&init_once);
    } else {
        if (priority && strcmp(priority,
                               dpif_offload_provider_priority_list)) {
            VLOG_INFO_ONCE("'hw-offload-priority' configuration changed; "
                           "restart required");
        }
    }

    /* Handle other global configuration settings.
     *
     * According to the manual the 'hw-offload' parameter requires a restart
     * when changed.  In practice this is only needed on disable, as it will
     * not actually disable hw-offload when requested. */
     if (smap_get_bool(other_cfg, "hw-offload", false)) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once_enable)) {
            atomic_store_relaxed(&dpif_offload_global_enabled, true);
            VLOG_INFO("hw-offload API Enabled");

            if (smap_get_bool(other_cfg, "offload-rebalance", false)) {
                atomic_store_relaxed(&dpif_offload_rebalance_policy, true);
            }

            ovsthread_once_done(&once_enable);
        }
    }

    /* Filter out the 'hw-offload-priority' per port setting we need it before
     * ports are added, so we can assign the correct offload-provider.
     * Note that we can safely rebuild the map here, as we only access this
     * from the same (main) thread. */
    smap_clear(&port_order_cfg);
    for (int i = 0; i < cfg->n_bridges; i++) {
        const struct ovsrec_bridge *br_cfg = cfg->bridges[i];

        for (int j = 0; j < br_cfg->n_ports; j++) {
            const struct ovsrec_port *port_cfg = br_cfg->ports[j];

            priority = smap_get(&port_cfg->other_config,
                                "hw-offload-priority");
            if (priority) {
                smap_add(&port_order_cfg, port_cfg->name, priority);
            }
        }
    }
}

void
dpif_offload_flow_flush(struct dpif *dpif)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    const struct dpif_offload *offload;

    if (!dp_offload) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->flow_flush) {
            int err = offload->class->flow_flush(offload);
            if (err) {
                VLOG_ERR("Failed flow flush on dpif-offload provider "
                    "%s, error %s", dpif_offload_name(offload),
                    ovs_strerror(err));
            }
        }
    }
}

enum dpif_offload_impl_type
dpif_offload_get_impl_type(const struct dpif_offload *offload)
{
    return offload->class->impl_type;
}

enum dpif_offload_impl_type
dpif_offload_get_impl_type_by_class(const char *type)
{
    enum dpif_offload_impl_type impl_type = DPIF_OFFLOAD_IMPL_NONE;
    struct shash_node *node;

    ovs_mutex_lock(&dpif_offload_mutex);
    SHASH_FOR_EACH (node, &dpif_offload_classes) {
        const struct dpif_offload_class *class = node->data;

        if (!strcmp(type, class->type)) {
            impl_type = class->impl_type;
            break;
        }
    }
    ovs_mutex_unlock(&dpif_offload_mutex);

    return impl_type;
}

uint64_t
dpif_offload_flow_get_n_offloaded(const struct dpif *dpif)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    const struct dpif_offload *offload;
    uint64_t flow_count = 0;

    if (!dp_offload || !dpif_offload_is_offload_enabled()) {
        return 0;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->flow_get_n_offloaded) {
            flow_count += offload->class->flow_get_n_offloaded(offload);
        }
    }

    return flow_count;
}

uint64_t
dpif_offload_flow_get_n_offloaded_by_impl(const struct dpif *dpif,
                                          enum dpif_offload_impl_type type)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    const struct dpif_offload *offload;
    uint64_t flow_count = 0;

    if (!dp_offload || !dpif_offload_is_offload_enabled()) {
        return 0;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->flow_get_n_offloaded
            && type == dpif_offload_get_impl_type(offload)) {
            flow_count += offload->class->flow_get_n_offloaded(offload);
        }
    }

    return flow_count;
}

void
dpif_offload_meter_set(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_config *config)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    const struct dpif_offload *offload;

    if (!dp_offload) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->meter_set) {
            int err = offload->class->meter_set(offload, meter_id, config);
            if (err) {
                /* Offload APIs could fail, for example, because the offload
                 * is not supported. This is fine, as the offload API should
                 * take care of this. */
                VLOG_DBG_RL(&rl_dbg,
                            "Failed setting meter %u on dpif-offload provider"
                            " %s, error %s", meter_id.uint32,
                            dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
}

void
dpif_offload_meter_get(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_stats *stats)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    const struct dpif_offload *offload;

    if (!dp_offload) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->meter_get) {
            int err = offload->class->meter_get(offload, meter_id, stats);
            if (err) {
                VLOG_DBG_RL(&rl_dbg,
                            "Failed getting meter %u on dpif-offload provider"
                            " %s, error %s", meter_id.uint32,
                            dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
}

void
dpif_offload_meter_del(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_stats *stats)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    const struct dpif_offload *offload;

    if (!dp_offload) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->meter_del) {
            int err = offload->class->meter_del(offload, meter_id, stats);
            if (err) {
                VLOG_DBG_RL(&rl_dbg,
                            "Failed deleting meter %u on dpif-offload provider"
                            " %s, error %s", meter_id.uint32,
                            dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
}

/*
 * Further initializes a 'struct dpif_flow_dump' that was already initialized
 * by dpif_flow_dump_create(), preparing it for use by
 * dpif_offload_flow_dump_next().
 *
 * For more details, see the documentation of dpif_flow_dump_create(). */
void
dpif_offload_flow_dump_create(struct dpif_flow_dump *dump,
                              const struct dpif *dpif, bool terse)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    const struct dpif_offload *offload;
    size_t n_providers = 0;
    int i = 0;

    if (!dump || !dpif_offload_is_offload_enabled() || !dp_offload) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->flow_dump_create) {
            n_providers++;
        }
    }

    if (!n_providers) {
        return;
    }

    dump->offload_dumps = xmalloc(n_providers * sizeof(
        struct dpif_offload_flow_dump *));

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->flow_dump_create) {
            dump->offload_dumps[i++] = offload->class->flow_dump_create(
                offload, terse);
        }
    }
    dump->n_offload_dumps = i;
    dump->offload_dump_index = 0;
}

/* Destroys the 'dump' data associated with the offload flow dump.
 * This function is called as part of the general dump cleanup
 * by dpif_flow_dump_destroy().
 *
 * Returns 0 if all individual dpif-offload dump operations complete
 * without error.  If one or more providers return an error, the error
 * code from the first failing provider is returned as a positive errno
 * value. */
int
dpif_offload_flow_dump_destroy(struct dpif_flow_dump *dump)
{
    int error = 0;

    for (int i = 0; i < dump->n_offload_dumps; i++) {
        struct dpif_offload_flow_dump *offload_dump = dump->offload_dumps[i];
        const struct dpif_offload *offload = offload_dump->offload;
        int rc = offload->class->flow_dump_destroy(offload_dump);

        if (rc && rc != EOF) {
            VLOG_ERR("Failed flow dumping on dpif-offload provider "
                "%s, error %s", dpif_offload_name(offload),
                ovs_strerror(rc));
            if (!error) {
                error = rc;
            }
        }
    }
    ovs_mutex_destroy(&dump->offload_dump_mutex);
    free(dump->offload_dumps);
    return error;
}

static void
dpif_offload_advance_provider_dump(struct dpif_flow_dump_thread *thread)
{
    struct dpif_flow_dump *dump = thread->dump;

    ovs_mutex_lock(&dump->offload_dump_mutex);

    /* If we haven't finished (dumped all providers). */
    if (dump->offload_dump_index < dump->n_offload_dumps) {
        /* If we are the first to find that current dump is finished
         * advance it. */
        if (thread->offload_dump_index == dump->offload_dump_index) {
            thread->offload_dump_index = ++dump->offload_dump_index;
            /* Did we just finish the last dump? If so we are done. */
            if (dump->offload_dump_index == dump->n_offload_dumps) {
                thread->offload_dump_done = true;
            }
        } else {
            /* otherwise, we are behind, catch up */
            thread->offload_dump_index = dump->offload_dump_index;
        }
    } else {
        /* Some other thread finished. */
        thread->offload_dump_done = true;
    }

    ovs_mutex_unlock(&dump->offload_dump_mutex);
}

/* This function behaves exactly the same as dpif_flow_dump_next(),
 * so see its documentation for details. */
int dpif_offload_flow_dump_next(struct dpif_flow_dump_thread *thread,
                                struct dpif_flow *flows, int max_flows)
{
    int n_flows = 0;

    ovs_assert(max_flows > 0);

    /* The logic here processes all registered offload providers and
     * dumps all related flows. If done (i.e., it returns 0), continue
     * with the next offload provider. */
    while (!thread->offload_dump_done) {
        struct dpif_offload_flow_dump_thread *offload_thread;

        ovs_assert(thread->offload_dump_index < thread->n_offload_threads);
        offload_thread = thread->offload_threads[thread->offload_dump_index];
        n_flows = offload_thread->dump->offload->class->flow_dump_next(
            offload_thread, flows, max_flows);

        if (n_flows > 0) {
            /* If we got some flows, we need to return due to the constraint
             * on returned flows, as explained in dpif_flow_dump_next(). */
            break;
        }
        dpif_offload_advance_provider_dump(thread);
    }
    return MAX(n_flows, 0);
}

/* Further initializes a 'struct dpif_flow_dump_thread' that was already
 * initialized by dpif_flow_dump_thread_create(), preparing it for use by
 * dpif_offload_flow_dump_next(). */
void
dpif_offload_flow_dump_thread_create(struct dpif_flow_dump_thread *thread,
                                     struct dpif_flow_dump *dump)
{
    if (!dpif_offload_is_offload_enabled() || !dump
        || !dump->n_offload_dumps) {
        return;
    }

    thread->n_offload_threads = dump->n_offload_dumps;
    thread->offload_dump_done = false;
    thread->offload_dump_index = 0;
    thread->offload_threads = xmalloc(thread->n_offload_threads * sizeof(
        struct dpif_offload_flow_dump_thread *));

    for (int i = 0; i < dump->n_offload_dumps; i++) {
        struct dpif_offload_flow_dump *offload_dump = dump->offload_dumps[i];
        const struct dpif_offload *offload = offload_dump->offload;

        thread->offload_threads[i] = offload->class->flow_dump_thread_create(
            offload_dump);
    }
}

/* Destroys the 'thread' data associated with the offload flow dump.
 * This function is called as part of the general thread cleanup
 * by dpif_flow_dump_thread_destroy(). */
void
dpif_offload_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread)
{
    for (int i = 0; i < thread->n_offload_threads; i++) {
        struct dpif_offload_flow_dump_thread *offload_thread;
        const struct dpif_offload *offload;

        offload_thread = thread->offload_threads[i];
        offload = offload_thread->dump->offload;
        offload->class->flow_dump_thread_destroy(offload_thread);
    }
    free(thread->offload_threads);
}

static bool
dpif_offload_get_next_offload_for_dump(struct dpif_offload_port_dump *dump)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dump->dpif);
    const struct dpif_offload *offload;
    const struct dpif_offload *prev_offload;

    if (!dp_offload) {
        dump->offload = NULL;
        return false;
    }

    prev_offload = dump->offload;
    dump->offload = NULL;

    LIST_FOR_EACH (offload, dpif_list_node,
                   &dp_offload->offload_providers) {
        if (!prev_offload) {
            /* We need the first offload provider. */
            dump->offload = offload;
            break;
        }
        if (offload->dpif_list_node.next != &dp_offload->offload_providers
            && prev_offload == offload) {
            /* This is the current offload provider, so we need the next
             * one if available.  If not we will exit with !dump->offload. */
            dump->offload = CONTAINER_OF(offload->dpif_list_node.next,
                                         struct dpif_offload, dpif_list_node);
            break;
        }
    }

    return dump->offload ? true : false;
}

void
dpif_offload_port_dump_start(struct dpif_offload_port_dump *dump,
                             const struct dpif *dpif)
{
    memset(dump, 0, sizeof *dump);
    dump->dpif = dpif;
    if (!dpif_offload_get_next_offload_for_dump(dump)) {
        dump->error = EOF;
    } else {
        dump->error = dump->offload->class->port_dump_start(dump->offload,
                                                            &dump->state);
    }
}

bool
dpif_offload_port_dump_next(struct dpif_offload_port_dump *dump,
                            struct dpif_offload_port *port)
{
    const struct dpif_offload *offload = dump->offload;

    while (true) {

        if (dump->error) {
            break;
        }

        dump->error = offload->class->port_dump_next(offload, dump->state,
                                                     port);
        if (dump->error) {
            offload->class->port_dump_done(offload, dump->state);

            if (dump->error != EOF) {
                /* If the error is not EOF, we stop dumping ports from all
                 * providers and return it. */
                break;
            }

            if (dpif_offload_get_next_offload_for_dump(dump)) {
                offload = dump->offload;
                dump->error = offload->class->port_dump_start(offload,
                                                              &dump->state);
                continue;
            }
        }
        break;
    }

    return dump->error ? false : true;
}

int
dpif_offload_port_dump_done(struct dpif_offload_port_dump *dump)
{
    if (!dump->error && dump->offload) {
        dump->error = dump->offload->class->port_dump_done(dump->offload,
                                                           dump->state);
    }
    return dump->error == EOF ? 0 : dump->error;
}

struct netdev *
dpif_offload_offload_get_netdev_by_port_id(struct dpif_offload *offload,
                                           odp_port_t port_no)
{
    if (!dpif_offload_is_offload_enabled() || !offload) {
        return NULL;
    }

    return offload->class->get_netdev(offload, port_no);
}

struct netdev *
dpif_offload_get_netdev_by_port_id(struct dpif *dpif,
                                   struct dpif_offload **offload,
                                   odp_port_t port_no)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    struct dpif_offload *tmp_offload;
    struct netdev *netdev = NULL;

    if (!dp_offload || !dpif_offload_is_offload_enabled()) {
        return NULL;
    }

    LIST_FOR_EACH (tmp_offload, dpif_list_node,
                   &dp_offload->offload_providers) {
        netdev = tmp_offload->class->get_netdev(tmp_offload, port_no);
        if (netdev) {
            if (offload) {
                *offload = tmp_offload;
            }
            break;
        }
    }

    return netdev;
}

bool
dpif_offload_netdevs_out_of_resources(struct dpif *dpif)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    struct dpif_offload_port_dump dump;
    struct dpif_offload_port port;
    bool oor = false;

    if (!dp_offload || !dpif_offload_is_offload_enabled()) {
        return false;
    }

    DPIF_OFFLOAD_PORT_FOR_EACH (&port, &dump, dpif) {
        if (port.netdev->hw_info.oor) {
            oor = true;
            dpif_offload_port_dump_done(&dump);
            break;
        }
    }

    return oor;
}

/* This function tries to offload the operations to the dpif-offload
 * providers. It will return the number of operations not handled, whose
 * pointers are re-arranged and available in **ops. */
size_t
dpif_offload_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                     enum dpif_offload_type offload_type)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);
    const struct dpif_offload *offload;
    size_t n_ops_left = 0;

    if (!dp_offload || !dpif_offload_is_offload_enabled()) {
        return n_ops;
    }

    for (size_t i = 0; i < n_ops; i++) {
        ops[i]->error = -1;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &dp_offload->offload_providers) {
        if (offload->class->operate
            && offload->class->impl_type == DPIF_OFFLOAD_IMPL_HW_ONLY) {

            offload->class->operate(dpif, offload, ops, n_ops);

            for (size_t i = 0; i < n_ops; i++) {
                struct dpif_op *op = ops[i];

                if (op->error == EOPNOTSUPP) {
                    /* Not supported by this offload provider, try next one. */
                    op->error = -1;
                } else {
                    VLOG_DBG("Tried offloading %d to dpif-offload provider "
                             "%s, error %d",
                             op->type,
                             dpif_offload_name(offload), op->error);

                    switch (op->type) {
                    case DPIF_OP_FLOW_PUT:
                        log_flow_put_message(dpif, &this_module,
                                             &op->flow_put, 0);
                        break;
                    case DPIF_OP_FLOW_DEL:
                        log_flow_del_message(dpif, &this_module,
                                             &op->flow_del, 0);
                        break;
                    case DPIF_OP_FLOW_GET:
                        log_flow_get_message(dpif, &this_module,
                                             &op->flow_get, 0);
                        break;
                    case DPIF_OP_EXECUTE:
                        break;
                    }
                }
            }
        }
    }

    for (size_t i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];

        if (offload_type == DPIF_OFFLOAD_ALWAYS) {
          /* For DPIF_OFFLOAD_ALWAYS, we should keep the error values,
           * and mark the unprocessed ones as EOPNOTSUPP. This way, they
           * will not be processed by the dpif layer. */
            if (op->error < 0) {
                op->error = EOPNOTSUPP;
            }
            continue;
        }

        /* For the other offload types, operations that were not handled or
         * failed to offload should be processed by the dpif layer. */
        if (op->error != 0 && op->error != EEXIST) {
            op->error = 0;
            ops[n_ops_left++] = op;
        }
    }

    return n_ops_left;
}

#define MAX_FLOW_MARK       (UINT32_MAX - 1)
#define MAX_FLOW_MARK_USERS 8
static struct id_fpool *flow_mark_pool;

uint32_t
dpif_offload_allocate_flow_mark(void)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int uid = ovsthread_id_self() % MAX_FLOW_MARK_USERS;
    uint32_t flow_mark;

    if (ovsthread_once_start(&init_once)) {
        /* Haven't initiated yet, do it here. */
        flow_mark_pool = id_fpool_create(MAX_FLOW_MARK_USERS, 1,
                                         MAX_FLOW_MARK);
        ovsthread_once_done(&init_once);
    }

    if (id_fpool_new_id(flow_mark_pool, uid, &flow_mark)) {
        return flow_mark;
    }

    return INVALID_FLOW_MARK;
}

void
dpif_offload_free_flow_mark(uint32_t flow_mark)
{
    if (flow_mark != INVALID_FLOW_MARK) {
        unsigned int uid = ovsthread_id_self() % MAX_FLOW_MARK_USERS;

        id_fpool_free_id(flow_mark_pool, uid, flow_mark);
    }
}


bool
dpif_offload_netdev_same_offload(const struct netdev *a,
                                 const struct netdev *b)
{
    const struct dpif_offload *offload_a, *offload_b;

    offload_a = ovsrcu_get(const struct dpif_offload *, &a->dpif_offload);
    offload_b = ovsrcu_get(const struct dpif_offload *, &b->dpif_offload);

    return offload_a == offload_b;
}

int
dpif_offload_netdev_flush_flows(struct netdev *netdev)
{
    const struct dpif_offload *offload;

    offload = ovsrcu_get(const struct dpif_offload *, &netdev->dpif_offload);

    if (offload && offload->class->netdev_flow_flush) {
        return offload->class->netdev_flow_flush(offload, netdev);
    }
    return EOPNOTSUPP;
}

int
dpif_offload_netdev_hw_miss_packet_recover(struct netdev *netdev,
                                           struct dp_packet *packet)
{
    const struct dpif_offload *offload;
    bool miss_api_supported;
    int rc;

    atomic_read_relaxed(&netdev->hw_info.miss_api_supported,
                        &miss_api_supported);
    if (!miss_api_supported) {
        return EOPNOTSUPP;
    }

    offload = ovsrcu_get(const struct dpif_offload *, &netdev->dpif_offload);

    if (!offload || !offload->class->netdev_hw_miss_packet_recover) {
        if (offload) {
            /* Offload is configured and API unsupported by the port;
             * avoid subsequent calls. */
            atomic_store_relaxed(&netdev->hw_info.miss_api_supported, false);
        }
        return EOPNOTSUPP;
    }

    rc = offload->class->netdev_hw_miss_packet_recover(offload, netdev,
                                                       packet);
    if (rc == EOPNOTSUPP) {
        /* API unsupported by the port; avoid subsequent calls. */
        atomic_store_relaxed(&netdev->hw_info.miss_api_supported, false);
    }
    return rc;
}


struct dpif_offload_port_mgr *
dpif_offload_port_mgr_init(void)
{
    struct dpif_offload_port_mgr *mgr = xmalloc(sizeof *mgr);

    ovs_mutex_init(&mgr->cmap_mod_lock);

    cmap_init(&mgr->odp_port_to_port);
    cmap_init(&mgr->netdev_to_port);
    cmap_init(&mgr->ifindex_to_port);

    return mgr;
}

void dpif_offload_port_mgr_uninit(struct dpif_offload_port_mgr *mgr)
{
    if (!mgr) {
        return;
    }

    ovs_assert(cmap_count(&mgr->odp_port_to_port) == 0);
    ovs_assert(cmap_count(&mgr->netdev_to_port) == 0);
    ovs_assert(cmap_count(&mgr->ifindex_to_port) == 0);

    cmap_destroy(&mgr->odp_port_to_port);
    cmap_destroy(&mgr->netdev_to_port);
    cmap_destroy(&mgr->ifindex_to_port);
    free(mgr);
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_find_by_ifindex(struct dpif_offload_port_mgr *mgr,
                                      int ifindex)
{
    struct dpif_offload_port_mgr_port *port;

    if (ifindex < 0) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH (port, ifindex_node, hash_int(ifindex, 0),
                             &mgr->ifindex_to_port)
    {
        if (port->ifindex == ifindex) {
            return port;
        }
    }
    return NULL;
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_find_by_netdev(struct dpif_offload_port_mgr *mgr,
                                     struct netdev *netdev)
{
    struct dpif_offload_port_mgr_port *port;

    if (!netdev) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH (port, netdev_node, hash_pointer(netdev, 0),
                             &mgr->netdev_to_port)
    {
        if (port->netdev == netdev) {
            return port;
        }
    }
    return NULL;
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_find_by_odp_port(struct dpif_offload_port_mgr *mgr,
                                       odp_port_t port_no)
{
    struct dpif_offload_port_mgr_port *port;

    CMAP_FOR_EACH_WITH_HASH (port, odp_port_node,
                             hash_int(odp_to_u32(port_no), 0),
                             &mgr->odp_port_to_port)
    {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_remove(struct dpif_offload_port_mgr *mgr,
                             odp_port_t port_no, bool keep_netdev_ref)
{
    struct dpif_offload_port_mgr_port *port;

    ovs_mutex_lock(&mgr->cmap_mod_lock);

    port = dpif_offload_port_mgr_find_by_odp_port(mgr, port_no);

    if (port) {
        cmap_remove(&mgr->odp_port_to_port, &port->odp_port_node,
                    hash_int(odp_to_u32(port_no), 0));
        cmap_remove(&mgr->netdev_to_port, &port->netdev_node,
                    hash_pointer(port->netdev, 0));

        if (port->ifindex >= 0) {
            cmap_remove(&mgr->ifindex_to_port, &port->ifindex_node,
                        hash_int(port->ifindex, 0));
        }
        if (!keep_netdev_ref) {
            netdev_close(port->netdev);
        }
    }

    ovs_mutex_unlock(&mgr->cmap_mod_lock);
    return port;
}

bool
dpif_offload_port_mgr_add(struct dpif_offload_port_mgr *mgr,
                          struct dpif_offload_port_mgr_port *port,
                          struct netdev *netdev, odp_port_t port_no,
                          bool need_ifindex)
{
    ovs_assert(netdev);

    memset(port, 0, sizeof *port);
    port->netdev = netdev_ref(netdev);
    port->port_no = port_no;
    port->ifindex = need_ifindex ? netdev_get_ifindex(netdev) : -1;

    ovs_mutex_lock(&mgr->cmap_mod_lock);

    if (dpif_offload_port_mgr_find_by_odp_port(mgr, port_no)
        || dpif_offload_port_mgr_find_by_ifindex(mgr, port->ifindex)
        || dpif_offload_port_mgr_find_by_netdev(mgr, port->netdev)) {

        ovs_mutex_unlock(&mgr->cmap_mod_lock);
        return false;
    }

    cmap_insert(&mgr->odp_port_to_port, &port->odp_port_node,
                hash_int(odp_to_u32(port_no), 0));

    cmap_insert(&mgr->netdev_to_port, &port->netdev_node,
                hash_pointer(netdev, 0));

    if (port->ifindex >= 0) {
        cmap_insert(&mgr->ifindex_to_port, &port->ifindex_node,
                    hash_int(port->ifindex, 0));
    }

    ovs_mutex_unlock(&mgr->cmap_mod_lock);
    return true;
}

void
dpif_offload_port_mgr_traverse_ports(
    struct dpif_offload_port_mgr *mgr,
    bool (*cb)(struct dpif_offload_port_mgr_port *, void *),
    void *aux)
{
    struct dpif_offload_port_mgr_port *port;

    CMAP_FOR_EACH (port, odp_port_node, &mgr->odp_port_to_port) {
        if (cb(port, aux)) {
            break;
        }
    }
}

size_t
dpif_offload_port_mgr_port_count(struct dpif_offload_port_mgr *mgr)
{
    return cmap_count(&mgr->odp_port_to_port);
}

struct dpif_offload_port_mgr_dump_state {
    struct netdev *last_netdev;
    size_t port_index;
    size_t port_count;
    odp_port_t ports[];
};

int
dpif_offload_port_mgr_port_dump_start(struct dpif_offload_port_mgr *mgr,
                                      void **statep)
{
    size_t port_count = dpif_offload_port_mgr_port_count(mgr);
    struct dpif_offload_port_mgr_dump_state *state;
    struct dpif_offload_port_mgr_port *port;
    size_t added_port_count = 0;

    state = xmalloc(sizeof *state + (port_count * sizeof(odp_port_t)));

    DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, mgr) {
        if (added_port_count >= port_count) {
            break;
        }

        state->ports[added_port_count] = port->port_no;
        added_port_count++;
    }
    state->port_count = added_port_count;
    state->port_index = 0;
    state->last_netdev = NULL;

    *statep = state;
    return 0;
}

int dpif_offload_port_mgr_port_dump_next(struct dpif_offload_port_mgr *mgr,
                                         void *state_,
                                         struct dpif_offload_port *port)
{
    struct dpif_offload_port_mgr_dump_state *state = state_;
    struct dpif_offload_port_mgr_port *mgr_port;

    while (state->port_index < state->port_count) {

        mgr_port = dpif_offload_port_mgr_find_by_odp_port(
            mgr, state->ports[state->port_index++]);

        if (mgr_port) {
            port->netdev = netdev_ref(mgr_port->netdev);
            port->port_no = mgr_port->port_no;

            netdev_close(state->last_netdev);
            state->last_netdev = port->netdev;
            return 0;
        }
    }

    return EOF;
}

int
dpif_offload_port_mgr_port_dump_done(
    struct dpif_offload_port_mgr *mgr OVS_UNUSED, void *state_)
{
    struct dpif_offload_port_mgr_dump_state *state = state_;

    netdev_close(state->last_netdev);
    free(state);
    return 0;
}

/* XXX: Temporary functions below, which will be removed once fully
 *      refactored. */
struct netdev *dpif_netdev_offload_get_netdev_by_port_id(odp_port_t);
void dpif_netdev_offload_ports_traverse(
    bool (*cb)(struct netdev *, odp_port_t, void *), void *aux);

struct netdev *
dpif_netdev_offload_get_netdev_by_port_id(odp_port_t port_no)
{
    struct dp_offload *dp_offload;
    struct dpif dpif;

    ovs_mutex_lock(&dpif_offload_mutex);
    dp_offload = shash_find_data(&dpif_offload_providers, "netdev@ovs-netdev");
    ovs_mutex_unlock(&dpif_offload_mutex);

    if (!dp_offload) {
        return NULL;
    }

    memset(&dpif, 0, sizeof dpif);
    ovsrcu_set(&dpif.dp_offload, dp_offload);

    return dpif_offload_get_netdev_by_port_id(&dpif, NULL, port_no);
}

void
dpif_netdev_offload_ports_traverse(
    bool (*cb)(struct netdev *, odp_port_t, void *), void *aux)
{
    struct dpif_offload_port_dump dump;
    struct dp_offload *dp_offload;
    struct dpif_offload_port port;
    struct dpif dpif;

    ovs_mutex_lock(&dpif_offload_mutex);
    dp_offload = shash_find_data(&dpif_offload_providers, "netdev@ovs-netdev");
    ovs_mutex_unlock(&dpif_offload_mutex);

    if (!dp_offload) {
        return;
    }

    memset(&dpif, 0, sizeof dpif);
    ovsrcu_set(&dpif.dp_offload, dp_offload);

    DPIF_OFFLOAD_PORT_FOR_EACH (&port, &dump, &dpif) {
        if (cb(port.netdev, port.port_no, aux)) {
            dpif_offload_port_dump_done(&dump);
            break;
        }
    }
}
