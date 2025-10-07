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
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "util.h"
#include "tc.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_tc);

/* dpif offload interface for the tc implementation. */
struct dpif_offload_tc {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
};

static struct dpif_offload_tc *
dpif_offload_tc_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_tc_class);
    return CONTAINER_OF(offload, struct dpif_offload_tc, offload);
}

static int
dpif_offload_tc_enable_offload(struct dpif_offload *dpif_offload,
                               struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, dpif_offload);
    return 0;
}

static int
dpif_offload_tc_cleanup_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
                                struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, NULL);
    return 0;
}

static int
dpif_offload_tc_port_add(struct dpif_offload *dpif_offload,
                         struct netdev *netdev, odp_port_t port_no)
{
    struct dpif_offload_tc *offload_tc = dpif_offload_tc_cast(dpif_offload);
    struct dpif_offload_port_mgr_port *port = xmalloc(sizeof *port);

    if (dpif_offload_port_mgr_add(offload_tc->port_mgr, port, netdev,
                                  port_no, true)) {
        if (dpif_offload_is_offload_enabled()) {
            return dpif_offload_tc_enable_offload(dpif_offload, port);
        }
        return 0;
    }

    free(port);
    return EEXIST;
}

static int
dpif_offload_tc_port_del(struct dpif_offload *dpif_offload,
                         odp_port_t port_no)
{
    struct dpif_offload_tc *offload_tc = dpif_offload_tc_cast(dpif_offload);
    struct dpif_offload_port_mgr_port *port;
    int ret = 0;

    port = dpif_offload_port_mgr_remove(offload_tc->port_mgr, port_no, true);
    if (port) {
        if (dpif_offload_is_offload_enabled()) {
            ret = dpif_offload_tc_cleanup_offload(dpif_offload, port);
        }
        netdev_close(port->netdev);
        ovsrcu_postpone(free, port);
    }
    return ret;
}

static int
dpif_offload_tc_open(const struct dpif_offload_class *offload_class,
                     struct dpif *dpif, struct dpif_offload **dpif_offload)
{
    struct dpif_offload_tc *offload_tc;

    offload_tc = xmalloc(sizeof(struct dpif_offload_tc));

    dpif_offload_init(&offload_tc->offload, offload_class, dpif);
    offload_tc->port_mgr = dpif_offload_port_mgr_init();
    offload_tc->once_enable = (struct ovsthread_once) \
                              OVSTHREAD_ONCE_INITIALIZER;

    *dpif_offload = &offload_tc->offload;
    return 0;
}

static bool
dpif_offload_tc_cleanup_port(struct dpif_offload_port_mgr_port *port,
                             void *aux)
{
    struct dpif_offload *offload = aux;

    dpif_offload_tc_port_del(offload, port->port_no);
    return false;
}

static void
dpif_offload_tc_close(struct dpif_offload *dpif_offload)
{
    struct dpif_offload_tc *offload_tc = dpif_offload_tc_cast(dpif_offload);

    dpif_offload_port_mgr_traverse_ports(offload_tc->port_mgr,
                                         dpif_offload_tc_cleanup_port,
                                         dpif_offload);

    dpif_offload_port_mgr_uninit(offload_tc->port_mgr);
    free(offload_tc);
}

static bool dpif_offload_tc_late_enable(struct dpif_offload_port_mgr_port *p,
                                        void *aux)
{
    dpif_offload_tc_enable_offload(aux, p);
    return false;
}

static void
dpif_offload_tc_set_config(struct dpif_offload *offload,
                           const struct smap *other_cfg)
{
    struct dpif_offload_tc *offload_tc = dpif_offload_tc_cast(offload);

    /* We maintain the existing behavior where global configurations
     * are only accepted when hardware offload is initially enabled.
     * Once enabled, they cannot be updated or reconfigured. */
    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload_tc->once_enable)) {

            tc_set_policy(smap_get_def(other_cfg, "tc-policy",
                                       TC_POLICY_DEFAULT));

            dpif_offload_port_mgr_traverse_ports(offload_tc->port_mgr,
                                                 dpif_offload_tc_late_enable,
                                                 offload);

            ovsthread_once_done(&offload_tc->once_enable);
        }
    }
}

static bool
dpif_offload_tc_can_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
                            struct netdev *netdev)
{
    if (netdev_vport_is_vport_class(netdev->netdev_class) &&
        strcmp(netdev_get_dpif_type(netdev), "system")) {
        VLOG_DBG("%s: vport doesn't belong to the system datapath, skipping",
                 netdev_get_name(netdev));
        return false;
    }
    return true;
}

struct dpif_offload_class dpif_offload_tc_class = {
    .type = "tc",
    .supported_dpif_types = (const char *const[]) {
        "system",
        NULL},
    .open = dpif_offload_tc_open,
    .close = dpif_offload_tc_close,
    .set_config = dpif_offload_tc_set_config,
    .can_offload = dpif_offload_tc_can_offload,
    .port_add = dpif_offload_tc_port_add,
    .port_del = dpif_offload_tc_port_del,
};
