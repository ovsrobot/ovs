/*
 * Copyright (c) 2019 Red Hat, Inc.
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

#include "if-notifier-dpdk.h"
#include "ovs-thread.h"
#include "openvswitch/list.h"

static struct ovs_mutex dpdk_notifiers_mutex = OVS_MUTEX_INITIALIZER;
static struct ovs_list dpdk_all_notifiers OVS_GUARDED_BY(dpdk_notifiers_mutex) \
    = OVS_LIST_INITIALIZER(&dpdk_all_notifiers);

struct dpdk_notifier {
    struct ovs_list node;
    dpdk_notify_func *cb;
    void *aux;
};

struct dpdk_notifier *
dpdk_notifier_create(dpdk_notify_func *cb, void *aux)
{
    struct dpdk_notifier *new = xmalloc(sizeof *new);

    ovs_mutex_lock(&dpdk_notifiers_mutex);

    new->cb = cb;
    new->aux = aux;
    ovs_list_push_back(&dpdk_all_notifiers, &new->node);

    ovs_mutex_unlock(&dpdk_notifiers_mutex);

    return new;
}

void
dpdk_notifier_destroy(struct dpdk_notifier *notifier)
{
    if (!notifier) {
        return;
    }

    ovs_mutex_lock(&dpdk_notifiers_mutex);

    ovs_list_remove(&notifier->node);
    free(notifier);

    ovs_mutex_unlock(&dpdk_notifiers_mutex);
}

void
dpdk_notifierr_report_link(void)
{
    struct dpdk_notifier *notifier;

    ovs_mutex_lock(&dpdk_notifiers_mutex);

    LIST_FOR_EACH (notifier, node, &dpdk_all_notifiers) {
        if (!notifier->cb) {
            continue;
        }

        notifier->cb(notifier->aux);
    }

    ovs_mutex_unlock(&dpdk_notifiers_mutex);
}


