/*
 * Copyright (c) 2022 Intel.
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
#include <stdio.h>
#include <string.h>

#include "dpdk.h"
#include "dp-packet.h"
#include "odp-execute-private.h"
#include "odp-netlink.h"
#include "odp-util.h"
#include "openvswitch/vlog.h"


int32_t action_autoval_init(struct odp_execute_action_impl *self);
VLOG_DEFINE_THIS_MODULE(odp_execute_private);
static uint32_t active_action_impl_index;

static struct odp_execute_action_impl action_impls[] = {
    [ACTION_IMPL_SCALAR] = {
        .available = 1,
        .name = "scalar",
        .probe = NULL,
        .init_func = odp_action_scalar_init,
    },
};

static void
action_impl_init_funcs(struct odp_execute_action_impl *to)
{
    for (uint32_t i = 0; i < __OVS_ACTION_ATTR_MAX; i++) {
        atomic_init(&to->funcs[i], NULL);
    }
}

static void
action_impl_copy_funcs(struct odp_execute_action_impl *to,
                       const struct odp_execute_action_impl *from)
{
    for (uint32_t i = 0; i < __OVS_ACTION_ATTR_MAX; i++) {
        atomic_store_relaxed(&to->funcs[i], from->funcs[i]);
    }
}

int32_t
odp_execute_action_set(const char *name,
                       struct odp_execute_action_impl *active)
{
    uint32_t i;
    for (i = 0; i < ACTION_IMPL_MAX; i++) {
        /* String compare, and set ptrs atomically. */
        if (strcmp(action_impls[i].name, name) == 0) {
            action_impl_copy_funcs(active, &action_impls[i]);
            active_action_impl_index = i;
            return 0;
        }
    }
    return -1;
}

void
odp_execute_action_init(void)
{
    /* Call probe on each impl, and cache the result. */
    for (int i = 0; i < ACTION_IMPL_MAX; i++) {
        bool avail = true;
        if (action_impls[i].probe) {
            /* Return zero is success, non-zero means error. */
            avail = (action_impls[i].probe() == 0);
        }
        VLOG_INFO("Action implementation %s (available: %s)\n",
                  action_impls[i].name, avail ? "available" : "not available");
        action_impls[i].available = avail;
    }

    uint32_t i;
    for (i = 0; i < ACTION_IMPL_MAX; i++) {
        /* Initialize Actions function pointers. */
        action_impl_init_funcs(&action_impls[i]);

        /* Each impl's function array is initialized to reflect the scalar
         * implementation. This simplifies adding optimized implementations,
         * as the autovalidator can always compare all actions.
         *
         * Below copies the scalar functions to all other implementations.
         */
        if (i != ACTION_IMPL_SCALAR) {
            action_impl_copy_funcs(&action_impls[i],
                                   &action_impls[ACTION_IMPL_SCALAR]);
        }

        if (action_impls[i].init_func) {
            action_impls[i].init_func(&action_impls[i]);
        }
    }
}
