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
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

static struct odp_execute_action_impl action_impls[] = {
    [ACTION_IMPL_AUTOVALIDATOR] = {
        .available = 1,
        .name = "autovalidator",
        .probe = NULL,
        .init_func = action_autoval_init,
    },

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

/* Init sequence required to be scalar first to pick up the default scalar
* implementations, allowing over-riding of the optimized functions later.
*/
BUILD_ASSERT_DECL(ACTION_IMPL_SCALAR == 0);
BUILD_ASSERT_DECL(ACTION_IMPL_AUTOVALIDATOR == 1);

/* Loop over packets, and validate each one for the given action. */
static void
action_autoval_generic(void *dp OVS_UNUSED, struct dp_packet_batch *batch,
                       const struct nlattr *a, bool should_steal)
{
    uint32_t failed = 0;

    int type = nl_attr_type(a);
    enum ovs_action_attr attr_type = (enum ovs_action_attr) type;

    struct odp_execute_action_impl *scalar = &action_impls[ACTION_IMPL_SCALAR];

    struct dp_packet_batch good_batch;
    dp_packet_batch_clone(&good_batch, batch);

    scalar->funcs[attr_type](NULL, &good_batch, a, should_steal);

    for (uint32_t impl = ACTION_IMPL_BEGIN; impl < ACTION_IMPL_MAX; impl++) {
        /* Clone original batch and execute implementation under test. */
        struct dp_packet_batch test_batch;
        dp_packet_batch_clone(&test_batch, batch);
        action_impls[impl].funcs[attr_type](NULL, &test_batch, a,
                                            should_steal);

        /* Loop over implementations, checking each one. */
        for (uint32_t pidx = 0; pidx < batch->count; pidx++) {
            struct dp_packet *good_pkt = good_batch.packets[pidx];
            struct dp_packet *test_pkt = test_batch.packets[pidx];

            struct ds log_msg = DS_EMPTY_INITIALIZER;

            /* Compare packet length and payload contents. */
            bool eq = dp_packet_equal(good_pkt, test_pkt);

            if (!eq) {
                ds_put_format(&log_msg, "Packet: %d\nAction : ", pidx);
                format_odp_actions(&log_msg, a, a->nla_len, NULL);
                ds_put_format(&log_msg, "\nGood hex:\n");
                ds_put_hex_dump(&log_msg, dp_packet_data(good_pkt),
                                dp_packet_size(good_pkt), 0, false);
                ds_put_format(&log_msg, "Test hex:\n");
                ds_put_hex_dump(&log_msg, dp_packet_data(test_pkt),
                                dp_packet_size(test_pkt), 0, false);

                failed = 1;
            }

            /* Compare offsets and RSS */
            if (!dp_packet_compare_and_log(good_pkt, test_pkt, &log_msg)) {
                failed = 1;
            }

            uint32_t good_hash = dp_packet_get_rss_hash(good_pkt);
            uint32_t test_hash = dp_packet_get_rss_hash(test_pkt);

            if (good_hash != test_hash) {
                ds_put_format(&log_msg, "Autovalidation rss hash failed"
                              "\n");
                ds_put_format(&log_msg, "Good RSS hash : %u\n", good_hash);
                ds_put_format(&log_msg, "Test RSS hash : %u\n", test_hash);

                failed = 1;
            }

            if (failed) {
                VLOG_ERR_RL(&rl, "\nAutovalidation failed details:\n%s",
                            ds_cstr(&log_msg));
            }
        }
        dp_packet_delete_batch(&test_batch, 1);
    }
    dp_packet_delete_batch(&good_batch, 1);

    /* Apply the action to the original batch for continued processing. */
    scalar->funcs[attr_type](NULL, batch, a, should_steal);
}

int32_t
action_autoval_init(struct odp_execute_action_impl *self)
{
    self->funcs[OVS_ACTION_ATTR_POP_VLAN] = action_autoval_generic;

    return 0;
}
