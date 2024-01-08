/*
 * Copyright (c) 2023 Canonical Ltd.
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
#undef NDEBUG
#include "cooperative-multitasking.h"
#include "cooperative-multitasking-private.h"
#include "openvswitch/hmap.h"
#include "ovstest.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

static struct hmap cm_callbacks;

struct fixture_arg {
    bool called;
};

static void
fixture_run(struct fixture_arg *arg)
{
    COOPERATIVE_MULTITASKING_UPDATE(&fixture_run, arg, time_msec(), 0);
    if (arg) {
        arg->called = true;
    }
}

static void
fixture_other_run(struct fixture_arg *arg)
{
    COOPERATIVE_MULTITASKING_UPDATE(&fixture_other_run, arg, time_msec(), 0);
    if (arg) {
        arg->called = true;
    }
}

static void
test_cm_register(void)
{
    struct cooperative_multitasking_callback *cm_entry;
    struct fixture_arg arg1 = {
        .called = false,
    };
    struct fixture_arg arg2 = {
        .called = false,
    };

    timeval_stop();
    long long int now = time_msec();

    COOPERATIVE_MULTITASKING_REGISTER(&fixture_run, &arg1, 1000);
    COOPERATIVE_MULTITASKING_REGISTER(&fixture_run, &arg2, 2000);
    COOPERATIVE_MULTITASKING_REGISTER(&fixture_other_run, NULL, 3000);

    ovs_assert(hmap_count(&cm_callbacks) == 3);

    HMAP_FOR_EACH (cm_entry, node, &cm_callbacks) {
        if (cm_entry->arg == (void *)&arg1) {
            ovs_assert (cm_entry->cb == (void (*)(void *)) &fixture_run);
            ovs_assert (cm_entry->time_threshold == 1000);
            ovs_assert (cm_entry->last_run == now);
        } else if (cm_entry->arg == (void *)&arg2) {
            ovs_assert (cm_entry->cb == (void (*)(void *)) &fixture_run);
            ovs_assert (cm_entry->time_threshold == 2000);
            ovs_assert (cm_entry->last_run == now);
        } else if (cm_entry->cb == (void (*)(void *)) &fixture_other_run) {
            ovs_assert (cm_entry->arg == NULL);
            ovs_assert (cm_entry->time_threshold == 3000);
            ovs_assert (cm_entry->last_run == now);
        } else {
            OVS_NOT_REACHED();
        }
    }

    cooperative_multitasking_destroy();
}

static void
test_cm_update(void)
{
    struct cooperative_multitasking_callback *cm_entry;
    struct fixture_arg arg1 = {
        .called = false,
    };
    struct fixture_arg arg2 = {
        .called = false,
    };

    timeval_stop();
    long long int now = time_msec();

    /* first register a couple of callbacks. */
    COOPERATIVE_MULTITASKING_REGISTER(&fixture_run, &arg1, 0);
    COOPERATIVE_MULTITASKING_REGISTER(&fixture_run, &arg2, 0);

    ovs_assert(hmap_count(&cm_callbacks) == 2);

    HMAP_FOR_EACH (cm_entry, node, &cm_callbacks) {
        if (cm_entry->arg == (void *)&arg1) {
            ovs_assert (cm_entry->time_threshold == 0);
            ovs_assert (cm_entry->last_run == now);
        } else if (cm_entry->arg == (void *)&arg2) {
            ovs_assert (cm_entry->time_threshold == 0);
            ovs_assert (cm_entry->last_run == now);
        } else {
            OVS_NOT_REACHED();
        }
    }

    /* update 'last_run' and 'time_threshold' for each callback and validate
     * that the correct entry was actually updated. */
    COOPERATIVE_MULTITASKING_UPDATE(&fixture_run, &arg1, 1, 2);
    COOPERATIVE_MULTITASKING_UPDATE(&fixture_run, &arg2, 3, 4);

    HMAP_FOR_EACH (cm_entry, node, &cm_callbacks) {
        if (cm_entry->arg == (void *)&arg1) {
            ovs_assert (cm_entry->time_threshold == 2);
            ovs_assert (cm_entry->last_run == 1);
        } else if (cm_entry->arg == (void *)&arg2) {
            ovs_assert (cm_entry->time_threshold == 4);
            ovs_assert (cm_entry->last_run == 3);
        } else {
            OVS_NOT_REACHED();
        }
    }

    /* confirm that providing 0 for 'last_run' or 'time_threshold' leaves the
     * existing value untouched. */
    COOPERATIVE_MULTITASKING_UPDATE(&fixture_run, &arg1, 0, 5);
    COOPERATIVE_MULTITASKING_UPDATE(&fixture_run, &arg2, 6, 0);

    HMAP_FOR_EACH (cm_entry, node, &cm_callbacks) {
        if (cm_entry->arg == (void *)&arg1) {
            ovs_assert (cm_entry->time_threshold == 5);
            ovs_assert (cm_entry->last_run == 1);
        } else if (cm_entry->arg == (void *)&arg2) {
            ovs_assert (cm_entry->time_threshold == 4);
            ovs_assert (cm_entry->last_run == 6);
        } else {
            OVS_NOT_REACHED();
        }
    }

    cooperative_multitasking_destroy();
}

static void
test_cm_yield(void)
{
    struct cooperative_multitasking_callback *cm_entry;
    struct fixture_arg arg1 = {
        .called = false,
    };
    struct fixture_arg arg2 = {
        .called = false,
    };

    timeval_stop();
    long long int now = time_msec();

    /* first register a couple of callbacks. */
    COOPERATIVE_MULTITASKING_REGISTER(&fixture_run, &arg1, 1000);
    COOPERATIVE_MULTITASKING_REGISTER(&fixture_run, &arg2, 2000);

    ovs_assert(hmap_count(&cm_callbacks) == 2);

    /* call to yield should not execute callbacks until time threshold. */
    cooperative_multitasking_yield();
    ovs_assert(arg1.called == false);
    ovs_assert(arg2.called == false);

    HMAP_FOR_EACH (cm_entry, node, &cm_callbacks) {
        ovs_assert(cm_entry->last_run == now);
    }

    /* move clock forward and confirm the expected callbacks to be executed. */
    timeval_warp(0, 1000);
    timeval_stop();
    cooperative_multitasking_yield();
    ovs_assert(arg1.called == true);
    ovs_assert(arg2.called == false);

    /* move clock forward and confirm the expected callbacks to be executed. */
    arg1.called = arg2.called = false;
    timeval_warp(0, 1000);
    timeval_stop();
    cooperative_multitasking_yield();
    ovs_assert(arg1.called == true);
    ovs_assert(arg2.called == true);

    timeval_warp(0, 1);
    cooperative_multitasking_destroy();
}

static void
fixture_buggy_run(struct fixture_arg *arg)
{
    COOPERATIVE_MULTITASKING_UPDATE(&fixture_buggy_run, arg, time_msec(), 0);
    if (arg) {
        arg->called = true;
    }
    /* A real run function MUST NOT directly or indirectly call yield, this is
     * here to test the detection of such a programming error. */
    cooperative_multitasking_yield();
}

static void
test_cooperative_multitasking_nested_yield(int argc OVS_UNUSED, char *argv[])
{
    struct fixture_arg arg1 = {
        .called = false,
    };

    set_program_name(argv[0]);
    vlog_set_pattern(VLF_CONSOLE, "%c|%p|%m");
    vlog_set_levels(NULL, VLF_SYSLOG, VLL_OFF);

    time_msec(); /* ensure timeval is initialized */
    timeval_timewarp_enable();

    cooperative_multitasking_init(&cm_callbacks);

    COOPERATIVE_MULTITASKING_REGISTER(&fixture_buggy_run, &arg1, 1000);
    timeval_warp(0, 1000);
    cooperative_multitasking_yield();
    cooperative_multitasking_destroy();
}

static void
test_cooperative_multitasking(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    time_msec(); /* ensure timeval is initialized */
    timeval_timewarp_enable();

    cooperative_multitasking_init(&cm_callbacks);

    test_cm_register();
    test_cm_update();
    test_cm_yield();
}

OVSTEST_REGISTER("test-cooperative-multitasking",
                 test_cooperative_multitasking);
OVSTEST_REGISTER("test-cooperative-multitasking-nested-yield",
                 test_cooperative_multitasking_nested_yield);
