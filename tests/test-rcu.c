/*
 * Copyright (c) 2016 Nicira, Inc.
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
#include "fatal-signal.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "ovstest.h"
#include "util.h"

static void *
quiescer_main(void *aux OVS_UNUSED)
{
    /* A new thread must be not be quiescent */
    ovs_assert(!ovsrcu_is_quiescent());
    ovsrcu_quiesce_start();
    /* After the above call it must be quiescent */
    ovs_assert(ovsrcu_is_quiescent());

    return NULL;
}

static void
test_rcu_quiesce(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    pthread_t quiescer;

    quiescer = ovs_thread_create("quiescer", quiescer_main, NULL);

    /* This is the main thread of the process. After spawning its first
     * thread it must not be quiescent. */
    ovs_assert(!ovsrcu_is_quiescent());

    xpthread_join(quiescer, NULL);
}

OVSTEST_REGISTER("test-rcu-quiesce", test_rcu_quiesce);

struct rcu_user_aux {
    bool done;
};

static void
rcu_user_deferred(struct rcu_user_aux *aux)
{
    aux->done = true;
}

static void *
rcu_user_main(void *aux_)
{
    struct rcu_user_aux *aux = aux_;

    ovsrcu_quiesce();

    aux->done = false;
    ovsrcu_postpone(rcu_user_deferred, aux);

    ovsrcu_quiesce();

    return NULL;
}

#define N_THREAD 4

static void
test_rcu(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct rcu_user_aux main_aux = {0};
    struct rcu_user_aux aux[N_THREAD];
    pthread_t users[N_THREAD];
    size_t i;

    memset(aux, 0, sizeof aux);

    for (i = 0; i < ARRAY_SIZE(users); i++) {
        users[i] = ovs_thread_create("user", rcu_user_main, &aux[i]);
    }

    for (i = 0; i < ARRAY_SIZE(users); i++) {
        xpthread_join(users[i], NULL);
    }

    /* Register a last callback and verify that it will be properly executed
     * even if the RCU lib is exited without this thread quiescing.
     */
    ovsrcu_postpone(rcu_user_deferred, &main_aux);

    ovsrcu_exit();

    ovs_assert(main_aux.done);

    for (i = 0; i < ARRAY_SIZE(users); i++) {
        ovs_assert(aux[i].done);
    }
}

OVSTEST_REGISTER("test-rcu", test_rcu);
