/*
 * Copyright (c) 2021 NVIDIA Corporation.
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

#include <getopt.h>

#include <config.h>

#include "ovs-thread.h"
#include "ovs-rcu.h"
#include "ovstest.h"
#include "util.h"

enum ovsrcu_uaf_type {
    OVSRCU_UAF_QUIESCE,
    OVSRCU_UAF_TRY_QUIESCE,
    OVSRCU_UAF_QUIESCE_START_END,
};

static void *
rcu_uaf_main(void *aux)
{
    enum ovsrcu_uaf_type *type = aux;
    char *xx = xmalloc(2);

    xx[0] = 'a';
    ovsrcu_postpone(free, xx);
    switch (*type) {
    case OVSRCU_UAF_QUIESCE:
        ovsrcu_quiesce();
        break;
    case OVSRCU_UAF_TRY_QUIESCE:
        while (ovsrcu_try_quiesce()) {
            ;
        }
        break;
    case OVSRCU_UAF_QUIESCE_START_END:
        ovsrcu_quiesce_start();
        ovsrcu_quiesce_end();
        break;
    default:
        OVS_NOT_REACHED();
    }
    xx[1] = 'b';

    return NULL;
}

static void
usage(char *test_name)
{
    fprintf(stderr, "Usage: %s <quiesce|try-quiesce|quiesce-start-end>\n",
            test_name);
}

static void
test_rcu_uaf(int argc, char *argv[])
{
    char **args = argv + optind - 1;
    enum ovsrcu_uaf_type type;
    pthread_t quiescer;

    if (argc - optind != 1) {
        usage(args[0]);
        return;
    }

    set_program_name(argv[0]);

    if (!strcmp(args[1], "quiesce")) {
        type = OVSRCU_UAF_QUIESCE;
    } else if (!strcmp(args[1], "try-quiesce")) {
        type = OVSRCU_UAF_TRY_QUIESCE;
    } else if (!strcmp(args[1], "quiesce-start-end")) {
        type = OVSRCU_UAF_QUIESCE_START_END;
    } else {
        usage(args[0]);
        return;
    }

    /* Need to create a separate thread, to support try-quiesce. */
    quiescer = ovs_thread_create("rcu-uaf", rcu_uaf_main, &type);
    xpthread_join(quiescer, NULL);
}

OVSTEST_REGISTER("test-rcu-uaf", test_rcu_uaf);
