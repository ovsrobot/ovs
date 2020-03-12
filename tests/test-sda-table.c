/*
 * Copyright (c) 2020 Arm Limited.
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

/* A functional test for some of the functions and macros declared in
 * sda-table.h. */

#include <config.h>
#undef NDEBUG
#include "sda-table.h"
#include "id-pool.h"
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include "bitmap.h"
#include "command-line.h"
#include "ovstest.h"
#include "ovs-thread.h"
#include "util.h"

struct element {
    struct sda_table_node node;
};

/* Tests basic sda table insertion and deletion for single node chain. */
static void
test_sda_table_add_del_singlenode_chain(void)
{
    enum { N_ELEMS = 10000 };
    struct element elements[N_ELEMS];
    uint32_t id[N_ELEMS];

    size_t i;
    struct id_pool *pool = id_pool_create(0, UINT32_MAX - 1);
    struct sda_table sda = SDA_TABLE_INITIALIZER;
    const struct sda_table_node * node;
    bool ret;

    for (i = 0; i < N_ELEMS; i++) {
        ret = id_pool_alloc_id(pool, &id[i]);
        ovs_assert(ret == true);

        ret = sda_table_insert_node(&sda, id[i], &elements[id[i]].node);
        ovs_assert(ret == true);

        node = sda_table_find_node(&sda, id[i]);
        ovs_assert(node == &elements[id[i]].node);

        ret = sda_table_remove_node(&sda, id[i], &elements[id[i]].node);
        ovs_assert(ret == true);

        node = sda_table_find_node(&sda, id[i]);
        ovs_assert(node == NULL);

        id_pool_free_id(pool, id[i]);
    }

    sda_table_destroy(&sda);
    id_pool_destroy(pool);
}


static void
test_sda_table_add_del_multinode_chain(void)
{
    enum { N_ELEMS = 10000, N_NODES = 10 };
    struct element elements[N_ELEMS][N_NODES];
    uint32_t id[N_ELEMS];

    struct element *elm;
    size_t i, j;
    struct id_pool *pool = id_pool_create(0, UINT32_MAX - 1);
    struct sda_table  sda = SDA_TABLE_INITIALIZER;
    bool ret;

    for (i = 0; i < N_ELEMS; i++) {
        ret = id_pool_alloc_id(pool, &id[i]);
        ovs_assert(ret == true);

        for (j = 0; j < N_NODES; j++) {
            ret = sda_table_insert_node(&sda, id[i], &elements[id[i]][j].node);
            ovs_assert(ret == true);
        }

        SDA_TABLE_FOR_EACH_WITH_ID (elm, node, id[i], &sda) {
            for (j = 0; j < N_NODES; j++) {
                if (elm == &elements[id[i]][j]) {
                    break;
                }
            }
            ovs_assert(elm == &elements[id[i]][j]);
        }

        for (j = N_NODES / 2; j < N_NODES; j++) {
            ret = sda_table_remove_node(&sda, id[i], &elements[id[i]][j].node);
            ovs_assert(ret == true);
        }

        SDA_TABLE_FOR_EACH_WITH_ID (elm, node, id[i], &sda) {
            for (j = 0; j < N_NODES / 2; j++) {
                if (elm == &elements[id[i]][j]) {
                    break;
                }
            }
            ovs_assert(elm == &elements[id[i]][j]);
        }
    }

    for (i = N_ELEMS / 2; i < N_ELEMS; i++) {
        for (j = 0; j < N_NODES; j++) {
            ret = sda_table_remove_node(&sda, id[i], &elements[id[i]][j].node);
        }
        id_pool_free_id(pool, id[i]);

        SDA_TABLE_FOR_EACH_WITH_ID (elm, node, id[i], &sda) {
            ovs_assert(elm == NULL);
        }
    }

    for (i = 0; i < N_ELEMS / 2; i++) {
        SDA_TABLE_FOR_EACH_WITH_ID (elm, node, id[i], &sda) {
            for (j = 0; j < N_NODES; j++) {
                if (elm == &elements[id[i]][j]) {
                    break;
                }
            }
            ovs_assert(elm == &elements[id[i]][j]);
        }
    }

    sda_table_destroy(&sda);
    id_pool_destroy(pool);
}

static void
test_sda_table_invalid_add_del(void)
{
    enum { N_ELEMS = 10000, N_NODES = 10 };
    struct element elements;

    struct id_pool *pool = id_pool_create(0, UINT32_MAX - 1);
    struct sda_table sda = SDA_TABLE_INITIALIZER;
    bool ret;

    ret = sda_table_insert_node(&sda, SDA_TABLE_BASE_SIZE * 2, &elements.node);
    ovs_assert(ret == true);

    ret = sda_table_remove_node(&sda, SDA_TABLE_BASE_SIZE * 2, &elements.node);
    ovs_assert(ret == true);

    ret = sda_table_remove_node(&sda, SDA_TABLE_BASE_SIZE * 2, &elements.node);
    ovs_assert(ret == false);

    sda_table_destroy(&sda);
    id_pool_destroy(pool);
}


static void
run_tests(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_sda_table_add_del_singlenode_chain();
    test_sda_table_add_del_multinode_chain();
    test_sda_table_invalid_add_del();
    printf("\n");
}

static const struct ovs_cmdl_command commands[] = {
    {"check", NULL, 0, 1, run_tests, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
test_sda_table_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-sda-table", test_sda_table_main);
