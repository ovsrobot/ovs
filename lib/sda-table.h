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

#ifndef SDA_TABLE_H
#define SDA_TABLE_H 1

#include <config.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "ovs-rcu.h"
#include "util.h"

/* Concurrent scalable direct address table
 * ========================================
 *
 */

/* Scalable direct address table. It is composed of a series of arrays which
 * are dynamically allocated as needed. The size of arrays is 2 ^ 10, 2 ^ 10,
 * 2 ^ 11, 2 ^ 12 ... The index of the elements in each array increases in
 * order,
 * i.e array 0:  0      ~ 2 ^ 10 - 1,
 *     array 1:  2 ^ 10 ~ 2 ^ 11 - 1,
 *     array 2:  2 ^ 11 ~ 2 ^ 12 - 1.
 * When the index of inserted element is out of range of created arrays, a new
 * array needs be allocated.
 *
 *             +--------+-------+--------------------------+-------+
 *  array No.  |    0   |   1   |   2   |   3   |   ...    |   21  |
 *             +----|---+---|---+---|---+---|---+----------+---|---+
 *                  V       V       V       V                  V
 *               +----+   +----+  +----+  +----+
 * array size    |2^10|   |2^10|  |2^11|  |2^12|
 *               +----+   +----+  |    |  |    |
 *                                +----+  |    |
 *                                        |    |
 *                                        |    |
 *                                        +----+
 * If the element index is allocated by id_pool which always returns the lowest
 * available id, the size of the table will be gradually expanded to 2 ^ 10,
 * 2 ^ 11, 2 ^ 12 ...
 *
 * An element of the array is a chain header, whose address can be calculated
 * by index. Computing complexity of the address is O(1) and cost is small. So
 * table lookup has high performance. And sda table can support single writer,
 * multi-reader concurrent access by means of RCU protection.
 */

#define SDA_TABLE_BASE_SIZE_LOG2  10
#define SDA_TABLE_BASE_SIZE (1 << SDA_TABLE_BASE_SIZE_LOG2)
#define SDA_TABLE_ARRAY_NUM (32 - SDA_TABLE_BASE_SIZE_LOG2)

struct sda_table_node {
    OVSRCU_TYPE(struct sda_table_node *) next;
};

struct sda_table_cursor {
    const struct sda_table *sda;
    uint32_t array_id;
    uint32_t offset;
    struct sda_table_node *node;
};

static inline struct sda_table_node *
sda_table_node_next(const struct sda_table_node *node)
{
    return ovsrcu_get(struct sda_table_node *, &node->next);
}

static inline struct sda_table_node *
sda_table_node_next_protected(const struct sda_table_node *node)
{
    return ovsrcu_get_protected(struct sda_table_node *, &node->next);
}

struct sda_table {
     OVSRCU_TYPE(struct sda_table_node *) array[SDA_TABLE_ARRAY_NUM];
};

/* Initializer for an empty sda table. */
#define SDA_TABLE_INITIALIZER { { { NULL } } }

void sda_table_destroy(struct sda_table *sda);
bool sda_table_insert_node(struct sda_table *sda, uint32_t id,
                           struct sda_table_node *new);
bool sda_table_remove_node(struct sda_table *sda, uint32_t id,
                           struct sda_table_node *node);
const struct sda_table_node * sda_table_find_node(struct sda_table *sda,
                                                 uint32_t id);
struct sda_table_cursor sda_table_cursor_init(const struct sda_table *sda);
bool sda_table_cursor_next(struct sda_table_cursor *cursor);

#define SDA_TABLE_NODE_FOR_EACH(NODE, MEMBER, SDA_TABLE_NODE)             \
    for (INIT_CONTAINER(NODE, SDA_TABLE_NODE, MEMBER);                    \
         (NODE) != OBJECT_CONTAINING(NULL, NODE, MEMBER);                 \
         ASSIGN_CONTAINER(NODE, sda_table_node_next(&(NODE)->MEMBER), MEMBER))

#define SDA_TABLE_FOR_EACH_WITH_ID(NODE, MEMBER, ID, SDA_TABLE)          \
    SDA_TABLE_NODE_FOR_EACH(NODE, MEMBER, sda_table_find_node(SDA_TABLE, ID))

#define SDA_TABLE_CURSOR_FOR_EACH__(NODE, CURSOR, MEMBER)   \
    (sda_table_cursor_next(CURSOR)                           \
     ? (INIT_CONTAINER(NODE, (CURSOR)->node, MEMBER),   \
        true)                                           \
     : false)

#define SDA_TABLE_FOR_EACH(NODE, MEMBER, SDA_TABLE) \
        for (struct sda_table_cursor cursor__ =      \
            sda_table_cursor_init(SDA_TABLE);        \
             SDA_TABLE_CURSOR_FOR_EACH__ (NODE, &cursor__, MEMBER);  \
            )

#endif /* sda-table.h */
