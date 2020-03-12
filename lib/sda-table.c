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

#include <config.h>
#include "sda-table.h"
#include "util.h"

#define SDA_ARRAY_SIZE(ARRAYID) (ARRAYID == 0 ? SDA_TABLE_BASE_SIZE :    \
                            1 << (SDA_TABLE_BASE_SIZE_LOG2 + ARRAYID -1))

static bool
sda_table_find_node_header(struct sda_table *sda, uint32_t id,
                struct sda_table_node **header, bool create_array)
{
    struct sda_table_node *p_array;
    uint32_t array_id, offset;
    uint32_t l1 = leftmost_1bit_idx(id);

    array_id = id < SDA_TABLE_BASE_SIZE ?
             0 : l1 - SDA_TABLE_BASE_SIZE_LOG2 + 1;

    p_array = ovsrcu_get(struct sda_table_node *, &sda->array[array_id]);
    if (p_array == NULL) {
        if (create_array) {
            p_array = xzalloc_cacheline(sizeof(struct sda_table_node) *
                SDA_ARRAY_SIZE(array_id));
            ovsrcu_set(&sda->array[array_id], p_array);
        } else {
            return false;
        }
    }

    offset = id < SDA_TABLE_BASE_SIZE ?
             id : id - (1 << l1);
    *header = p_array + offset;

    return true;
}

bool
sda_table_insert_node(struct sda_table *sda, uint32_t id,
                    struct sda_table_node *new)
{
    struct sda_table_node *header = NULL;

    if (sda_table_find_node_header(sda, id, &header, true)) {
        struct sda_table_node *node = sda_table_node_next_protected(header);
        ovsrcu_set_hidden(&new->next, node);
        ovsrcu_set(&header->next, new);
        return true;
    } else {
        return false;
    }
}

bool
sda_table_remove_node(struct sda_table *sda, uint32_t id,
                        struct sda_table_node *node)
{
    struct sda_table_node *iter = NULL;

    if (sda_table_find_node_header(sda, id, &iter, false)) {
        for (;;) {
            struct sda_table_node *next = sda_table_node_next_protected(iter);

            if (next == node) {
                ovsrcu_set(&iter->next, sda_table_node_next_protected(node));
                return true;
            }
            else if (next == NULL) {
                return false;
            }
            iter = next;
        }
    }

    return false;
}

const struct sda_table_node *
sda_table_find_node(struct sda_table *sda, uint32_t id)
{
    struct sda_table_node * header = NULL;

    if (sda_table_find_node_header(sda, id, &header, false) && header) {
        return sda_table_node_next(header);
    } else {
        return NULL;
    }
}

void
sda_table_destroy(struct sda_table *sda)
{
    if (sda) {
        for (uint32_t i = 0; i < SDA_TABLE_ARRAY_NUM; i++) {
            const struct sda_table_node *b =
                ovsrcu_get(struct sda_table_node *, &sda->array[i]);
            if (b) {
                ovsrcu_postpone(free, &sda->array[i]);
                ovsrcu_set(&sda->array[i], NULL);
            }
        }
    }
}

struct sda_table_cursor
sda_table_cursor_init(const struct sda_table *sda)
{
    struct sda_table_cursor cursor;

    cursor.sda = sda;
    cursor.array_id = 0;
    cursor.offset = 0;
    cursor.node = NULL;

    return cursor;
}

bool
sda_table_cursor_next(struct sda_table_cursor *cursor)
{
    const struct sda_table *sda = cursor->sda;

    if (cursor->node) {
        cursor->node = sda_table_node_next(cursor->node);
        if (cursor->node) {
            return true;
        }
    }

    while (cursor->array_id < SDA_TABLE_ARRAY_NUM) {
        const struct sda_table_node *b =
            ovsrcu_get(struct sda_table_node *, &sda->array[cursor->array_id]);
        if (b == NULL) {
            break;
        }

        while (cursor->offset < SDA_ARRAY_SIZE(cursor->array_id)) {
            cursor->node = sda_table_node_next(b + cursor->offset++);
            if (cursor->node) {
                return true;
            }
        }

        cursor->array_id++;
        cursor->offset = 0;
    }

    return false;
}


