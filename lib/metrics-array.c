/*
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <math.h>
#include <stdint.h>

#include "metrics.h"
#include "metrics-private.h"
#include "openvswitch/util.h"
#include "util.h"

static size_t
metrics_array_size(struct metrics_node *node)
{
    struct metrics_array *a = metrics_node_cast(node);

    return sizeof(struct metrics_array) +
           a->n_entries * sizeof(struct metrics_entry);
}

static size_t
metrics_array_n_values(struct metrics_node *node)
{
    struct metrics_array *a = metrics_node_cast(node);

    return a->n_entries;
}

static void
metrics_array_check_entry(struct metrics_entry *entry)
{
    /* The entry has associated description. */
    ovs_assert(entry->help != NULL);
    /* The entry has a 'public' stable name. */
    ovs_assert(entry->name != NULL);
}

static void
metrics_array_check(struct metrics_node *node)
{
    struct metrics_array *a = metrics_node_cast(node);
    size_t i;

    ovs_assert(a->read != NULL);
    for (i = 0; i < a->n_entries; i++) {
        metrics_array_check_entry(&a->entries[i]);
    }
}

void
metrics_array_read_one(double *values OVS_UNUSED,
                     void *it OVS_UNUSED)
{
    /* This is a dummy function serving as a placeholder. */
}

static void
metrics_array_read_values(struct metrics_node *node,
                        struct metrics_visitor *visitor OVS_UNUSED,
                        double *values)
{
    struct metrics_array *a = metrics_node_cast(node);
    size_t i;

    if (a->read == metrics_array_read_one) {
        for (i = 0; i < a->n_entries; i++) {
            values[i] = 1.;
        }
    } else {
        a->read(values, visitor->it);
    }
}

static void
metrics_array_format_values(struct metrics_node *node,
                          struct metrics_visitor *visitor,
                          double *values)
{
    struct metrics_array *a = metrics_node_cast(node);
    struct format_aux *aux = visitor->ops_aux;
    struct metrics_header *hdr;
    size_t i;

    for (i = 0; i < a->n_entries; i++) {
        hdr = metrics_header_find(aux, node, &a->entries[i]);
        metrics_header_add_line(hdr, NULL, visitor, values[i]);
    }
}

struct metrics_class metrics_class_array = {
    .init = NULL,
    .size = metrics_array_size,
    .n_values = metrics_array_n_values,
    .check = metrics_array_check,
    .read_values = metrics_array_read_values,
    .format_values = metrics_array_format_values,
};
