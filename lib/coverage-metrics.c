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

#include "coverage.h"
#include "coverage-private.h"
#include "metrics.h"

static void
do_foreach_coverage_counter(metrics_visitor_cb callback,
                            struct metrics_visitor *visitor,
                            struct metrics_node *node,
                            struct metrics_label *labels,
                            size_t n_labels OVS_UNUSED)
{
    struct coverage_counter *c;
    size_t i;

    ovs_mutex_lock(&coverage_mutex);
    for (i = 0; i < n_coverage_counters; i++) {
        c = coverage_counters[i];
        labels[0].value = c->name;
        visitor->it = c;
        callback(visitor, node);
    }
    ovs_mutex_unlock(&coverage_mutex);
}

static void
coverage_metrics_read(double *value, void *c_)
{
    struct coverage_counter *c = c_;

    c->total += c->count();
    *value = c->total;
}

METRICS_SUBSYSTEM(coverage);
METRICS_IF(coverage, coverage_dbg, metrics_dbg_enabled);
METRICS_FOREACH(coverage_dbg, foreach_coverage_counter_dbg,
                do_foreach_coverage_counter, "counter");
METRICS_ENTRIES(foreach_coverage_counter_dbg, coverage_entries,
        "coverage", coverage_metrics_read,
        [0] = METRICS_COUNTER(, "Coverage counters labeled by their name."),
);

void
coverage_metrics_init(void)
{
    METRICS_REGISTER(coverage_entries);
}
