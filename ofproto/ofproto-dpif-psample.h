/*
 * Copyright (c) 2024 Red Hat, Inc.
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

#ifndef OFPROTO_DPIF_PSAMPLE_H
#define OFPROTO_DPIF_PSAMPLE_H 1

#include <stdbool.h>
#include <stdint.h>

struct dpif_flow_stats;
struct dpif_psample;
struct ovs_list;

struct dpif_psample *dpif_psample_create(void);
void dpif_psample_unref(struct dpif_psample *);
struct dpif_psample* dpif_psample_ref(const struct dpif_psample *);

bool dpif_psample_set_options(struct dpif_psample *, const struct ovs_list *);

bool dpif_psample_get_group_id(struct dpif_psample *, uint32_t, uint32_t *);

void dpif_psample_credit_stats(struct dpif_psample *, uint32_t,
                               const struct dpif_flow_stats *);
void dpif_psample_init(void);

#endif // OFPROTO_DPIF_PSAMPLE_H
