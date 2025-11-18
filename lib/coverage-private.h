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

#ifndef COVERAGE_PRIVATE_H
#define COVERAGE_PRIVATE_H 1

#include "coverage.h"

/* The coverage counters. */
extern struct coverage_counter **coverage_counters;
extern size_t n_coverage_counters;
extern size_t allocated_coverage_counters;

extern struct ovs_mutex coverage_mutex;

void coverage_metrics_init(void);

#endif /* COVERAGE_PRIVATE_H */
