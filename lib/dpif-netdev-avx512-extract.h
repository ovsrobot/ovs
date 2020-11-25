/*
 * Copyright (c) 2020 Intel.
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

#include "flow.h"
#include "dpif-netdev-private-thread.h"

/* TODO: This function accepts a string, which represents the pattern and
 * shuffles required for the users traffic type. Today this function has a
 * hard-coded pattern for Ether()/IP()/UDP() packets.
 *
 * A future revision of this patchset will include the parsing of the input
 * string to create the patterns, providing runtime flexibility in parsing
 * packets into miniflows.
 */
int32_t
miniflow_extract_avx512_insert(const char *pattern_string);

/* The study function runs the patterns from the control-path, and based on
 * some hit statistics can copy the pattern to the per-PMD pattern cache. Part
 * of the study() functionality is also to validate that hits on a pattern
 * result in an identical miniflow as the scalar miniflow_extract() function.
 * This is validated by calling the scalar version, and comparing output.
 */
uint32_t
miniflow_extract_avx512_study(struct dp_netdev_pmd_thread *pmd,
                              struct dp_packet *packet,
                              struct miniflow *dst);
