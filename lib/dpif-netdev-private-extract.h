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
#ifndef DPIF_NETDEV_AVX512_EXTRACT
#define DPIF_NETDEV_AVX512_EXTRACT 1

/* Forward declarations */
struct dp_packet;
struct miniflow;
struct dp_netdev_pmd_thread;

/* Function pointer prototype to be implemented in the optimized miniflow
 * extract code.
 */
typedef uint32_t (*miniflow_extract_func)(struct dp_netdev_pmd_thread *pmd,
                                          struct dp_packet *packet,
                                          struct miniflow *mf);

/* Today the avx512 implementation of miniflow extract is exposed to DPIF.
 * This will be abstracted like is done in DPCLS, with multiple implementations
 * being available to be selected.
 */

int32_t
miniflow_extract_avx512_probe(void);

int32_t
miniflow_extract_avx512_insert(const char *pattern_string);

uint32_t
miniflow_extract_avx512_study(struct dp_netdev_pmd_thread *pmd,
                              struct dp_packet *packet,
                              struct miniflow *dst);

uint32_t
miniflow_extract_avx512(struct dp_netdev_pmd_thread *pmd,
                        struct dp_packet *packet,
                        struct miniflow *mf);

#endif /* DPIF_NETDEV_AVX512_EXTRACT */
