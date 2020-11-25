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

/* Function pointer prototype to be implemented by optimized miniflow extract
 * code, to implement handling a new traffic pattern.
 * Returns 0 on success
 * Returns -ENOTSUP if the CPU does not support the required ISA
 */
typedef int32_t (*template_insert_func)(const char *pattern_string);

/* Structure representing the attributes of an optimized implementation. */
struct dpif_miniflow_extract_opt {
    /* Function to call to extract miniflows from a packet */
    miniflow_extract_func extract_func;

    /* Function called to insert a new traffic pattern. */
    template_insert_func insert_func;

    /* Name of the optimized implementation. */
    char *name;
};

/* Returns the opt structure for the requested implementation by name.
 * Returns zero on success, and opt points to a valid struct, or
 * returns a negative failure status.
 * -EINVAL : invalid name requested
 */
int32_t
dpif_miniflow_extract_opt_get(const char *name,
                              struct dpif_miniflow_extract_opt **opt);

#endif /* DPIF_NETDEV_AVX512_EXTRACT */
