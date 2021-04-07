/*
 * Copyright (c) 2021 Intel Corporation.
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

#ifndef DPIF_NETDEV_PRIVATE_DPIF_H
#define DPIF_NETDEV_PRIVATE_DPIF_H 1

#include "openvswitch/types.h"

/* Forward declarations to avoid including files */
struct dp_netdev_pmd_thread;
struct dp_packet_batch;

/* Typedef for DPIF functions.
 * Returns a bitmask of packets to handle, possibly including upcall/misses.
 */
typedef int32_t (*dp_netdev_input_func)(struct dp_netdev_pmd_thread *pmd,
                                        struct dp_packet_batch *packets,
                                        odp_port_t port_no);

/* Probe a DPIF implementation. This allows the implementation to validate CPU
 * ISA availability. Returns 0 if not available, returns 1 is valid to use.
 */
typedef int32_t (*dp_netdev_input_func_probe)(void);

/* Structure describing each available DPIF implmeentation. */
struct dpif_netdev_impl_info_t {
    /* Function pointer to execute to have this DPIF implementation run. */
    dp_netdev_input_func func;
    /* Function pointer to execute to check the CPU ISA is available to run.
     * May be NULL, which implies that it is always valid to use.
     */
    dp_netdev_input_func_probe probe;
    /* Name used to select this DPIF implementation. */
    const char *name;
};

/* This function returns all available implementations to the caller. The
 * quantity of implementations is returned by the int return value.
 */
uint32_t
dp_netdev_impl_get(const struct dpif_netdev_impl_info_t **out_impls);

/* This function checks all available DPIF implementations, and selects the
 * returns the function pointer to the one requested by "name".
 */
int32_t
dp_netdev_impl_get_by_name(const char *name, dp_netdev_input_func *out_func);

/* Returns the ./configure selected DPIF as default, used to initialize. */
dp_netdev_input_func dp_netdev_impl_get_default(void);

/* Available implementations of DPIF below */
int32_t
dp_netdev_input(struct dp_netdev_pmd_thread *pmd,
                struct dp_packet_batch *packets,
                odp_port_t in_port);

/* AVX512 enabled DPIF implementation and probe functions */
int32_t
dp_netdev_input_outer_avx512_probe(void);
int32_t
dp_netdev_input_outer_avx512(struct dp_netdev_pmd_thread *pmd,
                             struct dp_packet_batch *packets,
                             odp_port_t in_port);

#endif /* netdev-private.h */
