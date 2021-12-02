/*
 * Copyright (c) 2021 Intel.
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

#ifndef ODP_EXTRACT_PRIVATE
#define ODP_EXTRACT_PRIVATE 1

#include "odp-execute.h"

/* For __OVS_KEY_ATTR_MAX. */
#include "odp-netlink.h"
#include "dp-packet.h"
#include "ovs-atomic.h"

/* Forward declaration for typedef. */
struct odp_execute_action_impl;

/* Typedef for an initialization function that can initialize each
 * implementation, checking requirements such as CPU ISA.
 */
typedef int32_t (*odp_execute_action_init_func)
                    (struct odp_execute_action_impl *self);

/* Probe function is used to detect if this CPU has the ISA required
 * to run the optimized action implementation.
 * returns one on successful probe.
 * returns negative errno on failure.
 */
typedef int (*odp_execute_action_probe)(void);

/* Structure represents an implementation of the odp actions. */
struct odp_execute_action_impl {
    /* When set, the CPU ISA required for this implementation is available
     * and the implementation can be used.
     */
    bool available;

    /* Name of the implementation. */
    const char *name;

    /* Probe function is used to detect if this CPU has the ISA required
     * to run the optimized miniflow implementation. It is optional and
     * if it is not used, then it must be null.
     */
    odp_execute_action_probe probe;

    /* Called to check requirements and if usable, initializes the
     * implementation for use.
     */
    odp_execute_action_init_func init_func;

    /* An array of callback functions, one for each action. */
    ATOMIC(odp_execute_cb) funcs[__OVS_KEY_ATTR_MAX];
};

/* Order of Actions implementations. */
enum odp_execute_action_impl_idx {
    ACTION_IMPL_SCALAR,
    ACTION_IMPL_AUTOVALIDATOR,
    /* See ACTION_IMPL_BEGIN below, for "first to-be-validated" impl.
     * Do not change the autovalidator position in this list without updating
     * the define below.
     */
    #if (__x86_64__ && HAVE_AVX512F && HAVE_LD_AVX512_GOOD && __SSE4_2__)
    ACTION_IMPL_AVX512,
    #endif

    ACTION_IMPL_MAX,
};

/* Index to start verifying implementations from. */
BUILD_ASSERT_DECL(ACTION_IMPL_SCALAR == 0);
BUILD_ASSERT_DECL(ACTION_IMPL_AUTOVALIDATOR == 1);
#define ACTION_IMPL_BEGIN (ACTION_IMPL_AUTOVALIDATOR + 1)

/* Odp execute init handles setting up the state of the actions functions at
 * initialization time. It cannot return errors, as it must always succeed in
 * initializing the scalar/generic codepath.
 */
void odp_execute_action_init(void);

/* Update the current active functions to those requested in name. */
void odp_execute_action_get(struct ds *name);
int32_t odp_execute_action_set(const char *name,
                               struct odp_execute_action_impl *active);

/* Init function for the scalar implementation. Calls into the odp-execute.c
 * file, and initializes the function pointers for optimized action types.
 */
int32_t odp_action_scalar_init(struct odp_execute_action_impl *self);

/* Init function for the optimized with AVX512 actions. */
int32_t action_avx512_init(void);

/* Probe function to check ISA requirements. */
int32_t action_avx512_probe(void);

#endif /* ODP_EXTRACT_PRIVATE */
