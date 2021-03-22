/*
 * Copyright (c) 2020 Intel Corporation.
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
#include <errno.h>
#include "dpdk.h"
#include "dpif-netdev-lookup.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev_lookup);

#define LOOKUPS_MAX 3
static int subtable_lookups_size = 0;
static struct dpcls_subtable_lookup_info_t subtable_lookups[LOOKUPS_MAX];

void
dpcls_subtable_lookup_register(struct dpcls_subtable_lookup_info_t *lookup)
{
    VLOG_DBG("Registering dpcls subtable lookup implementation: %s"
             ", priority: %d.", lookup->name, lookup->prio);
    ovs_assert(subtable_lookups_size < LOOKUPS_MAX);
    subtable_lookups[subtable_lookups_size++] = *lookup;
}

void
dpcls_subtable_lookup_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (!ovsthread_once_start(&once)) {
        return;
    }

    /* The autovalidator implementation will not be used by default, it must
     * be enabled at compile time to be the default lookup implementation. The
     * user may enable it at runtime using the normal "prio-set" command if
     * desired. The compile time default switch is here to enable all unit
     * tests to transparently run with the autovalidator.
     */
#ifdef DPCLS_AUTOVALIDATOR_DEFAULT
    dpcls_subtable_autovalidator_register(255);
#else
    dpcls_subtable_autovalidator_register(0);
#endif

    dpcls_subtable_generic_register(1);

#if (__x86_64__ && HAVE_AVX512_DPCLS)
    /* Checks below performed here and not inside the _avx512_gather_register
     * function, because implementation of this function is already built with
     * support of these instruction sets.  Need to check here to avoid possible
     * illegal instruction execution. */
    if (dpdk_get_cpu_has_isa("x86_64", "avx512f") &&
        dpdk_get_cpu_has_isa("x86_64", "bmi2")    &&
        dpdk_get_cpu_has_isa("x86_64", "sse4.2")  &&
        dpdk_get_cpu_has_isa("x86_64", "popcnt")) {
        /* Runtime checks succeeded.  Current CPU supports all required
         * instruction sets for avx512 dpcls implementation. */
        dpcls_subtable_avx512_gather_register(0);
    }

#else
    /* Not registering AVX512 support as compile time requirements not met.
     * This could be due to a number of reasons:
     *  1) AVX512 or SSE4.2 instruction set not supported by compiler or
     *     explicitly disabled in compile time.
     *     The SSE4.2 instructions are required to use CRC32 ISA for high-
     *     performance hashing. Check that compiler supports -msse4.2 and
     *     -mavx512f.  Or check that OVS is not configured with -mno-sse4.2,
     *     -mno-avx512f or similar.
     *  2) The assembler in binutils versions 2.30 and 2.31 has bugs in AVX512
     *     assembly. Compile time probes check for this assembler issue, and
     *     disable the HAVE_LD_AVX512_GOOD check if an issue is detected.
     *     Please upgrade binutils, or backport this binutils fix commit:
     *     2069ccaf8dc28ea699bd901fdd35d90613e4402a
     */
#endif
     ovsthread_once_done(&once);
}

int32_t
dpcls_subtable_lookup_info_get(struct dpcls_subtable_lookup_info_t **out_ptr)
{
    if (out_ptr == NULL) {
        return -1;
    }

    *out_ptr = subtable_lookups;
    return subtable_lookups_size;
}

/* sets the priority of the lookup function with "name". */
int32_t
dpcls_subtable_set_prio(const char *name, uint8_t priority)
{
    for (int i = 0; i < subtable_lookups_size; i++) {
        if (strcmp(name, subtable_lookups[i].name) == 0) {
                subtable_lookups[i].prio = priority;
                VLOG_INFO("Subtable function '%s' set priority to %d\n",
                         name, priority);
                return 0;
        }
    }
    VLOG_WARN("Subtable function '%s' not found, failed to set priority\n",
              name);
    return -EINVAL;
}

dpcls_subtable_lookup_func
dpcls_subtable_get_best_impl(uint32_t u0_bit_count, uint32_t u1_bit_count)
{
    /* Iter over each subtable impl, and get highest priority one. */
    int32_t prio = -1;
    const char *name = NULL;
    dpcls_subtable_lookup_func best_func = NULL;

    for (int i = 0; i < subtable_lookups_size; i++) {
        int32_t probed_prio = subtable_lookups[i].prio;
        if (probed_prio > prio) {
            dpcls_subtable_lookup_func probed_func;
            probed_func = subtable_lookups[i].probe(u0_bit_count,
                                    u1_bit_count);
            if (probed_func) {
                best_func = probed_func;
                prio = probed_prio;
                name = subtable_lookups[i].name;
            }
        }
    }

    VLOG_DBG("Subtable lookup function '%s' with units (%d,%d), priority %d\n",
             name, u0_bit_count, u1_bit_count, prio);

    /* Programming error - we must always return a valid func ptr. */
    ovs_assert(best_func != NULL);

    return best_func;
}
