/*
 * Copyright (c) 2022 Intel.
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

#include "cpu.h"
#include "dp-packet.h"
#include "immintrin.h"
#include "odp-execute-private.h"
#include "odp-netlink.h"
#include "openvswitch/vlog.h"

/* Probe functions to check ISA requirements. */
static bool
avx512_isa_probe(void)
{
    static enum ovs_cpu_isa isa_required[] = {
        OVS_CPU_ISA_X86_AVX512F,
        OVS_CPU_ISA_X86_AVX512BW,
        OVS_CPU_ISA_X86_BMI2,
        OVS_CPU_ISA_X86_AVX512VL,
    };

    bool ret = true;
    for (int i = 0; i < ARRAY_SIZE(isa_required); i++) {
        if (!cpu_has_isa(isa_required[i])) {
            ret = -ENOTSUP;
        }
    }

    return ret;
}

int
action_avx512_init(struct odp_execute_action_impl *self)
{
    if (!avx512_isa_probe()) {
        return -ENOTSUP;
    }

    return 0;
}
