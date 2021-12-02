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

#include <config.h>
#include <errno.h>

#include "dpdk.h"
#include "odp-execute-private.h"
#include "odp-netlink.h"
#include "dp-packet.h"
#include "openvswitch/vlog.h"

#include "immintrin.h"


/* Probe functions to check ISA requirements. */
static int32_t
avx512_isa_probe(uint32_t needs_vbmi)
{
    static const char *isa_required[] = {
        "avx512f",
        "avx512bw",
        "bmi2",
        "avx512vl"
    };

    int32_t ret = 0;
    for (uint32_t i = 0; i < ARRAY_SIZE(isa_required); i++) {
        if (!dpdk_get_cpu_has_isa("x86_64", isa_required[i])) {
            ret = -ENOTSUP;
        }
    }

    if (needs_vbmi) {
        if (!dpdk_get_cpu_has_isa("x86_64", "avx512vbmi")) {
            ret = -ENOTSUP;
        }
    }

    return ret;
}

int32_t
action_avx512_probe(void)
{
    const uint32_t needs_vbmi = 0;
    return avx512_isa_probe(needs_vbmi);
}


int32_t
action_avx512_init(void)
{
    avx512_isa_probe(0);
    return 0;
}
