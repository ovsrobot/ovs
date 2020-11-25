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

#include <config.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "dpif-netdev-private-extract.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev_extract);

int32_t
miniflow_extract_avx512_probe(void);

int32_t
miniflow_extract_avx512_insert(const char *pattern_string);

uint32_t
miniflow_extract_avx512_study(struct dp_netdev_pmd_thread *pmd,
                              struct dp_packet *packet,
                              struct miniflow *dst);

/* Implementations of available extract opts. */
static struct dpif_miniflow_extract_opt mfex_impl[] = {
    {
        .extract_func = NULL,
        .insert_func = NULL,
        .name = "disable",
    },

/* Only enable AVX512 if compile time criteria are met. */
#if (__x86_64__ && HAVE_AVX512F && HAVE_LD_AVX512_GOOD)
    {
        .extract_func = miniflow_extract_avx512_study,
        .insert_func = miniflow_extract_avx512_insert,
        .name = "avx512",
    },
#endif
};


int32_t
dpif_miniflow_extract_opt_get(const char *name,
                              struct dpif_miniflow_extract_opt **opt)
{
    ovs_assert(opt);

    uint32_t i;
    for (i = 0; i < ARRAY_SIZE(mfex_impl); i++) {
        if (strcmp(name, mfex_impl[i].name) == 0) {
                *opt = &mfex_impl[i];
                return 0;
        }
    }
    return -EINVAL;
}
