/*
 * Copyright (c) 2020 Inspur, Inc.
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

#include "smap.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"
#include "dpdk.h"
#include "userspace-tso-segsz.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(userspace_tso_segsz);

#define DEFAULT_TSO_SEGSZ 1500
#define MAX_TSO_SEGSZ 9000
static uint16_t userspace_tso_segsz = DEFAULT_TSO_SEGSZ;

void
userspace_tso_segsz_init(const struct smap *ovs_other_config)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        int tso_segsz;

        tso_segsz = smap_get_int(ovs_other_config, "userspace-tso-segsz",
                       DEFAULT_TSO_SEGSZ);
        if ((tso_segsz < 0) || (tso_segsz > MAX_TSO_SEGSZ)) {
            tso_segsz = DEFAULT_TSO_SEGSZ;
        }
        userspace_tso_segsz = tso_segsz;
        VLOG_INFO("Userspace TSO segsz set to %u", userspace_tso_segsz);
        ovsthread_once_done(&once);
    }
}

uint16_t
get_userspace_tso_segsz(void)
{
    return userspace_tso_segsz;
}
