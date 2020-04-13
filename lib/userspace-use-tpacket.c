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
#include "userspace-tso.h"
#include "userspace-use-tpacket.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(userspace_use_tpacket);

static bool use_tpacket = true;

void
userspace_use_tpacket_init(const struct smap *ovs_other_config)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
#ifdef HAVE_TPACKET_V3
        int tpacket_ver = 3;

        if (userspace_tso_enabled()) {
            tpacket_ver = 2;
        }
        if (smap_get_bool(ovs_other_config, "userspace-use-tpacket", true)) {
#ifdef DPDK_NETDEV
            VLOG_INFO("Userspace is using tpacket v%d", tpacket_ver);
#else
            use_tpacket = false;
            VLOG_INFO("Userspace doesn't use tpacket");
#endif
        } else {
            use_tpacket = false;
            VLOG_INFO("Userspace doesn't use tpacket");
        }
#else
        use_tpacket = false;
#endif
        ovsthread_once_done(&once);
    }
}

bool
userspace_use_tpacket(void)
{
    return use_tpacket;
}
