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
#include "userspace-sock-buf-size.h"

VLOG_DEFINE_THIS_MODULE(userspace_sock_buf_size);

/* Default socket buffer size for system interface is
 * 1073741823, i.e. 1024 * 1024 * 1024 - 1, it can help
 * improve UDP performance, you can tune it per your
 * system by the below command
 *   ovs-vsctl set Open_vSwitch . \
 *     other_config:userspace_sock_buf_size = XXXX
 *
 * 1073741823 is maximum possible value, the value you
 * set must be less than or equal to 1073741823.
 */

/* Minimum socket buffer size, it is Linux default size */
#define MIN_SOCK_BUF_SIZE 212992

/* Maximum possible socket buffer size */
#define MAX_SOCK_BUF_SIZE 1073741823

#define DEFAULT_SOCK_BUF_SIZE MIN_SOCK_BUF_SIZE

static uint32_t userspace_sock_buf_size = DEFAULT_SOCK_BUF_SIZE;

void
userspace_sock_buf_size_init(const struct smap *ovs_other_config)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        uint32_t sock_buf_size;

        sock_buf_size = smap_get_int(ovs_other_config,
                                     "userspace-sock-buf-size",
                                     DEFAULT_SOCK_BUF_SIZE);
        if (sock_buf_size < MIN_SOCK_BUF_SIZE) {
            sock_buf_size = MIN_SOCK_BUF_SIZE;
        } else if (sock_buf_size > MAX_SOCK_BUF_SIZE) {
            sock_buf_size = MAX_SOCK_BUF_SIZE;
        }

        userspace_sock_buf_size = sock_buf_size;
        VLOG_INFO("Userspace socket buffer size for system interface: %d",
                  userspace_sock_buf_size);
        ovsthread_once_done(&once);
    }
}

uint32_t
userspace_get_sock_buf_size(void)
{
    return userspace_sock_buf_size;
}
