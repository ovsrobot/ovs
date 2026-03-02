/*
 * Copyright (c) 2025 Red Hat, Inc.
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

/* Weak stub definitions for DPDK symbols referenced by libopenvswitch objects.
 *
 * These stubs are compiled into libopenvswitch.a in a separate translation
 * unit from dpdk-stub.c.  This separation is critical: when linking
 * ovs-vswitchd (which also links libopenvswitchdpdk.a with real DPDK
 * definitions), the linker must be able to pull in these stubs without
 * also pulling in the dpdk-stub.o definitions of dpdk_init, dpdk_status,
 * etc., which would conflict with the real ones in dpdk.o.
 *
 * The stubs are declared OVS_WEAK so that if this object file is pulled
 * into ovs-vswitchd (e.g. to resolve rte_get_tsc_hz), the weak
 * free_dpdk_buf won't conflict with the strong definition in
 * netdev-dpdk.o. */

#include <config.h>

#ifdef DPDK_NETDEV

#include <stdint.h>

#include "dp-packet.h"
#include "util.h"

OVS_WEAK void
free_dpdk_buf(struct dp_packet *buf OVS_UNUSED)
{
    /* Should never be called in binaries not linked with DPDK.
     * DPBUF_DPDK packets cannot exist without DPDK initialization. */
    OVS_NOT_REACHED();
}

OVS_WEAK uint64_t
rte_get_tsc_hz(void)
{
    return 1;
}

#endif /* DPDK_NETDEV */
