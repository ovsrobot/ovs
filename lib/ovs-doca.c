/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

#include <config.h>

#include "compiler.h"
#include "ovs-doca.h"
#include "vswitch-idl.h"

#ifdef DOCA_NETDEV

#include <rte_common.h>
#include <rte_pmd_mlx5.h>

#include <doca_version.h>

/* DOCA disables dpdk steering as a constructor in higher priority.
 * Set a lower priority one to enable it back. Disable it only upon using
 * doca ports.
 */
RTE_INIT(dpdk_steering_enable)
{
    rte_pmd_mlx5_enable_steering();
}

void
ovs_doca_init(const struct smap *ovs_other_config OVS_UNUSED)
{
}

void
print_doca_version(void)
{
    puts(doca_version_runtime());
}

void
ovs_doca_status(const struct ovsrec_open_vswitch *cfg)
{
    if (!cfg) {
        return;
    }

    ovsrec_open_vswitch_set_doca_initialized(cfg, false);
    ovsrec_open_vswitch_set_doca_version(cfg, doca_version_runtime());
}

#else /* DOCA_NETDEV */

void
ovs_doca_init(const struct smap *ovs_other_config OVS_UNUSED)
{
}

void
print_doca_version(void)
{
}

void
ovs_doca_status(const struct ovsrec_open_vswitch *cfg)
{
    if (!cfg) {
        return;
    }

    ovsrec_open_vswitch_set_doca_initialized(cfg, false);
    ovsrec_open_vswitch_set_doca_version(cfg, "none");
}

#endif /* DOCA_NETDEV */
