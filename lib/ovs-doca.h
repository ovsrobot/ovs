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

#ifndef OVS_DOCA_H
#define OVS_DOCA_H

#include <config.h>

struct ovsrec_open_vswitch;
struct smap;

void ovs_doca_init(const struct smap *ovs_other_config);
void print_doca_version(void);
void ovs_doca_status(const struct ovsrec_open_vswitch *);

#endif /* OVS_DOCA_H */
