/*
 * Copyright (c) 2019 Red Hat, Inc.
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

#ifndef IF_NOTIFIER_DPDK_H
#define IF_NOTIFIER_DPDK_H 1

typedef void dpdk_notify_func(void *aux);

struct dpdk_notifier;

#ifdef DPDK_NETDEV

struct dpdk_notifier *dpdk_notifier_create(dpdk_notify_func *cb, void *aux);
void dpdk_notifier_destroy(struct dpdk_notifier *notifier);
void dpdk_notifierr_report_link(void);

#else

static inline struct dpdk_notifier *dpdk_notifier_create(
    dpdk_notify_func *cb OVS_UNUSED, void *aux OVS_UNUSED)
{
    return NULL;
}

static inline void dpdk_notifier_destroy(
    struct dpdk_notifier *notifier OVS_UNUSED)
{
}

#endif


#endif /* if-notifier-dpdk.h */
