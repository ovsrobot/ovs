/*
 * Copyright (c) 2018, 2019 Nicira, Inc.
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
#ifndef SPINLOCK_H
#define SPINLOCK_H 1

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "ovs-atomic.h"

typedef struct {
    atomic_int locked;
} ovs_spinlock_t;

static inline void
ovs_spinlock_init(ovs_spinlock_t *sl)
{
    atomic_init(&sl->locked, 0);
}

static inline void
ovs_spin_lock(ovs_spinlock_t *sl)
{
    int exp = 0, locked = 0;

    while (!atomic_compare_exchange_strong_explicit(&sl->locked, &exp, 1,
                memory_order_acquire,
                memory_order_relaxed)) {
        locked = 1;
        while (locked) {
            atomic_read_relaxed(&sl->locked, &locked);
        }
        exp = 0;
    }
}

static inline void
ovs_spin_unlock(ovs_spinlock_t *sl)
{
    atomic_store_explicit(&sl->locked, 0, memory_order_release);
}

static inline int OVS_UNUSED
ovs_spin_trylock(ovs_spinlock_t *sl)
{
    int exp = 0;
    return atomic_compare_exchange_strong_explicit(&sl->locked, &exp, 1,
                memory_order_acquire,
                memory_order_relaxed);
}
#endif
