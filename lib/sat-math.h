/*
 * Copyright (c) 2008, 2012, 2019 Nicira, Inc.
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

#ifndef SAT_MATH_H
#define SAT_MATH_H 1

#include <limits.h>
#include "openvswitch/util.h"

/* Returns x + y, clamping out-of-range results into the range of the return
 * type. */
static inline unsigned int
sat_add(unsigned int x, unsigned int y)
{
    return x + y >= x ? x + y : UINT_MAX;
}
static inline long long int
llsat_add(long long int x, long long int y)
{
    return (x >= 0 && y >= 0 && x > LLONG_MAX - y ? LLONG_MAX
            : x < 0 && y < 0 && x < LLONG_MIN - y ? LLONG_MIN
            : x + y);
}

/* Returns x - y, clamping out-of-range results into the range of the return
 * type. */
static inline unsigned int
sat_sub(unsigned int x, unsigned int y)
{
    return x >= y ? x - y : 0;
}
static inline long long int
llsat_sub(long long int x, long long int y)
{
    return (x >= 0 && y < 0 && x > LLONG_MAX + y ? LLONG_MAX
            : x < 0 && y >= 0 && x < LLONG_MIN + y ? LLONG_MIN
            : x - y);
}

/* Returns x * y, clamping out-of-range results into the range of the return
 * type. */
static inline unsigned int
sat_mul(unsigned int x, unsigned int y)
{
    return OVS_SAT_MUL(x, y);
}
long long int llsat_mul(long long int x, long long int y);

#endif /* sat-math.h */
