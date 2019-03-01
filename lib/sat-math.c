/*
 * Copyright (c) 2019 Nicira, Inc.
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
#include "sat-math.h"

/* Returns x * y, clamping out-of-range results into the range of the return
 * type. */
long long int
llsat_mul(long long int x, long long int y)
{
    return (  x > 0 && y > 0 && x >  LLONG_MAX / y ? LLONG_MAX
            : x < 0 && y > 0 && x <= LLONG_MIN / y ? LLONG_MIN
            : x > 0 && y < 0 && y <= LLONG_MIN / x ? LLONG_MIN
            /* Special case because -LLONG_MIN / -1 overflows: */
            : x == LLONG_MIN && y == -1 ? LLONG_MAX
            : x < 0 && y < 0 && x < LLONG_MIN / y ? LLONG_MAX
            : x * y);
}
