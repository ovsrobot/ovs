/*
 * Copyright (c) 2019 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

/* Avoid sparse warning: non-ANSI function declaration of function" */
#define numa_get_membind_compat() numa_get_membind_compat(void)
#define numa_get_interleave_mask_compat() numa_get_interleave_mask_compat(void)
#define numa_get_run_node_mask_compat() numa_get_run_node_mask_compat(void)

/* Get actual <numa.h> definitions for us to annotate and build on. */
#include_next<numa.h>
