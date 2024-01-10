/*
 * Copyright (c) 2023 Canonical Ltd.
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

#ifndef COOPERATIVE_MULTITASKING_H
#define COOPERATIVE_MULTITASKING_H 1

struct hmap;

void cooperative_multitasking_init(struct hmap *);

void cooperative_multitasking_register(void (*)(void *), void *,
                                       long long int, const char *);
#define COOPERATIVE_MULTITASKING_REGISTER(CB, ARG, TIME_THRESHOLD, MSG)       \
    cooperative_multitasking_register((void (*)(void *)) CB, (void *) ARG,    \
                                      TIME_THRESHOLD, MSG)

void cooperative_multitasking_destroy(void);

void cooperative_multitasking_update(void (*)(void *), void *, long long int,
                                     long long int);
#define COOPERATIVE_MULTITASKING_UPDATE(CB, ARG, LAST_RUN, TIME_THRESHOLD)    \
    cooperative_multitasking_update((void (*) (void *)) CB, (void *) ARG,     \
                                    LAST_RUN, TIME_THRESHOLD)

void cooperative_multitasking_yield_at(const char *);
#define cooperative_multitasking_yield() \
    cooperative_multitasking_yield_at(OVS_SOURCE_LOCATOR)

#endif /* COOPERATIVE_MULTITASKING_H */
