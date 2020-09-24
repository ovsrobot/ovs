/*
 * Copyright (c) 2020 Inspur Inc.
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

#ifndef USERSPACE_SOCK_SIZE_H
#define USERSPACE_SOCK_SIZE_H 1

void userspace_sock_buf_size_init(const struct smap *ovs_other_config);
uint32_t userspace_get_sock_buf_size(void);

#endif /* userspace-sock-buf-size.h */
