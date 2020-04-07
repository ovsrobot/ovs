/*
 * Copyright (c) 2020 VMware, Inc.
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

#ifndef CONNTRACK_TP_H
#define CONNTRACK_TP_H 1

void conn_init_expiration_with_tp(struct conntrack *ct, struct conn *conn,
                                  enum ct_timeout tm, long long now);
void conn_update_expiration_with_tp(struct conntrack *ct, struct conn *conn,
                                    enum ct_timeout tm, long long now);
#endif
