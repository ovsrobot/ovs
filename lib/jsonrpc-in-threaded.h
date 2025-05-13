/*
 * Copyright (c) 2025 NVIDIA Corporation.
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

#ifndef OVS_JSONRPC_IN_THREADED_H
#define OVS_JSONRPC_IN_THREADED_H

#include <config.h>
#include <pthread.h>

#include "openvswitch/thread.h"
#include "byteq.h"
#include "json.h"
#include "latch.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_RPC_IN_NUM_PENDING_JSONS 16

struct jsonrpc_in_threaded {
    struct ovs_mutex mutex;
    pthread_cond_t cond;
    pthread_t thread;
    struct byteq input;
    uint8_t input_buffer[65536*2];
    struct json_parser *parser;
    bool shutdown;
    struct latch result_latch;
    struct json *jsons[JSON_RPC_IN_NUM_PENDING_JSONS];
    unsigned int jsons_head;
    unsigned int jsons_tail;
};

void jsonrpc_in_threaded_init(struct jsonrpc_in_threaded *tin);
void *jsonrpc_in_threaded_read_buffer(struct jsonrpc_in_threaded *tin, size_t *size);
void jsonrpc_in_threaded_read_complete(struct jsonrpc_in_threaded *tin, size_t size);
struct json *jsonrpc_in_threaded_poll(struct jsonrpc_in_threaded *tin);
void jsonrpc_in_threaded_cleanup(struct jsonrpc_in_threaded *tin);
unsigned int jsonrpc_in_threaded_get_received_bytes(const struct jsonrpc_in_threaded *tin);
int jsonrpc_in_threaded_wait(struct jsonrpc_in_threaded *tin);
int jsonrpc_in_threaded_status(struct jsonrpc_in_threaded *tin);
bool jsonrpc_in_threaded_is_idle(struct jsonrpc_in_threaded *tin);
size_t jsonrpc_in_threaded_fill_stream_report_data(struct jsonrpc_in_threaded *tin, void *data, size_t datasz);

#ifdef __cplusplus
}
#endif

#endif
