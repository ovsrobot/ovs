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

#ifndef OVS_JSONRPC_IN_H
#define OVS_JSONRPC_IN_H

#include <config.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct json;
struct jsonrpc_in;

enum jsonrpc_in_mode {
    JSONRPC_IN_MODE_NORMAL,
    JSONRPC_IN_MODE_THREADED,
};

struct jsonrpc_in_config {
    enum jsonrpc_in_mode mode;
};

#define JSONRPC_IN_CONFIG_DEFAULT {             \
        .mode = JSONRPC_IN_MODE_NORMAL          \
}

enum jsonrpc_in_wait_result {
    JSONRPC_IN_IDLE,
    JSONRPC_IN_ACTIVE_WAKEUP_NOW,
    JSONRPC_IN_ACTIVE_SLEEP_HAS_ROOM,
    JSONRPC_IN_ACTIVE_SLEEP_NO_ROOM,
};

struct jsonrpc_in *jsonrpc_in_new(const struct jsonrpc_in_config *cfg);
void *jsonrpc_in_read_buffer(struct jsonrpc_in *input, size_t *size);
void jsonrpc_in_read_complete(struct jsonrpc_in *input, size_t size);
struct json *jsonrpc_in_poll(struct jsonrpc_in *input);
size_t jsonrpc_in_fill_stream_report_data(struct jsonrpc_in *input, void *data, size_t datasz);
void jsonrpc_in_cleanup(struct jsonrpc_in *input);
unsigned int jsonrpc_in_get_received_bytes(const struct jsonrpc_in *input);
enum jsonrpc_in_wait_result jsonrpc_in_wait(struct jsonrpc_in *input);
enum jsonrpc_in_wait_result jsonrpc_in_status(struct jsonrpc_in *input);
/* writes data that can be used as stream report */
size_t jsonrpc_in_fill_stream_report_data(struct jsonrpc_in *input, void *data, size_t datasz);

#ifdef __cplusplus
}
#endif

#endif
