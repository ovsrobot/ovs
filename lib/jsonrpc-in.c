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

#include <config.h>
#include <string.h>

#include "openvswitch/thread.h"
#include "jsonrpc-in.h"
#include "jsonrpc-in-normal.h"
#include "jsonrpc-in-threaded.h"
#include "util.h"
#include "json.h"
#include "byteq.h"

struct jsonrpc_in {
    struct jsonrpc_in_config config;
    union {
        struct jsonrpc_in_normal normal;
        struct jsonrpc_in_threaded threaded;
    };
};

struct jsonrpc_in *jsonrpc_in_new(const struct jsonrpc_in_config *cfg) {
    struct jsonrpc_in *input = xmalloc(sizeof(struct jsonrpc_in));
    input->config = *cfg;
    switch (input->config.mode) {
    case JSONRPC_IN_MODE_NORMAL:
        jsonrpc_in_normal_init(&input->normal);
        return input;
    case JSONRPC_IN_MODE_THREADED:
        jsonrpc_in_threaded_init(&input->threaded);
        return input;
    }
    OVS_NOT_REACHED();
    free(input);
    return NULL;
}

void *jsonrpc_in_read_buffer(struct jsonrpc_in *input, size_t *size) {
    switch (input->config.mode) {
    case JSONRPC_IN_MODE_NORMAL:
        return jsonrpc_in_normal_read_buffer(&input->normal, size);
    case JSONRPC_IN_MODE_THREADED:
        return jsonrpc_in_threaded_read_buffer(&input->threaded, size);
    }
    OVS_NOT_REACHED();
    return NULL;
}

void jsonrpc_in_read_complete(struct jsonrpc_in *input, size_t size) {
    switch (input->config.mode) {
    case JSONRPC_IN_MODE_NORMAL:
        jsonrpc_in_normal_read_complete(&input->normal, size);
        return;
    case JSONRPC_IN_MODE_THREADED:
        jsonrpc_in_threaded_read_complete(&input->threaded, size);
        return;
    }
    OVS_NOT_REACHED();
}

struct json *jsonrpc_in_poll(struct jsonrpc_in *input) {
    switch (input->config.mode) {
    case JSONRPC_IN_MODE_NORMAL:
        return jsonrpc_in_normal_poll(&input->normal);
    case JSONRPC_IN_MODE_THREADED:
        return jsonrpc_in_threaded_poll(&input->threaded);
    }
    OVS_NOT_REACHED();
    return NULL;
}

void jsonrpc_in_cleanup(struct jsonrpc_in *input) {
    switch (input->config.mode) {
    case JSONRPC_IN_MODE_NORMAL:
        jsonrpc_in_normal_cleanup(&input->normal);
        break;
    case JSONRPC_IN_MODE_THREADED:
        jsonrpc_in_threaded_cleanup(&input->threaded);
        break;
    }
    free(input);
}

unsigned int jsonrpc_in_get_received_bytes(const struct jsonrpc_in *input) {
    switch (input->config.mode) {
    case JSONRPC_IN_MODE_NORMAL:
        return jsonrpc_in_normal_get_received_bytes(&input->normal);
    case JSONRPC_IN_MODE_THREADED:
        return jsonrpc_in_threaded_get_received_bytes(&input->threaded);
    }
    OVS_NOT_REACHED();
    return 0;
}

enum jsonrpc_in_wait_result jsonrpc_in_wait(struct jsonrpc_in *input) {
    switch (input->config.mode) {
    case JSONRPC_IN_MODE_NORMAL:
        return jsonrpc_in_normal_wait(&input->normal);
    case JSONRPC_IN_MODE_THREADED:
        return jsonrpc_in_threaded_wait(&input->threaded);
    }
    OVS_NOT_REACHED();
    return 0;
}

enum jsonrpc_in_wait_result jsonrpc_in_status(struct jsonrpc_in *input) {
    switch (input->config.mode) {
    case JSONRPC_IN_MODE_NORMAL:
        return jsonrpc_in_normal_wait(&input->normal); /* sic! normal does not really wait */
    case JSONRPC_IN_MODE_THREADED:
        return jsonrpc_in_threaded_status(&input->threaded);
    }
    OVS_NOT_REACHED();
    return 0;
}

size_t jsonrpc_in_fill_stream_report_data(struct jsonrpc_in *input, void *data, size_t datasz) {
    switch (input->config.mode) {
    case JSONRPC_IN_MODE_NORMAL:
        return jsonrpc_in_normal_fill_stream_report_data(&input->normal, data, datasz);
    case JSONRPC_IN_MODE_THREADED:
        return jsonrpc_in_threaded_fill_stream_report_data(&input->threaded, data, datasz);
    }
    OVS_NOT_REACHED();
    return 0;
}

