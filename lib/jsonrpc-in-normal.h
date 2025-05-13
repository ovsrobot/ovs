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

#ifndef OVS_JSONRPC_IN_NORMAL_H
#define OVS_JSONRPC_IN_NORMAL_H

#include <config.h>
#include <stdbool.h>
#include "byteq.h"
#include "json.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct jsonrpc_in_normal {
    struct byteq input;
    uint8_t input_buffer[4096 * 32];
    struct json_parser *parser;
};

static inline void
jsonrpc_in_normal_init(struct jsonrpc_in_normal *nin)
{
    byteq_init(&nin->input, nin->input_buffer, sizeof nin->input_buffer);
    nin->parser = NULL;
}

static inline void *
jsonrpc_in_normal_read_buffer(struct jsonrpc_in_normal *nin, size_t *size)
{
    if (byteq_is_empty(&nin->input)) {
        *size = byteq_headroom(&nin->input);
        return byteq_head(&nin->input);
    } else {
        *size = 0;
        return NULL;
    }
}

static inline void
jsonrpc_in_normal_read_complete(struct jsonrpc_in_normal *nin, size_t size)
{
    byteq_advance_head(&nin->input, size);
}

static inline struct json *
jsonrpc_in_normal_poll(struct jsonrpc_in_normal *nin)
{
    size_t n = byteq_tailroom(&nin->input);
    if (n != 0) {
        if (nin->parser == NULL) {
            nin->parser = json_parser_create(0);
        }
        size_t used = json_parser_feed(nin->parser,
                                       (char *) byteq_tail(&nin->input), n);
        byteq_advance_tail(&nin->input, used);
    }
    if (nin->parser != NULL && json_parser_is_done(nin->parser)) {
        struct json *json = json_parser_finish(nin->parser);
        nin->parser = NULL;
        return json;
    }
    return NULL;
}

static inline void
jsonrpc_in_normal_cleanup(struct jsonrpc_in_normal *nin) {
    json_parser_abort(nin->parser);
    nin->parser = NULL;
}

static inline unsigned int
jsonrpc_in_normal_get_received_bytes(const struct jsonrpc_in_normal *nin)
{
    return nin->input.head;
}

static inline int
jsonrpc_in_normal_wait(struct jsonrpc_in_normal *nin)
{
    return byteq_is_empty(&nin->input)
        ? JSONRPC_IN_IDLE : JSONRPC_IN_ACTIVE_WAKEUP_NOW;
}

static inline size_t
jsonrpc_in_normal_fill_stream_report_data(struct jsonrpc_in_normal *nin,
                                          void *data, size_t datasz)
{
    if (nin->input.head < nin->input.size) {
        size_t towrite = MIN(datasz, nin->input.head);
        memcpy(data, nin->input.buffer, towrite);
        return towrite;
    } else {
        return 0;
    }
}

#ifdef __cplusplus
}
#endif

#endif
