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

/* Create jsonrcp input processor. Depends on mode.
 * if mode is threaded then all raw data will be sent to
 * separate thread for parsing. */
struct jsonrpc_in *jsonrpc_in_new(const struct jsonrpc_in_config *cfg);

/* Returns buffer for read from stream.
 * Pointer is valid until jsonrpc_in_read_complete called.
 * Size of data that can be written to buffer is returned in size
 * parameter. Returned size can be 0 and it means that
 * no room for more data is available. */
void *jsonrpc_in_read_buffer(struct jsonrpc_in *input, size_t *size);

/* Finishes read from stream with real amount of data
 * that has been read from the stream. */
void jsonrpc_in_read_complete(struct jsonrpc_in *input, size_t size);

/* Polls parser for the next parsed json return NULL if no new jsons
 * parsed. */
struct json *jsonrpc_in_poll(struct jsonrpc_in *input);

/* Function that is been called if to retrieve stream rport data
 * from input. This data is used to create better diagonstics
 * if stream of invalid type is connectect (for example TLS instead of TCP). */
size_t
jsonrpc_in_fill_stream_report_data(struct jsonrpc_in *input,
                                   void *data, size_t datasz);

/* Cleanup state of json rpc input processor */
void jsonrpc_in_cleanup(struct jsonrpc_in *input);

/* Returns counter of received bytes via stream */
unsigned int jsonrpc_in_get_received_bytes(const struct jsonrpc_in *input);

/* Called on input thread when it is going to wait
 * for next main loop. Threaded version of input adds
 * latch wait to polling descriptors if json parsing is in
 * progress at the moment.  */
enum jsonrpc_in_wait_result jsonrpc_in_wait(struct jsonrpc_in *input);
/* Same as wait but whithout adding additional polling descriptors */
enum jsonrpc_in_wait_result jsonrpc_in_status(struct jsonrpc_in *input);

/* Writes data that can be used as stream report. */
size_t
jsonrpc_in_fill_stream_report_data(struct jsonrpc_in *input,
                                   void *data, size_t datasz);

#ifdef __cplusplus
}
#endif

#endif
