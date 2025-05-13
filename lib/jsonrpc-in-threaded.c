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

#include "openvswitch/vlog.h"
#include "jsonrpc-in-threaded.h"
#include "jsonrpc-in.h"

VLOG_DEFINE_THIS_MODULE(jsonrpc_in_thr);

static void *jsonrpc_in_threaded_worker(void *dummy);

void
jsonrpc_in_threaded_init(struct jsonrpc_in_threaded *tin)
{
    ovs_mutex_init(&tin->mutex);
    pthread_cond_init(&tin->cond, NULL);
    byteq_init(&tin->input, tin->input_buffer, sizeof tin->input_buffer);
    tin->parser = NULL;
    tin->shutdown = false;
    latch_init(&tin->result_latch);
    tin->jsons_head = tin->jsons_tail = 0;
    pthread_create(&tin->thread, NULL, jsonrpc_in_threaded_worker, tin);
}

void *
jsonrpc_in_threaded_read_buffer(struct jsonrpc_in_threaded *tin, size_t *size)
{
    void *data = NULL;
    ovs_mutex_lock(&tin->mutex);
    *size = byteq_headroom(&tin->input);
    data = byteq_head(&tin->input);
    ovs_mutex_unlock(&tin->mutex);
    return data;
}

void
jsonrpc_in_threaded_read_complete(struct jsonrpc_in_threaded *tin, size_t size)
{
    ovs_mutex_lock(&tin->mutex);
    if (byteq_is_empty(&tin->input)) {
        /* Only need to signal thread if it was empty
         * (condition has changed) */
        pthread_cond_signal(&tin->cond);
    }
    byteq_advance_head(&tin->input, size);
    ovs_mutex_unlock(&tin->mutex);
}

struct json *
jsonrpc_in_threaded_poll(struct jsonrpc_in_threaded *tin)
{
    struct json *result = NULL;
    ovs_mutex_lock(&tin->mutex);
    if (tin->jsons_head != tin->jsons_tail) {
        result = tin->jsons[tin->jsons_tail % JSON_RPC_IN_NUM_PENDING_JSONS];
        tin->jsons_tail++;
    }
    ovs_mutex_unlock(&tin->mutex);
    return result;
}

void
jsonrpc_in_threaded_cleanup(struct jsonrpc_in_threaded *tin)
{
    ovs_mutex_lock(&tin->mutex);
    tin->shutdown = true;
    pthread_cond_signal(&tin->cond);
    ovs_mutex_unlock(&tin->mutex);
    void *dummy;
    pthread_join(tin->thread, &dummy);
    while (tin->jsons_tail != tin->jsons_head) {
        json_destroy(
            tin->jsons[tin->jsons_tail % JSON_RPC_IN_NUM_PENDING_JSONS]);
        tin->jsons_tail++;
    }
    latch_destroy(&tin->result_latch);
    ovs_mutex_destroy(&tin->mutex);
    pthread_cond_destroy(&tin->cond);
}

unsigned int
jsonrpc_in_threaded_get_received_bytes(const struct jsonrpc_in_threaded *tin)
{
    ovs_mutex_lock(&tin->mutex);
    unsigned int result = tin->input.head;
    ovs_mutex_unlock(&tin->mutex);
    return result;
}

int
jsonrpc_in_threaded_wait(struct jsonrpc_in_threaded *tin)
{
    ovs_mutex_lock(&tin->mutex);
    enum jsonrpc_in_wait_result result = JSONRPC_IN_IDLE;
    latch_poll(&tin->result_latch);
    if (tin->jsons_head != tin->jsons_tail) {
        result = JSONRPC_IN_ACTIVE_WAKEUP_NOW;
    } else if (!byteq_is_empty(&tin->input)) {
        latch_wait(&tin->result_latch);
        if (byteq_headroom(&tin->input) == 0) {
            result = JSONRPC_IN_ACTIVE_SLEEP_NO_ROOM;
        } else {
            result = JSONRPC_IN_ACTIVE_SLEEP_HAS_ROOM;
        }
    }
    ovs_mutex_unlock(&tin->mutex);
    return result;
}

int
jsonrpc_in_threaded_status(struct jsonrpc_in_threaded *tin)
{
    ovs_mutex_lock(&tin->mutex);
    enum jsonrpc_in_wait_result result = JSONRPC_IN_IDLE;
    if (tin->jsons_head != tin->jsons_tail) {
        result = JSONRPC_IN_ACTIVE_WAKEUP_NOW;
    } else if (!byteq_is_empty(&tin->input)) {
        if (byteq_headroom(&tin->input) == 0) {
            result = JSONRPC_IN_ACTIVE_SLEEP_NO_ROOM;
        } else {
            result = JSONRPC_IN_ACTIVE_SLEEP_HAS_ROOM;
        }
    }
    ovs_mutex_unlock(&tin->mutex);
    return result;
}

static void *
jsonrpc_in_threaded_worker(void *tin_raw)
{
    struct jsonrpc_in_threaded *tin = tin_raw;
    for (;;) {
        ovs_mutex_lock(&tin->mutex);
        /* Wait new data or until reader read json from result ring */
        while ((byteq_is_empty(&tin->input)
                || (tin->jsons_head - tin->jsons_tail)
                == JSON_RPC_IN_NUM_PENDING_JSONS)
               && !tin->shutdown) {
            ovs_mutex_cond_wait(&tin->cond, &tin->mutex);
        }
        if (tin->shutdown) {
            ovs_mutex_unlock(&tin->mutex);
            break;
        }
        /* Jsons ring must be able to fit result */
        ovs_assert(tin->jsons_head - tin->jsons_tail
                   < JSON_RPC_IN_NUM_PENDING_JSONS);

        const size_t tail_size = byteq_tailroom(&tin->input);
        const char *tail = (const char *) byteq_tail(&tin->input);
        ovs_mutex_unlock(&tin->mutex);
        if (tin->parser == NULL) {
            tin->parser = json_parser_create(0);
        }
        /* Parsing without mutex is safe because nobody can
         * can write data between tail and head. */
        size_t used = json_parser_feed(tin->parser, tail, tail_size);
        struct json *json = NULL;
        if (json_parser_is_done(tin->parser)) {
            json = json_parser_finish(tin->parser);
            tin->parser = NULL;
        }
        ovs_mutex_lock(&tin->mutex);
        bool was_staturated = byteq_headroom(&tin->input) == 0;
        byteq_advance_tail(&tin->input, used);
        if (json != NULL) {
            tin->jsons[tin->jsons_head % JSON_RPC_IN_NUM_PENDING_JSONS] = json;
            tin->jsons_head++;
            ovs_mutex_unlock(&tin->mutex);
        } else {
            ovs_mutex_unlock(&tin->mutex);
        }
        if (was_staturated || json != NULL) {
            latch_set(&tin->result_latch);
        }
    }
    return NULL;
}

size_t
jsonrpc_in_threaded_fill_stream_report_data(struct jsonrpc_in_threaded *tin,
                                            void *data, size_t datasz)
{
    ovs_mutex_lock(&tin->mutex);
    if (tin->input.head < tin->input.size) {
        size_t towrite = MIN(datasz, tin->input.head);
        memcpy(data, tin->input.buffer, towrite);
        ovs_mutex_unlock(&tin->mutex);
        return towrite;
    } else {
        ovs_mutex_unlock(&tin->mutex);
        return 0;
    }
}
