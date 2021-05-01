/*
 * Copyright (c) 2021, Red Hat, Inc.
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

#include "transaction-forward.h"

#include "coverage.h"
#include "jsonrpc.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovsdb.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(transaction_forward);

COVERAGE_DEFINE(txn_forward_cancel);
COVERAGE_DEFINE(txn_forward_complete);
COVERAGE_DEFINE(txn_forward_create);
COVERAGE_DEFINE(txn_forward_sent);

struct ovsdb_txn_forward {
    struct ovs_list new_node;    /* In 'new_transactions'. */
    struct hmap_node sent_node;  /* In 'sent_transactions'. */
    struct ovsdb *db;            /* Database of this transaction. */
    struct json *id;             /* 'id' of the forwarded transaction. */
    struct jsonrpc_msg *request; /* Original request. */
    struct jsonrpc_msg *reply;   /* Reply from the server. */
};

/* List that holds transactions waiting to be forwarded to the server. */
static struct ovs_list new_transactions =
    OVS_LIST_INITIALIZER(&new_transactions);
/* Hash map for transactions that are already sent and waits for reply. */
static struct hmap sent_transactions = HMAP_INITIALIZER(&sent_transactions);

struct ovsdb_txn_forward *
ovsdb_txn_forward_create(struct ovsdb *db, const struct jsonrpc_msg *request)
{
    struct ovsdb_txn_forward *txn_fwd = xzalloc(sizeof *txn_fwd);

    COVERAGE_INC(txn_forward_create);
    txn_fwd->db = db;
    txn_fwd->request = jsonrpc_msg_clone(request);
    ovs_list_push_back(&new_transactions, &txn_fwd->new_node);

    return txn_fwd;
}

static void
ovsdb_txn_forward_unlist(struct ovsdb_txn_forward *txn_fwd)
{
    if (!ovs_list_is_empty(&txn_fwd->new_node)) {
        ovs_list_remove(&txn_fwd->new_node);
        ovs_list_init(&txn_fwd->new_node);
    }
    if (!hmap_node_is_null(&txn_fwd->sent_node)) {
        hmap_remove(&sent_transactions, &txn_fwd->sent_node);
        hmap_node_nullify(&txn_fwd->sent_node);
    }
}

void
ovsdb_txn_forward_destroy(struct ovsdb_txn_forward *txn_fwd)
{
    if (!txn_fwd) {
        return;
    }

    ovsdb_txn_forward_unlist(txn_fwd);
    json_destroy(txn_fwd->id);
    jsonrpc_msg_destroy(txn_fwd->request);
    jsonrpc_msg_destroy(txn_fwd->reply);
    free(txn_fwd);
}

bool
ovsdb_txn_forward_is_complete(const struct ovsdb_txn_forward *txn_fwd)
{
    return txn_fwd->reply != NULL;
}

void
ovsdb_txn_forward_complete(const struct jsonrpc_msg *reply)
{
    struct ovsdb_txn_forward *t;
    size_t hash = json_hash(reply->id, 0);

    HMAP_FOR_EACH_WITH_HASH (t, sent_node, hash, &sent_transactions) {
        if (json_equal(reply->id, t->id)) {
            COVERAGE_INC(txn_forward_complete);
            t->reply = jsonrpc_msg_clone(reply);

            /* Replacing id with the id of the original request. */
            json_destroy(t->reply->id);
            t->reply->id = json_clone(t->request->id);

            hmap_remove(&sent_transactions, &t->sent_node);
            hmap_node_nullify(&t->sent_node);

            t->db->run_triggers_now = t->db->run_triggers = true;
            return;
        }
    }
}

struct jsonrpc_msg *
ovsdb_txn_forward_steal_reply(struct ovsdb_txn_forward *txn_fwd)
{
    struct jsonrpc_msg *reply = txn_fwd->reply;

    txn_fwd->reply = NULL;
    return reply;
}

void
ovsdb_txn_forward_run(struct jsonrpc_session *session)
{
    struct ovsdb_txn_forward *t, *next;
    struct jsonrpc_msg *request;

    /* Send all transactions that needs to be forwarded. */
    LIST_FOR_EACH_SAFE (t, next, new_node, &new_transactions) {
        request = jsonrpc_create_request(t->request->method,
                                         json_clone(t->request->params),
                                         &t->id);
        if (!jsonrpc_session_send(session, request)) {
            COVERAGE_INC(txn_forward_sent);
            ovs_list_remove(&t->new_node);
            ovs_list_init(&t->new_node);
            hmap_insert(&sent_transactions, &t->sent_node,
                        json_hash(t->id, 0));
        }
    }
}

void
ovsdb_txn_forward_wait(void)
{
    if (!ovs_list_is_empty(&new_transactions)) {
        poll_immediate_wake();
    }
}

void
ovsdb_txn_forward_cancel(struct ovsdb_txn_forward *txn_fwd)
{
    COVERAGE_INC(txn_forward_cancel);
    jsonrpc_msg_destroy(txn_fwd->reply);
    txn_fwd->reply = jsonrpc_create_error(json_string_create("canceled"),
                                          txn_fwd->request->id);
    ovsdb_txn_forward_unlist(txn_fwd);
}

void
ovsdb_txn_forward_cancel_all(bool sent_only)
{
    struct ovsdb_txn_forward *t, *next;

    HMAP_FOR_EACH_SAFE (t, next, sent_node, &sent_transactions) {
        ovsdb_txn_forward_cancel(t);
    }

    if (sent_only) {
        return;
    }

    LIST_FOR_EACH_SAFE (t, next, new_node, &new_transactions) {
        ovsdb_txn_forward_cancel(t);
    }
}
