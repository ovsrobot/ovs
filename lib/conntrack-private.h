/*
 * Copyright (c) 2015-2019 Nicira, Inc.
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

#ifndef CONNTRACK_PRIVATE_H
#define CONNTRACK_PRIVATE_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "cmap.h"
#include "conntrack.h"
#include "ct-dpif.h"
#include "ipf.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "unaligned.h"
#include "dp-packet.h"

struct ct_endpoint {
    union ct_addr addr;
    union {
        ovs_be16 port;
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

/* Verify that there is no padding in struct ct_endpoint, to facilitate
 * hashing in ct_endpoint_hash_add(). */
BUILD_ASSERT_DECL(sizeof(struct ct_endpoint) == sizeof(union ct_addr) + 4);

/* Changes to this structure need to be reflected in conn_key_hash()
 * and conn_key_cmp(). */
struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint16_t zone;
    uint8_t nw_proto;
};

/* This is used for alg expectations; an expectation is a
 * context created in preparation for establishing a data
 * connection. The expectation is created by the control
 * connection. */
struct alg_exp_node {
    /* Node in alg_expectations. */
    struct hmap_node node;
    /* Node in alg_expectation_refs. */
    struct hindex_node node_ref;
    /* Key of data connection to be created. */
    struct conn_key key;
    /* Corresponding key of the control connection. */
    struct conn_key master_key;
    /* The NAT replacement address to be used by the data connection. */
    union ct_addr alg_nat_repl_addr;
    /* The data connection inherits the master control
     * connection label and mark. */
    ovs_u128 master_label;
    uint32_t master_mark;
    /* True if for NAT application, the alg replaces the dest address;
     * otherwise, the source address is replaced.  */
    bool nat_rpl_dst;
};

struct conn {
    struct conn_key key;
    struct conn_key rev_key;
    struct conn_key master_key; /* Only used for orig_tuple support. */
    struct ovs_mutex lock;
    long long expiration;
    struct ovs_list exp_node;
    struct cmap_node cm_node;
    ovs_u128 label;
    struct nat_action_info_t *nat_info;
    char *alg;
    struct conn *nat_conn; /* The NAT 'conn' context, if there is one. */
    int seq_skew;
    uint32_t mark;
    uint8_t conn_type; /* See ct_conn_type. */
    /* TCP sequence skew direction due to NATTing of FTP control messages;
     * true if reply direction. */
    bool seq_skew_dir;
    bool alg_related; /* True if alg data connection. */
};

enum ct_update_res {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
};

enum ct_conn_type {
    CT_CONN_TYPE_DEFAULT,
    CT_CONN_TYPE_UN_NAT,
};

/* Timeouts: all the possible timeout states passed to update_expiration()
 * are listed here. The name will be prefix by CT_TM_ and the value is in
 * milliseconds */
#define CT_TIMEOUTS \
    CT_TIMEOUT(TCP_FIRST_PACKET, 30 * 1000) \
    CT_TIMEOUT(TCP_OPENING, 30 * 1000) \
    CT_TIMEOUT(TCP_ESTABLISHED, 24 * 60 * 60 * 1000) \
    CT_TIMEOUT(TCP_CLOSING, 15 * 60 * 1000) \
    CT_TIMEOUT(TCP_FIN_WAIT, 45 * 1000) \
    CT_TIMEOUT(TCP_CLOSED, 30 * 1000) \
    CT_TIMEOUT(OTHER_FIRST, 60 * 1000) \
    CT_TIMEOUT(OTHER_MULTIPLE, 60 * 1000) \
    CT_TIMEOUT(OTHER_BIDIR, 30 * 1000) \
    CT_TIMEOUT(ICMP_FIRST, 60 * 1000) \
    CT_TIMEOUT(ICMP_REPLY, 30 * 1000)

/* The smallest of the above values: it is used as an upper bound for the
 * interval between two rounds of cleanup of expired entries */
#define CT_TM_MIN (30 * 1000)

#define CT_TIMEOUT(NAME, VAL) BUILD_ASSERT_DECL(VAL >= CT_TM_MIN);
    CT_TIMEOUTS
#undef CT_TIMEOUT

enum ct_timeout {
#define CT_TIMEOUT(NAME, VALUE) CT_TM_##NAME,
    CT_TIMEOUTS
#undef CT_TIMEOUT
    N_CT_TM
};

struct conntrack {
    struct ovs_mutex ct_lock;
    struct cmap conns OVS_GUARDED;
    struct ovs_list exp_lists[N_CT_TM] OVS_GUARDED;

    /* Salt for hashing a connection key. */
    uint32_t hash_basis;
    /* The thread performing periodic cleanup of the connection
     * tracker. */
    pthread_t clean_thread;
    /* Latch to destroy the 'clean_thread' */
    struct latch clean_thread_exit;

    /* Number of connections currently in the connection tracker. */
    atomic_count n_conn;
    /* Connections limit. When this limit is reached, no new connection
     * will be accepted. */
    atomic_uint n_conn_limit;

    /* This lock is used to guard alg_expectations and alg_expectation_refs.
     */
    struct ovs_rwlock resources_lock;
    /* Hash table for alg expectations. Expectations are created
     * by control connections to help create data connections. */
    struct hmap alg_expectations OVS_GUARDED;
    /* Used to lookup alg expectations from the control context. */
    struct hindex alg_expectation_refs OVS_GUARDED;

    /* Fragmentation handling context. */
    struct ipf *ipf;
};

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;
extern struct ct_l4_proto ct_proto_icmp4;
extern struct ct_l4_proto ct_proto_icmp6;

struct ct_l4_proto {
    struct conn *(*new_conn)(struct conntrack *ct, struct dp_packet *pkt,
                             long long now);
    bool (*valid_new)(struct dp_packet *pkt);
    enum ct_update_res (*conn_update)(struct conntrack *ct, struct conn *conn,
                                      struct dp_packet *pkt, bool reply,
                                      long long now);
    void (*conn_get_protoinfo)(const struct conn *,
                               struct ct_dpif_protoinfo *);
};

extern long long ct_timeout_val[];


/* ct_lock must be held. */
static inline void
conn_init_expiration(struct conntrack *ct, struct conn *conn,
                     enum ct_timeout tm, long long now)
{
    conn->expiration = now + ct_timeout_val[tm];
    ovs_list_push_back(&ct->exp_lists[tm], &conn->exp_node);
}

/* The conn entry lock must be held on entry and exit. */
static inline void
conn_update_expiration(struct conntrack *ct, struct conn *conn,
                       enum ct_timeout tm, long long now)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_mutex_unlock(&conn->lock);

    ovs_mutex_lock(&ct->ct_lock);
    ovs_mutex_lock(&conn->lock);
    conn->expiration = now + ct_timeout_val[tm];
    ovs_list_remove(&conn->exp_node);
    ovs_list_push_back(&ct->exp_lists[tm], &conn->exp_node);
    ovs_mutex_unlock(&conn->lock);
    ovs_mutex_unlock(&ct->ct_lock);

    ovs_mutex_lock(&conn->lock);
}

static inline uint32_t
tcp_payload_length(struct dp_packet *pkt)
{
    const char *tcp_payload = dp_packet_get_tcp_payload(pkt);
    if (tcp_payload) {
        return ((char *) dp_packet_tail(pkt) - dp_packet_l2_pad_size(pkt)
                - tcp_payload);
    } else {
        return 0;
    }
}

#endif /* conntrack-private.h */
