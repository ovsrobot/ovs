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
#include "mpsc-queue.h"
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

/* Verify that nw_proto stays uint8_t as it's used to index into l4_protos[] */
BUILD_ASSERT_DECL(MEMBER_SIZEOF(struct conn_key, nw_proto) == sizeof(uint8_t));

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
    struct conn_key parent_key;
    /* The NAT replacement address to be used by the data connection. */
    union ct_addr alg_nat_repl_addr;
    /* The data connection inherits the parent control
     * connection label and mark. */
    ovs_u128 parent_label;
    uint32_t parent_mark;
    /* True if for NAT application, the alg replaces the dest address;
     * otherwise, the source address is replaced.  */
    bool nat_rpl_dst;
};

/* Timeouts: all the possible timeout states passed to update_expiration()
 * are listed here. The name will be prefix by CT_TM_ and the value is in
 * milliseconds */
#define CT_TIMEOUTS \
    CT_TIMEOUT(TCP_FIRST_PACKET) \
    CT_TIMEOUT(TCP_OPENING) \
    CT_TIMEOUT(TCP_ESTABLISHED) \
    CT_TIMEOUT(TCP_CLOSING) \
    CT_TIMEOUT(TCP_FIN_WAIT) \
    CT_TIMEOUT(TCP_CLOSED) \
    CT_TIMEOUT(OTHER_FIRST) \
    CT_TIMEOUT(OTHER_MULTIPLE) \
    CT_TIMEOUT(OTHER_BIDIR) \
    CT_TIMEOUT(ICMP_FIRST) \
    CT_TIMEOUT(ICMP_REPLY)

enum ct_timeout {
#define CT_TIMEOUT(NAME) CT_TM_##NAME,
    CT_TIMEOUTS
#undef CT_TIMEOUT
    N_CT_TM
};

enum OVS_PACKED_ENUM ct_conn_type {
    CT_CONN_TYPE_DEFAULT,
    CT_CONN_TYPE_UN_NAT,
};

struct conn_expire {
    struct mpsc_queue_node node;
    /* Timeout state of the connection.
     * It follows the connection state updates.
     */
    enum ct_timeout tm;
    atomic_flag reschedule;
    struct ovs_refcount refcount;
};

struct conn {
    /* Immutable data. */
    struct conn_key key;
    struct conn_key rev_key;
    struct conn_key parent_key; /* Only used for orig_tuple support. */
    struct cmap_node cm_node;
    struct nat_action_info_t *nat_info;
    char *alg;
    struct conn *nat_conn; /* The NAT 'conn' context, if there is one. */

    /* Inserted once by a PMD, then managed by the 'ct_clean' thread. */
    struct conn_expire exp;

    /* Mutable data. */
    struct ovs_mutex lock; /* Guards all mutable fields. */
    ovs_u128 label;
    long long expiration;
    uint32_t mark;
    int seq_skew;

    /* Immutable data. */
    int32_t admit_zone; /* The zone for managing zone limit counts. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */

    /* Mutable data. */
    bool seq_skew_dir; /* TCP sequence skew direction due to NATTing of FTP
                        * control messages; true if reply direction. */
    bool cleaned; /* True if cleaned from expiry lists. */

    /* Immutable data. */
    bool alg_related; /* True if alg data connection. */
    enum ct_conn_type conn_type;

    uint32_t tp_id; /* Timeout policy ID. */
};

enum ct_update_res {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
    CT_UPDATE_VALID_NEW,
};

struct conntrack {
    struct ovs_mutex ct_lock; /* Protects 2 following fields. */
    struct cmap conns OVS_GUARDED;
    struct mpsc_queue exp_lists[N_CT_TM];
    struct cmap zone_limits OVS_GUARDED;
    struct hmap timeout_policies OVS_GUARDED;
    uint32_t hash_basis; /* Salt for hashing a connection key. */
    pthread_t clean_thread; /* Periodically cleans up connection tracker. */
    struct latch clean_thread_exit; /* To destroy the 'clean_thread'. */

    /* Counting connections. */
    atomic_count n_conn; /* Number of connections currently tracked. */
    atomic_uint n_conn_limit; /* Max connections tracked. */

    /* Expectations for application level gateways (created by control
     * connections to help create data connections, e.g. for FTP). */
    struct ovs_rwlock resources_lock; /* Protects fields below. */
    struct hmap alg_expectations OVS_GUARDED; /* Holds struct
                                               * alg_exp_nodes. */
    struct hindex alg_expectation_refs OVS_GUARDED; /* For lookup from
                                                     * control context.  */

    struct ipf *ipf; /* Fragmentation handling context. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */
    atomic_bool tcp_seq_chk; /* Check TCP sequence numbers. */
};

/* Lock acquisition order:
 *    1. 'ct_lock'
 *    2. 'conn->lock'
 *    3. 'resources_lock'
 */

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;
extern struct ct_l4_proto ct_proto_icmp4;
extern struct ct_l4_proto ct_proto_icmp6;

struct ct_l4_proto {
    struct conn *(*new_conn)(struct conntrack *ct, struct dp_packet *pkt,
                             long long now, uint32_t tp_id);
    bool (*valid_new)(struct dp_packet *pkt);
    enum ct_update_res (*conn_update)(struct conntrack *ct, struct conn *conn,
                                      struct dp_packet *pkt, bool reply,
                                      long long now);
    void (*conn_get_protoinfo)(const struct conn *,
                               struct ct_dpif_protoinfo *);
};

static inline void
conn_expire_append(struct conntrack *ct, struct conn *conn)
{
    if (ovs_refcount_try_ref_rcu(&conn->exp.refcount)) {
        atomic_flag_clear(&conn->exp.reschedule);
        mpsc_queue_insert(&ct->exp_lists[conn->exp.tm], &conn->exp.node);
    }
}

static inline void
conn_expire_prepend(struct conntrack *ct, struct conn *conn)
    OVS_REQUIRES(ct->exp_lists[conn->exp.tm].read_lock)
{
    if (ovs_refcount_try_ref_rcu(&conn->exp.refcount)) {
        /* Do not change 'reschedule' state, if this expire node is put
         * at the tail of the list, it will be re-examined next sweep.
         */
        mpsc_queue_push_back(&ct->exp_lists[conn->exp.tm], &conn->exp.node);
    }
}

#endif /* conntrack-private.h */
