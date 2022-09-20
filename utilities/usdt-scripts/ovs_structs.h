/*
 * Copyright (c) 2022 Red Hat, Inc.
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
 *
 *
 * The purpose of this include file is to define commonly used OVS data
 * structures so they can easily be used/accessed by BPF programs.
 */
#ifndef OVS_STRUCTS_H
#define OVS_STRUCTS_H 1

/* From eBPF we do not care about atomic reading for now :) */
#define ATOMIC(TYPE) TYPE


/* Various typedef's. */
typedef uint32_t HANDLE;


/* The below we can not get from importing the pthread.h file as this will
 * clash with the Linux kernel includes done by BCC. */
typedef struct pthread_mutex_s {
    char size[OVS_PTHREAD_MUTEX_T_SIZE];
} pthread_mutex_t;


/* Included from lib/ovs-rcu.h */
#define OVSRCU_TYPE(TYPE) struct { ATOMIC(TYPE) p; }


/* Included from lib/ovs-atomic.h */
typedef ATOMIC(bool)               atomic_bool;
typedef ATOMIC(int)                atomic_int;
typedef ATOMIC(unsigned int)       atomic_uint;
typedef ATOMIC(long long)          atomic_llong;
typedef ATOMIC(unsigned long long) atomic_ullong;


/* Included from include/openvswitch/list.h */
struct ovs_list {
    struct ovs_list *prev;
    struct ovs_list *next;
};


/* Included from lib/latch.h */
struct latch {
    HANDLE wevent;
    bool is_set;
};

/* Included from lib/ovs-thread.h */
struct ovs_barrier_impl;
struct ovs_barrier {
    OVSRCU_TYPE(struct ovs_barrier_impl *) impl;
};


/* Included from include/openvswitch/thread.h */
struct ovs_mutex {
    pthread_mutex_t lock;
    const char *where;
};


/* Include from ofproto/ofproto-dpif.c */
struct udpif {
    struct ovs_list list_node;

    struct dpif *dpif;
    struct dpif_backer *backer;

    struct handler *handlers;
    uint32_t n_handlers;

    struct revalidator *revalidators;
    uint32_t n_revalidators;

    struct latch exit_latch;

    struct seq *reval_seq;
    bool reval_exit;
    struct ovs_barrier reval_barrier;
    struct dpif_flow_dump *dump;
    long long int dump_duration;
    struct seq *dump_seq;
    atomic_bool enable_ufid;

    bool pause;
    struct latch pause_latch;
    struct ovs_barrier pause_barrier;

    struct umap *ukeys;

    unsigned int max_n_flows;
    unsigned int avg_n_flows;

    atomic_uint flow_limit;

    atomic_uint n_flows;
    atomic_llong n_flows_timestamp;
    struct ovs_mutex n_flows_mutex;

    struct unixctl_conn **conns;
    uint64_t conn_seq;
    size_t n_conns;

    long long int offload_rebalance_time;
};


#endif /* OVS_STRUCTS_H */
