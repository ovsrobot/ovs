/*
 * Copyright (c) 2020 VMware, Inc.
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

#include "conntrack-private.h"
#include "conntrack-tp.h"
#include "ct-dpif.h"
#include "dp-packet.h"

#include "openvswitch/vlog.h"
VLOG_DEFINE_THIS_MODULE(conntrack_tp);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

#define DEFAULT_TP_ID 0

static const char *ct_timeout_str[] = {
#define CT_TIMEOUT(NAME, VALUE) #NAME,
    CT_TIMEOUTS
#undef CT_TIMEOUT
};

static const char *dpif_ct_timeout_str[] = {
#define xstr(s) #s
#define CT_DPIF_TP_TCP_ATTR(NAME, VAL) xstr(TCP_##NAME),
    CT_DPIF_TP_TCP_ATTRS
#undef CT_DPIF_TP_TCP_ATTR
#define CT_DPIF_TP_UDP_ATTR(NAME, VAL) xstr(UDP_##NAME),
    CT_DPIF_TP_UDP_ATTRS
#undef CT_DPIF_TP_UDP_ATTR
#define CT_DPIF_TP_ICMP_ATTR(NAME, VAL) xstr(ICMP_##NAME),
    CT_DPIF_TP_ICMP_ATTRS
#undef CT_DPIF_TP_ICMP_ATTR
#undef xstr
};

static unsigned int ct_dpif_timeout_value_def[] = {
#define CT_DPIF_TP_TCP_ATTR(NAME, VAL) [CT_DPIF_TP_ATTR_TCP_##NAME] = VAL,
    CT_DPIF_TP_TCP_ATTRS
#undef CT_DPIF_TP_TCP_ATTR
#define CT_DPIF_TP_UDP_ATTR(NAME, VAL) [CT_DPIF_TP_ATTR_UDP_##NAME] = VAL,
    CT_DPIF_TP_UDP_ATTRS
#undef CT_DPIF_TP_UDP_ATTR
#define CT_DPIF_TP_ICMP_ATTR(NAME, VAL) [CT_DPIF_TP_ATTR_ICMP_##NAME] = VAL,
    CT_DPIF_TP_ICMP_ATTRS
#undef CT_DPIF_TP_ICMP_ATTR
};

static void OVS_UNUSED
timeout_policy_dump(struct timeout_policy *tp)
{
    bool present;
    int i;

    VLOG_DBG("Timeout Policy ID %u:", tp->policy.id);
    for (i = 0; i < ARRAY_SIZE(tp->policy.attrs); i++) {
        if (tp->policy.present & (1 << i)) {
            present = !!(tp->policy.present & (1 << i));
            VLOG_DBG("  Policy: %s present: %u value: %u",
                      dpif_ct_timeout_str[i], present, tp->policy.attrs[i]);
        }
    }
}

static struct timeout_policy *
timeout_policy_lookup(struct conntrack *ct, int32_t tp_id)
    OVS_REQUIRES(ct->ct_lock)
{
    struct timeout_policy *tp;
    uint32_t hash;

    hash = hash_int(tp_id, ct->hash_basis);
    HMAP_FOR_EACH_IN_BUCKET (tp, node, hash, &ct->timeout_policies) {
        if (tp->policy.id == tp_id) {
            return tp;
        }
    }
    return NULL;
}

struct timeout_policy *
timeout_policy_get(struct conntrack *ct, int32_t tp_id)
{
    struct timeout_policy *tp;

    ovs_mutex_lock(&ct->ct_lock);
    tp = timeout_policy_lookup(ct, tp_id);
    if (!tp) {
        ovs_mutex_unlock(&ct->ct_lock);
        return NULL;
    }

    ovs_mutex_unlock(&ct->ct_lock);
    return tp;
}

static void
update_existing_tp(struct timeout_policy *tp_dst,
                   struct timeout_policy *tp_src)
{
    struct ct_dpif_timeout_policy *dst, *src;
    int i;

    dst = &tp_dst->policy;
    src = &tp_src->policy;

    /* Set the value and present bit to dst if present
     * bit in src is set.
     */
    for (i = 0; i < ARRAY_SIZE(dst->attrs); i++) {
        if (src->present & (1 << i)) {
            dst->attrs[i] = src->attrs[i];
            dst->present |= (1 << i);
        }
    }
}

static void
init_default_tp(struct timeout_policy *tp, uint32_t tp_id)
{
    tp->policy.id = tp_id;
    /* Initialize the timeout value to default, but not
     * setting the present bit.
     */
    tp->policy.present = 0;
    memcpy(tp->policy.attrs, ct_dpif_timeout_value_def,
           sizeof tp->policy.attrs);
}

static void
timeout_policy_create(struct conntrack *ct,
                      struct timeout_policy *new_tp)
    OVS_REQUIRES(ct->ct_lock)
{
    uint32_t tp_id = new_tp->policy.id;
    struct timeout_policy *tp;
    uint32_t hash;

    tp = xzalloc(sizeof *tp);
    init_default_tp(tp, tp_id);
    update_existing_tp(tp, new_tp);
    hash = hash_int(tp_id, ct->hash_basis);
    hmap_insert(&ct->timeout_policies, &tp->node, hash);
}

int
timeout_policy_update(struct conntrack *ct,
                      struct timeout_policy *new_tp)
{
    int err = 0;
    uint32_t tp_id = new_tp->policy.id;

    ovs_mutex_lock(&ct->ct_lock);
    struct timeout_policy *tp = timeout_policy_lookup(ct, tp_id);
    if (tp) {
        update_existing_tp(tp, new_tp);
    } else {
        timeout_policy_create(ct, new_tp);
    }
    ovs_mutex_unlock(&ct->ct_lock);
    return err;
}

void
timeout_policy_clean(struct conntrack *ct, struct timeout_policy *tp)
    OVS_REQUIRES(ct->ct_lock)
{
    hmap_remove(&ct->timeout_policies, &tp->node);
    free(tp);
}

int
timeout_policy_delete(struct conntrack *ct, uint32_t tp_id)
{
    ovs_mutex_lock(&ct->ct_lock);
    struct timeout_policy *tp = timeout_policy_lookup(ct, tp_id);
    if (tp) {
        timeout_policy_clean(ct, tp);
    } else {
        VLOG_WARN_RL(&rl, "Attempted delete of non-existent timeout "
                     "policy: zone %d", tp_id);
    }
    ovs_mutex_unlock(&ct->ct_lock);
    return 0;
}

void
timeout_policy_init(struct conntrack *ct)
    OVS_REQUIRES(ct->ct_lock)
{
    struct timeout_policy tp;

    hmap_init(&ct->timeout_policies);

    /* Create default timeout policy. */
    memset(&tp, 0, sizeof tp);
    tp.policy.id = DEFAULT_TP_ID;
    timeout_policy_create(ct, &tp);
}

static enum ct_dpif_tp_attr
tm_to_ct_dpif_tp(enum ct_timeout tm)
{
    switch (tm) {
    case CT_TM_TCP_FIRST_PACKET:
        return CT_DPIF_TP_ATTR_TCP_SYN_SENT;
    case CT_TM_TCP_OPENING:
        return CT_DPIF_TP_ATTR_TCP_SYN_RECV;
    case CT_TM_TCP_ESTABLISHED:
        return CT_DPIF_TP_ATTR_TCP_ESTABLISHED;
    case CT_TM_TCP_CLOSING:
        return CT_DPIF_TP_ATTR_TCP_FIN_WAIT;
    case CT_TM_TCP_FIN_WAIT:
        return CT_DPIF_TP_ATTR_TCP_TIME_WAIT;
    case CT_TM_TCP_CLOSED:
        return CT_DPIF_TP_ATTR_TCP_CLOSE;
    case CT_TM_OTHER_FIRST:
        return CT_DPIF_TP_ATTR_UDP_FIRST;
    case CT_TM_OTHER_BIDIR:
        return CT_DPIF_TP_ATTR_UDP_SINGLE;
    case CT_TM_OTHER_MULTIPLE:
        return CT_DPIF_TP_ATTR_UDP_MULTIPLE;
    case CT_TM_ICMP_FIRST:
        return CT_DPIF_TP_ATTR_ICMP_FIRST;
    case CT_TM_ICMP_REPLY:
        return CT_DPIF_TP_ATTR_ICMP_REPLY;
    case N_CT_TM:
    default:
        OVS_NOT_REACHED();
        break;
    }
    OVS_NOT_REACHED();
    return CT_DPIF_TP_ATTR_MAX;
}

static void
conn_update_expiration__(struct conntrack *ct, struct conn *conn,
                         enum ct_timeout tm, long long now,
                         uint32_t tp_value)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_mutex_unlock(&conn->lock);

    ovs_mutex_lock(&ct->ct_lock);
    ovs_mutex_lock(&conn->lock);
    if (!conn->cleaned) {
        conn->expiration = now + tp_value * 1000;
        ovs_list_remove(&conn->exp_node);
        ovs_list_push_back(&ct->exp_lists[tm], &conn->exp_node);
    }
    ovs_mutex_unlock(&conn->lock);
    ovs_mutex_unlock(&ct->ct_lock);

    ovs_mutex_lock(&conn->lock);
}

/* The conn entry lock must be held on entry and exit. */
void
conn_update_expiration(struct conntrack *ct, struct conn *conn,
                       enum ct_timeout tm, long long now)
    OVS_REQUIRES(ct->ct_lock)
{
    struct timeout_policy *tp;
    uint32_t val;

    tp = timeout_policy_lookup(ct, conn->tp_id);
    if (tp) {
        val = tp->policy.attrs[tm_to_ct_dpif_tp(tm)];
    } else {
        val = ct_dpif_timeout_value_def[tm_to_ct_dpif_tp(tm)];
    }
    VLOG_DBG_RL(&rl, "Update timeout %s with policy id=%d val=%u sec.",
                ct_timeout_str[tm], conn->tp_id, val);

    conn_update_expiration__(ct, conn, tm, now, val);
}

static void
conn_init_expiration__(struct conntrack *ct, struct conn *conn,
                       enum ct_timeout tm, long long now,
                       uint32_t tp_value)
{
    conn->expiration = now + tp_value * 1000;
    ovs_list_push_back(&ct->exp_lists[tm], &conn->exp_node);
}

/* ct_lock must be held. */
void
conn_init_expiration(struct conntrack *ct, struct conn *conn,
                     enum ct_timeout tm, long long now)
    OVS_REQUIRES(ct->ct_lock)
{
    struct timeout_policy *tp;
    uint32_t val;

    tp = timeout_policy_lookup(ct, conn->tp_id);
    if (tp) {
        val = tp->policy.attrs[tm_to_ct_dpif_tp(tm)];
    } else {
        val = ct_dpif_timeout_value_def[tm_to_ct_dpif_tp(tm)];
    }
    VLOG_DBG_RL(&rl, "Init timeout %s with policy id=%d val=%u sec.",
                ct_timeout_str[tm], conn->tp_id, val);

    conn_init_expiration__(ct, conn, tm, now, val);
}
