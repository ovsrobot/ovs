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
#include "dp-packet.h"

#include "openvswitch/vlog.h"
VLOG_DEFINE_THIS_MODULE(conntrack_tp);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static const char *ct_timeout_str[] = {
#define CT_TIMEOUT(NAME, VALUE) #NAME
    CT_TIMEOUTS
#undef CT_TIMEOUT
};

static inline bool
check_present_and_set(struct timeout_policy *tp, uint32_t *v,
                      enum ct_dpif_tp_attr attr)
{
    if (tp && (tp->p.present & (1 << attr))) {
        *v = tp->p.attrs[attr];
        return true;
    }
    return false;
}

#define TP_HAS_FUNC(ATTR)  \
static bool \
tp_has_##ATTR(struct timeout_policy *tp, uint32_t *v)              \
{                                                                  \
    return check_present_and_set(tp, v, CT_DPIF_TP_ATTR_##ATTR);   \
}

/* These functions check whether the timeout value is set from the
 * present bit.  If true, then set the value to '*v'.  For meaning
 * of each value, see CT_Timeout_Policy table at ovs-vswitchd.conf.db(5).
 */
TP_HAS_FUNC(TCP_SYN_SENT)
TP_HAS_FUNC(TCP_SYN_RECV)
TP_HAS_FUNC(TCP_ESTABLISHED)
TP_HAS_FUNC(TCP_FIN_WAIT)
TP_HAS_FUNC(TCP_TIME_WAIT)
TP_HAS_FUNC(TCP_CLOSE)
TP_HAS_FUNC(UDP_FIRST)
TP_HAS_FUNC(UDP_SINGLE)
TP_HAS_FUNC(UDP_MULTIPLE)
TP_HAS_FUNC(ICMP_FIRST)
TP_HAS_FUNC(ICMP_REPLY)

static bool
conn_update_expiration_with_policy(struct conntrack *ct, struct conn *conn,
                                   enum ct_timeout tm, long long now,
                                   struct timeout_policy *tp)
{
    uint32_t val;

    switch (tm) {
    case CT_TM_TCP_FIRST_PACKET:
        if (tp_has_TCP_SYN_SENT(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_TCP_OPENING:
        if (tp_has_TCP_SYN_RECV(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_TCP_ESTABLISHED:
        if (tp_has_TCP_ESTABLISHED(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_TCP_CLOSING:
        if (tp_has_TCP_FIN_WAIT(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_TCP_FIN_WAIT:
        if (tp_has_TCP_TIME_WAIT(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_TCP_CLOSED:
        if (tp_has_TCP_CLOSE(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_OTHER_FIRST:
        if (tp_has_UDP_FIRST(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_OTHER_BIDIR:
        if (tp_has_UDP_SINGLE(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_OTHER_MULTIPLE:
        if (tp_has_UDP_MULTIPLE(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_ICMP_FIRST:
        if (tp_has_ICMP_FIRST(tp, &val)) {
            goto update_with_val;
        }
        break;
    case CT_TM_ICMP_REPLY:
        if (tp_has_ICMP_REPLY(tp, &val)) {
            goto update_with_val;
        }
        break;
    case N_CT_TM:
    default:
        OVS_NOT_REACHED();
        break;
    }
    return false;

update_with_val:
    conn_update_expiration(ct, conn, tm, now, val, false);
    return true;
}

static bool
conn_init_expiration_with_policy(struct conntrack *ct, struct conn *conn,
                                 enum ct_timeout tm, long long now,
                                 struct timeout_policy *tp)
{
    uint32_t val;

    switch (tm) {
    case CT_TM_TCP_FIRST_PACKET:
        if (tp_has_TCP_SYN_SENT(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_TCP_OPENING:
        if (tp_has_TCP_SYN_RECV(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_TCP_ESTABLISHED:
        if (tp_has_TCP_ESTABLISHED(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_TCP_CLOSING:
        if (tp_has_TCP_FIN_WAIT(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_TCP_FIN_WAIT:
        if (tp_has_TCP_TIME_WAIT(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_TCP_CLOSED:
        if (tp_has_TCP_CLOSE(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_OTHER_FIRST:
        if (tp_has_UDP_FIRST(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_OTHER_BIDIR:
        if (tp_has_UDP_SINGLE(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_OTHER_MULTIPLE:
        if (tp_has_UDP_MULTIPLE(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_ICMP_FIRST:
        if (tp_has_ICMP_FIRST(tp, &val)) {
            goto init_with_val;
        }
        break;
    case CT_TM_ICMP_REPLY:
        if (tp_has_ICMP_REPLY(tp, &val)) {
            goto init_with_val;
        }
        break;
    case N_CT_TM:
    default:
        OVS_NOT_REACHED();
        break;
    }
    return false;

init_with_val:
    conn_init_expiration(ct, conn, tm, now, val, false);
    return true;
}

void
conn_init_expiration_with_tp(struct conntrack *ct, struct conn *conn,
                             enum ct_timeout tm, long long now)
{
    struct timeout_policy *tp;

    tp = timeout_policy_lookup(ct, conn->tpid);
    if (tp && conn_init_expiration_with_policy(ct, conn, tm, now, tp)) {
        VLOG_DBG_RL(&rl, "Init timeout %s with policy.",
                    ct_timeout_str[tm]);
    } else {
        /* Init with default. */
        conn_init_expiration(ct, conn, tm, now, 0, true);
    }
}

void
conn_update_expiration_with_tp(struct conntrack *ct, struct conn *conn,
                               enum ct_timeout tm, long long now)
{
    struct timeout_policy *tp;

    tp = timeout_policy_lookup(ct, conn->tpid);
    if (tp && conn_update_expiration_with_policy(ct, conn, tm, now, tp)) {
        VLOG_DBG_RL(&rl, "Update timeout %s with policy.",
                    ct_timeout_str[tm]);
    } else {
        /* Update with default. */
        conn_update_expiration(ct, conn, tm, now, 0, true);
    }
}
