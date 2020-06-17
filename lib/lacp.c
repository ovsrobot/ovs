/* Copyright (c) 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include "lacp.h"

#include <stdlib.h>

#include "connectivity.h"
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "dp-packet.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "openvswitch/shash.h"
#include "timer.h"
#include "timeval.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(lacp);

/* Masks for lacp_info state member. */
#define LACP_STATE_ACT  0x01 /* Activity. Active or passive? */
#define LACP_STATE_TIME 0x02 /* Timeout. Short or long timeout? */
#define LACP_STATE_AGG  0x04 /* Aggregation. Is the link is bondable? */
#define LACP_STATE_SYNC 0x08 /* Synchronization. Is the link in up to date? */
#define LACP_STATE_COL  0x10 /* Collecting. Is the link receiving frames? */
#define LACP_STATE_DIST 0x20 /* Distributing. Is the link sending frames? */
#define LACP_STATE_DEF  0x40 /* Defaulted. Using default partner info? */
#define LACP_STATE_EXP  0x80 /* Expired. Using expired partner info? */

#define LACP_FAST_TIME_TX 1000  /* Fast transmission rate. */
#define LACP_SLOW_TIME_TX 30000 /* Slow transmission rate. */
#define LACP_RX_MULTIPLIER 3    /* Multiply by TX rate to get RX rate. */

#define LACP_INFO_LEN 15
OVS_PACKED(
struct lacp_info {
    ovs_be16 sys_priority;            /* System priority. */
    struct eth_addr sys_id;           /* System ID. */
    ovs_be16 key;                     /* Operational key. */
    ovs_be16 port_priority;           /* Port priority. */
    ovs_be16 port_id;                 /* Port ID. */
    uint8_t state;                    /* State mask.  See LACP_STATE macros. */
});
BUILD_ASSERT_DECL(LACP_INFO_LEN == sizeof(struct lacp_info));

#define LACP_PDU_LEN 110
struct lacp_pdu {
    uint8_t subtype;          /* Always 1. */
    uint8_t version;          /* Always 1. */

    uint8_t actor_type;       /* Always 1. */
    uint8_t actor_len;        /* Always 20. */
    struct lacp_info actor;   /* LACP actor information. */
    uint8_t z1[3];            /* Reserved.  Always 0. */

    uint8_t partner_type;     /* Always 2. */
    uint8_t partner_len;      /* Always 20. */
    struct lacp_info partner; /* LACP partner information. */
    uint8_t z2[3];            /* Reserved.  Always 0. */

    uint8_t collector_type;   /* Always 3. */
    uint8_t collector_len;    /* Always 16. */
    ovs_be16 collector_delay; /* Maximum collector delay. Set to UINT16_MAX. */
    uint8_t z3[64];           /* Combination of several fields.  Always 0. */
};
BUILD_ASSERT_DECL(LACP_PDU_LEN == sizeof(struct lacp_pdu));

/* Implementation. */

enum pdu_subtype {
    SUBTYPE_UNUSED = 0,
    SUBTYPE_LACP,       /* Link Aggregation Control Protocol. */
    SUBTYPE_MARKER,     /* Link Aggregation Marker Protocol. */
};

enum sub_status {
    LACP_CURRENT,   /* Current State.  Partner up to date. */
    LACP_EXPIRED,   /* Expired State.  Partner out of date. */
    LACP_DEFAULTED, /* Defaulted State.  No partner. */
};

/* A LACP primary interface. */
struct lacp {
    struct ovs_list node;         /* Node in all_lacps list. */
    char *name;                   /* Name of this lacp object. */
    struct eth_addr sys_id;       /* System ID. */
    uint16_t sys_priority;        /* System Priority. */
    bool active;                  /* Active or Passive. */

    struct hmap subs;           /* Subs this LACP object controls. */
    struct sub *key_sub;        /* Sub whose ID will be the aggregation key. */

    bool fast;               /* True if using fast probe interval. */
    bool negotiated;         /* True if LACP negotiations were successful. */
    bool update;             /* True if lacp_update() needs to be called. */
    bool fallback_ab; /* True if fallback to active-backup on LACP failure. */

    struct ovs_refcount ref_cnt;
};

/* A LACP sub-interface. */
struct sub {
    void *aux;                    /* Handle used to identify this sub. */
    struct hmap_node node;        /* Node in primary's subs map. */

    struct lacp *lacp;            /* LACP object containing this sub. */
    uint16_t port_id;             /* Port ID. */
    uint16_t port_priority;       /* Port Priority. */
    uint16_t key;                 /* Aggregation Key. 0 if default. */
    char *name;                   /* Name of this sub. */

    enum sub_status status;       /* Sub status. */
    bool attached;                /* Attached. Traffic may flow. */
    bool carrier_up;              /* Carrier state of link. */
    struct lacp_info partner;     /* Partner information. */
    struct lacp_info ntt_actor;   /* Used to decide if we Need To Transmit. */
    struct timer tx;              /* Next message transmission timer. */
    struct timer rx;              /* Expected message receive timer. */

    uint32_t count_rx_pdus;         /* dot3adAggPortStatsLACPDUsRx */
    uint32_t count_rx_pdus_bad;     /* dot3adAggPortStatsIllegalRx */
    uint32_t count_rx_pdus_marker;  /* dot3adAggPortStatsMarkerPDUsRx */
    uint32_t count_tx_pdus;         /* dot3adAggPortStatsLACPDUsTx */
    uint32_t count_link_expired;    /* Num of times link expired */
    uint32_t count_link_defaulted;  /* Num of times link defaulted */
    uint32_t count_carrier_changed; /* Num of times link status changed */
};

static struct ovs_mutex mutex;
static struct ovs_list all_lacps__ = OVS_LIST_INITIALIZER(&all_lacps__);
static struct ovs_list *const all_lacps OVS_GUARDED_BY(mutex) = &all_lacps__;

static void lacp_update_attached(struct lacp *) OVS_REQUIRES(mutex);

static void sub_destroy(struct sub *) OVS_REQUIRES(mutex);
static void sub_set_defaulted(struct sub *) OVS_REQUIRES(mutex);
static void sub_set_expired(struct sub *) OVS_REQUIRES(mutex);
static void sub_get_actor(struct sub *, struct lacp_info *actor)
    OVS_REQUIRES(mutex);
static void sub_get_priority(struct sub *, struct lacp_info *priority)
    OVS_REQUIRES(mutex);
static bool sub_may_tx(const struct sub *)
    OVS_REQUIRES(mutex);
static struct sub *sub_lookup(const struct lacp *, const void *sub)
    OVS_REQUIRES(mutex);
static bool info_tx_equal(struct lacp_info *, struct lacp_info *)
    OVS_REQUIRES(mutex);
static bool sub_may_enable__(struct sub *sub) OVS_REQUIRES(mutex);

static unixctl_cb_func lacp_unixctl_show;
static unixctl_cb_func lacp_unixctl_show_stats;

/* Populates 'pdu' with a LACP PDU comprised of 'actor' and 'partner'. */
static void
compose_lacp_pdu(const struct lacp_info *actor,
                 const struct lacp_info *partner, struct lacp_pdu *pdu)
{
    memset(pdu, 0, sizeof *pdu);

    pdu->subtype = 1;
    pdu->version = 1;

    pdu->actor_type = 1;
    pdu->actor_len = 20;
    pdu->actor = *actor;

    pdu->partner_type = 2;
    pdu->partner_len = 20;
    pdu->partner = *partner;

    pdu->collector_type = 3;
    pdu->collector_len = 16;
    pdu->collector_delay = htons(0);
}

/* Parses 'p' which represents a packet containing a LACP PDU. This function
 * returns NULL if 'p' is malformed, or does not represent a LACP PDU format
 * supported by OVS.  Otherwise, it returns a pointer to the lacp_pdu contained
 * within 'p'. It also returns the subtype of PDU.*/

static const struct lacp_pdu *
parse_lacp_packet(const struct dp_packet *p, enum pdu_subtype *subtype)
{
    const struct lacp_pdu *pdu;

    pdu = dp_packet_at(p, (uint8_t *)dp_packet_l3(p) - (uint8_t *)dp_packet_data(p),
                    LACP_PDU_LEN);

    if (pdu && pdu->subtype == 1
        && pdu->actor_type == 1 && pdu->actor_len == 20
        && pdu->partner_type == 2 && pdu->partner_len == 20) {
        *subtype = SUBTYPE_LACP;
        return pdu;
    } else if (pdu && pdu->subtype == SUBTYPE_MARKER) {
        *subtype = SUBTYPE_MARKER;
        return NULL;
    } else{
        *subtype = SUBTYPE_UNUSED;
        return NULL;
    }
}

/* LACP Protocol Implementation. */

/* Initializes the lacp module. */
void
lacp_init(void)
{
    unixctl_command_register("lacp/show", "[port]", 0, 1,
                             lacp_unixctl_show, NULL);
    unixctl_command_register("lacp/show-stats", "[port]", 0, 1,
                             lacp_unixctl_show_stats, NULL);
}

static void
lacp_lock(void) OVS_ACQUIRES(mutex)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        ovs_mutex_init_recursive(&mutex);
        ovsthread_once_done(&once);
    }
    ovs_mutex_lock(&mutex);
}

static void
lacp_unlock(void) OVS_RELEASES(mutex)
{
    ovs_mutex_unlock(&mutex);
}

/* Creates a LACP object. */
struct lacp *
lacp_create(void) OVS_EXCLUDED(mutex)
{
    struct lacp *lacp;

    lacp = xzalloc(sizeof *lacp);
    hmap_init(&lacp->subs);
    ovs_refcount_init(&lacp->ref_cnt);

    lacp_lock();
    ovs_list_push_back(all_lacps, &lacp->node);
    lacp_unlock();
    return lacp;
}

struct lacp *
lacp_ref(const struct lacp *lacp_)
{
    struct lacp *lacp = CONST_CAST(struct lacp *, lacp_);
    if (lacp) {
        ovs_refcount_ref(&lacp->ref_cnt);
    }
    return lacp;
}

/* Destroys 'lacp' and its subs. Does nothing if 'lacp' is NULL. */
void
lacp_unref(struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    if (lacp && ovs_refcount_unref_relaxed(&lacp->ref_cnt) == 1) {
        struct sub *sub, *next;

        lacp_lock();
        HMAP_FOR_EACH_SAFE (sub, next, node, &lacp->subs) {
            sub_destroy(sub);
        }

        hmap_destroy(&lacp->subs);
        ovs_list_remove(&lacp->node);
        free(lacp->name);
        free(lacp);
        lacp_unlock();
    }
}

/* Configures 'lacp' with settings from 's'. */
void
lacp_configure(struct lacp *lacp, const struct lacp_settings *s)
    OVS_EXCLUDED(mutex)
{
    ovs_assert(!eth_addr_is_zero(s->id));

    lacp_lock();
    if (!lacp->name || strcmp(s->name, lacp->name)) {
        free(lacp->name);
        lacp->name = xstrdup(s->name);
    }

    if (!eth_addr_equals(lacp->sys_id, s->id)
        || lacp->sys_priority != s->priority) {
        lacp->sys_id = s->id;
        lacp->sys_priority = s->priority;
        lacp->update = true;
    }

    lacp->active = s->active;
    lacp->fast = s->fast;

    if (lacp->fallback_ab != s->fallback_ab_cfg) {
        lacp->fallback_ab = s->fallback_ab_cfg;
        lacp->update = true;
    }

    lacp_unlock();
}

/* Returns true if 'lacp' is configured in active mode, false if 'lacp' is
 * configured for passive mode. */
bool
lacp_is_active(const struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    bool ret;
    lacp_lock();
    ret = lacp->active;
    lacp_unlock();
    return ret;
}

/* Processes 'packet' which was received on 'sub_'.  This function should be
 * called on all packets received on 'sub_' with Ethernet Type ETH_TYPE_LACP.
 */
bool
lacp_process_packet(struct lacp *lacp, const void *sub_,
                    const struct dp_packet *packet)
    OVS_EXCLUDED(mutex)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const struct lacp_pdu *pdu;
    long long int tx_rate;
    struct sub *sub;
    bool lacp_may_enable = false;
    enum pdu_subtype subtype;

    lacp_lock();
    sub = sub_lookup(lacp, sub_);
    if (!sub) {
        goto out;
    }
    sub->count_rx_pdus++;

    pdu = parse_lacp_packet(packet, &subtype);
    switch (subtype) {
        case SUBTYPE_LACP:
            break;
        case SUBTYPE_MARKER:
            sub->count_rx_pdus_marker++;
            VLOG_DBG("%s: received a LACP marker PDU.", lacp->name);
            goto out;
        case SUBTYPE_UNUSED:
        default:
            sub->count_rx_pdus_bad++;
            VLOG_WARN_RL(&rl, "%s: received an unparsable LACP PDU.",
                         lacp->name);
            goto out;
    }

    /* On some NICs L1 state reporting is slow. In case LACP packets are
     * received while carrier (L1) state is still down, drop the LACP PDU and
     * trigger re-checking of L1 state. */
    if (!sub->carrier_up) {
        VLOG_INFO_RL(&rl, "%s: carrier state is DOWN,"
                     " dropping received LACP PDU.", sub->name);
        seq_change(connectivity_seq_get());
        goto out;
    }

    sub->status = LACP_CURRENT;
    tx_rate = lacp->fast ? LACP_FAST_TIME_TX : LACP_SLOW_TIME_TX;
    timer_set_duration(&sub->rx, LACP_RX_MULTIPLIER * tx_rate);

    sub->ntt_actor = pdu->partner;

    /* Update our information about our partner if it's out of date. This may
     * cause priorities to change so re-calculate attached status of all
     * subs. */
    if (memcmp(&sub->partner, &pdu->actor, sizeof pdu->actor)) {
        lacp->update = true;
        sub->partner = pdu->actor;
    }

    /* Evaluate may_enable here to avoid dropping of packets till main thread
     * sets may_enable to true. */
    lacp_may_enable = sub_may_enable__(sub);

out:
    lacp_unlock();

    return lacp_may_enable;
}

/* Returns the lacp_status of the given 'lacp' object (which may be NULL). */
enum lacp_status
lacp_status(const struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    if (lacp) {
        enum lacp_status ret;

        lacp_lock();
        ret = lacp->negotiated ? LACP_NEGOTIATED : LACP_CONFIGURED;
        lacp_unlock();
        return ret;
    } else {
        /* Don't take 'mutex'.  It might not even be initialized, since we
         * don't know that any lacp object has been created. */
        return LACP_DISABLED;
    }
}

/* Registers 'sub_' as subordinate to 'lacp'.  This should be called at least
 * once per sub in a LACP managed bond.  Should also be called whenever a
 * sub's settings change. */
void
lacp_sub_register(struct lacp *lacp, void *sub_,
                  const struct lacp_sub_settings *s)
    OVS_EXCLUDED(mutex)
{
    struct sub *sub;

    lacp_lock();
    sub = sub_lookup(lacp, sub_);
    if (!sub) {
        sub = xzalloc(sizeof *sub);
        sub->lacp = lacp;
        sub->aux = sub_;
        hmap_insert(&lacp->subs, &sub->node, hash_pointer(sub_, 0));
        sub_set_defaulted(sub);

        if (!lacp->key_sub) {
            lacp->key_sub = sub;
        }
    }

    if (!sub->name || strcmp(s->name, sub->name)) {
        free(sub->name);
        sub->name = xstrdup(s->name);
    }

    if (sub->port_id != s->id
        || sub->port_priority != s->priority
        || sub->key != s->key) {
        sub->port_id = s->id;
        sub->port_priority = s->priority;
        sub->key = s->key;

        lacp->update = true;

        if (lacp->active || lacp->negotiated) {
            sub_set_expired(sub);
        }
    }
    lacp_unlock();
}

/* Unregisters 'sub_' with 'lacp'.  */
void
lacp_sub_unregister(struct lacp *lacp, const void *sub_)
    OVS_EXCLUDED(mutex)
{
    struct sub *sub;

    lacp_lock();
    sub = sub_lookup(lacp, sub_);
    if (sub) {
        sub_destroy(sub);
        lacp->update = true;
    }
    lacp_unlock();
}

/* This function should be called whenever the carrier status of 'sub_' has
 * changed.  If 'lacp' is null, this function has no effect.*/
void
lacp_sub_carrier_changed(const struct lacp *lacp, const void *sub_,
                           bool carrier_up)
    OVS_EXCLUDED(mutex)
{
    struct sub *sub;
    if (!lacp) {
        return;
    }

    lacp_lock();
    sub = sub_lookup(lacp, sub_);
    if (!sub) {
        goto out;
    }

    if (sub->status == LACP_CURRENT || sub->lacp->active) {
        sub_set_expired(sub);
    }

    if (sub->carrier_up != carrier_up) {
        sub->carrier_up = carrier_up;
        sub->count_carrier_changed++;
    }

out:
    lacp_unlock();
}

static bool
sub_may_enable__(struct sub *sub) OVS_REQUIRES(mutex)
{
    /* The sub may be enabled if it's attached to an aggregator and its
     * partner is synchronized.*/
    return sub->attached && (sub->partner.state & LACP_STATE_SYNC
            || (sub->lacp && sub->lacp->fallback_ab
                && sub->status == LACP_DEFAULTED));
}

/* This function should be called before enabling 'sub_' to send or receive
 * traffic.  If it returns false, 'sub_' should not enabled.  As a
 * convenience, returns true if 'lacp' is NULL. */
bool
lacp_sub_may_enable(const struct lacp *lacp, const void *sub_)
    OVS_EXCLUDED(mutex)
{
    if (lacp) {
        struct sub *sub;
        bool ret = false;

        lacp_lock();
        sub = sub_lookup(lacp, sub_);
        if (sub) {
            /* It is only called when carrier is up. So, enable sub's
             * carrier state if it is currently down. */
            if (!sub->carrier_up) {
                sub->carrier_up = true;
            }
            ret = sub_may_enable__(sub);
        }
        lacp_unlock();
        return ret;
    } else {
        return true;
    }
}

/* Returns true if partner information on 'sub_' is up to date.  'sub_'
 * not being current, generally indicates a connectivity problem, or a
 * misconfigured (or broken) partner. */
bool
lacp_sub_is_current(const struct lacp *lacp, const void *sub_)
    OVS_EXCLUDED(mutex)
{
    struct sub *sub;
    bool ret;

    lacp_lock();
    sub = sub_lookup(lacp, sub_);
    ret = sub ? sub->status != LACP_DEFAULTED : false;
    lacp_unlock();
    return ret;
}

/* This function should be called periodically to update 'lacp'. */
void
lacp_run(struct lacp *lacp, lacp_send_pdu *send_pdu) OVS_EXCLUDED(mutex)
{
    struct sub *sub;

    lacp_lock();
    HMAP_FOR_EACH (sub, node, &lacp->subs) {
        if (timer_expired(&sub->rx)) {
            enum sub_status old_status = sub->status;

            if (sub->status == LACP_CURRENT) {
                sub_set_expired(sub);
                sub->count_link_expired++;
            } else if (sub->status == LACP_EXPIRED) {
                sub_set_defaulted(sub);
                sub->count_link_defaulted++;
            }
            if (sub->status != old_status) {
                seq_change(connectivity_seq_get());
            }
        }
    }

    if (lacp->update) {
        lacp_update_attached(lacp);
        seq_change(connectivity_seq_get());
    }

    HMAP_FOR_EACH (sub, node, &lacp->subs) {
        struct lacp_info actor;

        if (!sub_may_tx(sub)) {
            continue;
        }

        sub_get_actor(sub, &actor);

        if (timer_expired(&sub->tx)
            || !info_tx_equal(&actor, &sub->ntt_actor)) {
            long long int duration;
            struct lacp_pdu pdu;

            sub->ntt_actor = actor;
            compose_lacp_pdu(&actor, &sub->partner, &pdu);
            send_pdu(sub->aux, &pdu, sizeof pdu);
            sub->count_tx_pdus++;

            duration = (sub->partner.state & LACP_STATE_TIME
                        ? LACP_FAST_TIME_TX
                        : LACP_SLOW_TIME_TX);

            timer_set_duration(&sub->tx, duration);
            seq_change(connectivity_seq_get());
        }
    }
    lacp_unlock();
}

/* Causes poll_block() to wake up when lacp_run() needs to be called again. */
void
lacp_wait(struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    struct sub *sub;

    lacp_lock();
    HMAP_FOR_EACH (sub, node, &lacp->subs) {
        if (sub_may_tx(sub)) {
            timer_wait(&sub->tx);
        }

        if (sub->status != LACP_DEFAULTED) {
            timer_wait(&sub->rx);
        }
    }
    lacp_unlock();
}

/* Static Helpers. */

/* Updates the attached status of all subs controlled by 'lacp' and sets its
 * negotiated parameter to true if any subs are attachable. */
static void
lacp_update_attached(struct lacp *lacp) OVS_REQUIRES(mutex)
{
    struct sub *lead, *lead_current, *sub;
    struct lacp_info lead_pri;
    bool lead_enable;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 10);

    lacp->update = false;

    lead = NULL;
    lead_current = NULL;
    lead_enable = false;

    /* Check if there is a working interface.
     * Store as lead_current, if there is one. */
    HMAP_FOR_EACH (sub, node, &lacp->subs) {
        if (sub->status == LACP_CURRENT && sub->attached) {
            struct lacp_info pri;
            sub_get_priority(sub, &pri);
            if (!lead_current || memcmp(&pri, &lead_pri, sizeof pri) < 0) {
                lead_current = sub;
                lead = lead_current;
                lead_pri = pri;
                lead_enable = true;
            }
        }
    }

    /* Find interface with highest priority. */
    HMAP_FOR_EACH (sub, node, &lacp->subs) {
        struct lacp_info pri;

        sub->attached = false;

        /* XXX: In the future allow users to configure the expected system ID.
         * For now just special case loopback. */
        if (eth_addr_equals(sub->partner.sys_id, sub->lacp->sys_id)) {
            VLOG_WARN_RL(&rl, "interface %s: Loopback detected. Interface is "
                         "connected to its own bond", sub->name);
            continue;
        }

        if (sub->status == LACP_DEFAULTED) {
            if (lacp->fallback_ab) {
                sub->attached = true;
            }
            continue;
        }

        sub_get_priority(sub, &pri);
        bool enable = sub_may_enable__(sub);

        /* Check if partner MAC address is the same as on the working
         * interface. Activate sub only if the MAC is the same, or
         * there is no working interface. */
        if (!lead_current || (lead_current
            && eth_addr_equals(sub->partner.sys_id,
                               lead_current->partner.sys_id))) {
            sub->attached = true;
        }
        if (sub->attached &&
                (!lead
                 || enable > lead_enable
                 || (enable == lead_enable
                     && memcmp(&pri, &lead_pri, sizeof pri) < 0))) {
            lead = sub;
            lead_enable = enable;
            lead_pri = pri;
        }
    }

    lacp->negotiated = lead != NULL;

    if (lead) {
        HMAP_FOR_EACH (sub, node, &lacp->subs) {
            if ((lacp->fallback_ab && sub->status == LACP_DEFAULTED)
                || lead->partner.key != sub->partner.key
                || !eth_addr_equals(lead->partner.sys_id,
                                    sub->partner.sys_id)) {
                sub->attached = false;
            }
        }
    }
}

static void
sub_destroy(struct sub *sub) OVS_REQUIRES(mutex)
{
    if (sub) {
        struct lacp *lacp = sub->lacp;

        lacp->update = true;
        hmap_remove(&lacp->subs, &sub->node);

        if (lacp->key_sub == sub) {
            struct hmap_node *sub_node = hmap_first(&lacp->subs);

            if (sub_node) {
                lacp->key_sub = CONTAINER_OF(sub_node, struct sub, node);
            } else {
                lacp->key_sub = NULL;
            }
        }

        free(sub->name);
        free(sub);
    }
}

static void
sub_set_defaulted(struct sub *sub) OVS_REQUIRES(mutex)
{
    memset(&sub->partner, 0, sizeof sub->partner);

    sub->lacp->update = true;
    sub->status = LACP_DEFAULTED;
}

static void
sub_set_expired(struct sub *sub) OVS_REQUIRES(mutex)
{
    sub->status = LACP_EXPIRED;
    sub->partner.state |= LACP_STATE_TIME;
    sub->partner.state &= ~LACP_STATE_SYNC;

    timer_set_duration(&sub->rx, LACP_RX_MULTIPLIER * LACP_FAST_TIME_TX);
}

static void
sub_get_actor(struct sub *sub, struct lacp_info *actor)
    OVS_REQUIRES(mutex)
{
    struct lacp *lacp = sub->lacp;
    uint16_t key;
    uint8_t state = 0;

    if (lacp->active) {
        state |= LACP_STATE_ACT;
    }

    if (lacp->fast) {
        state |= LACP_STATE_TIME;
    }

    if (sub->attached) {
        state |= LACP_STATE_SYNC;
    }

    if (sub->status == LACP_DEFAULTED) {
        state |= LACP_STATE_DEF;
    }

    if (sub->status == LACP_EXPIRED) {
        state |= LACP_STATE_EXP;
    }

    if (hmap_count(&lacp->subs) > 1) {
        state |= LACP_STATE_AGG;
    }

    if (sub->attached || !lacp->negotiated) {
        state |= LACP_STATE_COL | LACP_STATE_DIST;
    }

    key = lacp->key_sub->key;
    if (!key) {
        key = lacp->key_sub->port_id;
    }

    actor->state = state;
    actor->key = htons(key);
    actor->port_priority = htons(sub->port_priority);
    actor->port_id = htons(sub->port_id);
    actor->sys_priority = htons(lacp->sys_priority);
    actor->sys_id = lacp->sys_id;
}

/* Given 'sub', populates 'priority' with data representing its LACP link
 * priority.  If two priority objects populated by this function are compared
 * using memcmp, the higher priority link will be less than the lower priority
 * link. */
static void
sub_get_priority(struct sub *sub, struct lacp_info *priority)
    OVS_REQUIRES(mutex)
{
    uint16_t partner_priority, actor_priority;

    /* Choose the lacp_info of the higher priority system by comparing their
     * system priorities and mac addresses. */
    actor_priority = sub->lacp->sys_priority;
    partner_priority = ntohs(sub->partner.sys_priority);
    if (actor_priority < partner_priority) {
        sub_get_actor(sub, priority);
    } else if (partner_priority < actor_priority) {
        *priority = sub->partner;
    } else if (eth_addr_compare_3way(sub->lacp->sys_id,
                                     sub->partner.sys_id) < 0) {
        sub_get_actor(sub, priority);
    } else {
        *priority = sub->partner;
    }

    /* Key and state are not used in priority comparisons. */
    priority->key = 0;
    priority->state = 0;
}

static bool
sub_may_tx(const struct sub *sub) OVS_REQUIRES(mutex)
{
    /* Check for L1 state as well as LACP state. */
    return (sub->carrier_up) && ((sub->lacp->active) ||
            (sub->status != LACP_DEFAULTED));
}

static struct sub *
sub_lookup(const struct lacp *lacp, const void *sub_) OVS_REQUIRES(mutex)
{
    struct sub *sub;

    HMAP_FOR_EACH_IN_BUCKET (sub, node, hash_pointer(sub_, 0),
                             &lacp->subs) {
        if (sub->aux == sub_) {
            return sub;
        }
    }

    return NULL;
}

/* Two lacp_info structures are tx_equal if and only if they do not differ in
 * ways which would require a lacp_pdu transmission. */
static bool
info_tx_equal(struct lacp_info *a, struct lacp_info *b)
{

    /* LACP specification dictates that we transmit whenever the actor and
     * remote_actor differ in the following fields: Port, Port Priority,
     * System, System Priority, Aggregation Key, Activity State, Timeout State,
     * Sync State, and Aggregation State. The state flags are most likely to
     * change so are checked first. */
    return !((a->state ^ b->state) & (LACP_STATE_ACT
                                      | LACP_STATE_TIME
                                      | LACP_STATE_SYNC
                                      | LACP_STATE_AGG))
        && a->port_id == b->port_id
        && a->port_priority == b->port_priority
        && a->key == b->key
        && a->sys_priority == b->sys_priority
        && eth_addr_equals(a->sys_id, b->sys_id);
}

static struct lacp *
lacp_find(const char *name) OVS_REQUIRES(mutex)
{
    struct lacp *lacp;

    LIST_FOR_EACH (lacp, node, all_lacps) {
        if (!strcmp(lacp->name, name)) {
            return lacp;
        }
    }

    return NULL;
}

static void
ds_put_lacp_state(struct ds *ds, uint8_t state)
{
    if (state & LACP_STATE_ACT) {
        ds_put_cstr(ds, " activity");
    }

    if (state & LACP_STATE_TIME) {
        ds_put_cstr(ds, " timeout");
    }

    if (state & LACP_STATE_AGG) {
        ds_put_cstr(ds, " aggregation");
    }

    if (state & LACP_STATE_SYNC) {
        ds_put_cstr(ds, " synchronized");
    }

    if (state & LACP_STATE_COL) {
        ds_put_cstr(ds, " collecting");
    }

    if (state & LACP_STATE_DIST) {
        ds_put_cstr(ds, " distributing");
    }

    if (state & LACP_STATE_DEF) {
        ds_put_cstr(ds, " defaulted");
    }

    if (state & LACP_STATE_EXP) {
        ds_put_cstr(ds, " expired");
    }
}

static void
lacp_print_details(struct ds *ds, struct lacp *lacp) OVS_REQUIRES(mutex)
{
    struct shash sub_shash = SHASH_INITIALIZER(&sub_shash);
    const struct shash_node **sorted_subs = NULL;

    struct sub *sub;
    int i;

    ds_put_format(ds, "---- %s ----\n", lacp->name);
    ds_put_format(ds, "  status: %s", lacp->active ? "active" : "passive");
    if (lacp->negotiated) {
        ds_put_cstr(ds, " negotiated");
    }
    ds_put_cstr(ds, "\n");

    ds_put_format(ds, "  sys_id: " ETH_ADDR_FMT "\n", ETH_ADDR_ARGS(lacp->sys_id));
    ds_put_format(ds, "  sys_priority: %u\n", lacp->sys_priority);
    ds_put_cstr(ds, "  aggregation key: ");
    if (lacp->key_sub) {
        ds_put_format(ds, "%u", lacp->key_sub->key
                                ? lacp->key_sub->key
                                : lacp->key_sub->port_id);
    } else {
        ds_put_cstr(ds, "none");
    }
    ds_put_cstr(ds, "\n");

    ds_put_cstr(ds, "  lacp_time: ");
    if (lacp->fast) {
        ds_put_cstr(ds, "fast\n");
    } else {
        ds_put_cstr(ds, "slow\n");
    }

    HMAP_FOR_EACH (sub, node, &lacp->subs) {
        shash_add(&sub_shash, sub->name, sub);
    }
    sorted_subs = shash_sort(&sub_shash);

    for (i = 0; i < shash_count(&sub_shash); i++) {
        char *status;
        struct lacp_info actor;

        sub = sorted_subs[i]->data;
        sub_get_actor(sub, &actor);
        switch (sub->status) {
        case LACP_CURRENT:
            status = "current";
            break;
        case LACP_EXPIRED:
            status = "expired";
            break;
        case LACP_DEFAULTED:
            status = "defaulted";
            break;
        default:
            OVS_NOT_REACHED();
        }

        ds_put_format(ds, "\ninterface: %s: %s %s\n", sub->name, status,
                      sub->attached ? "attached" : "detached");
        ds_put_format(ds, "  port_id: %u\n", sub->port_id);
        ds_put_format(ds, "  port_priority: %u\n", sub->port_priority);
        ds_put_format(ds, "  may_enable: %s\n", (sub_may_enable__(sub)
                                                 ? "true" : "false"));

        ds_put_format(ds, "\n  actor sys_id: " ETH_ADDR_FMT "\n",
                      ETH_ADDR_ARGS(actor.sys_id));
        ds_put_format(ds, "  actor sys_priority: %u\n",
                      ntohs(actor.sys_priority));
        ds_put_format(ds, "  actor port_id: %u\n",
                      ntohs(actor.port_id));
        ds_put_format(ds, "  actor port_priority: %u\n",
                      ntohs(actor.port_priority));
        ds_put_format(ds, "  actor key: %u\n",
                      ntohs(actor.key));
        ds_put_cstr(ds, "  actor state:");
        ds_put_lacp_state(ds, actor.state);
        ds_put_cstr(ds, "\n\n");

        ds_put_format(ds, "  partner sys_id: " ETH_ADDR_FMT "\n",
                      ETH_ADDR_ARGS(sub->partner.sys_id));
        ds_put_format(ds, "  partner sys_priority: %u\n",
                      ntohs(sub->partner.sys_priority));
        ds_put_format(ds, "  partner port_id: %u\n",
                      ntohs(sub->partner.port_id));
        ds_put_format(ds, "  partner port_priority: %u\n",
                      ntohs(sub->partner.port_priority));
        ds_put_format(ds, "  partner key: %u\n",
                      ntohs(sub->partner.key));
        ds_put_cstr(ds, "  partner state:");
        ds_put_lacp_state(ds, sub->partner.state);
        ds_put_cstr(ds, "\n");
    }

    shash_destroy(&sub_shash);
    free(sorted_subs);
}

static void
lacp_print_stats(struct ds *ds, struct lacp *lacp) OVS_REQUIRES(mutex)
{
    struct shash sub_shash = SHASH_INITIALIZER(&sub_shash);
    const struct shash_node **sorted_subs = NULL;

    struct sub *sub;
    int i;

    ds_put_format(ds, "---- %s statistics ----\n", lacp->name);

    HMAP_FOR_EACH (sub, node, &lacp->subs) {
        shash_add(&sub_shash, sub->name, sub);
    }
    sorted_subs = shash_sort(&sub_shash);

    for (i = 0; i < shash_count(&sub_shash); i++) {
        sub = sorted_subs[i]->data;
        ds_put_format(ds, "\ninterface: %s:\n", sub->name);
        ds_put_format(ds, "  TX PDUs: %u\n", sub->count_tx_pdus);
        ds_put_format(ds, "  RX PDUs: %u\n", sub->count_rx_pdus);
        ds_put_format(ds, "  RX Bad PDUs: %u\n", sub->count_rx_pdus_bad);
        ds_put_format(ds, "  RX Marker Request PDUs: %u\n",
                      sub->count_rx_pdus_marker);
        ds_put_format(ds, "  Link Expired: %u\n",
                      sub->count_link_expired);
        ds_put_format(ds, "  Link Defaulted: %u\n",
                      sub->count_link_defaulted);
        ds_put_format(ds, "  Carrier Status Changed: %u\n",
                      sub->count_carrier_changed);
    }

    shash_destroy(&sub_shash);
    free(sorted_subs);
}

static void
lacp_unixctl_show(struct unixctl_conn *conn, int argc, const char *argv[],
                  void *aux OVS_UNUSED) OVS_EXCLUDED(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct lacp *lacp;

    lacp_lock();
    if (argc > 1) {
        lacp = lacp_find(argv[1]);
        if (!lacp) {
            unixctl_command_reply_error(conn, "no such lacp object");
            goto out;
        }
        lacp_print_details(&ds, lacp);
    } else {
        LIST_FOR_EACH (lacp, node, all_lacps) {
            lacp_print_details(&ds, lacp);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    lacp_unlock();
}

static void
lacp_unixctl_show_stats(struct unixctl_conn *conn,
                  int argc,
                  const char *argv[],
                  void *aux OVS_UNUSED) OVS_EXCLUDED(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct lacp *lacp;

    lacp_lock();
    if (argc > 1) {
        lacp = lacp_find(argv[1]);
        if (!lacp) {
            unixctl_command_reply_error(conn, "no such lacp object");
            goto out;
        }
        lacp_print_stats(&ds, lacp);
    } else {
        LIST_FOR_EACH (lacp, node, all_lacps) {
            lacp_print_stats(&ds, lacp);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    lacp_unlock();
}

/* Extract a snapshot of the current state and counters for a sub port.
   Return false if the sub is not active. */
bool
lacp_get_sub_stats(const struct lacp *lacp, const void *sub_, struct lacp_sub_stats *stats)
    OVS_EXCLUDED(mutex)
{
    struct sub *sub;
    struct lacp_info actor;
    bool ret;

    ovs_mutex_lock(&mutex);

    sub = sub_lookup(lacp, sub_);
    if (sub) {
        ret = true;
        sub_get_actor(sub, &actor);
        stats->dot3adAggPortActorSystemID = actor.sys_id;
        stats->dot3adAggPortPartnerOperSystemID = sub->partner.sys_id;
        stats->dot3adAggPortAttachedAggID = (lacp->key_sub->key ?
                                             lacp->key_sub->key :
                                             lacp->key_sub->port_id);

        /* Construct my admin-state.  Assume aggregation is configured on. */
        stats->dot3adAggPortActorAdminState = LACP_STATE_AGG;
        if (lacp->active) {
            stats->dot3adAggPortActorAdminState |= LACP_STATE_ACT;
        }
        if (lacp->fast) {
            stats->dot3adAggPortActorAdminState |= LACP_STATE_TIME;
        }
        /* XXX Not sure how to know the partner admin state. It
         * might have to be captured and remembered during the
         * negotiation phase.
         */
        stats->dot3adAggPortPartnerAdminState = 0;

        stats->dot3adAggPortActorOperState = actor.state;
        stats->dot3adAggPortPartnerOperState = sub->partner.state;

        /* Read out the latest counters */
        stats->dot3adAggPortStatsLACPDUsRx = sub->count_rx_pdus;
        stats->dot3adAggPortStatsIllegalRx = sub->count_rx_pdus_bad;
        stats->dot3adAggPortStatsLACPDUsTx = sub->count_tx_pdus;
    } else {
        ret = false;
    }
    ovs_mutex_unlock(&mutex);
    return ret;

}
