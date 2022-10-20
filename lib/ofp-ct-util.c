
/* Copyright (c) 2022, Red Hat, Inc.
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
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "ct-dpif.h"
#include "ofp-ct-util.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/packets.h"

static inline bool
ofputil_ct_inet_addr_cmp_partial(const struct in6_addr *partial,
                                 const union ct_dpif_inet_addr *addr,
                                 const uint16_t l3_type)
{
    if (ipv6_is_zero(partial)) {
        return true;
    }

    if (l3_type == AF_INET && in6_addr_get_mapped_ipv4(partial) != addr->ip) {
        return false;
    }

    if (l3_type == AF_INET6 && !ipv6_addr_equals(partial, &addr->in6)) {
        return false;
    }

    return true;
}

static inline bool
ofputil_ct_tuple_ip_cmp_partial(const struct ofputil_ct_tuple *partial,
                                const struct ct_dpif_tuple *tuple,
                                const uint16_t l3_type, const uint8_t ip_proto)
{
    if (!ofputil_ct_inet_addr_cmp_partial(&partial->src,
                                          &tuple->src, l3_type)) {
        return false;
    }

    if (!ofputil_ct_inet_addr_cmp_partial(&partial->dst,
                                          &tuple->dst, l3_type)) {
        return false;
    }

    if (ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6) {
        if (partial->icmp_id != tuple->icmp_id) {
            return false;
        }

        if (partial->icmp_type != tuple->icmp_type) {
            return false;
        }

        if (partial->icmp_code != tuple->icmp_code) {
            return false;
        }
    } else {
        if (partial->src_port && partial->src_port != tuple->src_port) {
            return false;
        }

        if (partial->dst_port && partial->dst_port != tuple->dst_port) {
            return false;
        }
    }

    return true;
}

/* Compares the non-zero members if they match. This is useful for clearing
 * up all connections specified by a partial tuples for orig/reply. */
bool
ofputil_ct_match_cmp(const struct ofputil_ct_match *match,
                     const struct ct_dpif_entry *entry)
{
    if (match->l3_type && match->l3_type != entry->tuple_orig.l3_type) {
        return false;
    }

    if (match->ip_proto && match->ip_proto != entry->tuple_orig.ip_proto) {
        return false;
    }

    if (!ofputil_ct_tuple_ip_cmp_partial(&match->tuple_orig,
                                         &entry->tuple_orig,
                                         match->l3_type, match->ip_proto)) {
        return false;
    }

    if (!ofputil_ct_tuple_ip_cmp_partial(&match->tuple_reply,
                                         &entry->tuple_reply,
                                         match->l3_type, match->ip_proto)) {
        return false;
    }

    return true;
}

static void
ofputil_ct_tuple_format(struct ds *ds, const struct ofputil_ct_tuple *tuple,
                        uint8_t ip_proto)
{
    ds_put_cstr(ds, "src=");
    ipv6_format_mapped(&tuple->src, ds);
    ds_put_cstr(ds, ",dst=");
    ipv6_format_mapped(&tuple->dst, ds);
    if (ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6) {
        ds_put_format(ds, ",icmp_id=%u,icmp_type=%u,icmp_code=%u",
                      ntohs(tuple->icmp_id), tuple->icmp_type,
                      tuple->icmp_code);

    } else {
        ds_put_format(ds, ",src_port=%u,dst_port=%u", ntohs(tuple->src_port),
                      ntohs(tuple->dst_port));
    }
}

bool
ofputil_ct_tuple_is_five_tuple(const struct ofputil_ct_tuple *tuple,
                               uint8_t ip_proto)
{
    /* First check if we have address. */
    bool five_tuple = !ipv6_is_zero(&tuple->src) && !ipv6_is_zero(&tuple->dst);

    if (!(ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6)) {
        five_tuple = five_tuple && tuple->src_port && tuple->dst_port;
    }

    return five_tuple;
}

void
ofputil_ct_match_format(struct ds *ds, const struct ofputil_ct_match *match)
{
    ds_put_format(ds, " l3_type=%u,ip_proto=%u", match->l3_type,
                  match->ip_proto);
    ds_put_cstr(ds, ",orig=(");
    ofputil_ct_tuple_format(ds, &match->tuple_orig, match->ip_proto);
    ds_put_cstr(ds, "),reply=(");
    ofputil_ct_tuple_format(ds, &match->tuple_reply, match->ip_proto);
    ds_put_cstr(ds, ")");
}

static bool
ofputil_ct_tuple_ip_parse(struct in6_addr *addr, char *value, uint16_t l3_type)
{
    if (!ipv6_is_zero(addr)) {
        return false;
    }

    if (l3_type == AF_INET) {
        ovs_be32 ip = 0;

        ip_parse(value, &ip);
        *addr = in6_addr_mapped_ipv4(ip);
    } else {
        ipv6_parse(value, addr);
    }

    return true;
}

/* Parses a specification of a conntrack 5-tuple from 's' into 'tuple'.
 * Returns true on success.  Otherwise, returns false and puts the error
 * message in 'ds'. */
bool
ofputil_ct_match_parse(struct ofputil_ct_match *match, const char *s,
                       struct ds *ds)
{
    char *pos, *key, *value, *copy;

    memset(match, 0, sizeof *match);
    struct ofputil_ct_tuple *tuple = &match->tuple_orig;

    pos = copy = xstrdup(s);
    while (ofputil_parse_key_value(&pos, &key, &value)) {
        if (!*value) {
            ds_put_format(ds, "field %s missing value", key);
            goto error_with_msg;
        }

        if (!strcmp(key, "ct_nw_src") || !strcmp(key, "ct_nw_dst")
            || !strcmp(key, "ct_ipv6_src") || !strcmp(key, "ct_ipv6_dst")) {
            match->l3_type = key[6] == '6' ? AF_INET6 : AF_INET;
            uint8_t index = key[6] == '6' ? 8 : 6;
            struct in6_addr *addr = key[index] == 's'
                ? &tuple->src : &tuple->dst;

            if (!ofputil_ct_tuple_ip_parse(addr, value, match->l3_type)) {
                ds_put_format(ds, "%s is set multiple times", key);
                goto error;
            }
        } else if (!strcmp(key, "ct_nw_proto")) {
            char *err = str_to_u8(value, key, &match->ip_proto);

            if (err) {
                free(err);
                goto error_with_msg;
            }
        } else if (!strcmp(key, "ct_tp_src") || !strcmp(key, "ct_tp_dst")) {
            uint16_t port;
            char *err = str_to_u16(value, key, &port);

            if (err) {
                free(err);
                goto error_with_msg;
            }
            if (key[6] == 's') {
                tuple->src_port = htons(port);
            } else {
                tuple->dst_port = htons(port);
            }
        } else if (!strcmp(key, "icmp_type") || !strcmp(key, "icmp_code") ||
                   !strcmp(key, "icmp_id")) {
            if (match->ip_proto != IPPROTO_ICMP &&
                match->ip_proto != IPPROTO_ICMPV6) {
                ds_put_cstr(ds, "invalid L4 fields");
                goto error;
            }
            uint16_t icmp_id;
            char *err;

            if (key[5] == 't') {
                err = str_to_u8(value, key, &tuple->icmp_type);
            } else if (key[5] == 'c') {
                err = str_to_u8(value, key, &tuple->icmp_code);
            } else {
                err = str_to_u16(value, key, &icmp_id);
                tuple->icmp_id = htons(icmp_id);
            }
            if (err) {
                free(err);
                goto error_with_msg;
            }
        } else {
            ds_put_format(ds, "invalid conntrack tuple field: %s", key);
            goto error;
        }
    }

    if (!match->ip_proto && (tuple->src_port || tuple->dst_port)) {
        ds_put_cstr(ds, "port is set without protocol");
        goto error;
    }

    /* For the filtering to work with icmp we need to fill the reply direction
     * with correct information. */
    if (match->ip_proto == IPPROTO_ICMP) {
        switch (match->tuple_orig.icmp_type) {
        case ICMP4_ECHO_REQUEST:
            match->tuple_reply.icmp_type = ICMP4_ECHO_REPLY;
            break;
        case ICMP4_ECHO_REPLY:
            match->tuple_reply.icmp_type = ICMP4_ECHO_REQUEST;
            break;
        case ICMP4_TIMESTAMP:
            match->tuple_reply.icmp_type = ICMP4_TIMESTAMPREPLY;
            break;
        case ICMP4_TIMESTAMPREPLY:
            match->tuple_reply.icmp_type = ICMP4_TIMESTAMP;
            break;
        case ICMP4_INFOREQUEST:
            match->tuple_reply.icmp_type = ICMP4_INFOREPLY;
            break;
        case ICMP4_INFOREPLY:
            match->tuple_reply.icmp_type = ICMP4_INFOREQUEST;
            break;
        }
        match->tuple_reply.icmp_id = match->tuple_orig.icmp_id;
    } else if (match->ip_proto == IPPROTO_ICMPV6) {
        switch (match->tuple_orig.icmp_type) {
        case ICMP6_ECHO_REQUEST:
            match->tuple_reply.icmp_type = ICMP6_ECHO_REPLY;
            break;
        case ICMP6_ECHO_REPLY:
            match->tuple_reply.icmp_type = ICMP6_ECHO_REQUEST;
            break;
        }
        match->tuple_reply.icmp_id = match->tuple_orig.icmp_id;
    }

    free(copy);
    return true;

error_with_msg:
    ds_put_format(ds, "failed to parse field %s", key);
error:
    free(copy);
    return false;
}

void
ofputil_ct_match_decode(struct ofputil_ct_match *match, uint16_t *zone_id,
                        const struct ofp_header *oh)
{
    const struct nx_ct_flush *nx_flush = ofpmsg_body(oh);

    struct ofputil_ct_tuple *orig = &match->tuple_orig;
    struct ofputil_ct_tuple *reply = &match->tuple_reply;

    *zone_id = ntohs(nx_flush->zone_id);

    match->l3_type = nx_flush->family;
    match->ip_proto = nx_flush->ip_proto;

    memcpy(&orig->src, &nx_flush->orig_src, sizeof orig->src);
    memcpy(&orig->dst, &nx_flush->orig_dst, sizeof orig->dst);

    memcpy(&reply->src, &nx_flush->reply_src, sizeof reply->src);
    memcpy(&reply->dst, &nx_flush->reply_dst, sizeof reply->dst);

    orig->src_port = nx_flush->orig_src_port;
    reply->src_port = nx_flush->reply_src_port;

    if (match->ip_proto == IPPROTO_ICMP || match->ip_proto == IPPROTO_ICMPV6) {
        uint16_t icmp = ntohs(nx_flush->orig_dst_port);
        orig->icmp_type = icmp >> 8 & 0xff;
        orig->icmp_code = icmp & 0xff;

        icmp = ntohs(nx_flush->reply_dst_port);
        reply->icmp_type = icmp >> 8 & 0xff;
        reply->icmp_code = icmp & 0xff;
    } else {
        orig->dst_port = nx_flush->orig_dst_port;
        reply->dst_port = nx_flush->reply_dst_port;
    }
}

