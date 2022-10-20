/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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

#ifndef OPENVSWITCH_OFP_UTIL_H
#define OPENVSWITCH_OFP_UTIL_H 1

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "openvswitch/ofp-protocol.h"

struct ofp_header;

#ifdef __cplusplus
extern "C" {
#endif

struct ofputil_ct_tuple {
    struct in6_addr src;
    struct in6_addr dst;

    union {
        ovs_be16 src_port;
        ovs_be16 icmp_id;
    };
    union {
        ovs_be16 dst_port;
        struct {
            uint8_t icmp_code;
            uint8_t icmp_type;
        };
    };
};

struct ofputil_ct_match {
    uint8_t ip_proto;
    uint16_t l3_type;

    struct ofputil_ct_tuple tuple_orig;
    struct ofputil_ct_tuple tuple_reply;
};

bool ofputil_decode_hello(const struct ofp_header *,
                          uint32_t *allowed_versions);
struct ofpbuf *ofputil_encode_hello(uint32_t version_bitmap);
void ofputil_hello_format(struct ds *, const struct ofp_header *);

struct ofpbuf *ofputil_encode_echo_request(enum ofp_version);
struct ofpbuf *ofputil_encode_echo_reply(const struct ofp_header *);

struct ofpbuf *ofputil_encode_barrier_request(enum ofp_version);

struct ofpbuf *ofputil_ct_match_encode(const struct ofputil_ct_match *,
                                       uint16_t zone_id,
                                       enum ofp_version version);

#ifdef __cplusplus
}
#endif

#endif /* ofp-util.h */
