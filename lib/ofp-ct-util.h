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

#ifndef OVS_OFP_CT_UTIL_H
#define OVS_OFP_CT_UTIL_H

#include "ct-dpif.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/ofp-util.h"

bool ofputil_ct_match_cmp(const struct ofputil_ct_match *match,
                                 const struct ct_dpif_entry *entry);

bool ofputil_ct_tuple_is_zero(const struct ofputil_ct_tuple *tuple,
                              uint8_t ip_proto);

bool ofputil_ct_tuple_is_five_tuple(const struct ofputil_ct_tuple *tuple,
                                    uint8_t ip_proto);

void ofputil_ct_match_format(struct ds *ds,
                             const struct ofputil_ct_match *match);

bool ofputil_ct_tuple_parse(struct ofputil_ct_tuple *tuple, const char *s,
                            struct ds *ds, uint8_t *ip_proto,
                            uint16_t *l3_type);

bool ofputil_is_ct_match_zero(const struct ofputil_ct_match *match);

enum ofperr ofputil_ct_match_decode(struct ofputil_ct_match *match,
                                    bool *with_zone, uint16_t *zone_id,
                                    const struct ofp_header *oh);

void ofputil_ct_tuple_encode(const struct ofputil_ct_tuple *tuple,
                             struct ofpbuf *buf,
                             enum nx_ct_flush_tlv_type type, uint8_t ip_proto);

#endif /* lib/ofp-ct-util.h */
