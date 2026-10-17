/*
 * Copyright (c) 2011, 2014, 2017 Nicira, Inc.
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
#undef NDEBUG
#include "packets.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dp-packet.h"
#include "ovstest.h"

static void
test_ipv4_cidr(void)
{
    assert(ip_is_cidr(htonl(0x00000000)));
    assert(ip_is_cidr(htonl(0x80000000)));
    assert(ip_is_cidr(htonl(0xf0000000)));
    assert(ip_is_cidr(htonl(0xffffffe0)));
    assert(ip_is_cidr(htonl(0xffffffff)));

    assert(!ip_is_cidr(htonl(0x00000001)));
    assert(!ip_is_cidr(htonl(0x40000000)));
    assert(!ip_is_cidr(htonl(0x0fffffff)));
    assert(!ip_is_cidr(htonl(0xffffffd0)));
}

static void
test_ipv6_static_masks(void)
{
    /* The 'exact' and 'any' addresses should be identical to
     * 'in6addr_exact' and  'in6addr_any' definitions, but we redefine
     * them here since the pre-defined ones are used in the functions
     * we're testing. */
    struct in6_addr exact   = {{{ 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, \
                                  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff }}};

    struct in6_addr any     = {{{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
                                  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }}};

    struct in6_addr neither = {{{ 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, \
                                  0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef }}};

    assert(ipv6_mask_is_exact(&exact));
    assert(!ipv6_mask_is_exact(&any));
    assert(!ipv6_mask_is_exact(&neither));

    assert(!ipv6_mask_is_any(&exact));
    assert(ipv6_mask_is_any(&any));
    assert(!ipv6_mask_is_any(&neither));

}

static void
test_ipv6_cidr(void)
{
    struct in6_addr dest;

    struct in6_addr src   = {{{ 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, \
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }}};

    dest = ipv6_create_mask(0);
    assert(ipv6_mask_is_any(&dest));
    assert(ipv6_count_cidr_bits(&dest) == 0);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(128);
    assert(ipv6_mask_is_exact(&dest));
    assert(ipv6_count_cidr_bits(&dest) == 128);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(1);
    assert(ipv6_count_cidr_bits(&dest) == 1);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(13);
    assert(ipv6_count_cidr_bits(&dest) == 13);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(64);
    assert(ipv6_count_cidr_bits(&dest) == 64);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(95);
    assert(ipv6_count_cidr_bits(&dest) == 95);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(96);
    assert(ipv6_count_cidr_bits(&dest) == 96);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(97);
    assert(ipv6_count_cidr_bits(&dest) == 97);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(127);
    assert(ipv6_count_cidr_bits(&dest) == 127);
    assert(ipv6_is_cidr(&dest));

    src.s6_addr[8] = 0xf0;
    assert(ipv6_is_cidr(&src));
    assert(ipv6_count_cidr_bits(&src) == 68);

    src.s6_addr[15] = 0x01;
    assert(!ipv6_is_cidr(&src));
    src.s6_addr[15] = 0x00;
    assert(ipv6_is_cidr(&src));

    src.s6_addr[8] = 0x0f;
    assert(!ipv6_is_cidr(&src));
}


static void
test_ipv6_masking(void)
{
    struct in6_addr dest;
    struct in6_addr mask;

    mask = ipv6_create_mask(0);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 0);

    mask = ipv6_create_mask(1);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 1);

    mask = ipv6_create_mask(13);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 13);

    mask = ipv6_create_mask(127);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 127);

    mask = ipv6_create_mask(128);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 128);
}

static void
test_ipv6_parsing(void)
{
    struct in6_addr o_ipv6, p_ipv6;
    struct in6_addr mask;

    assert(inet_pton(AF_INET6, "2001:db8:0:0:0:0:2:1", &o_ipv6) == 1);

    assert(!ipv6_parse_masked("2001:db8:0:0:0:0:2:1/64", &p_ipv6, &mask));
    assert(ipv6_addr_equals(&o_ipv6, &p_ipv6));
    assert(ipv6_count_cidr_bits(&mask) == 64);

    assert(!ipv6_parse_masked("2001:db8:0:0:0:0:2:1/ffff:ffff:ffff:ffff::",
                              &p_ipv6, &mask));
    assert(ipv6_addr_equals(&o_ipv6, &p_ipv6));
    assert(ipv6_count_cidr_bits(&mask) == 64);

    assert(!ipv6_parse_masked("2001:db8:0:0:0:0:2:1", &p_ipv6, &mask));
    assert(ipv6_addr_equals(&o_ipv6, &p_ipv6));
    assert(ipv6_count_cidr_bits(&mask) == 128);
}

/* Checks that packet_set_nd() changes only the address of the option at
 * 'lla_ofs' into 'opts', or nothing if 'lla_ofs' is -1. */
static void
check_set_nd(const uint8_t *opts, size_t n, int lla_ofs)
{
    static const struct eth_addr sll = ETH_ADDR_C(aa, bb, cc, dd, ee, 01);
    static const struct eth_addr tll = ETH_ADDR_C(aa, bb, cc, dd, ee, 02);
    size_t size = sizeof(struct ovs_nd_msg) + n;
    struct ovs_nd_msg *ns = xzalloc(size);
    struct in6_addr target;
    struct dp_packet *packet;
    uint8_t *expected;

    memcpy(ns->options, opts, n);
    memcpy(&target, &ns->target, sizeof target);

    expected = xmemdup(ns->options, n);
    if (lla_ofs >= 0) {
        const struct eth_addr *mac = (opts[lla_ofs] == ND_OPT_SOURCE_LINKADDR
                                      ? &sll : &tll);

        memcpy(&expected[lla_ofs + 2], mac, sizeof *mac);
    }

    packet = dp_packet_clone_data(ns, size);
    free(ns);
    dp_packet_set_l4(packet, dp_packet_data(packet));
    packet_set_nd(packet, &target, sll, tll);

    ns = dp_packet_l4(packet);
    ovs_assert(!memcmp(ns->options, expected, n));

    dp_packet_delete(packet);
    free(expected);
}

static void
test_set_nd(void)
{
    static const uint8_t sll[] = {
        ND_OPT_SOURCE_LINKADDR, 1, 1, 2, 3, 4, 5, 6,
    };
    static const uint8_t mtu_tll[] = {
        5, 1, 0, 0, 0, 0, 5, 220,
        ND_OPT_TARGET_LINKADDR, 1, 1, 2, 3, 4, 5, 6,
    };
    static const uint8_t long_short[] = {
        3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        3, 1, 0, 0, 0, 0, 0, 0,
    };
    static const uint8_t long_sll[] = {
        3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ND_OPT_SOURCE_LINKADDR, 1, 1, 2, 3, 4, 5, 6,
    };
    static const uint8_t tll_sll[] = {
        ND_OPT_TARGET_LINKADDR, 1, 1, 2, 3, 4, 5, 6,
        ND_OPT_SOURCE_LINKADDR, 1, 1, 2, 3, 4, 5, 6,
    };

    check_set_nd(sll, 0, -1);
    check_set_nd(sll, sizeof sll, 0);
    check_set_nd(mtu_tll, sizeof mtu_tll, 8);
    check_set_nd(long_short, sizeof long_short, -1);
    check_set_nd(long_sll, sizeof long_sll, 16);
    check_set_nd(long_sll, 16, -1);
    check_set_nd(tll_sll, sizeof tll_sll, 0);
}

static void
test_hdr_accessors(void)
{
    uint8_t data[24] = { 0 };
    struct dp_packet *packet = dp_packet_clone_data(data, sizeof data);

    ovs_assert(!dp_packet_l3_hdr(packet, 0));
    ovs_assert(!dp_packet_l4_hdr(packet, 0));

    dp_packet_set_l3(packet, dp_packet_data(packet));
    dp_packet_set_l4(packet, (char *) dp_packet_data(packet) + 20);
    ovs_assert(dp_packet_l3_hdr(packet, 24) == dp_packet_data(packet));
    ovs_assert(!dp_packet_l3_hdr(packet, 25));
    ovs_assert(dp_packet_l4_hdr(packet, 4) == dp_packet_l4(packet));
    ovs_assert(!dp_packet_l4_hdr(packet, 5));

    dp_packet_set_l2_pad_size(packet, 4);
    ovs_assert(dp_packet_l3_hdr(packet, 20));
    ovs_assert(!dp_packet_l3_hdr(packet, 21));
    ovs_assert(dp_packet_l4_hdr(packet, 0));
    ovs_assert(!dp_packet_l4_hdr(packet, 1));

    dp_packet_set_l2_pad_size(packet, 0);
    dp_packet_set_size(packet, 16);
    ovs_assert(dp_packet_l3_hdr(packet, 16));
    ovs_assert(!dp_packet_l4_hdr(packet, 0));

    dp_packet_delete(packet);
}

/* Runs 'set' on a packet that holds the first 'n' bytes of 'hdr' as its L3
 * header, or as its L4 header if 'l4', and returns true if 'set' changed the
 * packet's data. */
static bool
check_set_hdr(const uint8_t *hdr, size_t n, bool l4,
              void (*set)(struct dp_packet *))
{
    struct dp_packet *packet = dp_packet_clone_data(hdr, n);
    bool changed;

    if (l4) {
        dp_packet_set_l4(packet, dp_packet_data(packet));
    } else {
        dp_packet_set_l3(packet, dp_packet_data(packet));
    }
    set(packet);
    changed = memcmp(dp_packet_data(packet), hdr, n) != 0;

    dp_packet_delete(packet);
    return changed;
}

static void
set_ipv4(struct dp_packet *packet)
{
    packet_set_ipv4(packet, htonl(0x0a000009), 0, 0, 0);
}

static void
set_ipv6(struct dp_packet *packet)
{
    struct in6_addr src = IN6ADDR_LOOPBACK_INIT;

    packet_set_ipv6(packet, &src, &in6addr_any, 0, 0, 0);
}

static void
set_tcp_port(struct dp_packet *packet)
{
    packet_set_tcp_port(packet, htons(1), htons(2));
}

static void
set_udp_port(struct dp_packet *packet)
{
    packet_set_udp_port(packet, htons(1), htons(2));
}

static void
set_sctp_port(struct dp_packet *packet)
{
    packet_set_sctp_port(packet, htons(1), htons(2));
}

static void
set_icmp(struct dp_packet *packet)
{
    packet_set_icmp(packet, ICMP4_DST_UNREACH, 1);
}

static void
set_igmp3_query(struct dp_packet *packet)
{
    packet_set_igmp3_query(packet, 10, htonl(0xe0000001), false, 2, 125);
}

static void
test_set_short_hdr(void)
{
    uint8_t hdr[IPV6_HEADER_LEN + 4] = { 0 };

    ovs_assert(check_set_hdr(hdr, IP_HEADER_LEN, false, set_ipv4));
    ovs_assert(!check_set_hdr(hdr, IP_HEADER_LEN - 1, false, set_ipv4));
    ovs_assert(check_set_hdr(hdr, IPV6_HEADER_LEN, false, set_ipv6));
    ovs_assert(!check_set_hdr(hdr, IPV6_HEADER_LEN - 1, false, set_ipv6));
    ovs_assert(check_set_hdr(hdr, 4, true, set_tcp_port));
    ovs_assert(!check_set_hdr(hdr, 3, true, set_tcp_port));
    ovs_assert(check_set_hdr(hdr, UDP_HEADER_LEN, true, set_udp_port));
    ovs_assert(!check_set_hdr(hdr, UDP_HEADER_LEN - 1, true, set_udp_port));
    ovs_assert(check_set_hdr(hdr, 4, true, set_sctp_port));
    ovs_assert(!check_set_hdr(hdr, 3, true, set_sctp_port));
    ovs_assert(check_set_hdr(hdr, ICMP_HEADER_LEN, true, set_icmp));
    ovs_assert(!check_set_hdr(hdr, ICMP_HEADER_LEN - 1, true, set_icmp));
    ovs_assert(check_set_hdr(hdr, IGMPV3_QUERY_HEADER_LEN, true,
                             set_igmp3_query));
    ovs_assert(!check_set_hdr(hdr, IGMPV3_QUERY_HEADER_LEN - 1, true,
                              set_igmp3_query));
}

static void
test_rh_present_no_l4(void)
{
    struct ovs_16aligned_ip6_hdr *nh;
    uint8_t hdr[IPV6_HEADER_LEN + 4] = { 0 };
    struct dp_packet *packet;
    bool first_frag = false;
    uint8_t nexthdr;

    /* A hop-by-hop options header cut after 4 bytes, so flow extraction
     * leaves the L4 offset unset. */
    nh = ALIGNED_CAST(struct ovs_16aligned_ip6_hdr *, hdr);
    nh->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_HOPOPTS;
    packet = dp_packet_clone_data(hdr, sizeof hdr);
    dp_packet_set_l3(packet, dp_packet_data(packet));

    ovs_assert(!packet_rh_present(packet, &nexthdr, &first_frag));
    ovs_assert(nexthdr == IPPROTO_HOPOPTS);

    dp_packet_delete(packet);
}

static void
test_set_ipv6_addr_short_icmp6(void)
{
    struct ovs_16aligned_ip6_hdr *nh;
    uint8_t hdr[IPV6_HEADER_LEN + 2] = { 0 };
    struct in6_addr src = IN6ADDR_LOOPBACK_INIT;
    struct dp_packet *packet;
    uint8_t *l4;

    nh = ALIGNED_CAST(struct ovs_16aligned_ip6_hdr *, hdr);
    nh->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
    hdr[IPV6_HEADER_LEN] = 0x12;
    hdr[IPV6_HEADER_LEN + 1] = 0x34;
    packet = dp_packet_clone_data(hdr, sizeof hdr);
    dp_packet_set_l3(packet, dp_packet_data(packet));
    dp_packet_set_l4(packet, (char *) dp_packet_data(packet)
                             + IPV6_HEADER_LEN);

    packet_set_ipv6(packet, &src, &in6addr_any, 0, 0, 0);

    nh = dp_packet_l3(packet);
    ovs_assert(!memcmp(&nh->ip6_src, &src, sizeof src));
    l4 = dp_packet_l4(packet);
    ovs_assert(l4[0] == 0x12 && l4[1] == 0x34);

    dp_packet_delete(packet);
}

static void
test_packets_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    test_ipv4_cidr();
    test_ipv6_static_masks();
    test_ipv6_cidr();
    test_ipv6_masking();
    test_ipv6_parsing();
    test_set_nd();
    test_hdr_accessors();
    test_set_short_hdr();
    test_rh_present_no_l4();
    test_set_ipv6_addr_short_icmp6();
}

OVSTEST_REGISTER("test-packets", test_packets_main);
