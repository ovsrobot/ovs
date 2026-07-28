/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016,
 * 2017 Nicira, Inc.
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

#ifndef NETADDR_H
#define NETADDR_H 1

#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include "compiler.h"
#include "openvswitch/types.h"
#include "random.h"
#include "unaligned.h"
#include "util.h"

struct ds;

/* Ethernet address. */

#define ETH_ADDR_LEN           6

static const struct eth_addr eth_addr_broadcast OVS_UNUSED
    = ETH_ADDR_C(ff,ff,ff,ff,ff,ff);

static const struct eth_addr eth_addr_exact OVS_UNUSED
    = ETH_ADDR_C(ff,ff,ff,ff,ff,ff);

static const struct eth_addr eth_addr_zero OVS_UNUSED
    = ETH_ADDR_C(00,00,00,00,00,00);
static const struct eth_addr64 eth_addr64_zero OVS_UNUSED
    = ETH_ADDR64_C(00,00,00,00,00,00,00,00);

static const struct eth_addr eth_addr_stp OVS_UNUSED
    = ETH_ADDR_C(01,80,c2,00,00,00);

static const struct eth_addr eth_addr_lacp OVS_UNUSED
    = ETH_ADDR_C(01,80,c2,00,00,02);

static const struct eth_addr eth_addr_bfd OVS_UNUSED
    = ETH_ADDR_C(00,23,20,00,00,01);

static inline bool eth_addr_is_broadcast(const struct eth_addr a)
{
    return (a.be16[0] & a.be16[1] & a.be16[2]) == htons(0xffff);
}

static inline bool eth_addr_is_multicast(const struct eth_addr a)
{
    return a.ea[0] & 1;
}

static inline bool eth_addr_is_local(const struct eth_addr a)
{
    /* Local if it is either a locally administered address or a Nicira random
     * address. */
    return a.ea[0] & 2
        || (a.be16[0] == htons(0x0023)
            && (a.be16[1] & htons(0xff80)) == htons(0x2080));
}
static inline bool eth_addr_is_zero(const struct eth_addr a)
{
    return !(a.be16[0] | a.be16[1] | a.be16[2]);
}
static inline bool eth_addr64_is_zero(const struct eth_addr64 a)
{
    return !(a.be16[0] | a.be16[1] | a.be16[2] | a.be16[3]);
}

static inline int eth_mask_is_exact(const struct eth_addr a)
{
    return (a.be16[0] & a.be16[1] & a.be16[2]) == htons(0xffff);
}

static inline int eth_addr_compare_3way(const struct eth_addr a,
                                        const struct eth_addr b)
{
    return memcmp(&a, &b, sizeof a);
}
static inline int eth_addr64_compare_3way(const struct eth_addr64 a,
                                          const struct eth_addr64 b)
{
    return memcmp(&a, &b, sizeof a);
}

static inline bool eth_addr_equals(const struct eth_addr a,
                                   const struct eth_addr b)
{
    return !eth_addr_compare_3way(a, b);
}
static inline bool eth_addr64_equals(const struct eth_addr64 a,
                                     const struct eth_addr64 b)
{
    return !eth_addr64_compare_3way(a, b);
}

static inline bool eth_addr_equal_except(const struct eth_addr a,
                                         const struct eth_addr b,
                                         const struct eth_addr mask)
{
    return !(((a.be16[0] ^ b.be16[0]) & mask.be16[0])
             || ((a.be16[1] ^ b.be16[1]) & mask.be16[1])
             || ((a.be16[2] ^ b.be16[2]) & mask.be16[2]));
}

uint64_t eth_addr_to_uint64(const struct eth_addr ea);

static inline uint64_t eth_addr_vlan_to_uint64(const struct eth_addr ea,
                                               uint16_t vlan)
{
    return (((uint64_t) vlan << 48) | eth_addr_to_uint64(ea));
}

void eth_addr_from_uint64(uint64_t x, struct eth_addr *ea);

static inline struct eth_addr eth_addr_invert(const struct eth_addr src)
{
    struct eth_addr dst;

    for (int i = 0; i < ARRAY_SIZE(src.be16); i++) {
        dst.be16[i] = ~src.be16[i];
    }

    return dst;
}

void eth_addr_mark_random(struct eth_addr *ea);

static inline void eth_addr_random(struct eth_addr *ea)
{
    random_bytes((uint8_t *) ea, sizeof *ea);
    eth_addr_mark_random(ea);
}

static inline void eth_addr_nicira_random(struct eth_addr *ea)
{
    eth_addr_random(ea);

    /* Set the OUI to the Nicira one. */
    ea->ea[0] = 0x00;
    ea->ea[1] = 0x23;
    ea->ea[2] = 0x20;

    /* Set the top bit to indicate random Nicira address. */
    ea->ea[3] |= 0x80;
}

bool eth_addr_is_reserved(const struct eth_addr);
bool eth_addr_from_string(const char *, struct eth_addr *);

void eth_format_masked(const struct eth_addr ea,
                       const struct eth_addr *mask, struct ds *s);

/* Example:
 *
 * struct eth_addr mac;
 *    [...]
 * printf("The Ethernet address is "ETH_ADDR_FMT"\n", ETH_ADDR_ARGS(mac));
 *
 */
#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_ARGS(EA) ETH_ADDR_BYTES_ARGS((EA).ea)
#define ETH_ADDR_BYTES_ARGS(EAB) \
         (EAB)[0], (EAB)[1], (EAB)[2], (EAB)[3], (EAB)[4], (EAB)[5]
#define ETH_ADDR_STRLEN 17

/* Example:
 *
 * struct eth_addr64 eui64;
 *    [...]
 * printf("The EUI-64 address is "ETH_ADDR64_FMT"\n", ETH_ADDR64_ARGS(mac));
 *
 */
#define ETH_ADDR64_FMT \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":" \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR64_ARGS(EA) ETH_ADDR64_BYTES_ARGS((EA).ea64)
#define ETH_ADDR64_BYTES_ARGS(EAB) \
         (EAB)[0], (EAB)[1], (EAB)[2], (EAB)[3], \
         (EAB)[4], (EAB)[5], (EAB)[6], (EAB)[7]
#define ETH_ADDR64_STRLEN 23

/* Example:
 *
 * char *string = "1 00:11:22:33:44:55 2";
 * struct eth_addr mac;
 * int a, b;
 *
 * if (ovs_scan(string, "%d"ETH_ADDR_SCAN_FMT"%d",
 *              &a, ETH_ADDR_SCAN_ARGS(mac), &b)) {
 *     ...
 * }
 */
#define ETH_ADDR_SCAN_FMT "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8
#define ETH_ADDR_SCAN_ARGS(EA) \
    &(EA).ea[0], &(EA).ea[1], &(EA).ea[2], \
    &(EA).ea[3], &(EA).ea[4], &(EA).ea[5]

/* IPv4 address. */

#define IP_FMT "%"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32
#define IP_ARGS(ip)                             \
    ntohl(ip) >> 24,                            \
    (ntohl(ip) >> 16) & 0xff,                   \
    (ntohl(ip) >> 8) & 0xff,                    \
    ntohl(ip) & 0xff

/* Example:
 *
 * char *string = "1 33.44.55.66 2";
 * ovs_be32 ip;
 * int a, b;
 *
 * if (ovs_scan(string, "%d"IP_SCAN_FMT"%d", &a, IP_SCAN_ARGS(&ip), &b)) {
 *     ...
 * }
 */
#define IP_SCAN_FMT "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8
#define IP_SCAN_ARGS(ip)                                    \
        ((void) (ovs_be32) *(ip), &((uint8_t *) ip)[0]),    \
        &((uint8_t *) ip)[1],                               \
        &((uint8_t *) ip)[2],                               \
        &((uint8_t *) ip)[3]

#define IP_PORT_SCAN_FMT "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8":%"SCNu16
#define IP_PORT_SCAN_ARGS(ip, port)                                    \
        ((void) (ovs_be32) *(ip), &((uint8_t *) ip)[0]),    \
        &((uint8_t *) ip)[1],                               \
        &((uint8_t *) ip)[2],                               \
        &((uint8_t *) ip)[3],                               \
        ((void) (ovs_be16) *(port), (uint16_t *) port)

/* Returns true if 'netmask' is a CIDR netmask, that is, if it consists of N
 * high-order 1-bits and 32-N low-order 0-bits. */
static inline bool
ip_is_cidr(ovs_be32 netmask)
{
    uint32_t x = ~ntohl(netmask);
    return !(x & (x + 1));
}
static inline bool
ip_is_multicast(ovs_be32 ip)
{
    return (ip & htonl(0xf0000000)) == htonl(0xe0000000);
}
static inline bool
ip_is_local_multicast(ovs_be32 ip)
{
    return (ip & htonl(0xffffff00)) == htonl(0xe0000000);
}
int ip_count_cidr_bits(ovs_be32 netmask);
void ip_format_masked(ovs_be32 ip, ovs_be32 mask, struct ds *);
bool ip_parse(const char *s, ovs_be32 *ip);
char *ip_parse_port(const char *s, ovs_be32 *ip, ovs_be16 *port)
    OVS_WARN_UNUSED_RESULT;
char *ip_parse_masked(const char *s, ovs_be32 *ip, ovs_be32 *mask)
    OVS_WARN_UNUSED_RESULT;
char *ip_parse_cidr(const char *s, ovs_be32 *ip, unsigned int *plen)
    OVS_WARN_UNUSED_RESULT;
char *ip_parse_masked_len(const char *s, int *n, ovs_be32 *ip, ovs_be32 *mask)
    OVS_WARN_UNUSED_RESULT;
char *ip_parse_cidr_len(const char *s, int *n, ovs_be32 *ip,
                        unsigned int *plen)
    OVS_WARN_UNUSED_RESULT;

/* IPv6 address. */

/* Like struct in6_addr, but whereas that struct requires 32-bit alignment on
 * most implementations, this one only requires 16-bit alignment. */
union ovs_16aligned_in6_addr {
    ovs_be16 be16[8];
    ovs_16aligned_be32 be32[4];
};
BUILD_ASSERT_DECL(sizeof(union ovs_16aligned_in6_addr)
                  == sizeof(struct in6_addr));

#define IPV6_SCAN_FMT "%46[0123456789abcdefABCDEF:.]"
#define IPV6_SCAN_LEN 46

extern const struct in6_addr in6addr_exact;
#define IN6ADDR_EXACT_INIT { { { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, \
                                 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff } } }

extern const struct in6_addr in6addr_all_hosts;
#define IN6ADDR_ALL_HOSTS_INIT \
    { { { 0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,                     \
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01 } } }

extern const struct in6_addr in6addr_all_routers;
#define IN6ADDR_ALL_ROUTERS_INIT \
    { { { 0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,                     \
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02 } } }

extern const struct in6_addr in6addr_v4mapped_any;
#define IN6ADDR_V4MAPPED_ANY_INIT \
    { { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
          0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 } } }

static inline bool ipv6_addr_equals(const struct in6_addr *a,
                                    const struct in6_addr *b)
{
#ifdef IN6_ARE_ADDR_EQUAL
    return IN6_ARE_ADDR_EQUAL(a, b);
#else
    return !memcmp(a, b, sizeof(*a));
#endif
}

/* Checks the IPv6 address in 'mask' for all zeroes. */
static inline bool ipv6_mask_is_any(const struct in6_addr *mask) {
    return ipv6_addr_equals(mask, &in6addr_any);
}

static inline bool ipv6_mask_is_exact(const struct in6_addr *mask) {
    return ipv6_addr_equals(mask, &in6addr_exact);
}

static inline bool ipv6_is_all_hosts(const struct in6_addr *addr) {
    return ipv6_addr_equals(addr, &in6addr_all_hosts);
}

static inline bool ipv6_addr_is_set(const struct in6_addr *addr) {
    return !ipv6_addr_equals(addr, &in6addr_any);
}

static inline bool ipv6_addr_is_multicast(const struct in6_addr *ip) {
    return ip->s6_addr[0] == 0xff;
}

static inline struct in6_addr
in6_addr_mapped_ipv4(ovs_be32 ip4)
{
    struct in6_addr ip6;
    memset(&ip6, 0, sizeof(ip6));
    ip6.s6_addr[10] = 0xff, ip6.s6_addr[11] = 0xff;
    memcpy(&ip6.s6_addr[12], &ip4, 4);
    return ip6;
}

static inline void
in6_addr_set_mapped_ipv4(struct in6_addr *ip6, ovs_be32 ip4)
{
    *ip6 = in6_addr_mapped_ipv4(ip4);
}

static inline ovs_be32
in6_addr_get_mapped_ipv4(const struct in6_addr *addr)
{
    union ovs_16aligned_in6_addr *taddr =
        (union ovs_16aligned_in6_addr *) addr;
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        return get_16aligned_be32(&taddr->be32[3]);
    } else {
        return INADDR_ANY;
    }
}

void in6_addr_solicited_node(struct in6_addr *addr,
                             const struct in6_addr *ip6);

void in6_generate_eui64(struct eth_addr ea, const struct in6_addr *prefix,
                        struct in6_addr *lla);

void in6_generate_lla(struct eth_addr ea, struct in6_addr *lla);

/* Returns true if 'addr' is a link local address.  Otherwise, false. */
bool in6_is_lla(struct in6_addr *addr);

void ipv6_multicast_to_ethernet(struct eth_addr *eth,
                                const struct in6_addr *ip6);

void ipv6_format_addr(const struct in6_addr *addr, struct ds *);
void ipv6_format_addr_bracket(const struct in6_addr *addr, struct ds *,
                              bool bracket);
void ipv6_format_mapped(const struct in6_addr *addr, struct ds *);
void ipv6_format_masked(const struct in6_addr *addr,
                        const struct in6_addr *mask, struct ds *);
const char * ipv6_string_mapped(char *addr_str, const struct in6_addr *addr);
struct in6_addr ipv6_addr_bitand(const struct in6_addr *src,
                                 const struct in6_addr *mask);
struct in6_addr ipv6_addr_bitxor(const struct in6_addr *a,
                                 const struct in6_addr *b);
bool ipv6_is_zero(const struct in6_addr *a);
struct in6_addr ipv6_create_mask(int mask);
int ipv6_count_cidr_bits(const struct in6_addr *netmask);
bool ipv6_is_cidr(const struct in6_addr *netmask);
bool ipv6_addr_equals_masked(const struct in6_addr *a,
                             const struct in6_addr *b, int plen);

bool ipv6_parse(const char *s, struct in6_addr *ip);
char *ipv6_parse_masked(const char *s, struct in6_addr *ipv6,
                        struct in6_addr *mask);
char *ipv6_parse_cidr(const char *s, struct in6_addr *ip, unsigned int *plen)
    OVS_WARN_UNUSED_RESULT;
char *ipv6_parse_masked_len(const char *s, int *n, struct in6_addr *ipv6,
                            struct in6_addr *mask);
char *ipv6_parse_cidr_len(const char *s, int *n, struct in6_addr *ip,
                          unsigned int *plen)
    OVS_WARN_UNUSED_RESULT;

#endif /* netaddr.h */
