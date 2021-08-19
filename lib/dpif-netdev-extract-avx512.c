/*
 * Copyright (c) 2021 Intel.
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

/*
 * AVX512 Miniflow Extract.
 *
 * This file contains optimized implementations of miniflow_extract()
 * for specific common traffic patterns. The optimizations allow for
 * quick probing of a specific packet type, and if a match with a specific
 * type is found, a shuffle like procedure builds up the required miniflow.
 *
 * Process
 * ---------
 *
 * The procedure is to classify the packet based on the traffic type
 * using predifined bit-masks and arrage the packet header data using shuffle
 * instructions to a pre-defined place as required by the miniflow.
 * This elimates the if-else ladder to identify the packet data and add data
 * as per protocol which is present.
 */

#ifdef __x86_64__
/* Sparse cannot handle the AVX512 instructions. */
#if !defined(__CHECKER__)

#include <config.h>
#include <errno.h>
#include <immintrin.h>
#include <stdint.h>
#include <string.h>

#include "flow.h"
#include "dpdk.h"

#include "dpif-netdev-private-dpcls.h"
#include "dpif-netdev-private-extract.h"
#include "dpif-netdev-private-flow.h"

#define plen ip6_ctlun.ip6_un1.ip6_un1_plen

/* AVX512-BW level permutex2var_epi8 emulation. */
static inline __m512i
__attribute__((target("avx512bw")))
_mm512_maskz_permutex2var_epi8_skx(__mmask64 k_mask,
                                   __m512i v_data_0,
                                   __m512i v_shuf_idxs,
                                   __m512i v_data_1)
{
    /* Manipulate shuffle indexes for u16 size. */
    __mmask64 k_mask_odd_lanes = 0xAAAAAAAAAAAAAAAA;
    /* Clear away ODD lane bytes. Cannot be done above due to no u8 shift. */
    __m512i v_shuf_idx_evn = _mm512_mask_blend_epi8(k_mask_odd_lanes,
                                                    v_shuf_idxs,
                                                    _mm512_setzero_si512());
    v_shuf_idx_evn = _mm512_srli_epi16(v_shuf_idx_evn, 1);

    __m512i v_shuf_idx_odd = _mm512_srli_epi16(v_shuf_idxs, 9);

    /* Shuffle each half at 16-bit width. */
    __m512i v_shuf1 = _mm512_permutex2var_epi16(v_data_0, v_shuf_idx_evn,
                                                v_data_1);
    __m512i v_shuf2 = _mm512_permutex2var_epi16(v_data_0, v_shuf_idx_odd,
                                                v_data_1);

    /* Find if the shuffle index was odd, via mask and compare. */
    uint16_t index_odd_mask = 0x1;
    const __m512i v_index_mask_u16 = _mm512_set1_epi16(index_odd_mask);

    /* EVEN lanes, find if u8 index was odd,  result as u16 bitmask. */
    __m512i v_idx_even_masked = _mm512_and_si512(v_shuf_idxs,
                                                 v_index_mask_u16);
    __mmask32 evn_rotate_mask = _mm512_cmpeq_epi16_mask(v_idx_even_masked,
                                                        v_index_mask_u16);

    /* ODD lanes, find if u8 index was odd, result as u16 bitmask. */
    __m512i v_shuf_idx_srli8 = _mm512_srli_epi16(v_shuf_idxs, 8);
    __m512i v_idx_odd_masked = _mm512_and_si512(v_shuf_idx_srli8,
                                                v_index_mask_u16);
    __mmask32 odd_rotate_mask = _mm512_cmpeq_epi16_mask(v_idx_odd_masked,
                                                        v_index_mask_u16);
    odd_rotate_mask = ~odd_rotate_mask;

    /* Rotate and blend results from each index. */
    __m512i v_shuf_res_evn = _mm512_mask_srli_epi16(v_shuf1, evn_rotate_mask,
                                                    v_shuf1, 8);
    __m512i v_shuf_res_odd = _mm512_mask_slli_epi16(v_shuf2, odd_rotate_mask,
                                                    v_shuf2, 8);

    /* If shuffle index was odd, blend shifted version. */
    __m512i v_shuf_result = _mm512_mask_blend_epi8(k_mask_odd_lanes,
                                               v_shuf_res_evn, v_shuf_res_odd);

    __m512i v_zeros = _mm512_setzero_si512();
    __m512i v_result_kmskd = _mm512_mask_blend_epi8(k_mask, v_zeros,
                                                    v_shuf_result);

    return v_result_kmskd;
}

/* Wrapper function required to enable ISA. */
static inline __m512i
__attribute__((__target__("avx512vbmi")))
_mm512_maskz_permutexvar_epi8_wrap(__mmask64 kmask, __m512i idx, __m512i a)
{
    return _mm512_maskz_permutexvar_epi8(kmask, idx, a);
}


/* This file contains optimized implementations of miniflow_extract()
 * for specific common traffic patterns. The optimizations allow for
 * quick probing of a specific packet type, and if a match with a specific
 * type is found, a shuffle like procedure builds up the required miniflow.
 *
 * The functionality here can be easily auto-validated and tested against the
 * scalar miniflow_extract() function. As such, manual review of the code by
 * the community (although welcome) is not required. Confidence in the
 * correctness of the code can be confirmed from the autovalidator results.
 */

/* Generator for EtherType masks and values. */
#define PATTERN_ETHERTYPE_GEN(type_b0, type_b1) \
  0, 0, 0, 0, 0, 0, /* Ether MAC DST */                                 \
  0, 0, 0, 0, 0, 0, /* Ether MAC SRC */                                 \
  type_b0, type_b1, /* EtherType */

#define PATTERN_ETHERTYPE_MASK PATTERN_ETHERTYPE_GEN(0xFF, 0xFF)
#define PATTERN_ETHERTYPE_IPV4 PATTERN_ETHERTYPE_GEN(0x08, 0x00)
#define PATTERN_ETHERTYPE_DT1Q PATTERN_ETHERTYPE_GEN(0x81, 0x00)
#define PATTERN_ETHERTYPE_IPV6 PATTERN_ETHERTYPE_GEN(0x86, 0xDD)

/* VLAN (Dot1Q) patterns and masks. */
#define PATTERN_DT1Q_MASK                                               \
  0x00, 0x00, 0xFF, 0xFF,
#define PATTERN_DT1Q_IPV4                                               \
  0x00, 0x00, 0x08, 0x00,

/* Generator for checking IPv4 ver, ihl, and proto */
#define PATTERN_IPV4_GEN(VER_IHL, FLAG_OFF_B0, FLAG_OFF_B1, PROTO) \
  VER_IHL, /* Version and IHL */                                        \
  0, 0, 0, /* DSCP, ECN, Total Length */                                \
  0, 0, /* Identification */                                            \
  /* Flags/Fragment offset: don't match MoreFrag (MF) or FragOffset */  \
  FLAG_OFF_B0, FLAG_OFF_B1,                                             \
  0, /* TTL */                                                          \
  PROTO, /* Protocol */                                                 \
  0, 0, /* Header checksum */                                           \
  0, 0, 0, 0, /* Src IP */                                              \
  0, 0, 0, 0, /* Dst IP */

#define PATTERN_IPV4_MASK PATTERN_IPV4_GEN(0xFF, 0xFE, 0xFF, 0xFF)
#define PATTERN_IPV4_UDP PATTERN_IPV4_GEN(0x45, 0, 0, 0x11)
#define PATTERN_IPV4_TCP PATTERN_IPV4_GEN(0x45, 0, 0, 0x06)

#define NU 0
#define PATTERN_IPV4_UDP_SHUFFLE \
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, NU, NU, /* Ether */ \
  26, 27, 28, 29, 30, 31, 32, 33, NU, NU, NU, NU, 20, 15, 22, 23, /* IPv4 */  \
  34, 35, 36, 37, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, /* UDP */   \
  NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, /* Unused. */

/* TCP shuffle: tcp_ctl bits require mask/processing, not included here. */
#define PATTERN_IPV4_TCP_SHUFFLE \
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, NU, NU, /* Ether */ \
  26, 27, 28, 29, 30, 31, 32, 33, NU, NU, NU, NU, 20, 15, 22, 23, /* IPv4 */  \
  NU, NU, NU, NU, NU, NU, NU, NU, 34, 35, 36, 37, NU, NU, NU, NU, /* TCP */   \
  NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, /* Unused. */

#define PATTERN_DT1Q_IPV4_UDP_SHUFFLE                                         \
  /* Ether (2 blocks): Note that *VLAN* type is written here. */              \
  0,  1,  2,  3,  4,  5,  6,  7, 8,  9, 10, 11, 16, 17,  0,  0,               \
  /* VLAN (1 block): Note that the *EtherHdr->Type* is written here. */       \
  12, 13, 14, 15, 0, 0, 0, 0,                                                 \
  30, 31, 32, 33, 34, 35, 36, 37, 0, 0, 0, 0, 24, 19, 26, 27,     /* IPv4 */  \
  38, 39, 40, 41, NU, NU, NU, NU, /* UDP */

#define PATTERN_DT1Q_IPV4_TCP_SHUFFLE                                         \
  /* Ether (2 blocks): Note that *VLAN* type is written here. */              \
  0,  1,  2,  3,  4,  5,  6,  7, 8,  9, 10, 11, 16, 17,  0,  0,               \
  /* VLAN (1 block): Note that the *EtherHdr->Type* is written here. */       \
  12, 13, 14, 15, 0, 0, 0, 0,                                                 \
  30, 31, 32, 33, 34, 35, 36, 37, 0, 0, 0, 0, 24, 19, 26, 27,     /* IPv4 */  \
  NU, NU, NU, NU, NU, NU, NU, NU, 38, 39, 40, 41, NU, NU, NU, NU, /* TCP */   \
  NU, NU, NU, NU, NU, NU, NU, NU, /* Unused. */

/* Generator for checking IPv6 ver. */
#define PATTERN_IPV6_GEN(VER_TRC, PROTO)                                      \
  VER_TRC,     /* Version: 4bits and Traffic class: 4bits. */                 \
  0, 0, 0,     /* Traffic class: 4bits and Flow Label: 24bits. */             \
  0, 0,        /* Payload length 16bits. */                                   \
  PROTO, 0,    /* Next Header 8bits and Hop limit 8bits. */                   \
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* Src IP: 128bits. */      \
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* Dst IP: 128bits. */

#define PATTERN_IPV6_MASK PATTERN_IPV6_GEN(0xF0, 0xFF)
#define PATTERN_IPV6_UDP PATTERN_IPV6_GEN(0x60, 0x11)
#define PATTERN_IPV6_TCP PATTERN_IPV6_GEN(0x60, 0x06)

#define PATTERN_IPV6_SHUFFLE                                                  \
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, NU, NU, /* Ether */ \
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, /* IPv6 */  \
  38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, /* IPv6 */  \
  NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, /* Unused */

/* VLAN (Dot1Q) patterns and masks. */
#define PATTERN_DT1Q_MASK                                                     \
  0x00, 0x00, 0xFF, 0xFF,
#define PATTERN_DT1Q_IPV6                                                     \
  0x00, 0x00, 0x86, 0xDD,

#define PATTERN_DT1Q_IPV6_SHUFFLE                                             \
  /* Ether (2 blocks): Note that *VLAN* type is written here. */              \
  0,  1,  2,  3,  4,  5,  6,  7, 8,  9, 10, 11, 16, 17,  0,  0,               \
  /* VLAN (1 block): Note that the *EtherHdr->Type* is written here. */       \
  12, 13, 14, 15, 0, 0, 0, 0,                                                 \
  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, /* IPv6 */  \
  42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, /* IPv6 */  \
  NU, NU, NU, NU, NU, NU, NU, NU,                                 /* Unused */

/* Generation of K-mask bitmask values, to zero out data in result. Note that
 * these correspond 1:1 to the above "*_SHUFFLE" values, and bit used must be
 * set in this K-mask, and "NU" values must be zero in the k-mask. Each mask
 * defined here represents 2 blocks, so 16 bytes, so 4 characters (eg. 0xFFFF).
 *
 * Note the ULL suffix allows shifting by 32 or more without integer overflow.
 */
#define KMASK_ETHER     0x1FFFULL
#define KMASK_DT1Q      0x0FULL
#define KMASK_IPV4      0xF0FFULL
#define KMASK_UDP       0x000FULL
#define KMASK_TCP       0x0F00ULL
#define KMASK_IPV6      0xFFFFULL
#define KMASK_ETHER_IPV6     0x3FFFULL
#define KMASK_DT1Q_IPV6      0xFF0FULL
#define KMASK_IPV6_NOHDR     0x00FFULL

#define PATTERN_IPV4_UDP_KMASK \
    (KMASK_ETHER | (KMASK_IPV4 << 16) | (KMASK_UDP << 32))

#define PATTERN_IPV4_TCP_KMASK \
    (KMASK_ETHER | (KMASK_IPV4 << 16) | (KMASK_TCP << 32))

#define PATTERN_DT1Q_IPV4_UDP_KMASK \
    (KMASK_ETHER | (KMASK_DT1Q << 16) | (KMASK_IPV4 << 24) | (KMASK_UDP << 40))

#define PATTERN_DT1Q_IPV4_TCP_KMASK \
    (KMASK_ETHER | (KMASK_DT1Q << 16) | (KMASK_IPV4 << 24) | (KMASK_TCP << 40))

#define PATTERN_IPV6_KMASK \
    (KMASK_ETHER_IPV6 | (KMASK_IPV6 << 16) | (KMASK_IPV6 << 32))

#define PATTERN_DT1Q_IPV6_KMASK \
    (KMASK_ETHER_IPV6 | (KMASK_DT1Q_IPV6 << 16) | (KMASK_IPV6 << 32) | \
    (KMASK_IPV6_NOHDR << 48))

/* This union allows initializing static data as u8, but easily loading it
 * into AVX512 registers too. The union ensures proper alignment for the zmm.
 */
union mfex_data {
    uint8_t u8_data[64];
    __m512i zmm;
};

/* This structure represents a single traffic pattern. The AVX512 code to
 * enable the specifics for each pattern is largely the same, so it is
 * specialized to use the common profile data from here.
 *
 * Due to the nature of e.g. TCP flag handling, or VLAN CFI bit setting,
 * some profiles require additional processing. This is handled by having
 * all implementations call a post-process function, and specializing away
 * the big switch() that handles all traffic types.
 *
 * This approach reduces AVX512 code-duplication for each traffic type.
 */
struct mfex_profile {
    /* Required for probing a packet with the mfex pattern. */
    union mfex_data probe_mask;
    union mfex_data probe_data;

    /* Required for reshaping packet into miniflow. */
    union mfex_data store_shuf;
    __mmask64 store_kmsk;

    /* Constant data to set in mf.bits and dp_packet data on hit. */
    uint64_t mf_bits[FLOWMAP_UNITS];
    uint16_t dp_pkt_offs[4];
    uint16_t dp_pkt_min_size;

    /* Constant data offsets for Hashing. */
    uint8_t hash_pkt_offs[6];
};

/* Ensure dp_pkt_offs[4] is the correct size as in struct dp_packet. */
BUILD_ASSERT_DECL((OFFSETOFEND(struct dp_packet, l4_ofs)
                  - offsetof(struct dp_packet, l2_pad_size)) ==
                  MEMBER_SIZEOF(struct mfex_profile, dp_pkt_offs));

/* Ensure FLOWMAP_UNITS is 2 units, as the implementation assumes this. */
BUILD_ASSERT_DECL(FLOWMAP_UNITS == 2);

/* Ensure the miniflow-struct ABI is the expected version. */
BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

/* If the above build assert happens, this means that you might need to make
 * some modifications to the AVX512 miniflow extractor code. In general, the
 * AVX512 flow extractor code uses hardcoded miniflow->map->bits which are
 * defined into the mfex_profile structure as mf_bits. In addition to the
 * hardcoded bits, it also has hardcoded offsets/masks that tell the AVX512
 * code how to translate packet data in the required miniflow values. These
 * are stored in the mfex_profile structure as store_shuf and store_kmsk.
 * See the respective documentation on their usage.
 *
 * If you have made changes to the flow structure, but only additions, no
 * re-arranging of the actual members, you might be good to go. To be 100%
 * sure, if possible, run the AVX512 MFEX autovalidator tests on an AVX512
 * enabled machine.
 *
 * If you did make changes to the order, you have to run the autovalidator
 * tests on an AVX512 machine, and and in the case errors, the debug output
 * will show what miniflow or dp_packet properties are not being correctly
 * built from the input packet.
 *
 * In case your change increased the maximum size of the map, i.e.,
 * FLOWMAP_UNITS, you need to study the code as it will need some rewriting.
 *
 * If you are not using the AVX512 MFEX implementation at all, i.e. keeping it
 * to the default scalar implementation, see "ovs-appctl
 * dpif-netdev/miniflow-parser-get", you could ignore this assert, and just
 * just increase the FLOW_WC_SEQ number in the assert.
 */

enum MFEX_PROFILES {
    PROFILE_ETH_IPV4_UDP,
    PROFILE_ETH_IPV4_TCP,
    PROFILE_ETH_VLAN_IPV4_UDP,
    PROFILE_ETH_VLAN_IPV4_TCP,
    PROFILE_ETH_IPV6_UDP,
    PROFILE_ETH_IPV6_TCP,
    PROFILE_ETH_VLAN_IPV6_TCP,
    PROFILE_ETH_VLAN_IPV6_UDP,
    PROFILE_COUNT,
};

/* Packet offsets for 5 tuple Hash function. */
#define HASH_IPV4 \
    26, 30, 23, 34, 0, 0

#define HASH_DT1Q_IPV4 \
    30, 34, 27, 38, 0, 0

/* Static const instances of profiles. These are compile-time constants,
 * and are specialized into individual miniflow-extract functions.
 * NOTE: Order of the fields is significant, any change in the order must be
 * reflected in miniflow_extract()!
 */
static const struct mfex_profile mfex_profiles[PROFILE_COUNT] =
{
    [PROFILE_ETH_IPV4_UDP] = {
        .probe_mask.u8_data = { PATTERN_ETHERTYPE_MASK PATTERN_IPV4_MASK },
        .probe_data.u8_data = { PATTERN_ETHERTYPE_IPV4 PATTERN_IPV4_UDP},

        .store_shuf.u8_data = { PATTERN_IPV4_UDP_SHUFFLE },
        .store_kmsk = PATTERN_IPV4_UDP_KMASK,

        .mf_bits = { 0x18a0000000000000, 0x0000000000040401},
        .dp_pkt_offs = {
            0, UINT16_MAX, 14, 34,
        },
        .dp_pkt_min_size = 42,

        .hash_pkt_offs = { HASH_IPV4 },
    },

    [PROFILE_ETH_IPV4_TCP] = {
        .probe_mask.u8_data = { PATTERN_ETHERTYPE_MASK PATTERN_IPV4_MASK },
        .probe_data.u8_data = { PATTERN_ETHERTYPE_IPV4 PATTERN_IPV4_TCP},

        .store_shuf.u8_data = { PATTERN_IPV4_TCP_SHUFFLE },
        .store_kmsk = PATTERN_IPV4_TCP_KMASK,

        .mf_bits = { 0x18a0000000000000, 0x0000000000044401},
        .dp_pkt_offs = {
            0, UINT16_MAX, 14, 34,
        },
        .dp_pkt_min_size = 54,

        .hash_pkt_offs = { HASH_IPV4 },
    },

    [PROFILE_ETH_VLAN_IPV4_UDP] = {
        .probe_mask.u8_data = {
            PATTERN_ETHERTYPE_MASK PATTERN_DT1Q_MASK PATTERN_IPV4_MASK
        },
        .probe_data.u8_data = {
            PATTERN_ETHERTYPE_DT1Q PATTERN_DT1Q_IPV4 PATTERN_IPV4_UDP
        },

        .store_shuf.u8_data = { PATTERN_DT1Q_IPV4_UDP_SHUFFLE },
        .store_kmsk = PATTERN_DT1Q_IPV4_UDP_KMASK,

        .mf_bits = { 0x38a0000000000000, 0x0000000000040401},
        .dp_pkt_offs = {
            14, UINT16_MAX, 18, 38,
        },
        .dp_pkt_min_size = 46,

        .hash_pkt_offs = { HASH_DT1Q_IPV4 },
    },

    [PROFILE_ETH_VLAN_IPV4_TCP] = {
        .probe_mask.u8_data = {
            PATTERN_ETHERTYPE_MASK PATTERN_DT1Q_MASK PATTERN_IPV4_MASK
        },
        .probe_data.u8_data = {
            PATTERN_ETHERTYPE_DT1Q PATTERN_DT1Q_IPV4 PATTERN_IPV4_TCP
        },

        .store_shuf.u8_data = { PATTERN_DT1Q_IPV4_TCP_SHUFFLE },
        .store_kmsk = PATTERN_DT1Q_IPV4_TCP_KMASK,

        .mf_bits = { 0x38a0000000000000, 0x0000000000044401},
        .dp_pkt_offs = {
            14, UINT16_MAX, 18, 38,
        },
        .dp_pkt_min_size = 46,

        .hash_pkt_offs = { HASH_DT1Q_IPV4 },
    },

    [PROFILE_ETH_IPV6_UDP] = {
        .probe_mask.u8_data = { PATTERN_ETHERTYPE_MASK PATTERN_IPV6_MASK },
        .probe_data.u8_data = { PATTERN_ETHERTYPE_IPV6 PATTERN_IPV6_UDP },

        .store_shuf.u8_data = { PATTERN_IPV6_SHUFFLE },
        .store_kmsk = PATTERN_IPV6_KMASK,

        .mf_bits = { 0x18a0000000000000, 0x000000000004043c},
        .dp_pkt_offs = {
            0, UINT16_MAX, 14, 54,
        },
        .dp_pkt_min_size = 54,
    },

    [PROFILE_ETH_IPV6_TCP] = {
        .probe_mask.u8_data = { PATTERN_ETHERTYPE_MASK PATTERN_IPV6_MASK },
        .probe_data.u8_data = { PATTERN_ETHERTYPE_IPV6 PATTERN_IPV6_TCP },

        .store_shuf.u8_data = { PATTERN_IPV6_SHUFFLE },
        .store_kmsk = PATTERN_IPV6_KMASK,

        .mf_bits = { 0x18a0000000000000, 0x000000000004443c},
        .dp_pkt_offs = {
            0, UINT16_MAX, 14, 54,
        },
        .dp_pkt_min_size = 54,
    },

    [PROFILE_ETH_VLAN_IPV6_TCP] = {
        .probe_mask.u8_data = {
            PATTERN_ETHERTYPE_MASK PATTERN_DT1Q_MASK PATTERN_IPV6_MASK },
        .probe_data.u8_data = {
            PATTERN_ETHERTYPE_DT1Q PATTERN_DT1Q_IPV6 PATTERN_IPV6_TCP },

        .store_shuf.u8_data = { PATTERN_DT1Q_IPV6_SHUFFLE },
        .store_kmsk = PATTERN_DT1Q_IPV6_KMASK,

        .mf_bits = { 0x38a0000000000000, 0x000000000004443c},
        .dp_pkt_offs = {
            14, UINT16_MAX, 18, 58,
        },
        .dp_pkt_min_size = 66,
    },

    [PROFILE_ETH_VLAN_IPV6_UDP] = {
        .probe_mask.u8_data = {
            PATTERN_ETHERTYPE_MASK PATTERN_DT1Q_MASK PATTERN_IPV6_MASK },
        .probe_data.u8_data = {
            PATTERN_ETHERTYPE_DT1Q PATTERN_DT1Q_IPV6 PATTERN_IPV6_UDP },

        .store_shuf.u8_data = { PATTERN_DT1Q_IPV6_SHUFFLE },
        .store_kmsk = PATTERN_DT1Q_IPV6_KMASK,

        .mf_bits = { 0x38a0000000000000, 0x000000000004043c},
        .dp_pkt_offs = {
            14, UINT16_MAX, 18, 58,
        },
        .dp_pkt_min_size = 66,
    },
};

/* IPv6 header helper function to fix TC, flow label and next header. */
static inline void ALWAYS_INLINE
mfex_handle_ipv6_hdr_block(const uint8_t *ipv6, uint64_t *block)
{
    static const uint8_t data_shuf[16] = {
        0, 1, 2, 3, /* copy IPv6 label in place, it is masked later. */
        1, 0,       /* Byte-swap TC fields for LE usage. */
        7, 6,       /* Move TTL and next proto to MF required locations. */
    };

    /* BE mask for IPv6 label, and mask to strip away unwanted TC bits. */
    const uint64_t mask = 0xffff0f00 | (UINT64_MAX << 40);

    static const uint64_t mask_data[2] = { mask, mask };

    /* Load constant data. Is lifted to occur 1x per burst, not per packet. */
    __m128i ipv6_hdr = _mm_loadu_si128((void *) ipv6);
    __m128i v_mask = _mm_loadu_si128((void *) mask_data);
    __m128i v_shuf_mask = _mm_loadu_si128((void *) data_shuf);

    /* Shuffle data layout, shift 16-bits to get TC fixed, mask to cleanup. */
    __m128i v_ipv6 = _mm_shuffle_epi8(ipv6_hdr, v_shuf_mask);
    __m128i v_tc_shift = _mm_mask_slli_epi16(v_ipv6, 0b100, v_ipv6, 4);
    __m128i v_ipv6_m = _mm_and_si128(v_tc_shift, v_mask);

    *block = _mm_extract_epi64(v_ipv6_m, 0);
}

/* IPv6 Protocol specific helper functions, for handling L4 UDP/TCP. */
static inline void
mfex_handle_ipv6_l4(const uint8_t *ports, uint64_t *block)
{
    void *ptr_ports = (void *) ports;
    uint32_t l4_ports = *(uint32_t *) ptr_ports;
    *block = l4_ports;
}

/* IPv6 specific helper functions, for calculating offsets/lengths. */
static void
mfex_ipv6_set_l2_pad_size(struct dp_packet *pkt,
                          struct ovs_16aligned_ip6_hdr *nh,
                          uint32_t payload_size_ipv6)
{
    /* Handle dynamic l2_pad_size. */
    payload_size_ipv6 = payload_size_ipv6 - IPV6_HEADER_LEN;
    uint16_t p_len =  ntohs(nh->plen);
    dp_packet_set_l2_pad_size(pkt, payload_size_ipv6 - p_len);
}

static inline void
mfex_5tuple_hash_ipv4(struct dp_packet *packet, const uint8_t *pkt,
                      struct netdev_flow_key *key,
                      const uint8_t *pkt_offsets)
{
    if (!dp_packet_rss_valid(packet)) {
        uint32_t hash = 0;
        void *ipv4_src = (void *) &pkt[pkt_offsets[0]];
        void *ipv4_dst = (void *) &pkt[pkt_offsets[1]];
        void *ports_l4 = (void *) &pkt[pkt_offsets[3]];

        /* IPv4 Src and Dst. */
        hash = hash_add(hash, *(uint32_t *) ipv4_src);
        hash = hash_add(hash, *(uint32_t *) ipv4_dst);
        /* IPv4 proto. */
        hash = hash_add(hash, pkt[pkt_offsets[2]]);
        /* L4 ports. */
        hash = hash_add(hash, *(uint32_t *) ports_l4);
        hash = hash_finish(hash, 42);

        dp_packet_set_rss_hash(packet, hash);
        key->hash = hash;
    } else {
        key->hash = dp_packet_get_rss_hash(packet);
    }
    key->len = netdev_flow_key_size(miniflow_n_values(&key->mf));
}

/* Protocol specific helper functions, for calculating offsets/lenghts. */
static int32_t
mfex_ipv4_set_l2_pad_size(struct dp_packet *pkt, struct ip_header *nh,
                          uint32_t len_from_ipv4)
{
        /* Handle dynamic l2_pad_size. */
        uint16_t tot_len = ntohs(nh->ip_tot_len);
        if (OVS_UNLIKELY(tot_len > len_from_ipv4 ||
                (len_from_ipv4 - tot_len) > UINT16_MAX)) {
            return -1;
        }
        dp_packet_set_l2_pad_size(pkt, len_from_ipv4 - tot_len);
        return 0;
}

/* Fixup the VLAN CFI and PCP, reading the PCP from the input to this function,
 * and storing the output CFI bit bitwise-OR-ed with the PCP to miniflow.
 */
static void
mfex_vlan_pcp(const uint8_t vlan_pcp, uint64_t *block)
{
    /* Bitwise-OR in the CFI flag, keeping other data the same. */
    uint8_t *cfi_byte = (uint8_t *) block;
    cfi_byte[2] = 0x10 | vlan_pcp;
}

static void
mfex_handle_tcp_flags(const struct tcp_header *tcp, uint64_t *block)
{
    uint16_t ctl = (OVS_FORCE uint16_t) TCP_FLAGS_BE16(tcp->tcp_ctl);
    uint64_t ctl_u64 = ctl;
    *block = ctl_u64 << 32;
}

/* Generic loop to process any mfex profile. This code is specialized into
 * multiple actual MFEX implementation functions. Its marked ALWAYS_INLINE
 * to ensure the compiler specializes each instance. The code is marked "hot"
 * to inform the compiler this is a hotspot in the program, encouraging
 * inlining of callee functions such as the permute calls.
 */
static inline uint32_t ALWAYS_INLINE
__attribute__ ((hot))
mfex_avx512_process(struct dp_packet_batch *packets,
                    struct netdev_flow_key *keys,
                    uint32_t keys_size OVS_UNUSED,
                    odp_port_t in_port,
                    void *pmd_handle OVS_UNUSED,
                    const enum MFEX_PROFILES profile_id,
                    const uint32_t use_vbmi)
{
    uint32_t hitmask = 0;
    struct dp_packet *packet;

    /* Here the profile to use is chosen by the variable used to specialize
     * the function. This causes different MFEX traffic to be handled.
     */
    const struct mfex_profile *profile = &mfex_profiles[profile_id];

    /* Load profile constant data. */
    __m512i v_vals = _mm512_loadu_si512(&profile->probe_data);
    __m512i v_mask = _mm512_loadu_si512(&profile->probe_mask);
    __m512i v_shuf = _mm512_loadu_si512(&profile->store_shuf);

    __mmask64 k_shuf = profile->store_kmsk;
    __m128i v_bits = _mm_loadu_si128((void *) &profile->mf_bits);
    uint16_t dp_pkt_min_size = profile->dp_pkt_min_size;

    __m128i v_zeros = _mm_setzero_si128();
    __m128i v_blocks01 = _mm_insert_epi32(v_zeros, odp_to_u32(in_port), 1);

    DP_PACKET_BATCH_FOR_EACH (i, packet, packets) {
        /* If the packet is smaller than the probe size, skip it. */
        const uint32_t size = dp_packet_size(packet);
        if (size < dp_pkt_min_size) {
            continue;
        }

        /* Load packet data and probe with AVX512 mask & compare. */
        const uint8_t *pkt = dp_packet_data(packet);
        __m512i v_pkt0 = _mm512_loadu_si512(pkt);
        __m512i v_pkt0_masked = _mm512_and_si512(v_pkt0, v_mask);
        __mmask64 k_cmp = _mm512_cmpeq_epi8_mask(v_pkt0_masked, v_vals);
        if (k_cmp != UINT64_MAX) {
            continue;
        }

        /* Copy known dp packet offsets to the dp_packet instance. */
        memcpy(&packet->l2_pad_size, &profile->dp_pkt_offs,
               sizeof(uint16_t) * 4);

        /* Store known miniflow bits and first two blocks. */
        struct miniflow *mf = &keys[i].mf;
        uint64_t *bits = (void *) &mf->map.bits[0];
        uint64_t *blocks = miniflow_values(mf);
        _mm_storeu_si128((void *) bits, v_bits);
        _mm_storeu_si128((void *) blocks, v_blocks01);

        /* Permute the packet layout into miniflow blocks shape.
         * As different AVX512 ISA levels have different implementations,
         * this specializes on the "use_vbmi" attribute passed in.
         */
        __m512i v512_zeros = _mm512_setzero_si512();
        __m512i v_blk0;
        if (__builtin_constant_p(use_vbmi) && use_vbmi) {
            v_blk0 = _mm512_maskz_permutexvar_epi8_wrap(k_shuf, v_shuf,
                                                        v_pkt0);
        } else {
            v_blk0 = _mm512_maskz_permutex2var_epi8_skx(k_shuf, v_pkt0,
                                                        v_shuf, v512_zeros);
        }
        _mm512_storeu_si512(&blocks[2], v_blk0);


        /* Perform "post-processing" per profile, handling details not easily
         * handled in the above generic AVX512 code. Examples include TCP flag
         * parsing, adding the VLAN CFI bit, and handling IPv4 fragments.
         */
        switch (profile_id) {
        case PROFILE_COUNT:
            ovs_assert(0); /* avoid compiler warning on missing ENUM */
            break;

        case PROFILE_ETH_VLAN_IPV4_TCP: {
                mfex_vlan_pcp(pkt[14], &keys[i].buf[4]);

                uint32_t size_from_ipv4 = size - VLAN_ETH_HEADER_LEN;
                struct ip_header *nh = (void *)&pkt[VLAN_ETH_HEADER_LEN];
                if (mfex_ipv4_set_l2_pad_size(packet, nh, size_from_ipv4)) {
                    continue;
                }

                /* Process TCP flags, and store to blocks. */
                const struct tcp_header *tcp = (void *)&pkt[38];
                mfex_handle_tcp_flags(tcp, &blocks[7]);

                mfex_5tuple_hash_ipv4(packet, pkt, &keys[i],
                                      profile->hash_pkt_offs);
            } break;

        case PROFILE_ETH_VLAN_IPV4_UDP: {
                mfex_vlan_pcp(pkt[14], &keys[i].buf[4]);

                uint32_t size_from_ipv4 = size - VLAN_ETH_HEADER_LEN;
                struct ip_header *nh = (void *)&pkt[VLAN_ETH_HEADER_LEN];
                if (mfex_ipv4_set_l2_pad_size(packet, nh, size_from_ipv4)) {
                    continue;
                }

                mfex_5tuple_hash_ipv4(packet, pkt, &keys[i],
                                      profile->hash_pkt_offs);
            } break;

        case PROFILE_ETH_IPV4_TCP: {
                /* Process TCP flags, and store to blocks. */
                const struct tcp_header *tcp = (void *)&pkt[34];
                mfex_handle_tcp_flags(tcp, &blocks[6]);

                /* Handle dynamic l2_pad_size. */
                uint32_t size_from_ipv4 = size - sizeof(struct eth_header);
                struct ip_header *nh = (void *)&pkt[sizeof(struct eth_header)];
                if (mfex_ipv4_set_l2_pad_size(packet, nh, size_from_ipv4)) {
                    continue;
                }

                mfex_5tuple_hash_ipv4(packet, pkt, &keys[i],
                                      profile->hash_pkt_offs);
            } break;

        case PROFILE_ETH_IPV4_UDP: {
                /* Handle dynamic l2_pad_size. */
                uint32_t size_from_ipv4 = size - sizeof(struct eth_header);
                struct ip_header *nh = (void *)&pkt[sizeof(struct eth_header)];
                if (mfex_ipv4_set_l2_pad_size(packet, nh, size_from_ipv4)) {
                    continue;
                }

                mfex_5tuple_hash_ipv4(packet, pkt, &keys[i],
                                      profile->hash_pkt_offs);
            } break;

        case PROFILE_ETH_IPV6_UDP: {
                /* Handle dynamic l2_pad_size. */
                uint32_t payload_size_ipv6 = size - sizeof(struct eth_header);
                struct ovs_16aligned_ip6_hdr *nh = (void *)&pkt[sizeof
                                                   (struct eth_header)];
                mfex_ipv6_set_l2_pad_size(packet, nh, payload_size_ipv6);

                /* Process IPv6 header for TC, flow Label and next header. */
                mfex_handle_ipv6_hdr_block(&pkt[ETH_HEADER_LEN], &blocks[8]);

                /* Process UDP header. */
                mfex_handle_ipv6_l4((void *)&pkt[54], &blocks[9]);

            } break;

        case PROFILE_ETH_IPV6_TCP: {
                /* Handle dynamic l2_pad_size. */
                uint32_t payload_size_ipv6 = size - sizeof(struct eth_header);
                struct ovs_16aligned_ip6_hdr *nh = (void *)&pkt[sizeof
                                                   (struct eth_header)];
                mfex_ipv6_set_l2_pad_size(packet, nh, payload_size_ipv6);

                /* Process IPv6 header for TC, flow Label and next header. */
                mfex_handle_ipv6_hdr_block(&pkt[ETH_HEADER_LEN], &blocks[8]);

                /* Process TCP header. */
                mfex_handle_ipv6_l4((void *)&pkt[54], &blocks[10]);
                const struct tcp_header *tcp = (void *)&pkt[54];
                mfex_handle_tcp_flags(tcp, &blocks[9]);

            } break;

        case PROFILE_ETH_VLAN_IPV6_TCP: {
                mfex_vlan_pcp(pkt[14], &keys[i].buf[4]);

                /* Handle dynamic l2_pad_size. */
                uint32_t payload_size_ipv6 = size - VLAN_ETH_HEADER_LEN;
                struct ovs_16aligned_ip6_hdr *nh = (void *)&pkt
                                                   [VLAN_ETH_HEADER_LEN];
                mfex_ipv6_set_l2_pad_size(packet, nh, payload_size_ipv6);

                /* Process IPv6 header for TC, flow Label and next header. */
                mfex_handle_ipv6_hdr_block(&pkt[VLAN_ETH_HEADER_LEN],
                                           &blocks[9]);

                /* Process TCP header. */
                mfex_handle_ipv6_l4((void *)&pkt[58], &blocks[11]);
                const struct tcp_header *tcp = (void *)&pkt[58];
                mfex_handle_tcp_flags(tcp, &blocks[10]);

            } break;

        case PROFILE_ETH_VLAN_IPV6_UDP: {
                mfex_vlan_pcp(pkt[14], &keys[i].buf[4]);

                /* Handle dynamic l2_pad_size. */
                uint32_t payload_size_ipv6 = size - VLAN_ETH_HEADER_LEN;
                struct ovs_16aligned_ip6_hdr *nh = (void *)&pkt
                                                   [VLAN_ETH_HEADER_LEN];
                mfex_ipv6_set_l2_pad_size(packet, nh, payload_size_ipv6);

                /* Process IPv6 header for TC, flow Label and next header. */
                mfex_handle_ipv6_hdr_block(&pkt[VLAN_ETH_HEADER_LEN],
                                           &blocks[9]);

                /* Process UDP header. */
                mfex_handle_ipv6_l4((void *)&pkt[58], &blocks[10]);

            } break;
        default:
            break;
        };

        /* This packet has its miniflow created, add to hitmask. */
        hitmask |= 1 << i;
    }

    return hitmask;
}


#define DECLARE_MFEX_FUNC(name, profile)                                \
uint32_t                                                                \
__attribute__((__target__("avx512f")))                                  \
__attribute__((__target__("avx512vl")))                                 \
__attribute__((__target__("avx512vbmi")))                               \
mfex_avx512_vbmi_##name(struct dp_packet_batch *packets,                \
                        struct netdev_flow_key *keys, uint32_t keys_size,\
                        odp_port_t in_port, struct dp_netdev_pmd_thread \
                        *pmd_handle)                                    \
{                                                                       \
    return mfex_avx512_process(packets, keys, keys_size, in_port,       \
                               pmd_handle, profile, 1);                 \
}                                                                       \
                                                                        \
uint32_t                                                                \
__attribute__((__target__("avx512f")))                                  \
__attribute__((__target__("avx512vl")))                                 \
mfex_avx512_##name(struct dp_packet_batch *packets,                     \
                   struct netdev_flow_key *keys, uint32_t keys_size,    \
                   odp_port_t in_port, struct dp_netdev_pmd_thread      \
                   *pmd_handle)                                         \
{                                                                       \
    return mfex_avx512_process(packets, keys, keys_size, in_port,       \
                               pmd_handle, profile, 0);                 \
}

/* Each profile gets a single declare here, which specializes the function
 * as required.
 */
DECLARE_MFEX_FUNC(ip_udp, PROFILE_ETH_IPV4_UDP)
DECLARE_MFEX_FUNC(ip_tcp, PROFILE_ETH_IPV4_TCP)
DECLARE_MFEX_FUNC(dot1q_ip_udp, PROFILE_ETH_VLAN_IPV4_UDP)
DECLARE_MFEX_FUNC(dot1q_ip_tcp, PROFILE_ETH_VLAN_IPV4_TCP)
DECLARE_MFEX_FUNC(ipv6_udp, PROFILE_ETH_IPV6_UDP)
DECLARE_MFEX_FUNC(ipv6_tcp, PROFILE_ETH_IPV6_TCP)
DECLARE_MFEX_FUNC(dot1q_ipv6_tcp, PROFILE_ETH_VLAN_IPV6_TCP)
DECLARE_MFEX_FUNC(dot1q_ipv6_udp, PROFILE_ETH_VLAN_IPV6_UDP)

static int32_t
avx512_isa_probe(uint32_t needs_vbmi)
{
    static const char *isa_required[] = {
        "avx512f",
        "avx512bw",
        "bmi2",
    };

    int32_t ret = 0;
    for (uint32_t i = 0; i < ARRAY_SIZE(isa_required); i++) {
        if (!dpdk_get_cpu_has_isa("x86_64", isa_required[i])) {
            ret = -ENOTSUP;
        }
    }

    if (needs_vbmi) {
        if (!dpdk_get_cpu_has_isa("x86_64", "avx512vbmi")) {
            ret = -ENOTSUP;
        }
    }

    return ret;
}

/* Probe functions to check ISA requirements. */
int32_t
mfex_avx512_probe(void)
{
    const uint32_t needs_vbmi = 0;
    return avx512_isa_probe(needs_vbmi);
}

int32_t
mfex_avx512_vbmi_probe(void)
{
    const uint32_t needs_vbmi = 1;
    return avx512_isa_probe(needs_vbmi);
}

#endif /* __CHECKER__ */
#endif /* __x86_64__ */
