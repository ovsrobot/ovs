/*
 * Copyright (c) 2020 Intel.
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

#include "flow.h"
#include "dpif-netdev-private-thread.h"


/* This file contains optimized implementations of miniflow_extract()
 * for specific common traffic patterns. The optimizations allow for
 * quick probing of a specific packet type, and if a match with a specific
 * type is found, a shuffle like proceedure builds up the required miniflow
 */

#define MAX_PATTERN_COUNT (8)
#define MAX_PATTERN_SIZE (128)
#define MAX_SHUFFLE_COUNT (MAX_PATTERN_SIZE / 64)

/* A structure to represent each matched on packet pattern */
struct __attribute__((aligned(MAX_PATTERN_SIZE))) packet_pattern {
    uint8_t mask[MAX_PATTERN_SIZE];
    uint8_t data[MAX_PATTERN_SIZE];
};

/* Improvement: create this sttruct in dp-packet.h, and reuse-here. That would
 * avoid the requirement of the packed attribute.
 */
struct __attribute__((packed)) packet_offsets {
    uint8_t l2_pad_size;
    uint16_t l2_5_ofs;
    uint16_t l3_ofs;
    uint16_t l4_ofs;
};

/* Structure to represent the data-movement from pattern to miniflow. */
struct packet_pattern_shuffle {
    uint64_t kmasks[MAX_SHUFFLE_COUNT];
    struct packet_offsets offsets;
    uint8_t shuffle[MAX_PATTERN_SIZE];
};

/* structure that represents all per-thread pattern data. */
struct packet_pattern_cache {
    /* Minimum packet len for this pattern index to be a valid candidate. */
    uint8_t min_len[MAX_PATTERN_COUNT];

    /* Number of active patterns to match against. */
    uint8_t active_pattern_count;

    /* The mask and compare data itself. */
    struct packet_pattern patterns[MAX_PATTERN_COUNT];

    /* Miniflow bits that need to be set for each pattern. */
    struct miniflow miniflow_bits[MAX_PATTERN_COUNT];

    /* Structure to represent the data-movement from pattern to miniflow. */
    struct packet_pattern_shuffle shuffles[MAX_PATTERN_COUNT];

};

/* Single copy of control-path owned patterns. The contents of this struct will
 * be updated when the user runs a miniflow-pattern-add command. The contents
 * of this struct are only read in the datapath during the "study" phase, and
 * copied into a thread-local memory for the PMD threads for datapath usage.
 */
static struct packet_pattern_cache patterns_control_path;

/* Generator for EtherType masks and values. */
#define PATTERN_ETHERTYPE_GEN(type_b0, type_b1) \
  0, 0, 0, 0, 0, 0, /* Ether MAC DST */                                 \
  0, 0, 0, 0, 0, 0, /* Ether MAC SRC */                                 \
  type_b0, type_b1, /* EtherType */

#define PATTERN_ETHERTYPE_MASK PATTERN_ETHERTYPE_GEN(0xFF, 0xFF)
#define PATTERN_ETHERTYPE_IPV4 PATTERN_ETHERTYPE_GEN(0x08, 0x00)

/* Generator for checking IPv4 ver, ihl, and proto */
#define PATTERN_IPV4_GEN(VER_IHL, FLAG_OFF_B0, FLAG_OFF_B1, PROTO) \
  VER_IHL, /* Version and IHL */                                        \
  0, 0, 0, /* DSCP, ECN, Total Lenght */                                \
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

#define ETHER_IPV4_UDP_LEN (42)

#define NU 0
#define PATTERN_IPV4_UDP_SHUFFLE \
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, NU, NU, /* Ether */ \
  26, 27, 28, 29, 30, 31, 32, 33, NU, NU, NU, NU, 20, 15, 22, 23, /* IPv4 */  \
  34, 35, 36, 37, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, NU, /* UDP */

static int avx512vbmi_available;

/* Enable Icelake AVX-512 VBMI ISA for only this function. That allows the
 * compile to emit the instruction here, but not use AVX-512 VBMI outside
 * of this function.
 */
static inline __m512i __attribute__((__target__("avx512vbmi")))
packet_shuffle_avx512_icx(__mmask64 k_mask, __m512i v_pkt_data_0,
                          __m512i v_shuf_mask, __m512i v_pkt_data_1)
{
    return _mm512_maskz_permutex2var_epi8(k_mask, v_pkt_data_0,
                                          v_shuf_mask, v_pkt_data_1);
}

/* This function provides a Skylake and higher fallback for the byte-shuffle
 * that is required to implement miniflow extract correctly.
 */
static inline __m512i
packet_shuffle_avx512(__mmask64 k_mask, __m512i v_data_0, __m512i v_shuf_idxs,
                      __m512i v_data_1)
{
    if (avx512vbmi_available) {
        return packet_shuffle_avx512_icx(k_mask, v_data_0,
                                         v_shuf_idxs, v_data_1);
    }

    /* Clear away ODD lane bytes, shift down by 1 to get u8 to u16 idxs. */
    const __mmask64 k_mask_odd_lanes = 0xAAAAAAAAAAAAAAAA;
    __m512i v_shuf_idx_evn = _mm512_mask_blend_epi8(k_mask_odd_lanes,
                            v_shuf_idxs, _mm512_setzero_si512());
    v_shuf_idx_evn = _mm512_srli_epi16(v_shuf_idx_evn, 1);

    /* Clear away EVEN lane bytes by shifting out. Shift EVEN lane indexes down
     * by one bit too to achieve u8 to u16 conversion.
     */
    __m512i v_shuf_idx_odd = _mm512_srli_epi16(v_shuf_idxs, 9);

    /* Shuffle each of odd/even at 16-bit width. */
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

    /* Rotate based on low-bit-set bitmask, and blend results. */
    __m512i v_shuf_res_evn = _mm512_mask_srli_epi16(v_shuf1,
                                    evn_rotate_mask, v_shuf1, 8);
    __m512i v_shuf_res_odd = _mm512_mask_slli_epi16(v_shuf2,
                                    odd_rotate_mask, v_shuf2, 8);

    /* Blend results of two halves back together. */
    __m512i v_shuf_result = _mm512_mask_blend_epi8(k_mask_odd_lanes,
                                    v_shuf_res_evn, v_shuf_res_odd);

    /* k-mask the final result as requested. This is not easy to do before
     * here, as the instructions operate at u16 size, meaning the k-mask would
     * be interpreted as the wrong size.
     */
    __m512i v_zeros = _mm512_setzero_si512();
    __m512i v_shuf_res_masked = _mm512_mask_blend_epi8(k_mask, v_zeros,
                                                       v_shuf_result);
    return v_shuf_res_masked;
}


/* Matches all patterns provided, returns a bitmask of which pattern matched
 * the packet.
 */
static inline __attribute__((always_inline)) uint32_t
packet_pattern_avx512(struct dp_packet *dp_pkt, struct miniflow *mf,
                      struct packet_pattern_cache *cache,
                      const uint32_t num_patterns)
{
    uint8_t *pkt = dp_packet_data(dp_pkt);
    uint32_t pkt_len = dp_packet_size(dp_pkt);
    uint32_t in_port = odp_to_u32(dp_pkt->md.in_port.odp_port);

    /* Masked load to only load the valid packet data. */
    uint64_t mask1 = (1ULL << pkt_len) - 1;
    mask1 |= (pkt_len < 64) - 1;
    __mmask64 pkt_len_mask_0 = mask1;

    uint64_t mask2 = (1ULL << (pkt_len - 64)) - 1;
    mask2 |= (pkt_len < 128) - 1;
    mask2 &= (pkt_len <  64) - 1;
    __mmask64 pkt_len_mask_1 = mask2;

    __m512i v_pkt_data_0 = _mm512_maskz_loadu_epi8(pkt_len_mask_0, &pkt[0]);
    __m512i v_pkt_data_1 = _mm512_maskz_loadu_epi8(pkt_len_mask_1, &pkt[64]);

    /* Loop over the patterns provided. Note that this loop can be compile-time
     * unrolled for specialized versions with set numbers of patterns.
     */
    uint32_t hitmask = 0;
    for (uint32_t i = 0; i < num_patterns; i++) {
        struct packet_pattern *patterns = cache->patterns;

        /* Mask and match the packet data and pattern, results in hit bit. */
        __m512i v_mask_0 = _mm512_loadu_si512(&patterns[i].mask[0]);
        __m512i v_data_0 = _mm512_loadu_si512(&patterns[i].data[0]);
        __m512i v_pkt_masked = _mm512_and_si512(v_pkt_data_0, v_mask_0);
        __mmask64 cmp_mask = _mm512_cmpeq_epi8_mask(v_pkt_masked, v_data_0);

        uint32_t hit = (cmp_mask == UINT64_MAX);
        hitmask |= (hit << i);
    }

    /* If a pattern was hit, build the miniflow using the pattern shuffle. */
    if (OVS_LIKELY(hitmask)) {
        uint32_t idx = __builtin_ctzll(hitmask);

        /* Copy the pattern miniflow bits to the destination miniflow. */
        struct miniflow *pattern_mf_bits = &cache->miniflow_bits[idx];
        __m128i v_pattern_mf_bits = _mm_load_si128((void *)pattern_mf_bits);
        _mm_storeu_si128((void *)mf, v_pattern_mf_bits);

        /* Compute bytes 0-63 of miniflow. */
        struct packet_pattern_shuffle *shuffle = &cache->shuffles[idx];
        __mmask64 k_shuf_0 = shuffle->kmasks[0];
        __m512i v_shuf_mask_0 = _mm512_loadu_si512(&shuffle->shuffle[0]);
        __m512i v_mf_blocks_0 = packet_shuffle_avx512(k_shuf_0, v_pkt_data_0,
                                    v_shuf_mask_0, v_pkt_data_1);

        /* Compute bytes 64-127 of miniflow. */
        __mmask64 k_shuf_1 = shuffle->kmasks[1];
        __m512i v_shuf_mask_1 = _mm512_loadu_si512(&shuffle->shuffle[1]);
        __m512i v_mf_blocks_1 = packet_shuffle_avx512(k_shuf_1, v_pkt_data_0,
                                    v_shuf_mask_1, v_pkt_data_1);

        /* Miniflow Blocks contains first 2 blocks of non-packet-parsed data,
         * such as the dp hash, in port, ct_mark, and packet_type. On outer
         * packets, they are always zero except for in_port.
         */
        uint64_t *mf_blocks = miniflow_values(mf);
        __m128i v_blocks_01 = _mm_setzero_si128();
        v_blocks_01 = _mm_insert_epi32(v_blocks_01, in_port, 1);
        _mm_storeu_si128((void *)&mf_blocks[0], v_blocks_01);

        /* Store the computed miniflow blocks. */
        _mm512_storeu_si512(&mf_blocks[2], v_mf_blocks_0);
        _mm512_storeu_si512(&mf_blocks[2 + 8], v_mf_blocks_1);

        /* Set dp packet offsets from the pattern metadata.  */
        memcpy(&dp_pkt->l2_pad_size, &shuffle->offsets,
               sizeof(struct packet_offsets));
    }

    return hitmask;
}

/* Check that the runtime CPU has the required ISA avialable. Also check for
 * AVX-512 Vector Bit Manipulation Instructions (VBMI), which allow a faster
 * code-path to be used due to a native byte permute instruction.
 */
int32_t
miniflow_extract_avx512_probe(void)
{
    int avx512f_available = dpdk_get_cpu_has_isa("x86_64", "avx512f");
    int bmi2_available = dpdk_get_cpu_has_isa("x86_64", "bmi2");
    avx512vbmi_available = dpdk_get_cpu_has_isa("x86_64", "avx512vbmi");

    uint32_t min_isa_ok = avx512f_available && bmi2_available;
    printf("%s : minimum ISA avialable: %s, AVX-512 VBMI available: %s\n",
           __func__, min_isa_ok ? "yes" : "no",
           avx512vbmi_available ? "yes" : "no");
    return min_isa_ok;
}

/* TODO: This function accepts a string, which represents the pattern and
 * shuffles required for the users traffic type. Today this function has a
 * hard-coded pattern for Ether()/IP()/UDP() packets.
 *
 * A future revision of this patchset will include the parsing of the input
 * string to create the patterns, providing runtime flexibility in parsing
 * packets into miniflows.
 */
int32_t
miniflow_extract_avx512_insert(const char *pattern_string)
{
    (void)patterns_control_path;
    (void)pattern_string;

    /* Add hard-coded Ether/IPv4/UDP implementation for demonstration. */
    patterns_control_path.active_pattern_count = 1;

    /* Ether/IPv4/UDP pattern metadata */
    patterns_control_path.patterns[0] = (struct packet_pattern) {
        .mask = { PATTERN_ETHERTYPE_MASK PATTERN_IPV4_MASK },
        .data = { PATTERN_ETHERTYPE_IPV4 PATTERN_IPV4_UDP },
    };

    printf("%s: pattern 0 mask:\n", __func__);
    ovs_hex_dump(stdout, &patterns_control_path.patterns[0].mask,
                 MAX_PATTERN_SIZE, 0, false);
    printf("%s: pattern 0 data:\n", __func__);
    ovs_hex_dump(stdout, &patterns_control_path.patterns[0].data,
                 MAX_PATTERN_SIZE, 0, false);

    patterns_control_path.miniflow_bits[0] = (struct miniflow) {
        .map = { .bits = {0x18a0000000000000, 0x0000000000040401}, }
    };
    printf("pattern[0] mf bits %08llx %08llx\n",
        patterns_control_path.miniflow_bits[0].map.bits[0],
        patterns_control_path.miniflow_bits[0].map.bits[1]);

    /* Kmask and Shuffle for Ether/IPv4/UDP. Created by inspecting miniflow
     * built from packet data, and reproduced using AVX-512 instructions with
     * k-masks to zero parts of the miniflow as required.
     */
    patterns_control_path.shuffles[0] = (struct packet_pattern_shuffle) {
        .kmasks = { 0b0000111111110000111111110011111111111111, 0 },
        .offsets = {
            .l2_pad_size = 0,
            .l2_5_ofs = UINT16_MAX,
            .l3_ofs = 14,
            .l4_ofs = 34,
        },
        .shuffle = {PATTERN_IPV4_UDP_SHUFFLE},
    };
    printf("pattern[0] kmask[0] %08lx, kmask[1] %08lx, shuffle hexdump:\n",
           patterns_control_path.shuffles[0].kmasks[0],
           patterns_control_path.shuffles[0].kmasks[1]);
    ovs_hex_dump(stdout, &patterns_control_path.shuffles[0], MAX_PATTERN_SIZE,
                 0, false);

    return 0;
};

/* The study function runs the patterns from the control-path, and based on
 * some hit statistics can copy the pattern to the per-PMD pattern cache. Part
 * of the study() functionality is also to validate that hits on a pattern
 * result in an identical miniflow as the scalar miniflow_extract() function.
 * This is validated by calling the scalar version, and comparing output.
 */
uint32_t
miniflow_extract_avx512_study(struct dp_netdev_pmd_thread *pmd,
                              struct dp_packet *packet,
                              struct miniflow *dst)
{
    /* Run using the user supplied patterns. */
    uint32_t match = miniflow_extract_avx512(pmd, packet, dst);

    if (match) {
        /* Save off AVX512 created dp_packet offsets for verification. */
        struct packet_offsets vec_offsets;
        memcpy(&vec_offsets, &packet->l2_pad_size,
               sizeof(struct packet_offsets));

        /* Check the result vs the scalar miniflow-extract for correctness. */
        struct netdev_flow_key scalar_mf_key = {0};
        struct miniflow *scalar_mf = &scalar_mf_key.mf;
        miniflow_extract(packet, scalar_mf);

        /* Validate miniflow data is identical. */
        uint32_t mf_bit_count = count_1bits(scalar_mf->map.bits[0]) +
                                    count_1bits(scalar_mf->map.bits[1]);
        size_t compare_size = sizeof(uint64_t) * (2 + mf_bit_count);
        if (memcmp(scalar_mf, dst, compare_size)) {
            printf("%s: Scalar miniflow output:\n", __func__);
            ovs_hex_dump(stdout, scalar_mf, compare_size, 0, false);
            printf("%s: AVX512 miniflow output:\n", __func__);
            ovs_hex_dump(stdout, dst, compare_size, 0, false);
            printf("error in miniflow compare, see hexdumps() above\n");
        }

        /* Validate that dp_packet offsets are identical. */
        if (memcmp(&vec_offsets, &packet->l2_pad_size,
                   sizeof(struct packet_offsets))) {
            printf("VECTOR code DP packet properties: %d, %d, %d, %d\n",
                   vec_offsets.l2_pad_size, vec_offsets.l2_5_ofs,
                   vec_offsets.l3_ofs, vec_offsets.l4_ofs);
            printf("Scalar code DP packet properties: %d, %d, %d, %d\n",
                   packet->l2_pad_size, packet->l2_5_ofs, packet->l3_ofs,
                   packet->l4_ofs);
            ovs_assert("error in packet offsets, see printf()s above\n");
        }

    }

    /* Check if the study function should study more packets, or if it is
     * done. When done, we change the per-PMD function pointer to the datapath
     * implementation without study for better performance.
     */
    int64_t study_more = --pmd->miniflow_study_pkts;
    if (!study_more) {
        printf("%s : setting func ptr to remove study(), study_pkts = %ld\n",
               __func__, study_more);
        pmd->miniflow_extract_opt = miniflow_extract_avx512;
    }

    return match;
}

uint32_t
miniflow_extract_avx512(struct dp_netdev_pmd_thread *pmd,
                        struct dp_packet *packet,
                        struct miniflow *mf)
{
    /* TODO: alloc pattern cache per PMD thread. */
    (void)pmd;

    /* Execute the pattern matching using the PMD pattern cache. */
    uint32_t match_hit = packet_pattern_avx512(packet, mf,
                                               &patterns_control_path, 1);
    return match_hit;
}
