/*
 * Copyright (c) 2022 Intel.
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

#ifdef __x86_64__
/* Sparse cannot handle the AVX512 instructions. */
#if !defined(__CHECKER__)


#include <config.h>
#include <errno.h>

#include "csum.h"
#include "cpu.h"
#include "dp-packet.h"
#include "immintrin.h"
#include "odp-execute-private.h"
#include "odp-netlink.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(odp_execute_avx512);
BUILD_ASSERT_DECL(offsetof(struct dp_packet, l2_5_ofs) +
                  MEMBER_SIZEOF(struct dp_packet, l2_5_ofs) ==
                  offsetof(struct dp_packet, l3_ofs));

BUILD_ASSERT_DECL(offsetof(struct dp_packet, l3_ofs) +
                           MEMBER_SIZEOF(struct dp_packet, l3_ofs) ==
                           offsetof(struct dp_packet, l4_ofs));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ethernet, eth_dst) +
                  MEMBER_SIZEOF(struct ovs_key_ethernet, eth_dst) ==
                  offsetof(struct ovs_key_ethernet, eth_src));

static struct odp_execute_action_impl active_impl;

static inline void ALWAYS_INLINE
avx512_dp_packet_resize_l2(struct dp_packet *b, int resize_by_bytes)
{
    /* Update packet size/data pointers */
    if (resize_by_bytes >= 0) {
        dp_packet_prealloc_headroom(b, resize_by_bytes);
    } else {
        ovs_assert(dp_packet_size(b) - dp_packet_l2_pad_size(b) >=
                    -resize_by_bytes);
    }

    dp_packet_set_data(b, (char *) dp_packet_data(b) - resize_by_bytes);
    dp_packet_set_size(b, dp_packet_size(b) + resize_by_bytes);

    /* Increment u16 packet offset values */
    const __m128i v_zeros = _mm_setzero_si128();
    const __m128i v_u16_max = _mm_cmpeq_epi16(v_zeros, v_zeros);

    /* Only these lanes can be incremented/decremented for L2. */
    const uint8_t k_lanes = 0b1110;
    __m128i v_offset = _mm_set1_epi16(abs(resize_by_bytes));

    /* Load packet and compare with UINT16_MAX */
    void *adjust_ptr = &b->l2_pad_size;
    __m128i v_adjust_src = _mm_loadu_si128(adjust_ptr);

    /* Generate K mask to use for updating offset values of
    * the packet buffer. */
    __mmask8 k_cmp = _mm_mask_cmpneq_epu16_mask(k_lanes, v_adjust_src,
                                                    v_u16_max);

    /* Update VLAN_HEADER_LEN using compare mask, store results. */
    __m128i v_adjust_wip;

    if (resize_by_bytes >= 0) {
        v_adjust_wip = _mm_mask_add_epi16(v_adjust_src, k_cmp,
                                            v_adjust_src, v_offset);
    } else {
        v_adjust_wip = _mm_mask_sub_epi16(v_adjust_src, k_cmp,
                                            v_adjust_src, v_offset);
    }

    _mm_storeu_si128(adjust_ptr, v_adjust_wip);
}

static void
action_avx512_pop_vlan(void *dp OVS_UNUSED, struct dp_packet_batch *batch,
                       const struct nlattr *a OVS_UNUSED,
                       bool should_steal OVS_UNUSED)
{
    struct dp_packet *packet;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        struct vlan_eth_header *veh = dp_packet_eth(packet);

        if (veh && dp_packet_size(packet) >= sizeof *veh &&
            eth_type_vlan(veh->veth_type)) {

            __m128i v_ether = _mm_loadu_si128((void *) veh);
            __m128i v_realign = _mm_alignr_epi8(v_ether, _mm_setzero_si128(),
                                                16 - VLAN_HEADER_LEN);
            _mm_storeu_si128((void *) veh, v_realign);
            avx512_dp_packet_resize_l2(packet, -VLAN_HEADER_LEN);
        }
    }
}

static void
action_avx512_push_vlan(void *dp OVS_UNUSED, struct dp_packet_batch *batch,
                       const struct nlattr *a,
                       bool should_steal OVS_UNUSED)
{
    struct dp_packet *packet;
    const struct ovs_action_push_vlan *vlan = nl_attr_get(a);
    ovs_be16 tpid, tci;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        tpid = vlan->vlan_tpid;
        tci = vlan->vlan_tci;

        avx512_dp_packet_resize_l2(packet, VLAN_HEADER_LEN);

        /* Build up the VLAN TCI/TPID, and merge with the moving of Ether. */
        char *pkt_data = (char *) dp_packet_data(packet);
        const uint16_t tci_proc = tci & htons(~VLAN_CFI);
        const uint32_t tpid_tci = (tci_proc << 16) | tpid;

        static const uint8_t vlan_push_shuffle_mask[16] = {
        4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 0xFF, 0xFF, 0xFF, 0xFF
        };

        __m128i v_ether = _mm_loadu_si128((void *) pkt_data);
        __m128i v_index = _mm_loadu_si128((void *) vlan_push_shuffle_mask);
        __m128i v_shift = _mm_shuffle_epi8(v_ether, v_index);
        __m128i v_vlan_hdr = _mm_insert_epi32(v_shift, tpid_tci, 3);
        _mm_storeu_si128((void *) pkt_data, v_vlan_hdr);

    }
}

static void
action_avx512_eth_set_addrs(void *dp OVS_UNUSED, struct dp_packet_batch *batch,
                       const struct nlattr *a,
                       bool should_steal OVS_UNUSED)
{
    a = nl_attr_get(a);
    const struct ovs_key_ethernet *key = nl_attr_get(a);
    const struct ovs_key_ethernet *mask = get_mask(a, struct ovs_key_ethernet);
    struct dp_packet *packet;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {

        struct eth_header *eh = dp_packet_eth(packet);

        if (!eh) {
            continue;
        }

        __m128i v_src = _mm_maskz_loadu_epi16(0x3F, key);
        __m128i v_mask = _mm_maskz_loadu_epi16(0x3F, mask);
        __m128i v_dst = _mm_maskz_loadu_epi16(0xFF, eh);

        __m128i dst_masked = _mm_andnot_si128(v_mask, v_dst);
        __m128i res = _mm_or_si128(v_src, dst_masked);

        __m128i res_blend = _mm_blend_epi16(v_dst, res, 0x3F);
        _mm_storeu_si128((void *) eh, res_blend);
    }
}

static inline uint16_t ALWAYS_INLINE
avx512_l4_update_csum(struct ip_header *old_header, __m256i res)
{
    uint16_t tmp_checksum;
    __m256i v_zeros = _mm256_setzero_si256();
    __m256i v_swap16a = _mm256_setr_epi16(0x0100, 0xffff, 0x0302, 0xffff,
                                          0x0504, 0xffff, 0x0706, 0xffff,
                                          0x0100, 0xffff, 0x0302, 0xffff,
                                          0xffff, 0xffff, 0xffff, 0xffff);
    __m256i v_swap16b = _mm256_setr_epi16(0x0908, 0xffff, 0xffff, 0xffff,
                                          0x0d0c, 0xffff, 0x0f0e, 0xffff,
                                          0xffff, 0xffff, 0xffff, 0xffff,
                                          0xffff, 0xffff, 0xffff, 0xffff);
    __m256i v_swap32a = _mm256_setr_epi32(0x0, 0x4, 0xF, 0xF,
                                          0xF, 0xF, 0xF, 0xF);

    __m256i oh = _mm256_loadu_si256((void *) old_header);
    oh = _mm256_mask_blend_epi16(0x3C0, oh, res);
    __m256i v_shuf1 = _mm256_shuffle_epi8(oh, v_swap16a);
    __m256i v_shuf2 = _mm256_shuffle_epi8(oh, v_swap16b);

    /* Add field values. */
    __m256i v_sum = _mm256_add_epi32(v_shuf1, v_shuf2);

    /* Perform horizontal add to go from 8x32-bits to 2x32-bits. */
    v_sum = _mm256_hadd_epi32(v_sum, v_zeros);
    v_sum = _mm256_hadd_epi32(v_sum, v_zeros);

    /* Shuffle 32-bit value from 3rd lane into first lane for final hadd. */
    v_sum = _mm256_permutexvar_epi32(v_swap32a, v_sum);
    v_sum = _mm256_hadd_epi32(v_sum, v_zeros);
    v_sum = _mm256_hadd_epi16(v_sum, v_zeros);

    /* Extract checksum value. */
    tmp_checksum = _mm256_extract_epi16(v_sum, 0);

    return ~tmp_checksum;
}

static inline uint16_t ALWAYS_INLINE
avx512_ipv4_recalc_csum(__m256i res)
{
    uint32_t new_checksum;
    __m256i v_zeros = _mm256_setzero_si256();

    __m256i v_swap16a = _mm256_setr_epi16(0x0100, 0xffff, 0x0302, 0xffff,
                                          0x0504, 0xffff, 0x0706, 0xffff,
                                          0x0100, 0xffff, 0x0302, 0xffff,
                                          0xffff, 0xffff, 0xffff, 0xffff);

    __m256i v_swap16b = _mm256_setr_epi16(0x0908, 0xffff, 0xffff, 0xffff,
                                          0x0d0c, 0xffff, 0x0f0e, 0xffff,
                                          0xffff, 0xffff, 0xffff, 0xffff,
                                          0xffff, 0xffff, 0xffff, 0xffff);

    __m256i v_swap32a = _mm256_setr_epi32(0x0, 0x4, 0xF, 0xF,
                                          0xF, 0xF, 0xF, 0xF);

    __m256i v_shuf1 = _mm256_shuffle_epi8(res, v_swap16a);
    __m256i v_shuf2 = _mm256_shuffle_epi8(res, v_swap16b);

    /* Add field values. */
    __m256i v_sum = _mm256_add_epi32(v_shuf1, v_shuf2);

    /* Perform horizontal add to go from 8x32-bits to 2x32-bits. */
    v_sum = _mm256_hadd_epi32(v_sum, v_zeros);
    v_sum = _mm256_hadd_epi32(v_sum, v_zeros);

    /* Shuffle 32-bit value from 3rd lane into first lane for final hadd. */
    v_sum = _mm256_permutexvar_epi32(v_swap32a, v_sum);
    v_sum = _mm256_hadd_epi32(v_sum, v_zeros);
    v_sum = _mm256_hadd_epi16(v_sum, v_zeros);

    /* Extract new checksum value. */
    new_checksum = _mm256_extract_epi16(v_sum, 0);

    return ~new_checksum;
}

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv4, ipv4_src) +
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_src) ==
                  offsetof(struct ovs_key_ipv4, ipv4_dst));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv4, ipv4_dst) +
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_dst) ==
                  offsetof(struct ovs_key_ipv4, ipv4_proto));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv4, ipv4_proto) +
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_proto) ==
                  offsetof(struct ovs_key_ipv4, ipv4_tos));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv4, ipv4_tos) +
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_tos) ==
                  offsetof(struct ovs_key_ipv4, ipv4_ttl));

static void
action_avx512_ipv4_set_addrs(void *dp OVS_UNUSED,
                             struct dp_packet_batch *batch,
                             const struct nlattr *a,
                             bool should_steal OVS_UNUSED)
{
    a = nl_attr_get(a);
    const struct ovs_key_ipv4 *key = nl_attr_get(a);
    const struct ovs_key_ipv4 *mask = get_mask(a, struct ovs_key_ipv4);
    struct dp_packet *packet;
    ovs_be16 old_csum;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        struct ip_header *nh = dp_packet_l3(packet);
        old_csum = nh->ip_csum;

        __m256i v_key = _mm256_loadu_si256((void *) key);
        __m256i v_mask = _mm256_loadu_si256((void *) mask);
        __m256i v_packet = _mm256_loadu_si256((void *) nh);

        /* Shuffle key and mask to match ip_header struct layout. */
        static const uint8_t ip_shuffle_mask[32] = {
            0xFF, 5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            6, 0xFF, 0xFF, 0xFF, 0, 1, 2, 3,
            0, 1, 2, 3, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        __m256i v_shuf32 = _mm256_setr_epi32(0x0, 0x2, 0xF, 0xF,
                                             0x1, 0xF, 0xF, 0xF);

        __m256i v_shuffle = _mm256_loadu_si256((void *) ip_shuffle_mask);

        __m256i v_key_shuf = _mm256_permutexvar_epi32(v_shuf32, v_key);
        v_key_shuf = _mm256_shuffle_epi8(v_key_shuf, v_shuffle);

        __m256i v_mask_shuf = _mm256_permutexvar_epi32(v_shuf32, v_mask);
        v_mask_shuf = _mm256_shuffle_epi8(v_mask_shuf, v_shuffle);

        __m256i v_pkt_masked = _mm256_andnot_si256(v_mask_shuf, v_packet);
        __m256i v_res = _mm256_or_si256(v_key_shuf, v_pkt_masked);

        /* Update checksum. */
        uint16_t checksum = avx512_ipv4_recalc_csum(v_res);

        /* Insert new checksum. */
        v_res = _mm256_insert_epi16(v_res, checksum, 5);

       /* If ip_src or ip_dst has been modified, L4 checksum needs to
        * be updated too.
        */
        int update_mask = _mm256_movemask_epi8(v_mask);
        if (update_mask & 0xFF) {

            uint16_t tmp_checksum = avx512_l4_update_csum(nh, v_res);
            tmp_checksum = ~tmp_checksum;
            uint16_t csum;

            if (nh->ip_proto == IPPROTO_UDP) {
                /* New UDP checksum. */
                struct udp_header *uh = dp_packet_l4(packet);
                if (uh->udp_csum) {
                    uint16_t old_udp_checksum = ~uh->udp_csum;

                    uint32_t udp_checksum = old_csum + tmp_checksum;
                    udp_checksum = csum_finish(udp_checksum);
                    uint16_t udp_csum = ~udp_checksum;

                    uint32_t nw_udp_checksum = udp_csum + old_udp_checksum;

                    csum =  csum_finish(nw_udp_checksum);

                    /* Insert new udp checksum. */
                    v_res = _mm256_insert_epi16(v_res, csum, 13);
                }
            }
            if (nh->ip_proto == IPPROTO_TCP) {
                /* New TCP checksum. */
                struct tcp_header *th = dp_packet_l4(packet);
                uint16_t old_tcp_checksum = ~th->tcp_csum;

                uint32_t tcp_checksum = old_csum + tmp_checksum;
                tcp_checksum = csum_finish(tcp_checksum);
                uint16_t tcp_csum = ~tcp_checksum;

                uint32_t nw_tcp_checksum = tcp_csum + old_tcp_checksum;

                csum =  csum_finish(nw_tcp_checksum);

                th->tcp_csum = csum;
            }
        }

        /* Store new IP header. */
        _mm256_storeu_si256((void *) nh, v_res);
    }
}

static void
action_avx512_set_masked(void *dp OVS_UNUSED,
                         struct dp_packet_batch *batch OVS_UNUSED,
                         const struct nlattr *a,
                         bool should_steal OVS_UNUSED)
{
    a = nl_attr_get(a);
    enum ovs_key_attr attr_type = nl_attr_type(a);

    if (active_impl.set_masked_funcs[attr_type]) {
        active_impl.set_masked_funcs[attr_type](NULL, batch, a, should_steal);
    }

}

/* Probe functions to check ISA requirements. */
static int32_t
avx512_isa_probe(uint32_t needs_vbmi)
{
    static enum ovs_cpu_isa isa_required[] = {
        OVS_CPU_ISA_X86_AVX512F,
        OVS_CPU_ISA_X86_AVX512BW,
        OVS_CPU_ISA_X86_BMI2,
        OVS_CPU_ISA_X86_AVX512VL
    };

    int32_t ret = 0;
    for (uint32_t i = 0; i < ARRAY_SIZE(isa_required); i++) {
        if (!cpu_has_isa(isa_required[i])) {
            ret = -ENOTSUP;
        }
    }

    if (needs_vbmi) {
        if (!cpu_has_isa(OVS_CPU_ISA_X86_AVX512VBMI)) {
            ret = -ENOTSUP;
        }
    }

    return ret;
}

int32_t
action_avx512_probe(void)
{
    const uint32_t needs_vbmi = 0;
    return avx512_isa_probe(needs_vbmi);
}

int32_t
action_avx512_init(struct odp_execute_action_impl *self)
{
    avx512_isa_probe(0);
    self->funcs[OVS_ACTION_ATTR_POP_VLAN] = action_avx512_pop_vlan;
    self->funcs[OVS_ACTION_ATTR_PUSH_VLAN] = action_avx512_push_vlan;
    self->funcs[OVS_ACTION_ATTR_SET_MASKED] = action_avx512_set_masked;
    self->set_masked_funcs[OVS_KEY_ATTR_ETHERNET] =
                            action_avx512_eth_set_addrs;
    self->set_masked_funcs[OVS_KEY_ATTR_IPV4] =
                            action_avx512_ipv4_set_addrs;
    active_impl = *self;

    return 0;
}

#endif
#endif
