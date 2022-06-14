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

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ethernet, eth_src) +
                  MEMBER_SIZEOF(struct ovs_key_ethernet, eth_src) ==
                  offsetof(struct ovs_key_ethernet, eth_dst));

static struct odp_execute_action_impl avx512_impl;

/* Adjust the size of the l2 portion of the dp_packet, updating the l2
 * pointer and the layer offsets. The function will broadcast resize_by_bytes
 * across a register and uses a kmask to identify which lanes should be
 * incremented/decremented. Either an add or subtract will be performed
 * and the result is stored back to the original packet. */
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

    const __m128i v_zeros = _mm_setzero_si128();
    const __m128i v_u16_max = _mm_cmpeq_epi16(v_zeros, v_zeros);

    const uint8_t k_lanes = 0b1110;
    __m128i v_offset = _mm_set1_epi16(abs(resize_by_bytes));

    /* Load 128 bits from the dp_packet structure starting at the l2_pad_size
     * offset. */
    void *adjust_ptr = &b->l2_pad_size;
    __m128i v_adjust_src = _mm_loadu_si128(adjust_ptr);

    __mmask8 k_cmp = _mm_mask_cmpneq_epu16_mask(k_lanes, v_adjust_src,
                                                v_u16_max);

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

/* This function will load the entire vlan_eth_header into a 128-bit wide
 * register. Then use an 8-byte realign to shift the header right by 12 bytes
 * to remove the vlan header and store the results back to the orginal header.
 */
static void
action_avx512_pop_vlan(struct dp_packet_batch *batch,
                       const struct nlattr *a OVS_UNUSED)
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

/* This function will load the entire eth_header into a 128-bit wide register.
 * Then use an 8-byte shuffle to shift the data left to make room for
 * the vlan header. Insert the new vlan header and then store back to the
 * original packet. */
static void
action_avx512_push_vlan(struct dp_packet_batch *batch, const struct nlattr *a)
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

/* This function will load the contents of eth_header into a 128-bit wide
 * register. Then an 8-byte shuffle is required to shuffle both key and
 * mask to match the layout of the eth_header struct. A bitwise ANDNOT and OR
 * is performed on the entire header and results are stored back. */
static void
action_avx512_eth_set_addrs(struct dp_packet_batch *batch,
                            const struct nlattr *a)
{
    a = nl_attr_get(a);
    const struct ovs_key_ethernet *key = nl_attr_get(a);
    const struct ovs_key_ethernet *mask = get_mask(a, struct ovs_key_ethernet);
    struct dp_packet *packet;

    __m128i v_src = _mm_loadu_si128((void *) key);
    __m128i v_mask = _mm_loadu_si128((void *) mask);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {

        struct eth_header *eh = dp_packet_eth(packet);

        if (!eh) {
            continue;
        }

        static const uint8_t eth_shuffle[16] = {
            6, 7, 8, 9, 10, 11, 0, 1,
            2, 3, 4, 5, 12, 13, 14, 15
        };

        __m128i v_dst = _mm_loadu_si128((void *) eh);
        __m128i v_shuf = _mm_loadu_si128((void *) eth_shuffle);

        v_src = _mm_shuffle_epi8(v_src, v_shuf);
        v_mask = _mm_shuffle_epi8(v_mask, v_shuf);

        __m128i dst_masked = _mm_andnot_si128(v_mask, v_dst);
        __m128i res = _mm_or_si128(v_src, dst_masked);

        __m128i res_blend = _mm_blend_epi16(v_dst, res, 0x3F);
        _mm_storeu_si128((void *) eh, res_blend);
    }
}

static void
action_avx512_set_masked(struct dp_packet_batch *batch OVS_UNUSED,
                         const struct nlattr *a)
{
    a = nl_attr_get(a);
    enum ovs_key_attr attr_type = nl_attr_type(a);

    if (avx512_impl.set_masked_funcs[attr_type]) {
        avx512_impl.set_masked_funcs[attr_type](batch, a);
    }
}

/* Probe functions to check ISA requirements. */
static bool
avx512_isa_probe(void)
{
    static enum ovs_cpu_isa isa_required[] = {
        OVS_CPU_ISA_X86_AVX512F,
        OVS_CPU_ISA_X86_AVX512BW,
        OVS_CPU_ISA_X86_BMI2,
        OVS_CPU_ISA_X86_AVX512VL,
    };

    bool ret = true;
    for (int i = 0; i < ARRAY_SIZE(isa_required); i++) {
        if (!cpu_has_isa(isa_required[i])) {
            ret = -ENOTSUP;
        }
    }

    return ret;
}

int
action_avx512_init(struct odp_execute_action_impl *self)
{
    if (!avx512_isa_probe()) {
        return -ENOTSUP;
    }

    /* Set function pointers for actions that can be applied directly, these
     * are identified by OVS_ACTION_ATTR_*. */
    self->funcs[OVS_ACTION_ATTR_POP_VLAN] = action_avx512_pop_vlan;
    self->funcs[OVS_ACTION_ATTR_PUSH_VLAN] = action_avx512_push_vlan;
    self->funcs[OVS_ACTION_ATTR_SET_MASKED] = action_avx512_set_masked;

    /* Set function pointers that need a 2nd-level function. SET_MASKED action
     * requires further processing for action type. Note that 2nd level items
     * are identified by OVS_KEY_ATTR_*. */
    self->set_masked_funcs[OVS_KEY_ATTR_ETHERNET] =
                            action_avx512_eth_set_addrs;
    avx512_impl = *self;

    return 0;
}

#endif
#endif
