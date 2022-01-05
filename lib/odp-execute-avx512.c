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

#ifdef __x86_64__
/* Sparse cannot handle the AVX512 instructions. */
#if !defined(__CHECKER__)


#include <config.h>
#include <errno.h>

#include "cpu.h"
#include "odp-execute-private.h"
#include "odp-netlink.h"
#include "dp-packet.h"
#include "openvswitch/vlog.h"

#include "immintrin.h"

VLOG_DEFINE_THIS_MODULE(odp_execute_avx512);
BUILD_ASSERT_DECL(offsetof(struct dp_packet, l2_5_ofs) +
                  MEMBER_SIZEOF(struct dp_packet, l2_5_ofs) ==
                  offsetof(struct dp_packet, l3_ofs));

BUILD_ASSERT_DECL(offsetof(struct dp_packet, l3_ofs) +
                           MEMBER_SIZEOF(struct dp_packet, l3_ofs) ==
                           offsetof(struct dp_packet, l4_ofs));

enum OPERATION {
    OP_ADD,
    OP_SUB,
};

static inline void ALWAYS_INLINE
avx512_dp_packet_resize_l2(struct dp_packet *b, int increment,
                           enum OPERATION op)
{
    /* update packet size/data pointers */
    if (increment >= 0) {
        dp_packet_prealloc_headroom(b, increment);
    } else {
        ovs_assert(dp_packet_size(b) - dp_packet_l2_pad_size(b) >= -increment);
    }

    dp_packet_set_data(b, (char *) dp_packet_data(b) - increment);
    dp_packet_set_size(b, dp_packet_size(b) + increment);

    /* Increment u16 packet offset values */
    const __m128i v_zeros = _mm_setzero_si128();
    const __m128i v_u16_max = _mm_cmpeq_epi16(v_zeros, v_zeros);

    /* Only these lanes can be incremented/decremented for L2. */
    const uint8_t k_lanes = 0b1110;
    __m128i v_offset = _mm_set1_epi16(abs(increment));

    /* Load packet and compare with UINT16_MAX */
    void *adjust_ptr = &b->l2_pad_size;
    __m128i v_adjust_src = _mm_loadu_si128(adjust_ptr);
    __mmask8 k_cmp = _mm_mask_cmpneq_epu16_mask(k_lanes, v_adjust_src,
                                                    v_u16_max);

    /* Update VLAN_HEADER_LEN using compare mask, store results. */
    __m128i v_adjust_wip;
    switch (op) {
    case OP_ADD:
        v_adjust_wip = _mm_mask_add_epi16(v_adjust_src, k_cmp,
                                            v_adjust_src, v_offset);
        break;
    case OP_SUB:
        v_adjust_wip = _mm_mask_sub_epi16(v_adjust_src, k_cmp,
                                            v_adjust_src, v_offset);
        break;
    }

    _mm_storeu_si128(adjust_ptr, v_adjust_wip);

}

static inline void ALWAYS_INLINE
avx512_eth_pop_vlan(struct dp_packet *packet)
{
    struct vlan_eth_header *veh = dp_packet_eth(packet);

    if (veh && dp_packet_size(packet) >= sizeof *veh &&
        eth_type_vlan(veh->veth_type)) {

        __m128i v_ether = _mm_loadu_si128((void *) veh);
        __m128i v_realign = _mm_alignr_epi8(v_ether, _mm_setzero_si128(),
                                            16 - VLAN_HEADER_LEN);
        _mm_storeu_si128((void *) veh, v_realign);
        avx512_dp_packet_resize_l2(packet, -VLAN_HEADER_LEN, OP_SUB);
    }
}

static void
action_avx512_pop_vlan(void *dp OVS_UNUSED, struct dp_packet_batch *batch,
                       const struct nlattr *a OVS_UNUSED,
                       bool should_steal OVS_UNUSED)
{
    struct dp_packet *packet;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        avx512_eth_pop_vlan(packet);
    }
}

static inline void ALWAYS_INLINE
avx512_eth_push_vlan(struct dp_packet *packet, ovs_be16 tpid, ovs_be16 tci)
{
    avx512_dp_packet_resize_l2(packet, VLAN_HEADER_LEN, OP_ADD);

    /* Build up the VLAN TCI/TPID, and merge with the moving of Ether. */
    char *new_pkt_data = (char *) dp_packet_data(packet);

    const uint16_t tci_proc = tci & htons(~VLAN_CFI);
    const uint32_t tpid_tci = (tci_proc << 16) | tpid;
    __m128i v_ether = _mm_loadu_si128((void *) new_pkt_data);

    static const uint8_t vlan_push_shuffle_mask[16] = {
    4, 5, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 0xFF, 0xFF, 0xFF, 0xFF
    };

    __m128i v_index = _mm_loadu_si128((void *) vlan_push_shuffle_mask);
    __m128i v_shift = _mm_shuffle_epi8(v_ether, v_index);
    __m128i v_vlan_hdr = _mm_insert_epi32(v_shift, tpid_tci, 3);
     _mm_storeu_si128((void *) new_pkt_data, v_vlan_hdr);
}

static void
action_avx512_push_vlan(void *dp OVS_UNUSED, struct dp_packet_batch *batch,
                       const struct nlattr *a,
                       bool should_steal OVS_UNUSED)
{
    struct dp_packet *packet;
    const struct ovs_action_push_vlan *vlan = nl_attr_get(a);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        avx512_eth_push_vlan(packet, vlan->vlan_tpid, vlan->vlan_tci);
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

    return 0;
}

#endif
#endif
