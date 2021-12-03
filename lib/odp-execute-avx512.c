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

#include "dpdk.h"
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

static inline void ALWAYS_INLINE
avx512_dp_packet_resize_l2(struct dp_packet *b, int increment)
{
    /* update packet size/data pointers */
    dp_packet_set_data(b, (char *) dp_packet_data(b) - increment);
    dp_packet_set_size(b, dp_packet_size(b) + increment);

    /* Increment u16 packet offset values */
    const __m128i v_zeros = _mm_setzero_si128();
    const __m128i v_u16_max = _mm_cmpeq_epi16(v_zeros, v_zeros);

    /* Only these lanes can be incremented for push-VLAN action. */
    const uint8_t k_lanes = 0b1110;
    __m128i v_offset = _mm_set1_epi16(VLAN_HEADER_LEN);

    /* Load packet and compare with UINT16_MAX */
    void *adjust_ptr = &b->l2_pad_size;
    __m128i v_adjust_src = _mm_loadu_si128(adjust_ptr);
    __mmask8 k_cmp = _mm_mask_cmpneq_epu16_mask(k_lanes, v_adjust_src,
                                                    v_u16_max);

    /* Add VLAN_HEADER_LEN using compare mask, store results. */
    __m128i v_adjust_wip = _mm_mask_sub_epi16(v_adjust_src, k_cmp,
                                              v_adjust_src, v_offset);
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
        avx512_dp_packet_resize_l2(packet, -VLAN_HEADER_LEN);

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

/* Probe functions to check ISA requirements. */
static int32_t
avx512_isa_probe(uint32_t needs_vbmi)
{
    static const char *isa_required[] = {
        "avx512f",
        "avx512bw",
        "bmi2",
        "avx512vl"
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

    return 0;
}

#endif
#endif
