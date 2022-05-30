/*
 * Copyright (c) 2022 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __ERSPAN_H_
#define __ERSPAN_H_ 1

#include "Flow.h"
#include "IpHelper.h"
#include "NetProto.h"

/*
 * GRE header for ERSPAN type I encapsulation (4 octets [34:37])
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |0|0|0|0|0|00000|000000000|00000|    Protocol Type for ERSPAN   |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  The Type I ERSPAN frame format is based on the barebones IP + GRE
 *  encapsulation (as described above) on top of the raw mirrored frame.
 *  There is no extra ERSPAN header.
 *
 *
 * GRE header for ERSPAN type II and II encapsulation (8 octets [34:41])
 *       0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |0|0|0|1|0|00000|000000000|00000|    Protocol Type for ERSPAN   |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |      Sequence Number (increments per packet per session)      |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Note that in the above GRE header [RFC1701] out of the C, R, K, S,
 *  s, Recur, Flags, Version fields only S (bit 03) is set to 1. The
 *  other fields are set to zero, so only a sequence number follows.
 *
 *  ERSPAN Version 1 (Type II) header (8 octets [42:49])
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Ver  |          VLAN         | COS | En|T|    Session ID     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Reserved         |                  Index                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *  ERSPAN Version 2 (Type III) header (12 octets [42:49])
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Ver  |          VLAN         | COS |BSO|T|     Session ID    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Timestamp                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             SGT               |P|    FT   |   Hw ID   |D|Gra|O|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *      Platform Specific SubHeader (8 octets, optional)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Platf ID |               Platform Specific Info              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Platform Specific Info                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * GRE proto ERSPAN type I/II = 0x88BE, type III = 0x22EB
 */

typedef struct _OVS_ERSPAN_VPORT {
    UINT64 ipId;
    UINT32 seqno;
    UINT16 vlan;
    UINT8 index;
} OVS_ERSPAN_VPORT, *POVS_ERSPAN_VPORT;

typedef struct _ERSPANHdr {
#ifdef WORDS_BIGENDIAN
    UINT8 ver:4,
          vlan_upper:4;
    UINT8 vlan:8;
    UINT8 cos:3,
          en:2,
          t:1,
          session_id_upper:2;
    UINT8 session_id:8;
#else
    UINT8 vlan_upper:4,
          ver:4;
    UINT8 vlan:8;
    UINT8 session_id_upper:2,
          t:1,
          en:2,
          cos:3;
    UINT8 session_id:8;
#endif
    UINT32 index;
} ERSPANHdr, *PERSPANHdr;


#define ETH_P_ERSPAN    0x88BE
#define ETH_P_ERSPAN2   0x22EB
#define ERSPAN_VERSION  0x1

#define VER_MASK    0xf000
#define VLAN_MASK   0x0fff
#define COS_MASK    0xe000
#define EN_MASK     0x1800
#define T_MASK      0x0400
#define ID_MASK     0x03ff
#define INDEX_MASK  0xfffff

#define ERSPAN_VERSION2 0x2 /* ERSPAN type III*/
#define BSO_MASK    EN_MASK
#define SGT_MASK    0xffff0000
#define P_MASK      0x8000
#define FT_MASK     0x7c00
#define HWID_MASK   0x03f0
#define DIR_MASK    0x0008
#define GRA_MASK    0x0006
#define O_MASK      0x0001

#define HWID_OFFSET    4
#define DIR_OFFSET     3

enum erspan_encap_type {
    ERSPAN_ENCAP_NOVLAN = 0x0,  /* originally without VLAN tag */
    ERSPAN_ENCAP_ISL = 0x1,     /* originally ISL encapsulated */
    ERSPAN_ENCAP_8021Q = 0x2,   /* originally 802.1Q encapsulated */
    ERSPAN_ENCAP_INFRAME = 0x3, /* VLAN tag perserved in frame */
};

NTSTATUS OvsInitErspanTunnel(POVS_VPORT_ENTRY vport);

VOID OvsCleanupErspanTunnel(POVS_VPORT_ENTRY vport);

NDIS_STATUS OvsEncapErspan(POVS_VPORT_ENTRY vport,
    PNET_BUFFER_LIST curNbl,
    OvsIPTunnelKey* tunKey,
    POVS_SWITCH_CONTEXT switchContext,
    POVS_PACKET_HDR_INFO layers,
    PNET_BUFFER_LIST* newNbl,
    POVS_FWD_INFO switchFwdInfo);

NDIS_STATUS OvsDecapErspan(POVS_SWITCH_CONTEXT switchContext,
    PNET_BUFFER_LIST curNbl,
    OvsIPTunnelKey* tunKey,
    PNET_BUFFER_LIST* newNbl);

static inline void
SetSessionId(ERSPANHdr *ershdr, UINT16 id)
{
    ershdr->session_id = id & 0xff;
    ershdr->session_id_upper = (id >> 8) & 0x3;
}

static inline UINT16
GetSessionId(const ERSPANHdr *ershdr)
{
    return (ershdr->session_id_upper << 8) + ershdr->session_id;
}

static inline void
SetVlan(ERSPANHdr *ershdr, UINT16 vlan)
{
    ershdr->vlan = vlan & 0xff;
    ershdr->vlan_upper = (vlan >> 8) & 0xf;
}

static inline UINT16
GetVlan(const ERSPANHdr *ershdr)
{
    return (ershdr->vlan_upper << 8) + ershdr->vlan;
}

static inline UINT8
TosToCos(UINT8 tos)
{
    UINT8 dscp, cos;

    dscp = tos >> 2;
    cos = dscp >> 3;
    return cos;
}

#endif /* __ERSPAN_H_ */
