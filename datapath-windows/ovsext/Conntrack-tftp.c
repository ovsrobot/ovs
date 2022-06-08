/*
 * Copyright (c) 2022 VMware, Inc.
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
#include <string.h>
#include "Actions.h"
#include "Conntrack.h"
#include "PacketParser.h"
#include "Util.h"

NDIS_STATUS
OvsCtHandleTftp(PNET_BUFFER_LIST curNbl, OvsFlowKey *key,
                OVS_PACKET_HDR_INFO *layers, UINT64 currentTime,
                POVS_CT_ENTRY entry)
{
    UDPHdr udpStorage;
    const UDPHdr *udp = NULL;
    struct ct_addr serverIp;
    struct ct_addr clientIp;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    udp = OvsGetUdp(curNbl, layers->l4Offset, &udpStorage);
    if (!udp) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    RtlZeroMemory(&serverIp, sizeof(serverIp));
    RtlZeroMemory(&clientIp, sizeof(clientIp));

    if (OvsCtRelatedLookup(entry->key, currentTime)) {
        return NDIS_STATUS_SUCCESS;
    }

    if (layers->isIPv4) {
        serverIp.ipv4 = key->ipKey.nwDst;
        clientIp.ipv4 = key->ipKey.nwSrc;
        status = OvsCtRelatedEntryCreate(key->ipKey.nwProto,
                                         key->l2.dlType,
                                         serverIp,
                                         clientIp,
                                         0,
                                         udp->source,
                                         currentTime,
                                         entry);
    } else {
        serverIp.ipv6 = key->ipv6Key.ipv6Dst;
        clientIp.ipv6 = key->ipv6Key.ipv6Src;
        status = OvsCtRelatedEntryCreate(key->ipv6Key.nwProto,
                                         key->l2.dlType,
                                         serverIp,
                                         clientIp,
                                         0,
                                         udp->source,
                                         currentTime,
                                         entry);
    }

    return status;
}