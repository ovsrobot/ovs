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

#include <config.h>
#include <pcap.h>
#undef NDEBUG
#include "dpif-netdev-private-dpcls.h"
#include "dpif-netdev-private-extract.h"
#include "dpif-netdev-private-thread.h"
#include "packets.h"
#include "ovstest.h"
#include "util.h"

static void
test_mfex_main(int argc, char *argv[])
{

    struct dp_packet_batch packets;
    struct netdev_flow_key keys[NETDEV_MAX_BURST];
    struct dp_packet *buf;
    struct pcap_pkthdr header;
    char error_buffer[PCAP_ERRBUF_SIZE];
    const u_char *packet_char;
    pcap_t *handle;
    struct dp_netdev_pmd_thread *pmd = xzalloc(sizeof (*pmd));

    if (argc < 2) {
        ovs_fatal(errno, "Pcap file name not provided");
    }

    handle = pcap_open_offline(argv[1], error_buffer);
    if (!handle) {
        ovs_fatal(errno, "failed to open pcap file");
    }

    pmd->miniflow_extract_opt = NULL;
    dp_packet_batch_init(&packets);
    dpif_miniflow_extract_init();

    while ((packet_char = pcap_next(handle, &header))) {
        buf = dp_packet_new(header.caplen);
        dp_packet_put(buf, packet_char, header.caplen);
        buf->mbuf.data_len = (uint16_t) header.caplen;
        dp_packet_batch_add(&packets, buf);

        if (dp_packet_batch_size(&packets)  == NETDEV_MAX_BURST) {
            dpif_miniflow_extract_autovalidator(&packets, &keys[0],
                                                NETDEV_MAX_BURST, 1, pmd);
            dp_packet_delete_batch(&packets, true);
        }
    }

    free(pmd);
    pcap_close(handle);
}

OVSTEST_REGISTER("test-mfex", test_mfex_main);
