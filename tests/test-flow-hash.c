#include <config.h>
#include <string.h>
#include "lib/flow.h"
#include "lib/dp-packet.h"
#include "tests/ovstest.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(test_flow_hash);

struct packet_hashes {
    uint32_t flow_hash;
    uint32_t miniflow_hash;
};

/* Utility to print hex dump of a packet */
static void
log_hex_dump(const char *label, const uint8_t *data, size_t len)
{
    char line[128];
    size_t i;

    VLOG_INFO("%s (len=%lu):", label, (unsigned long) len);
    for (i = 0; i < len; i += 16) {
        size_t j, line_len = 0;
        line_len += snprintf(line + line_len, sizeof(line) - line_len,
                             "  %04x: ", i);
        for (j = 0; j < 16 && i + j < len; j++) {
            line_len += snprintf(line + line_len, sizeof(line) - line_len,
                                 "%02x ", data[i + j]);
        }
        VLOG_INFO("%s", line);
    }
}

/* Extracts flow and miniflow from packet and computes their 5-tuple hashes */
static struct packet_hashes
get_packet_hashes(const void *data, size_t size,
                  uint32_t basis,
                  const char *label)
{
    struct packet_hashes hashes;
    struct dp_packet packet;
    dp_packet_use_const(&packet, data, size);

    struct flow flow;
    flow_extract(&packet, &flow);
    hashes.flow_hash = flow_hash_5tuple(&flow, basis);

    struct {
        struct miniflow miniflow;
        uint64_t buffer[FLOW_U64S];
    } mf_buf;
    miniflow_extract(&packet, &mf_buf.miniflow);
    hashes.miniflow_hash = miniflow_hash_5tuple(&mf_buf.miniflow, basis);

    const char *frag_type;
    uint8_t frag_flags = flow.nw_frag & FLOW_NW_FRAG_MASK;

    if (frag_flags == 0) {
        frag_type = "not fragmented";
    } else if (frag_flags & FLOW_NW_FRAG_LATER) {
        frag_type = "non-first fragment";
    } else {
        frag_type = "first fragment or unknown";
    }

    VLOG_INFO("%s:", label);
    VLOG_INFO("  Src IP: "IP_FMT", Dst IP: "IP_FMT,
              IP_ARGS(&flow.nw_src),
              IP_ARGS(&flow.nw_dst));
    VLOG_INFO("  Src Port: %u, Dst Port: %u, Proto: %u",
              ntohs(flow.tp_src),
              ntohs(flow.tp_dst),
              flow.nw_proto);
    VLOG_INFO("  Frag Type: %s", frag_type);
    VLOG_INFO("  flow_hash:     0x%08x", hashes.flow_hash);
    VLOG_INFO("  miniflow_hash: 0x%08x", hashes.miniflow_hash);

    log_hex_dump(label, data, size);

    return hashes;
}

static void
test_udp_fragment_hash_consistency(int argc OVS_UNUSED,
                                   char *argv[] OVS_UNUSED)
{
    const uint32_t basis = 54321;

    /* Packet 1: Normal, unfragmented UDP packet (DF bit set). */
    const uint8_t normal_packet[] = {
        0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,
        0x00,0x00,0x00,0x02,0x08,0x00,0x45,0x00,
        0x00,0x28,0x12,0x34,0x40,0x00,0x40,0x11,
        0x7c,0xd1,0xc0,0xa8,0x01,0x01,0xc0,0xa8,
        0x01,0x02,0xc0,0x01,0xc0,0x02,0x00,0x18,
        0xab,0xcd,'a','b','c','d','e','f','g',
        'h','i','j','k','l'
    };

    /* Packet 2: First fragment (MF bit set, offset 0). */
    const uint8_t first_frag_packet[] = {
        0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,
        0x00,0x00,0x00,0x02,0x08,0x00,0x45,0x00,
        0x00,0x1c,0x12,0x34,0x20,0x00,0x40,0x11,
        0x7c,0xd7,0xc0,0xa8,0x01,0x01,0xc0,0xa8,
        0x01,0x02,0xc0,0x01,0xc0,0x02,0x00,0x18,
        0xab,0xcd
    };

    /* Packet 3: Second/Middle fragment (MF bit set, non-zero offset). */
    const uint8_t middle_frag_packet[] = {
        0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,
        0x00,0x00,0x00,0x02,0x08,0x00,0x45,0x00,
        0x00,0x1c,0x12,0x34,0x20,0x01,0x40,0x11,
        0x7c,0xd6,0xc0,0xa8,0x01,0x01,0xc0,0xa8,
        0x01,0x02,'i','j','k','l','m','n','o','p'
    };

    /* Packet 4: Last fragment (MF bit clear, non-zero offset). */
    const uint8_t last_frag_packet[] = {
        0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,
        0x00,0x00,0x00,0x02,0x08,0x00,0x45,0x00,
        0x00,0x1a,0x12,0x34,0x00,0x02,0x40,0x11,
        0x9c,0xd5,0xc0,0xa8,0x01,0x01,0xc0,0xa8,
        0x01,0x02,'q','r','s','t','u','v'
    };

    struct packet_hashes
        normal_h = get_packet_hashes(normal_packet,
                                     sizeof(normal_packet),
                                     basis,
                                     "Normal Packet");
    struct packet_hashes
        first_frag_h = get_packet_hashes(first_frag_packet,
                                         sizeof(first_frag_packet),
                                         basis,
                                         "First Fragment");
    struct packet_hashes
        middle_frag_h = get_packet_hashes(middle_frag_packet,
                                          sizeof(middle_frag_packet),
                                          basis,
                                          "Middle Fragment");
    struct packet_hashes
        last_frag_h = get_packet_hashes(last_frag_packet,
                                        sizeof(last_frag_packet),
                                        basis,
                                        "Last Fragment");

    ovs_assert(normal_h.flow_hash      == normal_h.miniflow_hash);
    ovs_assert(first_frag_h.flow_hash  == first_frag_h.miniflow_hash);
    ovs_assert(middle_frag_h.flow_hash == middle_frag_h.miniflow_hash);
    ovs_assert(last_frag_h.flow_hash   == last_frag_h.miniflow_hash);

    ovs_assert(normal_h.flow_hash != first_frag_h.flow_hash);
    ovs_assert(middle_frag_h.flow_hash == last_frag_h.flow_hash);
    ovs_assert(first_frag_h.flow_hash == middle_frag_h.flow_hash);
}

OVSTEST_REGISTER("test-flow-hash", test_udp_fragment_hash_consistency);
